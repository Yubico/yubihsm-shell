/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winhttp.h>
#include <winsock.h>
#include <wchar.h>
#include <stdbool.h>
#include <stdint.h>

#include "yubihsm.h"
#include "internal.h"
#include "debug_lib.h"

#define MAX_STR_LEN 128
#define UNUSED(x) (void) (x)

struct urlComponents {
  bool https;
  wchar_t hostname[MAX_STR_LEN + 1];
  int port;
  wchar_t path[MAX_STR_LEN + 1];
};

struct state {
  HINTERNET session;
  HINTERNET connection;
  yh_connector *connector;
  struct urlComponents status_url;
  struct urlComponents api_url;
};

uint8_t YH_INTERNAL _yh_verbosity;
FILE YH_INTERNAL *_yh_output;

static bool parseUrl(const char *url, struct urlComponents *components) {
  wchar_t wUrl[MAX_STR_LEN * 2];
  size_t len = mbstowcs(wUrl, url, _countof(wUrl));
  if (len == _countof(wUrl)) {
    return false;
  }

  URL_COMPONENTS c = {sizeof(c)};
  c.lpszHostName = components->hostname;
  c.dwHostNameLength = _countof(components->hostname);
  c.lpszUrlPath = components->path;
  c.dwUrlPathLength = _countof(components->path);

  if (!WinHttpCrackUrl(wUrl, (DWORD) len, 0, &c)) {
    return false;
  }

  components->https = c.nScheme == INTERNET_SCHEME_HTTPS;
  components->port = c.nPort;

  return true;
}

static void backend_set_verbosity(uint8_t verbosity, FILE *output) {
  _yh_verbosity = verbosity;
  _yh_output = output;
}

static yh_rc backend_init(uint8_t verbosity, FILE *output) {
  DBG_INFO("backend_init");
  backend_set_verbosity(verbosity, output);
  return YHR_SUCCESS;
}

static void backend_cleanup(void) { DBG_INFO("backend_cleanup"); }

static yh_backend *backend_create(void) {
  DBG_INFO("backend_create");
  yh_backend *backend = calloc(1, sizeof(yh_backend));
  if (backend) {
    backend->session =
      WinHttpOpen(L"YubiHSM WinHttp/" VERSION, WINHTTP_ACCESS_TYPE_NO_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  }
  return backend;
}

static void backend_disconnect(yh_backend *connection) {
  DBG_INFO("backend_disconnect");
  WinHttpCloseHandle(connection->connection);
  WinHttpCloseHandle(connection->session);
  free(connection);
}

static yh_rc backend_connect(yh_connector *connector, int timeout) {
  DBG_INFO("backend_connect");
  if (timeout == 0) {
    // TODO: what does winhttp do if it gets timeout 0?
    timeout = 300;
  }

  yh_backend *backend = connector->connection;
  backend->connector = connector;

  if (!parseUrl(connector->status_url, &backend->status_url)) {
    DBG_ERR("Status URL parsing failed.");
    return YHR_INVALID_PARAMETERS;
  }

  if (!parseUrl(connector->api_url, &backend->api_url)) {
    DBG_ERR("Api URL parsing failed.");
    return YHR_INVALID_PARAMETERS;
  }

  DBG_INFO("Connecting to %s", connector->status_url);
  backend->connection =
    WinHttpConnect(backend->session, backend->status_url.hostname,
                   backend->status_url.port, 0);
  if (!backend->connection) {
    DBG_ERR("Failed connecting to %s", connector->status_url);
    return YHR_CONNECTOR_ERROR;
  }

  HINTERNET request =
    WinHttpOpenRequest(backend->connection, L"GET", backend->status_url.path,
                       NULL, NULL, WINHTTP_DEFAULT_ACCEPT_TYPES,
                       backend->status_url.https ? WINHTTP_FLAG_SECURE : 0);
  if (!request) {
    DBG_ERR("Failed opening request to %s", connector->status_url);
    return YHR_CONNECTOR_ERROR;
  }
  if (timeout > 0) {
    if (!WinHttpSetTimeouts(request, timeout * 1000, timeout * 1000,
                            timeout * 1000, timeout * 1000)) {
      DBG_ERR("Failed setting timeouts.");
    }
  }

  DBG_INFO("Sending request to %s", connector->status_url);
  if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
    DBG_ERR("Failed sending request to %s", connector->status_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  if (!WinHttpReceiveResponse(request, 0)) {
    DBG_ERR("Failed receiving response from %s", connector->status_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  DWORD dwStatusCode, dwSize = sizeof(dwStatusCode);

  if (!WinHttpQueryHeaders(request,
                           WINHTTP_QUERY_STATUS_CODE |
                             WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
                           WINHTTP_NO_HEADER_INDEX)) {
    DBG_ERR("Failed retrieveing status code from %s",
            backend->connector->status_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  if (dwStatusCode != 200) {
    DBG_ERR("Invalid status code %u received from %s", dwStatusCode,
            backend->connector->status_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  char buf[256];
  DWORD offs = 0, bytes;
  while (WinHttpReadData(request, buf + offs, sizeof(buf) - offs, &bytes)) {
    if (bytes == 0)
      break;
    offs += bytes;
    if (offs >= sizeof(buf))
      break;
  }

  DBG_INFO("Read %u bytes from %s", offs, connector->status_url);

  WinHttpCloseHandle(request);

  parse_status_data(buf, connector);
  if (!connector->has_device) {
    DBG_ERR("Response from %s indicates no device is present",
            connector->status_url);
    return YHR_CONNECTOR_NOT_FOUND;
  }

  return YHR_SUCCESS;
}

static yh_rc backend_send_msg(yh_backend *backend, Msg *msg, Msg *response,
                              const char *identifier) {
  uint16_t raw_len = ntohs(msg->st.len) + 3;
  wchar_t hsm_identifier[64];
  wchar_t *headers = WINHTTP_NO_ADDITIONAL_HEADERS;
  DWORD headers_len = 0;

  if (identifier != NULL && strlen(identifier) > 0 && strlen(identifier) < 32) {
    headers_len =
      swprintf(hsm_identifier, 64, L"YubiHSM-Session: %hs", identifier);
    headers = hsm_identifier;
  }

  HINTERNET request =
    WinHttpOpenRequest(backend->connection, L"POST", backend->api_url.path,
                       NULL, NULL, WINHTTP_DEFAULT_ACCEPT_TYPES,
                       backend->api_url.https ? WINHTTP_FLAG_SECURE : 0);
  if (!request) {
    DBG_ERR("Failed opening request to %s", backend->connector->api_url);
    return YHR_CONNECTOR_ERROR;
  }

  // TODO: replace these magic numbers with something better.
  //  of note here is the 250s timeout on receive, generating rsa4096 might take
  //  some time..
  if (!WinHttpSetTimeouts(request, 30 * 1000, 30 * 1000, 250 * 1000,
                          250 * 1000)) {
    DBG_ERR("Failed setting timeouts.");
  }

  DBG_INFO("Sending %u bytes to %s", raw_len, backend->connector->api_url);
  if (!WinHttpSendRequest(request, headers, headers_len, msg->raw, raw_len,
                          raw_len, 0)) {
    DBG_ERR("Failed sending request to %s", backend->connector->api_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  if (!WinHttpReceiveResponse(request, 0)) {
    DBG_ERR("Failed receiving response from %s", backend->connector->api_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  DWORD dwStatusCode, dwSize = sizeof(dwStatusCode);

  if (!WinHttpQueryHeaders(request,
                           WINHTTP_QUERY_STATUS_CODE |
                             WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
                           WINHTTP_NO_HEADER_INDEX)) {
    DBG_ERR("Failed retrieveing status code from %s",
            backend->connector->api_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  if (dwStatusCode != 200) {
    DBG_ERR("Invalid status code %u received from %s", dwStatusCode,
            backend->connector->api_url);
    WinHttpCloseHandle(request);
    return YHR_CONNECTOR_ERROR;
  }

  DWORD offs = 0, bytes;
  while (WinHttpReadData(request, response->raw + offs,
                         sizeof(response->raw) - offs, &bytes)) {
    if (bytes == 0)
      break;
    offs += bytes;
    if (offs >= sizeof(response->raw))
      break;
  }

  DBG_INFO("Read %u bytes from %s", offs, backend->connector->api_url);

  WinHttpCloseHandle(request);

  if (offs < 3) {
    DBG_ERR("Not enough data received; %lu", offs);
    return YHR_WRONG_LENGTH;
  }

  if (ntohs(response->st.len) != offs - 3) {
    DBG_ERR("Wrong length received, %d vs %lu", ntohs(response->st.len), offs);
    return YHR_WRONG_LENGTH;
  }

  return YHR_SUCCESS;
}

static yh_rc backend_option(yh_backend *connection, yh_connector_option opt,
                            const void *val) {
  (void) connection;
  (void) opt;
  (void) val;

  DBG_ERR("Backend options not (yet?) supported with winhttp");
  return YHR_CONNECTOR_ERROR;
}

static struct backend_functions f = {backend_init,     backend_create,
                                     backend_connect,  backend_disconnect,
                                     backend_send_msg, backend_cleanup,
                                     backend_option,   backend_set_verbosity};

#ifdef STATIC
struct backend_functions *http_backend_functions(void) {
#else
struct backend_functions *backend_functions(void) {
#endif
  return &f;
}
