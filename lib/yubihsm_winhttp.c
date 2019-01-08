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

struct urlComponents {
  bool https;
  wchar_t hostname[MAX_STR_LEN + 1];
  int port;
  wchar_t path[MAX_STR_LEN + 1];
};

enum stage {
  NO_INIT,
  REQUEST_SENT,
  RESPONSE_WAITING,
  RESPONSE_RECEIVED,
  DATA_AVAILABLE,
  DATA_WAITING,
  READ_COMPLETE,
  REQUEST_SUCCESS,
  REQUEST_ERROR,
  CLOSE_WAITING,
  REQUEST_CLOSED,
  REQUEST_DONE,
};

struct context {
  enum stage stage;
  CRITICAL_SECTION mtx;
  HINTERNET req;
  uint16_t len;
};

struct state {
  HINTERNET internet;
  HINTERNET con;
  yh_connector *connector;
  struct context *context;
};

uint8_t YH_INTERNAL _yh_verbosity;
FILE YH_INTERNAL *_yh_output;

static bool parseUrl(char *url, struct urlComponents *components) {
  wchar_t wUrl[129];
  size_t len = strlen(url);

  if (len > 128) {
    return false;
  }
  mbstowcs(wUrl, url, len);
  URL_COMPONENTS c = {0};
  c.dwStructSize = sizeof(c);
  c.dwSchemeLength = -1;
  c.dwHostNameLength = -1;
  c.dwUrlPathLength = -1;

  if (WinHttpCrackUrl(wUrl, len, 0, &c) != TRUE) {
    return false;
  }

  if (c.nScheme == INTERNET_SCHEME_HTTPS) {
    components->https = true;
  } else {
    components->https = false;
  }

  if (c.dwHostNameLength > MAX_STR_LEN || c.dwUrlPathLength > MAX_STR_LEN) {
    return false;
  }
  wcsncpy_s(components->hostname,
            sizeof(components->hostname) / sizeof(components->hostname[0]),
            c.lpszHostName, c.dwHostNameLength);
  wcsncpy_s(components->path,
            sizeof(components->path) / sizeof(components->path[0]),
            c.lpszUrlPath, c.dwUrlPathLength);
  components->port = c.nPort;
  return true;
}

static void CALLBACK http_callback(HINTERNET internet __attribute__((unused)),
                                   DWORD_PTR context, DWORD status,
                                   LPVOID statusInfo, DWORD statusInfoLen) {
  struct context *c = (struct context *) context;
  enum stage new_stage = NO_INIT;
  EnterCriticalSection(&c->mtx);
  switch (status) {
    case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
      DBG_INFO("sendreq complete");
      new_stage = REQUEST_SENT;
      break;
    case WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED:
      DBG_INFO("response received");
      new_stage = RESPONSE_RECEIVED;
      break;
    case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
      DBG_INFO("data available");
      new_stage = DATA_AVAILABLE;
      break;
    case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
      DBG_INFO("read complete");
      new_stage = READ_COMPLETE;
      c->len = statusInfoLen;
      break;
    case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: {
      WINHTTP_ASYNC_RESULT *result = (WINHTTP_ASYNC_RESULT *) statusInfo;
      DBG_ERR("Request error: %lu %lu", (long unsigned) result->dwResult,
              result->dwError);
      new_stage = REQUEST_ERROR;
    } break;
    case WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
      DBG_INFO("handle closing");
      new_stage = REQUEST_CLOSED;
      break;
  }
  if (new_stage > c->stage) {
    c->stage = new_stage;
  }
  LeaveCriticalSection(&c->mtx);
}

static void backend_set_verbosity(uint8_t verbosity, FILE *output) {
  _yh_verbosity = verbosity;
  _yh_output = output;
}

static yh_rc backend_init(uint8_t verbosity, FILE *output) {
  backend_set_verbosity(verbosity, output);
  return YHR_SUCCESS;
}

static void backend_cleanup(void) {}

static yh_backend *backend_create(void) {
  DBG_INFO("Doing backend_create");
  yh_backend *backend = calloc(1, sizeof(yh_backend));
  backend->internet =
    WinHttpOpen(L"YubiHSM WinHttp/" VERSION, WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
                WINHTTP_FLAG_ASYNC);
  backend->context = calloc(1, sizeof(struct context));
  InitializeCriticalSection(&backend->context->mtx);
  WinHttpSetOption(backend->internet, WINHTTP_OPTION_CONTEXT_VALUE,
                   &backend->context, sizeof(backend->context));
  WinHttpSetStatusCallback(backend->internet, http_callback,
                           WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS, 0);
  return backend;
}

static void backend_disconnect(yh_backend *connection) {
  WinHttpCloseHandle(connection->con);
  WinHttpCloseHandle(connection->internet);
  Sleep(1);
  EnterCriticalSection(&connection->context->mtx);
  DeleteCriticalSection(&connection->context->mtx);
  free(connection->context);
  free(connection);
}

static yh_rc backend_connect(yh_connector *connector, int timeout) {
  uint8_t buf[MAX_STR_LEN + 1];
  yh_rc res = YHR_CONNECTOR_ERROR;

  ZeroMemory(buf, MAX_STR_LEN + 1);

  if (timeout == 0) {
    // TODO: what does winhttp do if it gets timeout 0?
    timeout = 300;
  }

  struct urlComponents components = {0};
  yh_backend *backend = connector->connection;
  backend->connector = connector;
  DBG_INFO("setting up connection to %s", connector->status_url);
  if (parseUrl(connector->status_url, &components) == false) {
    DBG_INFO("URL parsing failed.");
    return YHR_INVALID_PARAMETERS;
  }
  backend->con =
    WinHttpConnect(backend->internet, components.hostname, components.port, 0);
  backend->context->stage = NO_INIT;
  backend->context->len = 0;
  backend->context->req =
    WinHttpOpenRequest(backend->con, L"GET", components.path, NULL, NULL,
                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                       components.https ? WINHTTP_FLAG_SECURE : 0);
  if (timeout > 0) {
    WinHttpSetTimeouts(backend->context->req, timeout * 1000, timeout * 1000,
                       timeout * 1000, timeout * 1000);
  }
  WinHttpSendRequest(backend->context->req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

  DWORD dwStatusCode = 0;
  DWORD dwSize = sizeof(dwStatusCode);
  bool complete = false;

  while (!complete) {
    enum stage new_stage = 0;
    EnterCriticalSection(&backend->context->mtx);
    switch (backend->context->stage) {
      case REQUEST_SENT:
        DBG_INFO("Request sent");
        WinHttpReceiveResponse(backend->context->req, NULL);
        new_stage = RESPONSE_WAITING;
        break;
      case RESPONSE_RECEIVED:
        DBG_INFO("Response received");
        WinHttpQueryDataAvailable(backend->context->req, NULL);
        break;
      case DATA_AVAILABLE:
        DBG_INFO("Data available");
        if (WinHttpReadData(backend->context->req, buf, MAX_STR_LEN, NULL) ==
            FALSE) {
          DBG_ERR("Failed request for new data: %lu", GetLastError());
          new_stage = REQUEST_ERROR;
        } else {
          new_stage = DATA_WAITING;
        }
        break;
      case READ_COMPLETE:
        DBG_INFO("Read complete");
        WinHttpQueryHeaders(backend->context->req,
                            WINHTTP_QUERY_STATUS_CODE |
                              WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode,
                            &dwSize, WINHTTP_NO_HEADER_INDEX);

        WinHttpCloseHandle(backend->context->req);
        if (dwStatusCode != HTTP_STATUS_OK) {
          DBG_ERR("Got HTTP error from server: %lu", dwStatusCode);
          new_stage = REQUEST_ERROR;
          res = YHR_CONNECTOR_NOT_FOUND;
        } else {
          parse_status_data((char *) buf, connector);
          new_stage = REQUEST_SUCCESS;
          res = YHR_SUCCESS;
        }
        break;
      case REQUEST_ERROR:
        DBG_INFO("Request error");
      case REQUEST_CLOSED:
        new_stage = REQUEST_DONE;
        complete = true;
        break;
      default:
        break;
    }
    if (new_stage > backend->context->stage) {
      backend->context->stage = new_stage;
    }
    LeaveCriticalSection(&backend->context->mtx);
  }

  return res;
}

static yh_rc backend_send_msg(yh_backend *connection, Msg *msg, Msg *response) {
  struct urlComponents components = {0};
  bool complete = false;
  yh_rc yrc = YHR_CONNECTOR_ERROR;
  uint16_t raw_len = msg->st.len + 3;
  DWORD dwStatusCode = 0;
  DWORD dwSize = sizeof(dwStatusCode);

  DBG_INFO("sending message to %s", connection->connector->api_url);
  if (parseUrl(connection->connector->api_url, &components) == false) {
    return yrc;
  }

  // swap the length in the message
  msg->st.len = htons(msg->st.len);

  connection->context->stage = NO_INIT;
  connection->context->len = 0;
  connection->context->req =
    WinHttpOpenRequest(connection->con, L"POST", components.path, NULL, NULL,
                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                       components.https ? WINHTTP_FLAG_SECURE : 0);
  // TODO: replace these magic numbers with something better.
  //  of note here is the 250s timeout on receive, generating rsa4096 might take
  //  some time..
  WinHttpSetTimeouts(connection->context->req, 30 * 1000, 30 * 1000, 250 * 1000,
                     250 * 1000);

  WinHttpSendRequest(connection->context->req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                     msg->raw, raw_len, raw_len, 0);

  while (!complete) {
    enum stage new_stage = 0;
    EnterCriticalSection(&connection->context->mtx);
    switch (connection->context->stage) {
      case REQUEST_SENT:
        DBG_INFO("Request sent");
        WinHttpReceiveResponse(connection->context->req, NULL);
        new_stage = RESPONSE_WAITING;
        break;
      case RESPONSE_RECEIVED:
        DBG_INFO("Response received");
        WinHttpQueryDataAvailable(connection->context->req, NULL);
        break;
      case DATA_AVAILABLE:
        DBG_INFO("Data available");
        if (WinHttpReadData(connection->context->req, response->raw,
                            SCP_MSG_BUF_SIZE, NULL) == FALSE) {
          DBG_ERR("Failed request for new data: %lu", GetLastError());
          new_stage = REQUEST_ERROR;
        } else {
          new_stage = DATA_WAITING;
        }
        break;
      case READ_COMPLETE:
        DBG_INFO("Read complete");
        if (connection->context->len == 0) {
          // NOTE: this is a hack to try to handle the case where we get 0
          // bytes..
          DBG_INFO(
            "Got a 0 length response, hoping there's more on the wire for us.");
          new_stage = connection->context->stage = RESPONSE_RECEIVED;
          break;
        }

        WinHttpQueryHeaders(connection->context->req,
                            WINHTTP_QUERY_STATUS_CODE |
                              WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode,
                            &dwSize, WINHTTP_NO_HEADER_INDEX);

        if (dwStatusCode != HTTP_STATUS_OK) {
          DBG_ERR("Got HTTP error from server: %lu", dwStatusCode);
          new_stage = REQUEST_ERROR;
          yrc = YHR_CONNECTOR_ERROR;
        } else {
          WinHttpCloseHandle(connection->context->req);
          response->st.len = ntohs(response->st.len);
          if (response->st.len + 3 == connection->context->len) {
            new_stage = REQUEST_SUCCESS;
            yrc = YHR_SUCCESS;
          } else {
            DBG_ERR("Wrong length received, %d vs %d", response->st.len + 3,
                    connection->context->len);
            new_stage = REQUEST_ERROR;
            yrc = YHR_WRONG_LENGTH;
          }
        }
        break;
      case REQUEST_ERROR:
        DBG_ERR("Request error");
        yrc = YHR_CONNECTOR_ERROR;
        WinHttpCloseHandle(connection->context->req);
      case REQUEST_CLOSED:
        complete = true;
        new_stage = REQUEST_DONE;
        break;
      default:
        break;
    }
    if (new_stage > connection->context->stage) {
      connection->context->stage = new_stage;
    }
    LeaveCriticalSection(&connection->context->mtx);
  }

  // restore the msg len
  msg->st.len = ntohs(msg->st.len);

  return yrc;
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
