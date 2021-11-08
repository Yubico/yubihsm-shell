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

#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include "yubihsm.h"
#include "internal.h"
#include "debug_lib.h"

#include "curl/curl.h"

struct state {
  CURL *curl;
};

struct curl_data {
  uint8_t *ptr;
  uint8_t *end;
};

#ifndef STATIC
uint8_t YH_INTERNAL _yh_verbosity;
FILE YH_INTERNAL *_yh_output;
#endif

static size_t curl_callback_write(void *ptr, size_t size, size_t nmemb,
                                  void *stream) {

  struct curl_data *data = (struct curl_data *) stream;

  // Multiply & check for overflow
  size_t tot = size * nmemb;
  if (tot < size || tot < nmemb) {
    return 0;
  }

  // Add & check for overflow
  uint8_t *new_ptr = data->ptr + tot;
  if (new_ptr < data->ptr || new_ptr > data->end) {
    return 0;
  }

  memcpy(data->ptr, ptr, tot);
  data->ptr = new_ptr;

  return tot;
}

static void backend_set_verbosity(uint8_t verbosity, FILE *output) {
  _yh_verbosity = verbosity;
  _yh_output = output;
}

static yh_rc backend_init(uint8_t verbosity, FILE *output) {
  DBG_INFO("backend_init");
  CURLcode rc;

  backend_set_verbosity(verbosity, output);

  rc = curl_global_init(
    CURL_GLOBAL_DEFAULT); // NOTE(adma): this funciton is not thread safe
  if (rc != CURLE_OK) {
    DBG_ERR("%s", curl_easy_strerror(rc));
    return YHR_CONNECTION_ERROR;
  }

  return YHR_SUCCESS;
}

static yh_backend *backend_create() {
  DBG_INFO("backend_create");
  return curl_easy_init();
}

static yh_rc backend_connect(yh_connector *connector, int timeout) {
  DBG_INFO("backend_connect");

  CURLcode rc;
  uint8_t scratch[257] = {0};
  struct curl_data data = {scratch, scratch + sizeof(scratch) - 1};
  char curl_error[CURL_ERROR_SIZE] = {0};

  DBG_INFO("Trying to connect to %s", connector->status_url);

  curl_easy_setopt(connector->connection, CURLOPT_URL, connector->status_url);
  curl_easy_setopt(connector->connection, CURLOPT_CONNECTTIMEOUT, timeout);
#ifdef CURLOPT_TCP_KEEPALIVE
  curl_easy_setopt(connector->connection, CURLOPT_TCP_KEEPALIVE, 1);
#endif /* CURLOPT_TCP_KEEPALIVE */
  curl_easy_setopt(connector->connection, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt(connector->connection, CURLOPT_USERAGENT,
                   "YubiHSM curl/" VERSION);

  curl_easy_setopt(connector->connection, CURLOPT_WRITEFUNCTION,
                   curl_callback_write);

  curl_easy_setopt(connector->connection, CURLOPT_ERRORBUFFER, curl_error);

  curl_easy_setopt(connector->connection, CURLOPT_WRITEDATA, &data);

  rc = curl_easy_perform(connector->connection);
  if (rc != CURLE_OK) {
    if (strlen(curl_error) > 0) {
      DBG_ERR("Failure when connecting: '%s'", curl_error);
    } else {
      DBG_ERR("Failure when connecting: '%s'", curl_easy_strerror(rc));
    }
    return YHR_CONNECTOR_NOT_FOUND;
  }

  size_t size = data.ptr - scratch;
  size_t len = strlen((char *) scratch);

  if (len != size) {
    DBG_ERR("Amount of data received does not match scratch buffer. Expected "
            "%zu, found %zu",
            len, size);
    return YHR_GENERIC_ERROR;
  }

  parse_status_data((char *) scratch, connector);

  if (!connector->has_device) {
    DBG_ERR("Failure when connecting: Connector has no device");
    return YHR_CONNECTOR_NOT_FOUND;
  }

  DBG_INFO("Found working connector");

  curl_easy_setopt(connector->connection, CURLOPT_URL, connector->api_url);

  return YHR_SUCCESS;
}

static void backend_disconnect(yh_backend *connection) {
  DBG_INFO("backend_disconnect");
  curl_easy_cleanup(connection);
}

static yh_rc backend_send_msg(yh_backend *connection, Msg *msg, Msg *response,
                              const char *identifier) {
  CURLcode rc;
  yh_rc yrc = YHR_CONNECTION_ERROR;
  int32_t trf_len = ntohs(msg->st.len) + 3;
  struct curl_data data = {response->raw,
                           response->raw + sizeof(response->raw)};
  struct curl_slist *headers = NULL;
  char curl_error[CURL_ERROR_SIZE] = {0};
  char hsm_identifier[64];

  headers = curl_slist_append(NULL, "Content-Type: application/octet-stream");

  if (identifier != NULL && strlen(identifier) > 0 && strlen(identifier) < 32) {
    snprintf(hsm_identifier, 64, "YubiHSM-Session: %s", identifier);
    headers = curl_slist_append(headers, hsm_identifier);
  }

  curl_easy_setopt(connection, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(connection, CURLOPT_POSTFIELDS, (void *) msg->raw);
  curl_easy_setopt(connection, CURLOPT_POSTFIELDSIZE, trf_len);

  curl_easy_setopt(connection, CURLOPT_WRITEDATA, &data);
  curl_easy_setopt(connection, CURLOPT_ERRORBUFFER, curl_error);

  // NOTE(adma): connection is actually established here the first time
  rc = curl_easy_perform(connection);
  curl_slist_free_all(headers);
  if (rc != CURLE_OK) {
    goto sm_failure;
  }

  size_t size = data.ptr - response->raw;

  if (size < 3) {
    DBG_ERR("Not enough data received: %zu", size);
    return YHR_WRONG_LENGTH;
  }

  if (ntohs(response->st.len) != size - 3) {
    DBG_ERR("Wrong length received, %d vs %zu", ntohs(response->st.len), size);
    return YHR_WRONG_LENGTH;
  }

  return YHR_SUCCESS;

sm_failure:

  if (strlen(curl_error) > 0) {
    DBG_ERR("Curl perform failed: '%s'", curl_error);
  } else {
    DBG_ERR("Curl perform failed: '%s'", curl_easy_strerror(rc));
  }

  return yrc;
}

static void backend_cleanup(void) {
  DBG_INFO("backend_cleanup");
  /* by all rights we should call curl_global_cleanup() here, but.. if curl is
   * using openssl that will cleanup all openssl context, which if we're called
   * through pkcs11_engine and our pkcs11 module will break everything, so we
   * don't. */
  // curl_global_cleanup();
}

static yh_rc backend_option(yh_backend *connection, yh_connector_option opt,
                            const void *val) {
  CURLoption option;
  const char *optname;

  switch (opt) {
    case YH_CONNECTOR_HTTPS_CA:
      option = CURLOPT_CAINFO;
      optname = "CURLOPT_CAINFO";
      break;
    case YH_CONNECTOR_HTTPS_CERT:
      option = CURLOPT_SSLCERT;
      optname = "CURLOPT_SSLCERT";
      break;
    case YH_CONNECTOR_HTTPS_KEY:
      option = CURLOPT_SSLKEY;
      optname = "CURLOPT_SSLKEY";
      break;
    case YH_CONNECTOR_PROXY_SERVER:
      option = CURLOPT_PROXY;
      optname = "CURLOPT_PROXY";
      break;
    case YH_CONNECTOR_NOPROXY:
      option = CURLOPT_NOPROXY;
      optname = "CURLOPT_NOPROXY";
      break;
    default:
      DBG_ERR("%d is an unknown option", opt);
      return YHR_INVALID_PARAMETERS;
  }
  CURLcode rc = curl_easy_setopt(connection, option, val);
  if (rc == CURLE_OK) {
    DBG_INFO("Successfully set %s.", optname);
    return YHR_SUCCESS;
  } else {
    DBG_ERR("Failed to set %s (%d): %s", optname, rc, curl_easy_strerror(rc));
    return YHR_CONNECTOR_ERROR;
  }
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
