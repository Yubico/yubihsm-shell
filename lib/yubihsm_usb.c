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

#include <stdint.h>
#include <string.h>
#ifdef __WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include "yubihsm.h"
#include "internal.h"
#include "yubihsm_usb.h"
#include "debug_lib.h"

uint8_t YH_INTERNAL _yh_verbosity;
FILE YH_INTERNAL *_yh_output;

static void backend_set_verbosity(uint8_t verbosity, FILE *output) {
  _yh_verbosity = verbosity;
  _yh_output = output;
}

static yh_rc backend_init(uint8_t verbosity, FILE *output) {
  backend_set_verbosity(verbosity, output);
  return YHR_SUCCESS;
}

static yh_rc backend_connect(yh_connector *connector, int timeout) {
  unsigned long serial = 0;

  yh_rc ret = YHR_CONNECTOR_ERROR;
  yh_backend *backend = NULL;

  (void) timeout;

  if (parse_usb_url(connector->api_url, &serial) == false) {
    DBG_ERR("Failed to parse URL: '%s'", connector->api_url);
    goto out;
  }

  backend = connector->connection;
  usb_set_serial(backend, serial);
  if (usb_open_device(backend) == false) {
    DBG_ERR("No device returned");
    goto out;
  }

  ret = YHR_SUCCESS;
  connector->has_device = 1;
out:
  return ret;
}

static void backend_disconnect(yh_backend *connection) {
  usb_destroy(&connection);
}

static yh_rc backend_send_msg(yh_backend *connection, Msg *msg, Msg *response) {
  int32_t trf_len = msg->st.len + 3;
  yh_rc ret = YHR_GENERIC_ERROR;
  unsigned long read_len;
  msg->st.len = htons(msg->st.len);

  for (int i = 0; i <= 1; i++) {
    if (ret != YHR_GENERIC_ERROR) {
      DBG_INFO("Reconnecting device");
      usb_close(connection);
      if (usb_open_device(connection) == false) {
        DBG_ERR("Failed reconnecting device");
        return YHR_CONNECTION_ERROR;
      }
    }
    if (usb_write(connection, msg->raw, trf_len) == 0) {
      ret = YHR_CONNECTION_ERROR;
      DBG_ERR("USB write failed");
      continue;
    }

    read_len = SCP_MSG_BUF_SIZE;
    if (usb_read(connection, response->raw, &read_len) == 0) {
      ret = YHR_CONNECTION_ERROR;
      DBG_ERR("USB read failed");
      continue;
    }
    ret = YHR_SUCCESS;
    break;
  }

  if (ret != YHR_SUCCESS) {
    return ret;
  }

  if (read_len < 3) {
    DBG_ERR("Not enough data received; %lu", read_len);
    return YHR_WRONG_LENGTH;
  }

  response->st.len = ntohs(response->st.len);

  if (response->st.len != read_len - 3) {
    DBG_ERR("Wrong length received, %d vs %lu", response->st.len, read_len);
    return YHR_WRONG_LENGTH;
  }

  return YHR_SUCCESS;
}

static void backend_cleanup(void) {}

static yh_rc backend_option(yh_backend *connection, yh_connector_option opt,
                            const void *val) {
  (void) connection;
  (void) opt;
  (void) val;

  DBG_ERR("Backend options not (yet?) supported for USB");
  return YHR_CONNECTOR_ERROR;
}

static struct backend_functions f = {backend_init,     backend_create,
                                     backend_connect,  backend_disconnect,
                                     backend_send_msg, backend_cleanup,
                                     backend_option,   backend_set_verbosity};

#ifdef STATIC
struct backend_functions *usb_backend_functions(void) {
#else
struct backend_functions *backend_functions(void) {
#endif
  return &f;
}
