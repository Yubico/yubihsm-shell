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

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "util.h"

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

#define N_OPERATIONS 5

const uint8_t password[] = "password";

int main(void) {
  yh_connector *connector = NULL;
  yh_session *session = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;

  uint16_t authkey = 1;

  const char *connector_url;

  connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }

  yrc = yh_init();
  assert(yrc == YHR_SUCCESS);

  yrc = yh_init_connector(connector_url, &connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_connect(connector, 0);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_create_session_derived(connector, authkey, password,
                                  sizeof(password), false, &session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_authenticate_session(session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);
  printf("Flushing existing logs\n");

  uint16_t unlogged_boot, unlogged_auth;
  yh_log_entry logs[YH_MAX_LOG_ENTRIES];
  size_t n_items = sizeof(logs) / sizeof(yh_log_entry);
  yh_log_entry last_previous_log;
  yh_log_entry *last_previous_log_ptr = &last_previous_log;

  yrc = yh_util_get_log_entries(session, &unlogged_boot, &unlogged_auth, logs,
                                &n_items);
  assert(yrc == YHR_SUCCESS);

  if (n_items != 0) {
    memcpy(&last_previous_log, logs + n_items - 1, sizeof(yh_log_entry));
  } else {
    last_previous_log_ptr = NULL;
  }

  uint16_t last_index = logs[n_items - 1].number;

  yrc = yh_util_set_log_index(session, last_index);
  assert(yrc == YHR_SUCCESS);

  printf("Performing some operations\n");

  for (uint16_t i = 0; i < N_OPERATIONS; i++) {
    yh_object_descriptor descriptor;
    yrc = yh_util_get_object_info(session, authkey, YH_AUTHENTICATION_KEY,
                                  &descriptor);
    assert(yrc == YHR_SUCCESS);
  }

  printf("Getting logs\n");

  n_items = sizeof(logs) / sizeof(yh_log_entry);
  yrc = yh_util_get_log_entries(session, &unlogged_boot, &unlogged_auth, logs,
                                &n_items);
  assert(yrc == YHR_SUCCESS);

  assert(n_items == N_OPERATIONS + 1);

  fprintf(stdout, "%d unlogged boots found\n", unlogged_boot);
  fprintf(stdout, "%d unlogged authentications found\n", unlogged_auth);

  char digest_buf[(2 * YH_LOG_DIGEST_SIZE) + 1];

  if (n_items == 0) {
    fprintf(stdout, "No logs to extract\n");
    return 0;
  } else if (n_items == 1) {
    fprintf(stdout, "Found 1 item\n");
  } else {
    fprintf(stdout, "Found %zu items\n", n_items);
  }

  for (uint16_t i = 0; i < n_items; i++) {
    format_digest(logs[i].digest, digest_buf, YH_LOG_DIGEST_SIZE);
    fprintf(stdout,
            "item: %5u -- cmd: 0x%02x -- length: %4u -- session key: "
            "0x%04x -- target key: 0x%04x -- second key: 0x%04x -- "
            "result: 0x%02x -- tick: %lu -- hash: %s\n",
            logs[i].number, logs[i].command, logs[i].length,
            logs[i].session_key, logs[i].target_key, logs[i].second_key,
            logs[i].result, (unsigned long) logs[i].systick, digest_buf);
  }

  bool ret = yh_verify_logs(logs, n_items, last_previous_log_ptr);
  assert(ret == true);

  printf("Logs correctly verified\n");

  uint8_t option[128];
  size_t option_len;

  option[0] = YHC_SET_OPTION;
  option[1] = 0x00;
  option_len = 2;
  yrc =
    yh_util_set_option(session, YH_OPTION_COMMAND_AUDIT, option_len, option);
  assert(yrc == YHR_SUCCESS);

  option_len = sizeof(option);
  yrc =
    yh_util_get_option(session, YH_OPTION_COMMAND_AUDIT, option, &option_len);
  assert(yrc == YHR_SUCCESS);

  assert(option_len % 2 == 0);
  bool option_found = false;
  for (size_t i = 0; i < option_len; i += 2) {
    if (option[i] == YHC_SET_OPTION) {
      assert(option[i + 1] == 0);
      option_found = true;
      break;
    }
  }
  assert(option_found == true);

  option[0] = YHC_SET_OPTION;
  option[1] = 0x01;
  option_len = 2;
  yrc =
    yh_util_set_option(session, YH_OPTION_COMMAND_AUDIT, option_len, option);
  assert(yrc == YHR_SUCCESS);

  option_len = sizeof(option);
  yrc =
    yh_util_get_option(session, YH_OPTION_COMMAND_AUDIT, option, &option_len);
  assert(yrc == YHR_SUCCESS);

  assert(option_len % 2 == 0);
  option_found = false;
  for (size_t i = 0; i < option_len; i += 2) {
    if (option[i] == YHC_SET_OPTION) {
      assert(option[i + 1] == 1);
      option_found = true;
      break;
    }
  }
  assert(option_found == true);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yh_disconnect(connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return EXIT_SUCCESS;
}
