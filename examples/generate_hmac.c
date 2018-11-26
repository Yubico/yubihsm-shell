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

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char *key_label = "label";
const uint8_t password[] = "password";
const uint8_t data[] = "sudo make me a sandwich";

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

  printf("Successfully established session %02d using Authentication Key "
         "%04x\n",
         session_id, authkey);

  yh_capabilities capabilities = {{0}};
  yrc = yh_string_to_capabilities("sign-hmac:verify-hmac", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_hmac_key(session, &key_id, key_label, domain_five,
                                  &capabilities, YH_ALGO_HMAC_SHA256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated HMAC-SHA256 key with ID %04x\n", key_id);

  uint8_t hmac_data[64];
  size_t hmac_data_len = sizeof(hmac_data);
  yrc = yh_util_sign_hmac(session, key_id, data, sizeof(data) - 1, hmac_data,
                          &hmac_data_len);
  assert(yrc == YHR_SUCCESS);

  printf("HMAC of data (%zu bytes) is:", hmac_data_len);
  for (uint16_t i = 0; i < hmac_data_len; i++) {
    printf(" %02x", hmac_data[i]);
  }
  printf("\n");

  bool verified;
  yrc = yh_util_verify_hmac(session, key_id, hmac_data, hmac_data_len, data,
                            sizeof(data) - 1, &verified);
  assert(yrc == YHR_SUCCESS);

  if (verified == true) {
    printf("Successfully verified HMAC\n");
  } else {
    printf("Unable to verify HMAC\n");
  }

  hmac_data[0] += 1;
  yrc = yh_util_verify_hmac(session, key_id, hmac_data, hmac_data_len, data,
                            sizeof(data) - 1, &verified);
  assert(yrc == YHR_SUCCESS);

  if (verified == true) {
    printf("Successfully verified HMAC\n");
  } else {
    printf("Unable to verify HMAC\n");
  }

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yh_disconnect(connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return 0;
}
