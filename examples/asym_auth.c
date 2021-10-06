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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const uint8_t password[] = "password";
const uint8_t data[] = "sudo make me a sandwich";

static int compare_algorithm(const void *a, const void *b) {
  return (*(const yh_algorithm *) a - *(const yh_algorithm *) b);
}

int main(void) {
  yh_connector *connector = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;

  const char *connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }

  yrc = yh_init();
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "unable to initialize yubihsm: %s\n", yh_strerror(yrc));
    exit(EXIT_FAILURE);
  }

  yrc = yh_init_connector(connector_url, &connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_connect(connector, 0);
  assert(yrc == YHR_SUCCESS);

  char *received_url;
  yrc = yh_get_connector_address(connector, &received_url);
  assert(yrc == YHR_SUCCESS);

  yh_set_verbosity(connector, YH_VERB_ALL);

  uint8_t d_major, d_minor, d_patch;
  uint32_t serial;
  uint8_t log_total, log_used;
  yh_algorithm algorithms[YH_MAX_ALGORITHM_COUNT];
  size_t n_algorithms = sizeof(algorithms);
  yrc =
    yh_util_get_device_info(connector, &d_major, &d_minor, &d_patch, &serial,
                            &log_total, &log_used, algorithms, &n_algorithms);
  assert(yrc == YHR_SUCCESS);

  yh_algorithm key = YH_ALGO_EC_P256_YUBICO_AUTHENTICATION;
  if (!bsearch(&key, algorithms, n_algorithms, sizeof(key),
               compare_algorithm)) {
    fprintf(stderr, "Skipping this test because the device does not support "
                    "aymmetric authentication\n");
    exit(EXIT_SUCCESS);
  }

  printf("Send a plain (unencrypted, unauthenticated) echo command\n");

  uint16_t data_len = sizeof(data) - 1;
  uint8_t response[sizeof(data)] = {0};
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;
  yrc = yh_send_plain_msg(connector, YHC_ECHO, data, data_len, &response_cmd,
                          response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to send ECHO command: %s\n", yh_strerror(yrc));
    exit(EXIT_FAILURE);
  }

  printf("Response (%zu bytes): \"%s\"\n", response_len, response);

  yh_session *session = NULL;
  uint16_t authkey = 1;

  yrc = yh_create_session_derived(connector, authkey, password,
                                  sizeof(password) - 1, false, &session);
  assert(yrc == YHR_SUCCESS);

  authkey = 2;

  yh_util_delete_object(session, authkey, YH_AUTHENTICATION_KEY);
  // Ignore result here

  uint8_t sk_oce[YH_EC_P256_PRIVKEY_LEN], pk_oce[YH_EC_P256_PUBKEY_LEN];
  yrc = yh_util_generate_ec_p256_key(sk_oce, sizeof(sk_oce), pk_oce,
                                     sizeof(pk_oce));
  assert(yrc == YHR_SUCCESS);

  yh_capabilities caps = {{0}};
  yrc = yh_string_to_capabilities("change-authentication-key,get-pseudo-random",
                                  &caps);
  assert(yrc == YHR_SUCCESS);

  // The public key is imported without the uncompressed point marker (value
  // 0x04), so skip the first byte
  yrc = yh_util_import_authentication_key(session, &authkey, "EC Auth Key",
                                          0xffff, &caps, &caps, pk_oce + 1,
                                          sizeof(pk_oce) - 1, NULL, 0);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  uint8_t pk_sd[YH_EC_P256_PUBKEY_LEN];
  size_t pk_sd_len = sizeof(pk_sd);

  yrc = yh_util_get_device_pubkey(connector, pk_sd, &pk_sd_len, NULL);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_create_session_asym(connector, authkey, sk_oce, sizeof(sk_oce),
                               pk_sd, pk_sd_len, &session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);

  uint8_t buf[32];
  size_t buf_len = sizeof(buf);
  yrc = yh_util_get_pseudo_random(session, buf_len, buf, &buf_len);
  assert(yrc == YHR_SUCCESS);

  printf("Send a secure echo command\n");

  uint8_t response2[sizeof(data)] = {0};
  size_t response2_len = sizeof(response);
  yh_cmd response2_cmd;
  yrc = yh_send_secure_msg(session, YHC_ECHO, data, data_len, &response2_cmd,
                           response2, &response2_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to send ECHO command: %s\n", yh_strerror(yrc));
    exit(EXIT_FAILURE);
  }

  printf("Response (%zu bytes): \"%s\"\n", response_len, response);

  assert(response_len == response2_len);
  assert(memcmp(response, response2, response_len) == 0);

  yrc = yh_util_generate_ec_p256_key(sk_oce, sizeof(sk_oce), pk_oce,
                                     sizeof(pk_oce));
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_change_authentication_key(session, &authkey, pk_oce + 1,
                                          sizeof(pk_oce) - 1, NULL, 0);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_create_session_asym(connector, authkey, sk_oce, sizeof(sk_oce),
                               pk_sd, pk_sd_len, &session);
  assert(yrc == YHR_SUCCESS);

  buf_len = sizeof(buf);
  yrc = yh_util_get_pseudo_random(session, buf_len, buf, &buf_len);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_disconnect(connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return 0;
}
