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

#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const uint8_t password[] = "password";
const uint8_t data[] = "sudo make me a sandwich";

int main(void) {
  yh_connector *connector = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;

  EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!EC_KEY_generate_key(key)) {
    fprintf(stderr, "Unable to generate random EC key\n");
    exit(EXIT_FAILURE);
  }

  uint8_t sk_oce[32];
  int sk_oce_len = BN_bn2bin(EC_KEY_get0_private_key(key), sk_oce);
  if (sk_oce_len < 0) {
    fprintf(stderr, "Unable to get random private key\n");
    exit(EXIT_FAILURE);
  }

  uint8_t pk_oce[65];
  if (EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                         POINT_CONVERSION_UNCOMPRESSED, pk_oce, sizeof(pk_oce),
                         NULL) != sizeof(pk_oce)) {
    fprintf(stderr, "Unable to get random public key\n");
    exit(EXIT_FAILURE);
  }

  EC_KEY_free(key);
  key = NULL;

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

  printf("Send a plain (unencrypted, unauthenticated) echo command\n");

  uint16_t data_len = sizeof(data) - 1;
  uint8_t response[sizeof(data)] = {0};
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;
  yrc = yh_send_plain_msg(connector, YHC_ECHO, data, data_len, &response_cmd,
                          response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to send ECHO command): %s\n", yh_strerror(yrc));
    exit(EXIT_FAILURE);
  }

  if (response_cmd == YHC_ERROR) {
    fprintf(stderr, "Unable to get echo data: %s (%x)\n",
            yh_strerror(response[0]), response[0]);
    exit(EXIT_FAILURE);
  }

  printf("Response (%zu bytes): \"%s\"\n", response_len, response);

  yh_session *session = NULL;
  uint16_t authkey = 1;

  yrc = yh_create_session_derived(connector, authkey, password,
                                  sizeof(password), false, &session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_authenticate_session(session);

  assert(yrc == YHR_SUCCESS);

  authkey = 2;

  yrc = yh_util_delete_object(session, authkey, YH_AUTHENTICATION_KEY);
  assert(yrc == YHR_SUCCESS);

  yh_capabilities caps = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  // The public key is imported without the uncompressed point marker (value
  // 0x04), so skip the first byte
  yrc = yh_util_import_authentication_key(session, &authkey, "EC Auth Key",
                                          0xffff, &caps, &caps, pk_oce + 1,
                                          sizeof(pk_oce) - 1, 0, 0);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  uint8_t pk_sd[128];
  size_t pk_sd_len = sizeof(pk_sd);

  yrc = yh_get_device_pubkey(connector, pk_sd, &pk_sd_len);

  assert(yrc == YHR_SUCCESS);

  yrc = yh_create_session_asym(connector, authkey, sk_oce, sk_oce_len, pk_sd,
                               pk_sd_len, false, &session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);

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

  if (response_cmd == YHC_ERROR) {
    fprintf(stderr, "Unable to get echo data: %s (%x)\n",
            yh_strerror(response[0]), response[0]);
    exit(EXIT_FAILURE);
  }

  printf("Response (%zu bytes): \"%s\"\n", response_len, response);

  assert(response_len == response2_len);
  assert(memcmp(response, response2, response_len) == 0);

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