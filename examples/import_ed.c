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

#include "util.h"

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char ed25519_pvtkey_file[] = "ed25519_pvtkey.pem";
const char *key_label = "label";
const uint8_t password[] = "password";
const uint8_t data[] = {0x72};
const uint8_t expected_signature[] =
  {0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f,
   0x64, 0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76,
   0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99,
   0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae,
   0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00};
const uint8_t expected_public_key[] = {0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89,
                                       0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
                                       0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e,
                                       0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
                                       0x2a, 0xf4, 0x66, 0x0c};

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

  FILE *fp = fopen(ed25519_pvtkey_file, "rb");
  assert(fp != NULL);

  yh_algorithm algorithm = 0;
  uint8_t key[2048];
  size_t key_material_len = sizeof(key);
  if (!read_file(fp, key, &key_material_len)) {
    assert(false);
  }
  bool ret = read_private_key(key, key_material_len, &algorithm, key,
                              &key_material_len, false);
  assert(ret == true);
  assert(algorithm == YH_ALGO_EC_ED25519);

  yh_capabilities capabilities = {{0}};
  yrc = yh_string_to_capabilities("sign-eddsa", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_import_ed_key(session, &key_id, key_label, domain_five,
                              &capabilities, algorithm, key);
  assert(yrc == YHR_SUCCESS);

  printf("Key imported with ID %04x\n", key_id);

  printf("Signing %zu bytes of data\n", sizeof(data));

  uint8_t signature[128];
  size_t signature_len = sizeof(signature);
  yrc = yh_util_sign_eddsa(session, key_id, data, sizeof(data), signature,
                           &signature_len);
  assert(yrc == YHR_SUCCESS);

  printf("Signature (%zu bytes) is:", signature_len);
  for (unsigned int i = 0; i < signature_len; i++) {
    printf(" %02x", signature[i]);
  }
  printf("\n");

  assert(signature_len == 64);
  assert(memcmp(signature, expected_signature, 64) == 0);

  uint8_t public_key[512];
  size_t public_key_len = sizeof(public_key);
  yrc =
    yh_util_get_public_key(session, key_id, public_key, &public_key_len, NULL);
  assert(yrc == YHR_SUCCESS);

  assert(public_key_len == 32);
  assert(memcmp(public_key, expected_public_key, 32) == 0);

  printf("Public key (%zu bytes) is:", public_key_len);
  for (unsigned int i = 0; i < public_key_len; i++) {
    printf(" %02x", public_key[i]);
  }
  printf("\n");

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
