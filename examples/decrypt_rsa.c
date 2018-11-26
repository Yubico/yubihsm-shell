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
#include <openssl/rsa.h>

#include "util.h"

#include <yubihsm.h>

#include "openssl-compat.h"

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char rsa2048_pvtkey_file[] = "rsa2048_pvtkey.pem";
const char *key_label = "label";
const uint8_t password[] = "password";
const uint8_t data[] = "sudo make me a sandwich";
const uint8_t sha1_empty_string[] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b,
                                     0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                                     0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};

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

  FILE *fp = fopen(rsa2048_pvtkey_file, "rb");
  assert(fp != NULL);

  yh_algorithm algorithm = 0;
  uint8_t key[2048];
  size_t key_material_len = sizeof(key);
  if (!read_file(fp, key, &key_material_len)) {
    assert(false);
  }
  bool ret2 = read_private_key(key, key_material_len, &algorithm, key,
                               &key_material_len, false);
  assert(ret2 == true);
  assert(algorithm == YH_ALGO_RSA_2048);

  yh_capabilities capabilities = {{0}};
  yrc = yh_string_to_capabilities("decrypt-pkcs,decrypt-oaep", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_import_rsa_key(session, &key_id, key_label, domain_five,
                               &capabilities, algorithm, key,
                               key + (key_material_len / 2));
  assert(yrc == YHR_SUCCESS);

  printf("Key imported with ID %04x\n", key_id);

  uint8_t public_key[512];
  size_t public_key_len = sizeof(public_key);
  yrc =
    yh_util_get_public_key(session, key_id, public_key, &public_key_len, NULL);
  assert(yrc == YHR_SUCCESS);

  printf("Public key (%zu bytes) is:", public_key_len);
  for (unsigned int i = 0; i < public_key_len; i++) {
    printf(" %02x", public_key[i]);
  }
  printf("\n");

  BIGNUM *n = BN_bin2bn(public_key, public_key_len, NULL);
  assert(n != NULL);

  BIGNUM *e = BN_bin2bn((const unsigned char *) "\x01\x00\x01", 3, NULL);
  assert(e != NULL);

  RSA *rsa = RSA_new();
  assert(RSA_set0_key(rsa, n, e, NULL) != 0);

  uint8_t encrypted[512];
  int ret =
    RSA_public_encrypt(sizeof(data), data, encrypted, rsa, RSA_PKCS1_PADDING);
  assert(ret == RSA_size(rsa));

  uint8_t decrypted[512];
  size_t decrypted_len = sizeof(decrypted);
  yrc = yh_util_decrypt_pkcs1v1_5(session, key_id, encrypted, ret, decrypted,
                                  &decrypted_len);
  assert(yrc == YHR_SUCCESS);

  assert(memcmp(data, decrypted, decrypted_len) == 0);

  printf("PKCS1v1.5 decrypted data matches\n");

  ret = RSA_public_encrypt(sizeof(data), data, encrypted, rsa,
                           RSA_PKCS1_OAEP_PADDING);
  assert(ret == RSA_size(rsa));

  decrypted_len = sizeof(decrypted);
  yrc =
    yh_util_decrypt_oaep(session, key_id, encrypted, ret, decrypted,
                         &decrypted_len, (const uint8_t *) sha1_empty_string,
                         sizeof(sha1_empty_string), YH_ALGO_MGF1_SHA1);
  assert(yrc == YHR_SUCCESS);

  assert(memcmp(data, decrypted, decrypted_len) == 0);

  printf("OAEP decrypted data matches\n");

  RSA_free(rsa);
  rsa = NULL;

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
