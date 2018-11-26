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

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include "util.h"

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

  printf("Successfully established session %02d\n", session_id);

  yh_capabilities capabilities = {{0}};
  yrc = yh_string_to_capabilities("sign-ecdsa", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_ec_key(session, &key_id, key_label, domain_five,
                                &capabilities, YH_ALGO_EC_P256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated key with ID %04x\n", key_id);

  printf("Data to sign (%zu bytes) is: %s\n", sizeof(data) - 1, data);

  EVP_MD_CTX *mdctx = NULL;
  uint8_t hashed_data[32];
  unsigned int hashed_data_len;

  mdctx = EVP_MD_CTX_create();
  assert(mdctx != NULL);
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, data, sizeof(data) - 1);
  EVP_DigestFinal_ex(mdctx, hashed_data, &hashed_data_len);
  EVP_MD_CTX_destroy(mdctx);

  printf("Hash of data (%d bytes) is:", EVP_MD_size(EVP_sha256()));
  for (unsigned int i = 0; i < hashed_data_len; i++) {
    printf(" %02x", hashed_data[i]);
  }
  printf("\n");

  uint8_t signature[128];
  size_t signature_len = sizeof(signature);
  yrc = yh_util_sign_ecdsa(session, key_id, hashed_data, hashed_data_len,
                           signature, &signature_len);
  assert(yrc == YHR_SUCCESS);

  printf("Signature (%zu bytes) is:", signature_len);
  for (unsigned int i = 0; i < signature_len; i++) {
    printf(" %02x", signature[i]);
  }
  printf("\n");

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

  EC_KEY *eckey = EC_KEY_new();
  int nid = algo2nid(YH_ALGO_EC_P256);
  EC_POINT *point;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);

  EC_GROUP_set_asn1_flag(group, nid);
  EC_KEY_set_group(eckey, group);
  point = EC_POINT_new(group);

  memmove(public_key + 1, public_key, public_key_len);
  public_key[0] = 0x04; // hack to make it a valid ec pubkey..
  public_key_len++;

  EC_POINT_oct2point(group, point, public_key, public_key_len, NULL);

  EC_KEY_set_public_key(eckey, point);

  if (ECDSA_verify(0, hashed_data, hashed_data_len, signature, signature_len,
                   eckey) == 1) {
    printf("Signature successfully verified\n");
  } else {
    printf("Unable to verify signature\n");
  }

  EC_POINT_free(point);
  EC_KEY_free(eckey);
  EC_GROUP_free(group);

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
