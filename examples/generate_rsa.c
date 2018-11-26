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

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "util.h"
#include "openssl-compat.h"

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
  yrc = yh_string_to_capabilities("sign-pkcs", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_rsa_key(session, &key_id, key_label, domain_five,
                                 &capabilities, YH_ALGO_RSA_2048);
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

  uint8_t signature[512];
  size_t signature_len = sizeof(signature);
  yrc = yh_util_sign_pkcs1v1_5(session, key_id, true, hashed_data,
                               hashed_data_len, signature, &signature_len);
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

  BIGNUM *n = BN_bin2bn(public_key, public_key_len, NULL);
  assert(n != NULL);

  BIGNUM *e = BN_bin2bn((const unsigned char *) "\x01\x00\x01", 3, NULL);
  assert(e != NULL);

  RSA *rsa = RSA_new();
  assert(RSA_set0_key(rsa, n, e, NULL) != 0);

  if (RSA_verify(EVP_MD_type(EVP_sha256()), hashed_data, hashed_data_len,
                 signature, signature_len, rsa) == 1) {
    printf("Signature successfully verified\n");
  } else {
    printf("Unable to verify signature\n");
  }

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
