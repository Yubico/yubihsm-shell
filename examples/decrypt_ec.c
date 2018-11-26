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
#include <openssl/evp.h>

#include "util.h"

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char *key_label = "label";
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

  yh_capabilities capabilities = {{0}};
  yrc = yh_string_to_capabilities("derive-ecdh", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_ec_key(session, &key_id, key_label, domain_five,
                                &capabilities, YH_ALGO_EC_P256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated key with ID %04x\n", key_id);

  uint8_t public_key[512];
  size_t public_key_len = sizeof(public_key);
  yrc =
    yh_util_get_public_key(session, key_id, public_key, &public_key_len, NULL);
  assert(yrc == YHR_SUCCESS);

  printf("Public key (%zd bytes) is:", public_key_len);
  for (size_t i = 0; i < public_key_len; i++) {
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

  // Create the context for parameter generation
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  assert(pctx != NULL);

  // Initialise the parameter generation
  assert(EVP_PKEY_paramgen_init(pctx) == 1);

  // We're going to use the ANSI X9.62 Prime 256v1 curve
  assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) ==
         1);

  // Create the parameter object params
  EVP_PKEY *params = NULL;
  assert(EVP_PKEY_paramgen(pctx, &params) == 1);

  // Create the context for the key generation
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
  assert(kctx != NULL);

  // Generate the key
  EVP_PKEY *pkey = NULL;
  assert(EVP_PKEY_keygen_init(kctx) == 1);
  assert(EVP_PKEY_keygen(kctx, &pkey) == 1);

  // Get the peer's public key, and provide the peer with our public key
  EVP_PKEY *peerkey = EVP_PKEY_new();
  assert(peerkey != NULL);
  assert(EVP_PKEY_set1_EC_KEY(peerkey, eckey) == 1);

  // Create the context for the shared secret derivation
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  assert(ctx != NULL);

  // Initialise
  assert(EVP_PKEY_derive_init(ctx) == 1);

  // Provide the peer public key
  assert(EVP_PKEY_derive_set_peer(ctx, peerkey) == 1);

  uint8_t secret[64];
  size_t secret_len = sizeof(secret_len);

  // Determine buffer length for shared secret
  assert(EVP_PKEY_derive(ctx, NULL, &secret_len));

  // Derive the shared secret
  assert(EVP_PKEY_derive(ctx, secret, &secret_len) == 1);

  EC_KEY *eckey2 = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_POINT *pub = EC_KEY_get0_public_key(eckey2);

  uint8_t pubkey[128];
  size_t pubkey_len = sizeof(pubkey);

  pubkey_len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                  pubkey, pubkey_len, NULL);
  assert(pubkey_len == 65);

  uint8_t computed_secret[128];
  size_t computed_secret_len = sizeof(computed_secret);
  yrc = yh_util_derive_ecdh(session, key_id, pubkey, pubkey_len,
                            computed_secret, &computed_secret_len);
  assert(yrc == YHR_SUCCESS);

  assert(computed_secret_len == secret_len);
  assert(memcmp(secret, computed_secret, computed_secret_len) == 0);

  printf("Secrets match\n");

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peerkey);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(pctx);
  EC_POINT_free(point);
  EC_KEY_free(eckey);
  EC_KEY_free(eckey2);
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
