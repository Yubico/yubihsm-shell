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

const char rsa2048_pvtkey_file[] = "rsa2048_pvtkey.pem";
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
                                  sizeof(password) - 1, false, &session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);

  FILE *fp = fopen(rsa2048_pvtkey_file, "rb");
  assert(fp != NULL);

  yh_algorithm algorithm = 0;
  uint8_t privkey[2048];
  size_t key_material_len = sizeof(privkey);
  if (!read_file(fp, privkey, &key_material_len)) {
    assert(false);
  }
  bool ret = read_private_key(privkey, key_material_len, &algorithm, privkey,
                              &key_material_len, false);
  assert(ret == true);
  assert(algorithm == YH_ALGO_RSA_2048);

  yh_capabilities capabilities = {{0}};
  yrc = yh_string_to_capabilities("sign-pss", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_import_rsa_key(session, &key_id, key_label, domain_five,
                               &capabilities, algorithm, privkey,
                               privkey + (key_material_len / 2));
  assert(yrc == YHR_SUCCESS);

  printf("Key imported with ID %04x\n", key_id);

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
  yrc = yh_util_sign_pss(session, key_id, hashed_data, hashed_data_len,
                         signature, &signature_len, 32, YH_ALGO_MGF1_SHA256);
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

  EVP_PKEY *key = EVP_PKEY_new();
  assert(EVP_PKEY_assign_RSA(key, rsa) == 1);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  EVP_MD *evp_md = EVP_MD_meth_dup(EVP_sha256());
  EVP_MD *evp_mgf1md = EVP_MD_meth_dup(EVP_sha256());
#endif
  assert(ctx != NULL);
  assert(EVP_PKEY_verify_init(ctx) == 1);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  assert(EVP_PKEY_CTX_set_signature_md(ctx, evp_md) == 1);
#else
  assert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1);
#endif
  assert(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) == 1);
  assert(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 32) == 1);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  assert(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, evp_mgf1md) == 1);
#else
  assert(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) == 1);
#endif

  if (EVP_PKEY_verify(ctx, signature, signature_len, hashed_data,
                      hashed_data_len) == 1) {
    printf("Signature successfully verified\n");
  } else {
    printf("Unable to verify signature\n");
  }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  EVP_MD_meth_free(evp_md);
  EVP_MD_meth_free(evp_mgf1md);
#endif
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);

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
