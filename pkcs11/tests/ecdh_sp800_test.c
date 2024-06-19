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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "../pkcs11y.h"
#include "common.h"

#define BUFSIZE 1024

CK_BYTE P224_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21};
CK_BYTE P256_PARAMS[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                         0xce, 0x3d, 0x03, 0x01, 0x07};
CK_BYTE P384_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
CK_BYTE P521_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

static CK_FUNCTION_LIST_3_0_PTR p11;
static CK_SESSION_HANDLE session;

char *CURVES[] = {"secp224r1", "prime256v1", "secp384r1", "secp521r1"};
CK_BYTE *CURVE_PARAMS[] = {P224_PARAMS, P256_PARAMS, P384_PARAMS, P521_PARAMS};
CK_ULONG CURVE_LENS[] = {sizeof(P224_PARAMS), sizeof(P256_PARAMS),
                         sizeof(P384_PARAMS), sizeof(P521_PARAMS)};
int CURVE_COUNT = sizeof(CURVE_PARAMS) / sizeof(CURVE_PARAMS[0]);
size_t CURVE_ECDH_LEN[] = {28, 32, 48, 66};

static void success(const char *message) { printf("%s. OK\n", message); }

static void fail(const char *message) { printf("%s. FAIL!\n", message); }

static void increment_ctr(uint8_t *ctr, size_t len) {
  while (len > 0) {
    if (++ctr[--len]) {
      break;
    }
  }
}

static void generate_keypair_yh(CK_BYTE *curve, CK_ULONG curve_len,
                                CK_OBJECT_HANDLE_PTR publicKeyPtr,
                                CK_OBJECT_HANDLE_PTR privateKeyPtr) {
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

  CK_BBOOL ck_true = CK_TRUE;

  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  char *label = "ecdhtest";

  CK_ATTRIBUTE publicKeyTemplate[] = {{CKA_CLASS, &pubkey_class,
                                       sizeof(pubkey_class)},
                                      {CKA_VERIFY, &ck_true, sizeof(ck_true)},
                                      {CKA_KEY_TYPE, &key_type,
                                       sizeof(key_type)},
                                      {CKA_LABEL, label, strlen(label)},
                                      {CKA_EC_PARAMS, curve, curve_len}};

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &privkey_class,
                                        sizeof(privkey_class)},
                                       {CKA_LABEL, label, strlen(label)},
                                       {CKA_DERIVE, &ck_true, sizeof(ck_true)}};

  if ((p11->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, 5,
                              privateKeyTemplate, 3, publicKeyPtr,
                              privateKeyPtr)) != CKR_OK) {
    fail("Failed to generate EC key pair on YubiHSM");
    exit(EXIT_FAILURE);
  }
  success("Generated EC key pair on YubiHSM");
}

static EVP_PKEY *generate_keypair_openssl(const char *curve) {
  EVP_PKEY *pkey = NULL;
  EC_KEY *eckey = NULL;
  int eccgrp = OBJ_txt2nid(curve);
  eckey = EC_KEY_new_by_curve_name(eccgrp);
  if (!(EC_KEY_generate_key(eckey))) {
    fail("Failed to generate EC keypair with openssl");
  }
  pkey = EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
    fail("Failed to assign ECC key to EVP_PKEY structure");
  }
  return pkey;
}

static CK_ULONG get_yhsize(CK_OBJECT_HANDLE object) {
  CK_ULONG len;
  if ((p11->C_GetObjectSize(session, object, &len)) != CKR_OK) {
    printf("Failed to get size of object 0x%lx from yubihsm-pkcs11. FAIL\n",
           object);
    return 0;
  }
  return len;
}

static CK_ULONG get_yhvalue(CK_OBJECT_HANDLE object, unsigned char *value,
                            CK_ULONG object_size) {
  if (object_size > 0) {
    CK_ATTRIBUTE template[] = {{CKA_VALUE, value, object_size}};
    if ((p11->C_GetAttributeValue(session, object, template,
                                  sizeof(template) / sizeof(template[0]))) ==
        CKR_OK) {
      return object_size;
    } else {
      printf("Failed to retrieve object value from yubihsm-pkcs11. 0x%lx\n",
             object);
    }
  }
  return 0;
}

static CK_RV yh_derive(unsigned char *peerkey_bytes, int peerkey_len,
                       CK_OBJECT_HANDLE privkey, CK_ULONG kdf, char *label,
                       CK_OBJECT_HANDLE_PTR ecdh_key, CK_ULONG value_len,
                       CK_ULONG ecdh_len) {
  CK_ECDH1_DERIVE_PARAMS params;
  params.kdf = kdf;
  params.pSharedData = NULL;
  params.ulSharedDataLen = 0;
  params.pPublicData = peerkey_bytes;
  params.ulPublicDataLen = peerkey_len;

  CK_MECHANISM mechanism = {CKM_ECDH1_DERIVE, &params, sizeof(params)};

  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
  CK_ATTRIBUTE derivedKeyTemplate[] =
    {{CKA_CLASS, &key_class, sizeof(key_class)},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
     {CKA_VALUE_LEN, &value_len, sizeof(value_len)},
     {CKA_LABEL, label, strlen(label)}};

  CK_RV rv = CKR_OK;

  rv =
    p11->C_DeriveKey(session, &mechanism, privkey, derivedKeyTemplate,
                     sizeof(derivedKeyTemplate) / sizeof(derivedKeyTemplate[0]),
                     ecdh_key);
  if (rv != CKR_OK) {
    return rv;
  }

  CK_ULONG actual_len = get_yhsize(*ecdh_key);
  if ((ecdh_len != actual_len)) {
    printf("Derived ECDH is not the expected length. Expected %lu. Found %lu\n",
           ecdh_len, actual_len);
    rv = CKR_FUNCTION_FAILED;
  }

  return rv;
}

static unsigned int do_hash(const EVP_MD *md, uint8_t *hashed,
                            unsigned char *raw_derived,
                            size_t raw_derived_len) {

  EVP_MD_CTX *mdctx = NULL;
  unsigned int len = 0;

  mdctx = EVP_MD_CTX_create();
  if (mdctx == NULL) {
    fail("Failed to create Hash context");
    return 0;
  }

  if (EVP_DigestInit_ex(mdctx, md, NULL) == 0) {
    fail("Failed to initialize digest");
    goto h_free;
  }

  if (EVP_DigestUpdate(mdctx, raw_derived, raw_derived_len) != 1) {
    fail("Failed to update digest");
    goto h_free;
  }
  if (EVP_DigestFinal_ex(mdctx, hashed, &len) != 1) {
    fail("Failed to finalize digest");
    len = 0;
    goto h_free;
  }

h_free:
  if (mdctx != NULL) {
    EVP_MD_CTX_destroy(mdctx);
  }
  return len;
}

static size_t openssl_derive(CK_ULONG kdf, EVP_PKEY *private_key,
                             EVP_PKEY *peer_key, unsigned char **ecdh_key,
                             CK_ULONG expected_ecdh_len) {

  /* Create the context for the shared secret derivation */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
  if (!ctx) {
    fail("Failed to create new openssl context");
    return 0;
  }

  EVP_MD_CTX *mdctx = NULL;
  size_t len = 0;
  /* Initialize derivation function*/
  if (EVP_PKEY_derive_init(ctx) != 1) {
    fail("Failed to initialize openssl contex");
    goto c_free;
  }

  /* Set the peer public key */
  if (EVP_PKEY_derive_set_peer(ctx, peer_key) != 1) {
    fail("Failed to set the peer public key in the openssl context");
    goto c_free;
  }

  /* Determine buffer length for shared secret */
  if (EVP_PKEY_derive(ctx, NULL, &len) != 1) {
    fail("Failed to determine derived key expected size with openssl");
    goto c_free;
  }

  /* Create the buffer */
  unsigned char *derived = OPENSSL_malloc(len);
  if (derived == NULL) {
    fail("Failed to allocate the buffer to hold the ECDH key derived with "
         "openssl");
    len = 0;
    goto c_free;
  }

  /* Derive the shared secret */
  if ((EVP_PKEY_derive(ctx, derived, &len)) != 1) {
    fail("Failed to derive ECDH key with openssl");
    len = 0;
    goto c_free;
  }

  *ecdh_key = malloc(BUFSIZE);
  if (*ecdh_key == NULL) {
    fail("Failed to allocate the buffer to hold the ECDH key derived with "
         "openssl");
    len = 0;
    goto c_free;
  }

  size_t output_bits = 0;
  const EVP_MD *md = NULL;
  switch (kdf) {
    case CKD_NULL:
      memcpy(*ecdh_key, derived, len);
      goto c_truncate;
    case CKD_SHA1_KDF_SP800:
      md = EVP_sha1();
      output_bits = 160;
      break;
    case CKD_SHA256_KDF_SP800:
      md = EVP_sha256();
      output_bits = 256;
      break;
    case CKD_SHA384_KDF_SP800:
      md = EVP_sha384();
      output_bits = 384;
      break;
    case CKD_SHA512_KDF_SP800:
      md = EVP_sha512();
      output_bits = 384;
      break;
  }

  size_t l = expected_ecdh_len * 8;
  size_t reps = 1 + l / output_bits;

  uint8_t res[BUFSIZE] = {0};
  size_t res_len = 0;
  size_t ctr_len = 4;

  uint8_t k[BUFSIZE] = {0};
  size_t k_len = len + ctr_len;
  memset(k, 0, ctr_len);
  memcpy(k + ctr_len, derived, len);

  size_t hashed_len = 0;
  for (size_t i = 0; i < reps; i++) {
    increment_ctr(k, ctr_len);

    hashed_len = do_hash(md, res + res_len, k, k_len);
    if (hashed_len == 0) {
      fail("Failed to apply hash function");
      len = 0;
      goto c_free;
    }
    res_len += hashed_len;
  }

  if (expected_ecdh_len > res_len) {
    fail("Derived key is too short");
    len = 0;
    goto c_free;
  }

  memcpy(*ecdh_key, res, expected_ecdh_len);
  memset((*ecdh_key) + expected_ecdh_len, 0, BUFSIZE - expected_ecdh_len);
  len = expected_ecdh_len;

c_truncate:
  if (expected_ecdh_len < len) {
    size_t offset = len - expected_ecdh_len;
    memmove(*ecdh_key, *ecdh_key + offset, expected_ecdh_len);
    len = expected_ecdh_len;
  }

c_free:
  if (len == 0) {
    free(*ecdh_key);
  }
  EVP_PKEY_CTX_free(ctx);
  if (mdctx != NULL) {
    EVP_MD_CTX_destroy(mdctx);
  }
  EVP_PKEY_free(peer_key);
  EVP_PKEY_free(private_key);

  return len;
}

static unsigned char *openssl_derive_ecdh(CK_ULONG kdf, EVP_PKEY *private_key,
                                          CK_OBJECT_HANDLE peer_key,
                                          CK_ULONG expected_ecdh_len,
                                          size_t *ecdh_len) {
  CK_LONG peerkey_len = get_yhsize(peer_key);
  if (peerkey_len == 0) {
    fail("Failed to get peer key size");
    return 0;
  }

  unsigned char peerkey_bytes[peerkey_len]; // public key in DER
  if (get_yhvalue(peer_key, peerkey_bytes, peerkey_len) == 0) {
    fail("Failed to retrieve public key from yubihsm-pkcs11");
    return 0;
  }

  const unsigned char *p = peerkey_bytes;
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, peerkey_len);
  if (pkey == NULL) {
    fail("Failed to parse device public key with OpenSSL");
    return NULL;
  }

  unsigned char *derivekey_openssl = malloc(BUFSIZE);
  *ecdh_len = openssl_derive(kdf, private_key, pkey, &derivekey_openssl,
                             expected_ecdh_len);
  if (*ecdh_len == 0) {
    fail("Failed to derive key with openssl");
  }
  return derivekey_openssl;
}

static void run_test(void *handle, const char *curve, CK_ULONG kdf,
                     CK_OBJECT_HANDLE yh_privkey, CK_OBJECT_HANDLE yh_pubkey,
                     CK_ULONG value_len, CK_ULONG ecdh_len, CK_RV exp_res) {

  printf("EC key %s, KDF 0x%lx, value_len %lu. derived ECDH length: %lu. "
         "Expected error code: 0x%lx....",
         curve, kdf, value_len, ecdh_len, exp_res);

  unsigned char *peerkey_bytes = NULL;

  // Generate keypair with openssl
  EVP_PKEY *peer_keypair = generate_keypair_openssl(curve);
  if (peer_keypair == NULL) {
    fail("Failed to generate keypair with OpenSSL");
    goto clean_on_fail;
  }

  EC_KEY *peerkey = EVP_PKEY_get1_EC_KEY(peer_keypair);

  int peerkey_len = i2o_ECPublicKey(peerkey, &peerkey_bytes);
  if (peerkey_len < 0) {
    fail("Failed to extract public key from EC keypair generated with openssl");
    goto clean_on_fail;
  }

  EC_KEY_free(peerkey);

  // Derive with yubihsm
  CK_OBJECT_HANDLE yh_ecdh_key;
  CK_RV rv = yh_derive(peerkey_bytes, peerkey_len, yh_privkey, kdf, "ecdh",
                       &yh_ecdh_key, value_len, ecdh_len);
  if (rv != exp_res) {
    fail("Wrong error code was returned");
    goto clean_on_fail;
  }
  OPENSSL_free(peerkey_bytes);

  // If testing error handling, no need to test further
  if (exp_res != CKR_OK) {
    printf("OK!\n");
    return;
  }

  // Derive with openssl
  size_t ecdh_openssl_len = 0;
  unsigned char *ecdh_openssl =
    openssl_derive_ecdh(kdf, peer_keypair, yh_pubkey, ecdh_len,
                        &ecdh_openssl_len);
  if (ecdh_openssl_len == 0) {
    fail("Failed to derive key with openssl");
    goto clean_on_fail;
  }

  // Compare sizes
  CK_ULONG ecdh1_len = get_yhsize(yh_ecdh_key);
  if (ecdh1_len != ecdh_openssl_len) {
    fail(
      "ECDH keys derived with yubihsm-pkcs11 and with openssl do not have the "
      "same size");
    goto clean_on_fail;
  }

  // Compare values
  unsigned char ecdh1_bytes[BUFSIZE]; // public key in DER
  if (get_yhvalue(yh_ecdh_key, ecdh1_bytes, ecdh1_len) == 0) {
    fail("Failed to retrieve derived key from yubihsm-pkcs11");
    goto clean_on_fail;
  }

  bool equal = true;
  for (unsigned int i = 0; i < ecdh_openssl_len; i++) {
    if (ecdh1_bytes[i] != ecdh_openssl[i]) {
      equal = false;
      break;
    }
  }

  OPENSSL_free(ecdh_openssl);

  if (!equal) {
    fail(
      "ECDH keys derived with yubihsm-pkcs11 and with openssl do not have the "
      "same value");
    goto clean_on_fail;
  }

  printf("OK!\n");
  return;

clean_on_fail:
  if (peerkey_bytes != NULL) {
    OPENSSL_free(peerkey_bytes);
  }
  close_session(p11, session);
  close_module(handle);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "usage: /path/to/yubihsm_pkcs11/module\n");
    exit(EXIT_FAILURE);
  }

  void *handle = open_module(argv[1]);
  p11 = get_function_list(handle);
  session = open_session(p11);
  print_session_state(p11, session);

  int exit_status = EXIT_SUCCESS;

  CK_OBJECT_HANDLE yh_pubkey[4], yh_privkey[4];
  for (int i = 0; i < CURVE_COUNT; i++) {

    generate_keypair_yh(CURVE_PARAMS[i], CURVE_LENS[i], &yh_pubkey[i],
                        &yh_privkey[i]);
  }
  printf("\n");

  for (int i = 0; i < CURVE_COUNT; i++) {
    run_test(handle, CURVES[i], CKD_NULL, yh_privkey[i], yh_pubkey[i], 128 / 8,
             128 / 8, CKR_OK);
    run_test(handle, CURVES[i], CKD_NULL, yh_privkey[i], yh_pubkey[i], 192 / 8,
             192 / 8, CKR_OK);
  }

  run_test(handle, CURVES[0], CKD_NULL, yh_privkey[0], yh_pubkey[0], 256 / 8,
           256 / 8, CKR_DATA_LEN_RANGE);
  run_test(handle, CURVES[1], CKD_NULL, yh_privkey[1], yh_pubkey[1], 256 / 8,
           256 / 8, CKR_OK);
  run_test(handle, CURVES[2], CKD_NULL, yh_privkey[2], yh_pubkey[2], 256 / 8,
           256 / 8, CKR_OK);
  run_test(handle, CURVES[3], CKD_NULL, yh_privkey[3], yh_pubkey[3], 256 / 8,
           256 / 8, CKR_OK);

  CK_ULONG key_lens[3] = {128, 192, 256};

  for (int i = 0; i < CURVE_COUNT; i++) {
    for (size_t j = 0; j < 3; j++) {
      run_test(handle, CURVES[i], CKD_SHA1_KDF_SP800, yh_privkey[i],
               yh_pubkey[i], key_lens[j] / 8, key_lens[j] / 8, CKR_OK);
      run_test(handle, CURVES[i], CKD_SHA256_KDF_SP800, yh_privkey[i],
               yh_pubkey[i], key_lens[j] / 8, key_lens[j] / 8, CKR_OK);
      run_test(handle, CURVES[i], CKD_SHA384_KDF_SP800, yh_privkey[i],
               yh_pubkey[i], key_lens[j] / 8, key_lens[j] / 8, CKR_OK);
      run_test(handle, CURVES[i], CKD_SHA512_KDF_SP800, yh_privkey[i],
               yh_pubkey[i], key_lens[j] / 8, key_lens[j] / 8, CKR_OK);
    }

    run_test(handle, CURVES[i], CKD_NULL, yh_privkey[i], yh_pubkey[i], 0,
             CURVE_ECDH_LEN[i], CKR_OK);
    run_test(handle, CURVES[i], CKD_SHA1_KDF_SP800, yh_privkey[i],
             yh_pubkey[i], 0, 20, CKR_OK);
    run_test(handle, CURVES[i], CKD_SHA256_KDF_SP800, yh_privkey[i],
             yh_pubkey[i], 0, 32, CKR_OK);
    run_test(handle, CURVES[i], CKD_SHA384_KDF_SP800, yh_privkey[i],
             yh_pubkey[i], 0, 48, CKR_OK);
    run_test(handle, CURVES[i], CKD_SHA512_KDF_SP800, yh_privkey[i],
             yh_pubkey[i], 0, 64, CKR_OK);
  }
  run_test(handle, CURVES[0], CKD_NULL, yh_privkey[0], yh_pubkey[0], 1024, 0,
           CKR_ATTRIBUTE_VALUE_INVALID);

  printf("\n");
  for (int i = 0; i < CURVE_COUNT; i++) {
    if (destroy_object(p11, session, yh_privkey[i])) {
      success("Deleted key from YubiHSM");
    }
  }
  close_session(p11, session);
  close_module(handle);
  return (exit_status);
}
