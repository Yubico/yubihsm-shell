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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "../pkcs11.h"
#include "../pkcs11y.h"
#include "common.h"

#define BUFSIZE 1024

CK_BYTE P224_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21};
CK_BYTE P256_PARAMS[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                         0xce, 0x3d, 0x03, 0x01, 0x07};
CK_BYTE P384_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
CK_BYTE P521_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

static CK_FUNCTION_LIST_PTR p11;
static CK_SESSION_HANDLE session;

char *CURVES[] = {"secp224r1", "prime256v1", "secp384r1", "secp521r1"};
CK_BYTE *CURVE_PARAMS[] = {P224_PARAMS, P256_PARAMS, P384_PARAMS, P521_PARAMS};
CK_ULONG CURVE_LENS[] = {sizeof(P224_PARAMS), sizeof(P256_PARAMS),
                         sizeof(P384_PARAMS), sizeof(P521_PARAMS)};
int CURVE_COUNT = sizeof(CURVE_PARAMS) / sizeof(CURVE_PARAMS[0]);
CK_ULONG KDFS[] = {CKD_NULL, CKD_SHA1_KDF_SP800, CKD_SHA256_KDF_SP800,
                   CKD_SHA384_KDF_SP800, CKD_SHA512_KDF_SP800};
int KDFS_LEN = sizeof(KDFS) / sizeof(CK_ULONG);

static void success(const char *message) { printf("%s. OK\n", message); }

static void fail(const char *message) { printf("%s. FAIL!\n", message); }

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
  OpenSSL_add_all_algorithms();
  int eccgrp = OBJ_txt2nid(curve);
  eckey = EC_KEY_new_by_curve_name(eccgrp);
  if (!(EC_KEY_generate_key(eckey))) {
    fail("Failed to generate EC keypair with openssl");
  } else {
    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
      fail("Failed to assign ECC key to EVP_PKEY structure");
    }
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
    if ((p11->C_GetAttributeValue(session, object, template, 1)) == CKR_OK) {
      return object_size;
    } else {
      printf("Failed to retrieve object value from yubihsm-pkcs11. 0x%lx\n",
             object);
    }
  }
  return 0;
}

static bool yh_derive(unsigned char *peerkey_bytes, int peerkey_len,
                      CK_OBJECT_HANDLE privkey, CK_ULONG kdf, char *label,
                      CK_OBJECT_HANDLE_PTR ecdh_key) {
  CK_ECDH1_DERIVE_PARAMS params;
  params.kdf = kdf;
  params.pSharedData = NULL;
  params.ulSharedDataLen = 0;
  params.pPublicData = peerkey_bytes;
  params.ulPublicDataLen = peerkey_len;

  CK_MECHANISM mechanism = {CKM_ECDH1_DERIVE, (void *) &params, sizeof(params)};

  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_AES;
  CK_BBOOL t = CK_TRUE;
  CK_BBOOL f = CK_FALSE;

  CK_ATTRIBUTE derivedKeyTemplate[] = {{CKA_CLASS, &key_class,
                                        sizeof(key_class)},
                                       {CKA_KEY_TYPE, &key_type,
                                        sizeof(key_type)},
                                       {CKA_TOKEN, &f, sizeof(f)},
                                       {CKA_ENCRYPT, &t, sizeof(t)},
                                       {CKA_DECRYPT, &t, sizeof(t)},
                                       {CKA_EXTRACTABLE, &t, sizeof(t)},
                                       {CKA_SENSITIVE, &f, sizeof(f)},
                                       {CKA_LABEL, label, strlen(label)}};

  CK_RV rv = p11->C_DeriveKey(session, &mechanism, privkey, derivedKeyTemplate,
                              8, ecdh_key);
  return rv == CKR_OK;
}

static bool yh_derive_ecdh(CK_OBJECT_HANDLE priv_key, EVP_PKEY *peer_keypair,
                           CK_OBJECT_HANDLE_PTR ecdh_key, CK_ULONG kdf,
                           char *label, bool print_fail) {
  EC_KEY *peerkey = EVP_PKEY_get1_EC_KEY(peer_keypair);
  unsigned char *peerkey_bytes = NULL;
  int peerkey_len = i2o_ECPublicKey(peerkey, &peerkey_bytes);
  if (peerkey_len < 0) {
    fail("Failed to extract public key from EC keypair generated with openssl");
    return false;
  }

  EC_KEY_free(peerkey);

  if (!yh_derive(peerkey_bytes, peerkey_len, priv_key, kdf, label, ecdh_key)) {
    if (print_fail) {
      fail("Failed to derive ECDH key on yubihsm-pkcs11");
    }
    OPENSSL_free(peerkey_bytes);
    return false;
  }

  OPENSSL_free(peerkey_bytes);

  return true;
}

static size_t openssl_derive(CK_ULONG kdf, EVP_PKEY *private_key,
                             EVP_PKEY *peer_key, unsigned char **ecdh_key) {

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

  const EVP_MD *md;
  switch (kdf) {
    case CKD_NULL:
      *ecdh_key = malloc(len);
      if (*ecdh_key == NULL) {
        fail("Failed to allocate the buffer to hold the ECDH key derived with "
             "openssl");
        len = 0;
        goto c_free;
      }
      memcpy(*ecdh_key, derived, len);
      goto c_free;
    case CKD_SHA1_KDF_SP800:
      md = EVP_sha1();
      break;
    case CKD_SHA256_KDF_SP800:
      md = EVP_sha256();
      break;
    case CKD_SHA384_KDF_SP800:
      md = EVP_sha384();
      break;
    case CKD_SHA512_KDF_SP800:
      md = EVP_sha512();
      break;
    default:
      fail("Unsupported KDF");
      len = 0;
      goto c_free;
  }

  mdctx = EVP_MD_CTX_create();
  if (mdctx == NULL) {
    fail("Failed to create Hash context");
    len = 0;
    goto c_free;
  }

  if (EVP_DigestInit_ex(mdctx, md, NULL) == 0) {
    fail("Failed to initialize digest");
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

  if (EVP_DigestUpdate(mdctx, derived, len) != 1) {
    fail("Failed to update digest");
    len = 0;
    goto c_free;
  }
  if (EVP_DigestFinal_ex(mdctx, *ecdh_key, (unsigned int *) &len) != 1) {
    fail("Failed to finalize digest");
    len = 0;
    goto c_free;
  }

c_free:
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
  *ecdh_len = openssl_derive(kdf, private_key, pkey, &derivekey_openssl);
  if (*ecdh_len == 0) {
    fail("Failed to derive key with openssl");
  }
  return derivekey_openssl;
}

static bool test_ecdh_value(const char *curve, CK_ULONG kdf,
                            CK_OBJECT_HANDLE yh_privkey,
                            CK_OBJECT_HANDLE yh_pubkey,
                            CK_OBJECT_HANDLE_PTR ecdh1) {

  // Generate keypair with openssl
  EVP_PKEY *openssl_keypair = generate_keypair_openssl(curve);
  if (openssl_keypair == NULL) {
    fail("Failed to generate keypair with OpenSSL");
    return false;
  }

  // Derive with yubihsm
  if (!yh_derive_ecdh(yh_privkey, openssl_keypair, ecdh1, kdf, "ecdh1", true)) {
    fail("Failed to derive ECDH in the YubiHSM");
    return false;
  }

  // Derive with openssl
  size_t ecdh_openssl_len = 0;
  unsigned char *ecdh_openssl =
    openssl_derive_ecdh(kdf, openssl_keypair, yh_pubkey, &ecdh_openssl_len);
  if (ecdh_openssl_len == 0) {
    fail("Failed to derive key with openssl");
    return false;
  }

  // Compare sizes
  CK_ULONG ecdh1_len = get_yhsize(*ecdh1);
  if (ecdh1_len != ecdh_openssl_len) {
    fail(
      "ECDH keys derived with yubihsm-pkcs11 and with openssl do not have the "
      "same size");
    return false;
  }

  // Compare values
  unsigned char ecdh1_bytes[BUFSIZE]; // public key in DER
  if (get_yhvalue(*ecdh1, ecdh1_bytes, ecdh1_len) == 0) {
    fail("Failed to retrieve derived key from yubihsm-pkcs11");
    return false;
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
    return false;
  }

  return true;
}

static bool test_duplicate_ecdh(const char *curve, CK_ULONG kdf,
                                CK_OBJECT_HANDLE yh_privkey,
                                CK_OBJECT_HANDLE_PTR ecdh2,
                                CK_OBJECT_HANDLE_PTR ecdh3) {
  EVP_PKEY *openssl_keypair = generate_keypair_openssl(curve);
  if (openssl_keypair == NULL) {
    return false;
  }

  if (!yh_derive_ecdh(yh_privkey, openssl_keypair, ecdh2, kdf, "ecdh2", true)) {
    EVP_PKEY_free(openssl_keypair);
    return false;
  }
  if (!yh_derive_ecdh(yh_privkey, openssl_keypair, ecdh3, kdf, "ecdh3", true)) {
    EVP_PKEY_free(openssl_keypair);
    return false;
  }
  EVP_PKEY_free(openssl_keypair);

  size_t ecdh1_len = get_yhsize(*ecdh2);
  size_t ecdh2_len = get_yhsize(*ecdh3);
  if (ecdh1_len == 0 || ecdh2_len == 0) {
    return false;
  }

  if (ecdh1_len != ecdh2_len) {
    fail(
      "2 ECDH keys derived from the same base keys do not have the same size");
    return false;
  }

  unsigned char ecdh1_value[BUFSIZE], ecdh2_value[BUFSIZE];
  if (get_yhvalue(*ecdh2, ecdh1_value, ecdh1_len) == 0) {
    return false;
  }
  if (get_yhvalue(*ecdh3, ecdh2_value, ecdh2_len) == 0) {
    return false;
  }

  bool equal = true;
  for (unsigned int i = 0; i < ecdh1_len; i++) {
    if (ecdh1_value[i] != ecdh2_value[i]) {
      equal = false;
      break;
    }
  }
  if (!equal) {
    fail(
      "ECDH keys derived from the same base keys do not have the same value");
    return false;
  }

  return true;
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

  CK_OBJECT_HANDLE yh_pubkey, yh_privkey;
  for (int i = 0; i < CURVE_COUNT; i++) {

    printf("\n/////// Testing curve %s\n", CURVES[i]);

    generate_keypair_yh(CURVE_PARAMS[i], CURVE_LENS[i], &yh_pubkey,
                        &yh_privkey);

    for (int j = 0; j < KDFS_LEN; j++) {
      CK_OBJECT_HANDLE ecdh1, ecdh2, ecdh3;

      printf("Testing the value of ECDH key derived by yubihsm-pkcs11 with KDF "
             "0x%lx...",
             KDFS[j]);
      if (test_ecdh_value(CURVES[i], KDFS[j], yh_privkey, yh_pubkey, &ecdh1)) {
        printf("OK!\n");
      } else {
        printf("FAIL!\n");
        exit_status = EXIT_FAILURE;
        goto c_clean;
      }

      printf("Testing that 2 ECDH keys derived with KDF 0x%lx and from the "
             "same base keys are equal... ",
             KDFS[j]);
      if (test_duplicate_ecdh(CURVES[i], KDFS[j], yh_privkey, &ecdh2, &ecdh3)) {
        printf("OK!\n");
      } else {
        printf("FAIL!\n");
        exit_status = EXIT_FAILURE;
        goto c_clean;
      }
    }

    destroy_object(p11, session, yh_privkey);
  }

c_clean:
  if (exit_status == EXIT_FAILURE) {
    destroy_object(p11, session, yh_privkey);
  }
  close_session(p11, session);
  close_module(handle);
  return (exit_status);
}
