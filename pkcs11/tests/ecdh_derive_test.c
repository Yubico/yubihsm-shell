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
#include <stdbool.h>

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

static CK_FUNCTION_LIST_PTR p11;
static CK_SESSION_HANDLE session;

char *CURVES[] = {"secp224r1", "prime256v1", "secp384r1", "secp521r1"};
CK_BYTE *CURVE_PARAMS[] = {P224_PARAMS, P256_PARAMS, P384_PARAMS, P521_PARAMS};
CK_ULONG CURVE_LENS[] = {sizeof(P224_PARAMS), sizeof(P256_PARAMS),
                         sizeof(P384_PARAMS), sizeof(P521_PARAMS)};
int CURVE_COUNT = sizeof(CURVE_PARAMS) / sizeof(CURVE_PARAMS[0]);

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
                      CK_OBJECT_HANDLE privkey, char *label,
                      CK_OBJECT_HANDLE_PTR ecdh_key) {
  CK_ECDH1_DERIVE_PARAMS params;
  params.kdf = CKD_NULL;
  params.pSharedData = NULL;
  params.ulSharedDataLen = 0;
  params.pPublicData = peerkey_bytes;
  params.ulPublicDataLen = peerkey_len;

  CK_MECHANISM mechanism = {CKM_ECDH1_DERIVE, (void *) &params, sizeof(params)};

  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;

  CK_ATTRIBUTE derivedKeyTemplate[] = {{CKA_CLASS, &key_class,
                                        sizeof(key_class)},
                                       {CKA_KEY_TYPE, &key_type,
                                        sizeof(key_type)},
                                       {CKA_LABEL, label, strlen(label)}};

  if ((p11->C_DeriveKey(session, &mechanism, privkey, derivedKeyTemplate, 3,
                        ecdh_key)) != CKR_OK) {
    return false;
  }
  return true;
}

static bool yh_derive_ecdh(CK_OBJECT_HANDLE priv_key, EVP_PKEY *peer_keypair,
                           CK_OBJECT_HANDLE_PTR ecdh_key, char *label,
                           bool print_fail) {
  EC_KEY *peerkey = EVP_PKEY_get1_EC_KEY(peer_keypair);
  unsigned char *peerkey_bytes = NULL;
  int peerkey_len = i2o_ECPublicKey(peerkey, &peerkey_bytes);
  if (peerkey_len < 0) {
    fail("Failed to extract public key from EC keypair generated with openssl");
    return false;
  }

  EC_KEY_free(peerkey);

  if (!yh_derive(peerkey_bytes, peerkey_len, priv_key, label, ecdh_key)) {
    if (print_fail) {
      fail("Failed to derive ECDH key on yubihsm-pkcs11");
    }
    OPENSSL_free(peerkey_bytes);
    return false;
  }

  OPENSSL_free(peerkey_bytes);

  return true;
}

static size_t openssl_derive(EVP_PKEY *private_key, EVP_PKEY *peer_key,
                             unsigned char **ecdh_key) {
  /* Create the context for the shared secret derivation */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
  if (!ctx) {
    fail("Failed to create new openssl context");
    return 0;
  }

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
  *ecdh_key = OPENSSL_malloc(len);
  if (*ecdh_key == NULL) {
    fail("Failed to allocate the buffer to hold the ECDH key derived with "
         "openssl");
    len = 0;
    goto c_free;
  }

  /* Derive the shared secret */
  if ((EVP_PKEY_derive(ctx, *ecdh_key, &len)) != 1) {
    fail("Failed to derive ECDH key with openssl");
    len = 0;
    goto c_free;
  }

c_free:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer_key);
  EVP_PKEY_free(private_key);

  return len;
}

static unsigned char *openssl_derive_ecdh(EVP_PKEY *private_key,
                                          CK_OBJECT_HANDLE peer_key,
                                          size_t *ecdh_len) {
  CK_LONG peerkey_len = get_yhsize(peer_key);
  if (peerkey_len == 0) {
    return 0;
  }

  unsigned char peerkey_bytes[peerkey_len]; // public key in DER
  if (get_yhvalue(peer_key, peerkey_bytes, peerkey_len) == 0) {
    fail("Failed to retrieve public key from yubihsm-pkcs11");
    return 0;
  }

  const unsigned char *p = peerkey_bytes;
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, peerkey_len);

  unsigned char *derivekey_openssl = NULL;
  *ecdh_len = openssl_derive(private_key, pkey, &derivekey_openssl);
  if (*ecdh_len == 0) {
    fail("Failed to derive key with openssl");
  }
  return derivekey_openssl;
}

static bool test_ecdh_value(const char *curve, CK_OBJECT_HANDLE yh_privkey,
                            CK_OBJECT_HANDLE yh_pubkey,
                            CK_OBJECT_HANDLE_PTR ecdh1) {

  // Generate keypair with openssl
  EVP_PKEY *openssl_keypair = generate_keypair_openssl(curve);
  if (openssl_keypair == NULL) {
    return false;
  }

  // Derive with yubihsm
  yh_derive_ecdh(yh_privkey, openssl_keypair, ecdh1, "ecdh1", true);

  // Derive with openssl
  size_t ecdh_openssl_len = 0;
  unsigned char *ecdh_openssl =
    openssl_derive_ecdh(openssl_keypair, yh_pubkey, &ecdh_openssl_len);
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

static bool test_duplicate_ecdh(const char *curve, CK_OBJECT_HANDLE yh_privkey,
                                CK_OBJECT_HANDLE_PTR ecdh2,
                                CK_OBJECT_HANDLE_PTR ecdh3) {
  EVP_PKEY *openssl_keypair = generate_keypair_openssl(curve);
  if (openssl_keypair == NULL) {
    return false;
  }

  if (!yh_derive_ecdh(yh_privkey, openssl_keypair, ecdh2, "ecdh2", true)) {
    EVP_PKEY_free(openssl_keypair);
    return false;
  }
  if (!yh_derive_ecdh(yh_privkey, openssl_keypair, ecdh3, "ecdh3", true)) {
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

static bool test_faulty_ecdh(const char *curve1, const char *curve2,
                             CK_OBJECT_HANDLE_PTR yh_privkey,
                             CK_OBJECT_HANDLE_PTR ecdh_key) {
  // Derive from keys of different curves
  EVP_PKEY *openssl_keypair = generate_keypair_openssl(curve2);
  if (openssl_keypair == NULL) {
    return false;
  }

  CK_OBJECT_HANDLE faulty_ecdh;
  if (yh_derive_ecdh(*yh_privkey, openssl_keypair, &faulty_ecdh, "", false)) {
    fail("Was able to derive ECDH key from EC keys of different curves");
    EVP_PKEY_free(openssl_keypair);
    return false;
  }
  EVP_PKEY_free(openssl_keypair);

  // Derive key from another derived key
  EVP_PKEY *key_openssl2 = generate_keypair_openssl(curve1);
  if (yh_derive_ecdh(*ecdh_key, key_openssl2, &faulty_ecdh, "", false)) {
    fail("Was able to derive ECDH key using another ECDH key");
    EVP_PKEY_free(key_openssl2);
    return false;
  }
  EVP_PKEY_free(key_openssl2);

  // Derive key using the wrong mechanism
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &key_class, sizeof(key_class)},
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
  };

  CK_RV rv = p11->C_DeriveKey(session, &mechanism, *yh_privkey, template, 2,
                              &faulty_ecdh);
  if (rv != CKR_MECHANISM_INVALID) {
    fail("Expected CKR_MECHANISM_INVALID when invalid mechanism is "
         "specified");
    return false;
  }

  return true;
}

/* This checks the same attributes that validate_ecdh_attributes() does but
 * makes sure the input buffer are too small for all of them and then
 * checks that we return the correct values in this case.
 */
static bool check_attributes_buffer_too_small(CK_OBJECT_HANDLE key_id) {
  CK_OBJECT_CLASS key_class;
  CK_KEY_TYPE key_type;
  CK_BBOOL is_local;
  CK_BBOOL is_token;
  CK_BBOOL is_destroyable;
  CK_BBOOL is_extractable;
  CK_BBOOL is_never_extractable;
  CK_BBOOL is_sensitive;
  CK_BBOOL is_always_sensitive;
  CK_BBOOL is_modifiable;
  CK_BBOOL is_copyable;
  CK_BBOOL is_sign;
  CK_BBOOL is_sign_recover;
  CK_BBOOL is_always_authenticated;
  CK_BBOOL is_unwrap;
  CK_BBOOL is_wrap;
  CK_BBOOL is_wrap_with_trusted;
  CK_BBOOL is_verify;
  CK_BBOOL is_encrypt;
  CK_BBOOL is_derive;

  CK_BYTE publicValue[1];
  char label[1] = {0};
  size_t label_len = sizeof(label) - 1;
  CK_BYTE id[1];

  CK_ATTRIBUTE template[] =
    {{CKA_CLASS, &key_class, sizeof(key_class) - 1},
     {CKA_ID, &id, sizeof(id) - 1},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type) - 1},
     {CKA_LOCAL, &is_local, sizeof(is_local) - 1},
     {CKA_TOKEN, &is_token, sizeof(is_token) - 1},
     {CKA_DESTROYABLE, &is_destroyable, sizeof(is_destroyable) - 1},
     {CKA_EXTRACTABLE, &is_extractable, sizeof(is_extractable) - 1},
     {CKA_NEVER_EXTRACTABLE, &is_never_extractable,
      sizeof(is_never_extractable) - 1},
     {CKA_SENSITIVE, &is_sensitive, sizeof(is_sensitive) - 1},
     {CKA_ALWAYS_SENSITIVE, &is_always_sensitive,
      sizeof(is_always_sensitive) - 1},
     {CKA_MODIFIABLE, &is_modifiable, sizeof(is_modifiable) - 1},
     {CKA_COPYABLE, &is_copyable, sizeof(is_copyable) - 1},
     {CKA_SIGN, &is_sign, sizeof(is_sign) - 1},
     {CKA_SIGN_RECOVER, &is_sign_recover, sizeof(is_sign_recover) - 1},
     {CKA_ALWAYS_AUTHENTICATE, &is_always_authenticated,
      sizeof(is_always_authenticated) - 1},
     {CKA_UNWRAP, &is_unwrap, sizeof(is_unwrap) - 1},
     {CKA_WRAP, &is_wrap, sizeof(is_wrap) - 1},
     {CKA_WRAP_WITH_TRUSTED, &is_wrap_with_trusted,
      sizeof(is_wrap_with_trusted) - 1},
     {CKA_VERIFY, &is_verify, sizeof(is_verify) - 1},
     {CKA_ENCRYPT, &is_encrypt, sizeof(is_encrypt) - 1},
     {CKA_DERIVE, &is_derive, sizeof(is_derive) - 1},
     {CKA_VALUE, &publicValue, sizeof(publicValue) - 1},
     {CKA_LABEL, label, label_len}};

  CK_ULONG attribute_count = 23;

  CK_RV rv =
    p11->C_GetAttributeValue(session, key_id, template, attribute_count);
  if (rv != CKR_BUFFER_TOO_SMALL) {
    fail("Should have returned buffer too small!");
    return false;
  }
  for (CK_ULONG i = 0; i < attribute_count; ++i) {
    if (template[i].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
      fail("ulValueLen should be CK_UNAVAILABLE_INFORMATION.");
      return false;
    }
  }
  return true;
}

static bool validate_ecdh_attributes(CK_OBJECT_HANDLE key_id,
                                     char *expected_label) {

  CK_OBJECT_CLASS key_class;
  CK_KEY_TYPE key_type;
  CK_BBOOL is_local;
  CK_BBOOL is_token;
  CK_BBOOL is_destroyable;
  CK_BBOOL is_extractable;
  CK_BBOOL is_never_extractable;
  CK_BBOOL is_sensitive;
  CK_BBOOL is_always_sensitive;
  CK_BBOOL is_modifiable;
  CK_BBOOL is_copyable;
  CK_BBOOL is_sign;
  CK_BBOOL is_sign_recover;
  CK_BBOOL is_always_authenticated;
  CK_BBOOL is_unwrap;
  CK_BBOOL is_wrap;
  CK_BBOOL is_wrap_with_trusted;
  CK_BBOOL is_verify;
  CK_BBOOL is_encrypt;
  CK_BBOOL is_derive;

  CK_BYTE publicValue[128];
  char label[41] = {0};
  size_t label_len = sizeof(label) - 1;

  CK_ATTRIBUTE template[] =
    {{CKA_CLASS, &key_class, sizeof(key_class)},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
     {CKA_LOCAL, &is_local, sizeof(is_local)},
     {CKA_TOKEN, &is_token, sizeof(is_token)},
     {CKA_DESTROYABLE, &is_destroyable, sizeof(is_destroyable)},
     {CKA_EXTRACTABLE, &is_extractable, sizeof(is_extractable)},
     {CKA_NEVER_EXTRACTABLE, &is_never_extractable,
      sizeof(is_never_extractable)},
     {CKA_SENSITIVE, &is_sensitive, sizeof(is_sensitive)},
     {CKA_ALWAYS_SENSITIVE, &is_always_sensitive, sizeof(is_always_sensitive)},
     {CKA_MODIFIABLE, &is_modifiable, sizeof(is_modifiable)},
     {CKA_COPYABLE, &is_copyable, sizeof(is_copyable)},
     {CKA_SIGN, &is_sign, sizeof(is_sign)},
     {CKA_SIGN_RECOVER, &is_sign_recover, sizeof(is_sign_recover)},
     {CKA_ALWAYS_AUTHENTICATE, &is_always_authenticated,
      sizeof(is_always_authenticated)},
     {CKA_UNWRAP, &is_unwrap, sizeof(is_unwrap)},
     {CKA_WRAP, &is_wrap, sizeof(is_wrap)},
     {CKA_WRAP_WITH_TRUSTED, &is_wrap_with_trusted,
      sizeof(is_wrap_with_trusted)},
     {CKA_VERIFY, &is_verify, sizeof(is_verify)},
     {CKA_ENCRYPT, &is_encrypt, sizeof(is_encrypt)},
     {CKA_DERIVE, &is_derive, sizeof(is_derive)},
     {CKA_VALUE, &publicValue, sizeof(publicValue)},
     {CKA_LABEL, label, label_len}};

  CK_ULONG attribute_count = 22;

  CK_RV rv =
    p11->C_GetAttributeValue(session, key_id, template, attribute_count);
  if (rv != CKR_OK) {
    fail("Failed to retrieve ECDH key attributes from yubihsm-pkcs11");
    return false;
  }

  if (key_class != CKO_SECRET_KEY) {
    fail("Derived ECDH key class is not CKO_SECRET_KEY");
    return false;
  }

  if (key_type != CKK_GENERIC_SECRET) {
    fail("Derived ECDH key type is not CKK_GENERIC_SECRET");
    return false;
  }

  if (is_local != CK_FALSE) {
    fail("Derived ECDH key LOCAL attribute is not CK_FALSE");
    return false;
  }

  if (is_token != CK_FALSE) {
    fail("Derived ECDH key TOKEN attribute is not CK_FALSE");
    return false;
  }

  if (is_destroyable != CK_TRUE) {
    fail("Derived ECDH key DESTROYABLE attribute is not CK_TRUE");
    return false;
  }

  if (is_extractable != CK_TRUE) {
    fail("Derived ECDH key EXTRACTABLE attribute is not CK_TRUE");
    return false;
  }

  if (is_never_extractable != CK_FALSE) {
    fail("Derived ECDH key NEVER_EXTRACTABLE attribute is not CK_FALSE");
    return false;
  }

  if (is_sensitive != CK_FALSE) {
    fail("Derived ECDH key SENSITIVE attribute is not CK_FALSE");
    return false;
  }

  if (is_always_sensitive != CK_FALSE) {
    fail("Derived ECDH key ALWAYS_SENSITIVE attribute is not CK_FALSE");
    return false;
  }

  if (is_modifiable != CK_FALSE) {
    fail("Derived ECDH key MODIFIABLE attribute is not CK_FALSE");
    return false;
  }

  if (is_copyable != CK_FALSE) {
    fail("Derived ECDH key COPYABLE attribute is not CK_FALSE");
    return false;
  }

  if (is_sign != CK_FALSE) {
    fail("Derived ECDH key SIGN attribute is not CK_FALSE");
    return false;
  }

  if (is_sign_recover != CK_FALSE) {
    fail("Derived ECDH key SIGN_RECOVER attribute is not CK_FALSE");
    return false;
  }

  if (is_always_authenticated != CK_FALSE) {
    fail("Derived ECDH key ALWAYS_AUTHENTICATED attribute is not CK_FALSE");
    return false;
  }

  if (is_unwrap != CK_FALSE) {
    fail("Derived ECDH key UNWRAP attribute is not CK_FALSE");
    return false;
  }

  if (is_wrap != CK_FALSE) {
    fail("Derived ECDH key WRAP attribute is not CK_FALSE");
    return false;
  }

  if (is_wrap_with_trusted != CK_FALSE) {
    fail("Derived ECDH key WRAP_WITH_TRUSTED attribute is not CK_FALSE");
    return false;
  }

  if (is_verify != CK_FALSE) {
    fail("Derived ECDH key VERIFY attribute is not CK_FALSE");
    return false;
  }

  if (is_encrypt != CK_FALSE) {
    fail("Derived ECDH key ENCRYPT attribute is not CK_FALSE");
    return false;
  }

  if (is_derive != CK_FALSE) {
    fail("Derived ECDH key DERIVE attribute is not CK_FALSE");
    return false;
  }

  if (strcmp(label, expected_label) != 0) {
    fail("Derived ECDH key does not have the expected label");
    return false;
  }

  return true;
}

static bool find(CK_ATTRIBUTE template[], CK_ULONG attribute_count,
                 CK_OBJECT_HANDLE_PTR ecdh1, CK_OBJECT_HANDLE_PTR ecdh2,
                 CK_OBJECT_HANDLE_PTR ecdh3, int expected_ecdh_count) {
  bool ret = true;
  if ((p11->C_FindObjectsInit(session, template, attribute_count)) != CKR_OK) {
    fail("Failed to initialize search function");
    return false;
  } else {
    int max_items_count = 256 + 255;
    CK_OBJECT_HANDLE found_objects[max_items_count];
    CK_ULONG total_objects_found;
    if ((p11->C_FindObjects(session, found_objects, max_items_count,
                            &total_objects_found)) == CKR_OK) {
      if ((expected_ecdh_count > 0) && (total_objects_found == 0)) {
        fail("Not enough objects were found");
        ret = false;
      } else {
        int found = 0;
        for (size_t i = 0; i < total_objects_found; i++) {
          if (found_objects[i] == *ecdh1 || found_objects[i] == *ecdh2 ||
              found_objects[i] == *ecdh3) {
            found++;
          }
        }
        if (found != expected_ecdh_count) {
          fail("Target object were not found or were found when they should "
               "not have");
          ret = false;
        }
      }
    } else {
      fail("Search operation failed");
      ret = false;
    }

    if ((p11->C_FindObjectsFinal(session)) != CKR_OK) {
      fail("Failed to finalize search function");
      ret = false;
    }
  }
  return ret;
}

static bool find_secret_keys(CK_OBJECT_HANDLE_PTR ecdh1,
                             CK_OBJECT_HANDLE_PTR ecdh2,
                             CK_OBJECT_HANDLE_PTR ecdh3) {
  CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;

  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &secret_key_class, sizeof(secret_key_class)}};
  return find(template, 1, ecdh1, ecdh2, ecdh3, 3);
}

static bool find_public_keys(CK_OBJECT_HANDLE_PTR ecdh1,
                             CK_OBJECT_HANDLE_PTR ecdh2,
                             CK_OBJECT_HANDLE_PTR ecdh3) {
  CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;

  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &public_key_class, sizeof(public_key_class)}};
  return find(template, 1, ecdh1, ecdh2, ecdh3, 0);
}

static bool find_secret_extractable_keys(CK_OBJECT_HANDLE_PTR ecdh1,
                                         CK_OBJECT_HANDLE_PTR ecdh2,
                                         CK_OBJECT_HANDLE_PTR ecdh3,
                                         int expected_count) {
  CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
  CK_BBOOL ck_true = CK_TRUE;

  CK_ATTRIBUTE template[] = {{CKA_CLASS, &secret_key_class,
                              sizeof(secret_key_class)},
                             {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)}};
  return find(template, 2, ecdh1, ecdh2, ecdh3, expected_count);
}

static bool find_secret_unextractable_keys(CK_OBJECT_HANDLE_PTR ecdh1,
                                           CK_OBJECT_HANDLE_PTR ecdh2,
                                           CK_OBJECT_HANDLE_PTR ecdh3) {
  CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
  CK_BBOOL ck_false = CK_FALSE;

  CK_ATTRIBUTE template[] = {{CKA_CLASS, &secret_key_class,
                              sizeof(secret_key_class)},
                             {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)}};
  return find(template, 2, ecdh1, ecdh2, ecdh3, 0);
}

static bool
find_secret_extractable_keys_wrong_label(CK_OBJECT_HANDLE_PTR ecdh1,
                                         CK_OBJECT_HANDLE_PTR ecdh2,
                                         CK_OBJECT_HANDLE_PTR ecdh3) {
  CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
  CK_BBOOL ck_true = CK_TRUE;

  char *label = "ecdhtest";
  CK_ATTRIBUTE template[] = {{CKA_CLASS, &secret_key_class,
                              sizeof(secret_key_class)},
                             {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
                             {CKA_LABEL, label, strlen(label)}};
  return find(template, 3, ecdh1, ecdh2, ecdh3, 0);
}

static bool find_secret_key_with_id(CK_OBJECT_HANDLE_PTR ecdh1,
                                    CK_OBJECT_HANDLE_PTR ecdh2,
                                    CK_OBJECT_HANDLE_PTR ecdh3,
                                    CK_OBJECT_HANDLE_PTR key) {
  CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;

  CK_ATTRIBUTE template[] = {{CKA_CLASS, &secret_key_class,
                              sizeof(secret_key_class)},
                             {CKA_ID, key, sizeof(*key)}};
  return find(template, 2, ecdh1, ecdh2, ecdh3, 0);
}

static bool find_secret_key_right_label(CK_OBJECT_HANDLE_PTR ecdh1,
                                        CK_OBJECT_HANDLE_PTR ecdh2,
                                        CK_OBJECT_HANDLE_PTR ecdh3) {
  CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;

  char *label = "ecdh2";
  CK_ATTRIBUTE template[] = {{CKA_CLASS, &secret_key_class,
                              sizeof(secret_key_class)},
                             {CKA_LABEL, label, strlen(label)}};
  return find(template, 2, ecdh1, ecdh2, ecdh3, 1);
}

static bool find_public_key_right_label(CK_OBJECT_HANDLE_PTR ecdh1,
                                        CK_OBJECT_HANDLE_PTR ecdh2,
                                        CK_OBJECT_HANDLE_PTR ecdh3) {

  CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;

  CK_ATTRIBUTE template[] = {{CKA_CLASS, &public_key_class,
                              sizeof(public_key_class)},
                             {CKA_LABEL, "ecdh2", strlen("ecdh2")}};
  return find(template, 2, ecdh1, ecdh2, ecdh3, 0);
}

static bool find_empty_template(CK_OBJECT_HANDLE_PTR ecdh1,
                                CK_OBJECT_HANDLE_PTR ecdh2,
                                CK_OBJECT_HANDLE_PTR ecdh3) {
  CK_ATTRIBUTE *template = NULL;
  return find(template, 0, ecdh1, ecdh2, ecdh3, 3);
}

static bool test_decrypt(CK_OBJECT_HANDLE_PTR ecdh) {
  CK_MECHANISM rsa_mechanism = {CKM_RSA_PKCS, NULL, 0};
  if ((p11->C_DecryptInit(session, &rsa_mechanism, *ecdh)) !=
      CKR_KEY_TYPE_INCONSISTENT) {
    fail("Initializing decryption did not return the error code "
         "CKR_KEY_TYPE_INCONSISTENT");
    return false;
  }
  return true;
}

static bool test_sign(CK_OBJECT_HANDLE_PTR ecdh) {
  CK_MECHANISM rsa_mechanism = {CKM_RSA_PKCS, NULL, 0};
  if ((p11->C_SignInit(session, &rsa_mechanism, *ecdh)) !=
      CKR_FUNCTION_NOT_SUPPORTED) {
    fail("Initializing signing did not return the error code "
         "CKR_FUNCTION_NOT_SUPPORTED");
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
    CK_OBJECT_HANDLE ecdh1, ecdh2, ecdh3;

    printf("Testing the value of ECDH key derived by yubihsm-pkcs11... ");
    if (test_ecdh_value(CURVES[i], yh_privkey, yh_pubkey, &ecdh1)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf(
      "Testing that 2 ECDH keys derived from the same base keys are equal... ");
    if (test_duplicate_ecdh(CURVES[i], yh_privkey, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Testing deriving ECDH keys with faulty parameters... ");
    if (test_faulty_ecdh(CURVES[i], i == 0 ? CURVES[i + 1] : CURVES[i - 1],
                         &yh_privkey, &ecdh1)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Validating ECDH attributes... ");
    if (validate_ecdh_attributes(ecdh1, "ecdh1")) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Validating ECDH attributes... but with too small buffers...");
    if (check_attributes_buffer_too_small(ecdh1)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    // ------- Start C_FindObjects functions test

    printf("Finding ECDH keys: secret keys... ");
    if (find_secret_keys(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: public keys... ");
    if (find_public_keys(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: secret, extractable keys... ");
    if (find_secret_extractable_keys(&ecdh1, &ecdh2, &ecdh3, 3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: secret, un-extractable keys... ");
    if (find_secret_unextractable_keys(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: secret, extractable keys with wrong label... ");
    if (find_secret_extractable_keys_wrong_label(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: secret key with specific ID... ");
    if (find_secret_key_with_id(&ecdh1, &ecdh2, &ecdh3, &yh_privkey)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: secret key with right label... ");
    if (find_secret_key_right_label(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: public key with right label... ");
    if (find_public_key_right_label(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Finding ECDH keys: use empty template... ");
    if (find_empty_template(&ecdh1, &ecdh2, &ecdh3)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    // ------- End C_FindObjects functions test

    printf("Destroying ECDH key 1... ");
    destroy_object(p11, session, ecdh1);
    if (find_secret_extractable_keys(&ecdh1, &ecdh2, &ecdh3, 2)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Destroying ECDH key 2... ");
    destroy_object(p11, session, ecdh3);
    if (find_secret_extractable_keys(&ecdh1, &ecdh2, &ecdh3, 1)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Testing decryption... ");
    if (test_decrypt(&ecdh2)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Testing signing... ");
    if (test_sign(&ecdh2)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
    }

    printf("Destroying ECDH key 3... ");
    destroy_object(p11, session, ecdh2);
    if (find_secret_extractable_keys(&ecdh1, &ecdh2, &ecdh3, 0)) {
      printf("OK!\n");
    } else {
      printf("FAIL!\n");
      exit_status = EXIT_FAILURE;
      goto c_clean;
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
