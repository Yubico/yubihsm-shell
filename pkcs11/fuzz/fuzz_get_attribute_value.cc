#include <assert.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/x509.h>

#include "../src/fuzz/fuzzer.h"

extern "C" {
#include "pkcs11.h"
#include "yubihsm_pkcs11.h"

uint8_t *backend_data;
size_t backend_data_len;
}

yh_connector *connector;
CK_FUNCTION_LIST_PTR p11;
CK_SESSION_HANDLE session;

static bool initialize() {
  CK_C_INITIALIZE_ARGS initArgs;
  char config[] = "connector=yhfuzz://yubihsm_fuzz debug";

  yh_set_verbosity(NULL, YH_VERB_ALL);

  C_GetFunctionList(&p11);

  memset(&initArgs, 0, sizeof(initArgs));
  initArgs.pReserved = (void *) config;
  CK_RV rv = p11->C_Initialize(&initArgs);
  assert(rv == CKR_OK);

  return true;
}

static EVP_PKEY *generate_keypair_openssl() {
  EVP_PKEY *pkey = NULL;
  EC_KEY *eckey = NULL;
  OpenSSL_add_all_algorithms();
  int eccgrp = OBJ_txt2nid("secp224r1");
  eckey = EC_KEY_new_by_curve_name(eccgrp);
  if (!(EC_KEY_generate_key(eckey))) {
  } else {
    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
    }
  }
  return pkey;
}

static int generate_keypair_yh(CK_OBJECT_HANDLE_PTR publicKeyPtr,
                               CK_OBJECT_HANDLE_PTR privateKeyPtr) {
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

  CK_BBOOL ck_true = CK_TRUE;

  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  char label[] = "ecdhtest";

  CK_BYTE P224_CURVE_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21};

  CK_ATTRIBUTE publicKeyTemplate[] =
    {{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
     {CKA_VERIFY, &ck_true, sizeof(ck_true)},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
     {CKA_LABEL, label, strlen(label)},
     {CKA_EC_PARAMS, P224_CURVE_PARAMS, sizeof(P224_CURVE_PARAMS)}};

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &privkey_class,
                                        sizeof(privkey_class)},
                                       {CKA_LABEL, label, strlen(label)},
                                       {CKA_DERIVE, &ck_true, sizeof(ck_true)}};

  if ((p11->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, 5,
                              privateKeyTemplate, 3, publicKeyPtr,
                              privateKeyPtr)) != CKR_OK) {
    return 0;
  }
  return 1;
}

typedef struct {
  int ecdh_key_count;
  CK_OBJECT_HANDLE obj_handle;
  CK_ULONG attribute_count;
} test_case_t;

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  static bool is_initialized = initialize();

  test_case_t test_case;
  CK_OBJECT_HANDLE yh_pubkey, yh_privkey;
  EVP_PKEY *openssl_keypair;
  EC_KEY *peerkey;
  unsigned char *peerkey_bytes;
  int peerkey_len;
  CK_ECDH1_DERIVE_PARAMS params;
  CK_MECHANISM mechanism;
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
  char label[] = "ecdh";
  CK_RV rv;
  CK_ATTRIBUTE derivedKeyTemplate[3];
  CK_OBJECT_HANDLE ecdh;

  if (size < sizeof(test_case_t)) {
    return 0;
  }
  memcpy(&test_case, data, sizeof(test_case));

  data += sizeof(test_case);
  size -= sizeof(test_case);

  if (test_case.ecdh_key_count > 10) {
    return 0;
  }

  if (test_case.attribute_count > 10) {
    return 0;
  }

  CK_ATTRIBUTE_PTR attribute_array =
    new CK_ATTRIBUTE[test_case.attribute_count];

  memset(&mechanism, 0, sizeof(mechanism));
  memset(&yh_pubkey, 0, sizeof(yh_pubkey));
  memset(&yh_privkey, 0, sizeof(yh_privkey));
  memset(attribute_array, 0, sizeof(CK_ATTRIBUTE) * test_case.attribute_count);

  rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
                          &session);
  assert(rv == CKR_OK);
  rv = p11->C_Login(session, CKU_USER,
                    (CK_UTF8CHAR_PTR) "0000" FUZZ_BACKEND_PASSWORD,
                    (CK_ULONG) strlen("0000" FUZZ_BACKEND_PASSWORD));
  assert(rv == CKR_OK);

  /* part of the implementation for C_GetAttributeValue applies to ECDH keys
   * in order to get better coverage of this function, we generate several ECDH
   * keys the ECDH keys are generated with calls to C_DeriveKey
   */

  if (generate_keypair_yh(&yh_pubkey, &yh_privkey) == 0) {
    goto harness_out;
  }

  for (int i = 0; i < test_case.ecdh_key_count; i++) {
    // Generate keypair with openssl
    openssl_keypair = generate_keypair_openssl();
    if (openssl_keypair == NULL) {
      return 0;
    }

    peerkey = EVP_PKEY_get1_EC_KEY(openssl_keypair);
    peerkey_bytes = NULL;
    peerkey_len = i2o_ECPublicKey(peerkey, &peerkey_bytes);
    assert(peerkey_len > 0);
    EC_KEY_free(peerkey);

    params.kdf = CKD_NULL;
    params.pSharedData = NULL;
    params.ulSharedDataLen = 0;
    params.pPublicData = peerkey_bytes;
    params.ulPublicDataLen = peerkey_len;

    memset(&mechanism, 0, sizeof(mechanism));
    mechanism.mechanism = CKM_ECDH1_DERIVE;
    mechanism.pParameter = (void *) &params;
    mechanism.ulParameterLen = sizeof(params);

    derivedKeyTemplate[0] = {CKA_CLASS, &key_class, sizeof(key_class)};
    derivedKeyTemplate[1] = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};
    derivedKeyTemplate[2] = {CKA_LABEL, label, strlen(label)};

    p11->C_DeriveKey(session, &mechanism, yh_privkey, derivedKeyTemplate, 3,
                     &ecdh);
  }

  for (int i = 0; i < test_case.attribute_count; i++) {
    unsigned long ulValueLen = 0;
    if (size > 0) {
      ulValueLen = data[0];
      data += 1;
      size -= 1;
    }
    if (size >= sizeof(unsigned long)) {
      memcpy(&attribute_array[i].type, data, sizeof(unsigned long));
      data += sizeof(unsigned long);
      size -= sizeof(unsigned long);
    }
    attribute_array[i].pValue = new uint8_t[ulValueLen];
    attribute_array[i].ulValueLen = ulValueLen;
  }

  backend_data = data;
  backend_data_len = size;

  p11->C_GetAttributeValue(session, test_case.obj_handle, attribute_array,
                           test_case.attribute_count);

harness_out:
  rv = p11->C_Logout(session);
  assert(rv == CKR_OK);
  rv = p11->C_CloseSession(session);
  assert(rv == CKR_OK);

  for (int i = 0; i < test_case.attribute_count; i++) {
    if (attribute_array[i].pValue != NULL) {
      delete[] (uint8_t *) attribute_array[i].pValue;
    }
  }
  delete[] attribute_array;

  fflush(stdout);
  return 0;
}
