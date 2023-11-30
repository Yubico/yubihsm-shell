#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "fuzzer/FuzzedDataProvider.h"
#include <algorithm>

#include <openssl/ec.h>
#include <openssl/x509.h>

#include "yubihsm_fuzz.h"

extern "C" {
#include "pkcs11.h"
#include "yubihsm_pkcs11.h"

uint8_t *backend_data;
size_t backend_data_len;
}

yh_connector *connector;
CK_FUNCTION_LIST_PTR p11;
CK_SESSION_HANDLE session;
CK_OBJECT_HANDLE yh_pubkey, yh_privkey;

#define ECDH_ATTRIBUTE_COUNT 2

static bool init_p11() {
  CK_C_INITIALIZE_ARGS initArgs;
  CK_RV rv;

  char config[] = "connector=yhfuzz://yubihsm_fuzz";
  // char config[] = "connector=yhfuzz://yubihsm_fuzz debug libdebug";

  C_GetFunctionList(&p11);

  memset(&initArgs, 0, sizeof(initArgs));
  initArgs.pReserved = config;

  rv = p11->C_Initialize(&initArgs);
  assert(rv == CKR_OK);

  return true;
}

static void deinit_session() {
  CK_RV rv;

  rv = p11->C_Logout(session);
  assert(rv == CKR_OK);

  rv = p11->C_CloseSession(session);
  assert(rv == CKR_OK);
}

static void init_session() {
  CK_RV rv;
  char pin[20] = "0000";

  strcat(pin, FUZZ_BACKEND_PASSWORD);

  memset(&session, 0, sizeof(session));

  rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
                          &session);
  assert(rv == CKR_OK);

  rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) pin,
                    (CK_ULONG) strlen(pin));
  assert(rv == CKR_OK);

  // rv = generate_ecdh_keypair();
  // assert(rv == CKR_OK);
};

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

void populate_attribute_template(CK_ATTRIBUTE_PTR *attribute_array,
                                 CK_ULONG attribute_count,
                                 FuzzedDataProvider *fdp) {
  CK_ATTRIBUTE_PTR new_array = new CK_ATTRIBUTE[attribute_count];
  memset(new_array, 0, sizeof(CK_ATTRIBUTE) * attribute_count);

  for (int i = 0; i < attribute_count; i++) {
    uint8_t ulValueLen = fdp->ConsumeIntegral<uint8_t>();

    new_array[i].type = fdp->ConsumeIntegral<CK_ATTRIBUTE_TYPE>();
    new_array[i].pValue = new uint8_t[ulValueLen]; // TODO populate pValue from
                                                   // fuzzer generated data?
    new_array[i].ulValueLen = ulValueLen;
  }

  *attribute_array = new_array;
}

void populate_derived_ecdh_key_template(CK_ATTRIBUTE_PTR *attribute_array,
                                        FuzzedDataProvider *fdp) {
  CK_ATTRIBUTE_PTR new_array = new CK_ATTRIBUTE[ECDH_ATTRIBUTE_COUNT];
  memset(new_array, 0, sizeof(CK_ATTRIBUTE) * ECDH_ATTRIBUTE_COUNT);

  uint8_t value_len = fdp->ConsumeIntegral<uint8_t>();
  std::vector<uint8_t> value = fdp->ConsumeBytes<uint8_t>(value_len);

  new_array[0].type = CKA_VALUE_LEN;
  new_array[0].ulValueLen = value_len;
  new_array[0].pValue = new uint8_t[value_len];

  memset(new_array[0].pValue, 0, value_len);
  memcpy(new_array[0].pValue, &value[0],
         std::min(value.size(), (size_t) value_len));

  uint8_t label_len = fdp->ConsumeIntegral<uint8_t>();

  new_array[1].type = CKA_LABEL;
  new_array[1].ulValueLen = label_len;
  new_array[1].pValue = new uint8_t[label_len]; // TODO populate pValue from
                                                // fuzzer generated data?
  *attribute_array = new_array;
}

void derive_ecdh_session_keys(uint8_t derived_key_count,
                              CK_ATTRIBUTE_PTR ecdh_attribute_array) {

  if (derived_key_count > 10) {
    // artificial limitation on the number of derived keys
    derived_key_count = 10;
  }

  for (int i = 0; i < derived_key_count; i++) {
    CK_OBJECT_HANDLE ecdh;

    CK_ECDH1_DERIVE_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.kdf = CKD_NULL;
    params.pSharedData = NULL;
    params.ulSharedDataLen = 0;
    // TODO populate pPublicData and ulPublicDataLen from fuzzer generated data?
    params.pPublicData = new uint8_t[50];
    params.ulPublicDataLen = 50;

    CK_MECHANISM mechanism;
    memset(&mechanism, 0, sizeof(mechanism));
    mechanism.mechanism = CKM_ECDH1_DERIVE;
    mechanism.pParameter = (void *) &params;
    mechanism.ulParameterLen = sizeof(params);

    p11->C_DeriveKey(session, &mechanism, yh_privkey, ecdh_attribute_array,
                     ECDH_ATTRIBUTE_COUNT, &ecdh);

    delete[] params.pPublicData;
  }
}

void free_attribute_template(CK_ATTRIBUTE_PTR attribute_array,
                             CK_ULONG attribute_count) {
  for (unsigned int i = 0; i < attribute_count; i++) {
    if (attribute_array[i].pValue != NULL) {
      delete[] (uint8_t *) attribute_array[i].pValue;
    }
  }
  delete[] attribute_array;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  typedef struct {
    CK_ULONG attribute_count;
    CK_OBJECT_HANDLE obj_handle;
    uint8_t derived_ecdh_key_count;
  } test_case_t;

  static bool p11_initialized = init_p11();

  if (size < sizeof(test_case_t)) {
    return 0;
  }

  FuzzedDataProvider *fdp = new FuzzedDataProvider(data, size);

  test_case_t test_case;
  memset(&test_case, 0, sizeof(test_case_t));
  test_case.attribute_count = fdp->ConsumeIntegral<CK_ULONG>();
  test_case.obj_handle = fdp->ConsumeIntegral<CK_OBJECT_HANDLE>();
  test_case.derived_ecdh_key_count = fdp->ConsumeIntegral<uint8_t>();

  /* limit the number of request attributes to 10
   * this is an artificial limitation to make fuzzer iterations faster
   */
  if (test_case.attribute_count > 10) {
    test_case.attribute_count = 10;
  }

  CK_ATTRIBUTE_PTR attribute_array;
  CK_ATTRIBUTE_PTR ecdh_attribute_array;
  populate_attribute_template(&attribute_array, test_case.attribute_count, fdp);
  populate_derived_ecdh_key_template(&ecdh_attribute_array, fdp);

  // the rest of the data is used for responses sent back by the backend
  std::vector<uint8_t> backend_vector = fdp->ConsumeRemainingBytes<uint8_t>();
  backend_data = &backend_vector[0];
  backend_data_len = backend_vector.size();

  init_session();

  /* objects of type ECDH_KEY_TYPE are treated differently by the
   * C_GetAttributeValue logic in order to improve coverage, we derive several
   * ECDH keys using C_DeriveKey
   */
  derive_ecdh_session_keys(test_case.derived_ecdh_key_count,
                           ecdh_attribute_array);

  p11->C_GetAttributeValue(session, test_case.obj_handle, attribute_array,
                           test_case.attribute_count);

  deinit_session();
  free_attribute_template(attribute_array, test_case.attribute_count);
  free_attribute_template(ecdh_attribute_array, ECDH_ATTRIBUTE_COUNT);

  delete fdp;

  fflush(stdout);
  return 0;
}
