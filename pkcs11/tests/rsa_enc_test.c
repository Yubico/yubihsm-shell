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
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "../pkcs11.h"

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

#define BUFSIZE 1024

CK_FUNCTION_LIST_PTR p11;
CK_SESSION_HANDLE session;

static void get_function_list(char *argv[]) {
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
  assert(handle != NULL);
  CK_C_GetFunctionList fn;

  *(void **) (&fn) = dlsym(handle, "C_GetFunctionList");
  assert(fn != NULL);

  CK_RV rv = fn(&p11);
  assert(rv == CKR_OK);
}

static void open_session() {
  CK_C_INITIALIZE_ARGS initArgs;
  memset(&initArgs, 0, sizeof(initArgs));

  const char *connector_url;
  connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }
  char config[256];
  assert(strlen(connector_url) + strlen("connector=") < 256);
  sprintf(config, "connector=%s", connector_url);
  initArgs.pReserved = (void *) config;
  CK_RV rv = p11->C_Initialize(&initArgs);
  assert(rv == CKR_OK);

  rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
                          &session);
  assert(rv == CKR_OK);

  char password[] = "0001password";
  rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) password,
                    (CK_ULONG) strlen(password));
  assert(rv == CKR_OK);
  printf("Session open and authenticated\n");
}

static void close_session() {
  CK_RV rv = p11->C_Logout(session);
  assert(rv == CKR_OK);

  rv = p11->C_Finalize(NULL);
  assert(rv == CKR_OK);
}

static void print_session_state() {
  CK_SESSION_INFO pInfo;
  CK_RV rv = p11->C_GetSessionInfo(session, &pInfo);
  assert(rv == CKR_OK);
  CK_STATE state = pInfo.state;

  printf("session state: ");
  switch (state) {
    case 0:
      printf("read-only public session\n");
      break;
    case 1:
      printf("read-only user functions\n");
      break;
    case 2:
      printf("read-write public session\n");
      break;
    case 3:
      printf("read-write user functions\n");
      break;
    case 4:
      printf("read-write so functions\n");
      break;
    default:
      printf("unknown state\n");
      break;
  }
}

static bool destroy_object(CK_OBJECT_HANDLE key) {
  if ((p11->C_DestroyObject(session, key)) != CKR_OK) {
    printf("WARN. Failed to destroy object 0x%lx on HSM. FAIL\n", key);
    return false;
  }
  return true;
}

static void import_rsa_key(int keylen, EVP_PKEY **evp, RSA **rsak,
                           CK_OBJECT_HANDLE_PTR keyid) {
  CK_BYTE e[] = {0x01, 0x00, 0x01};
  CK_BYTE *p, *q, *dp, *dq, *qinv;
  p = malloc(keylen / 16);
  q = malloc(keylen / 16);
  dp = malloc(keylen / 16);
  dq = malloc(keylen / 16);
  qinv = malloc(keylen / 16);

  BIGNUM *e_bn;
  CK_ULONG class_k = CKO_PRIVATE_KEY;
  CK_ULONG kt = CKK_RSA;
  CK_BYTE id = 0;
  const BIGNUM *bp, *bq, *biqmp, *bdmp1, *bdmq1;

  // unsigned char  *px;
  int p_len, q_len, dp_len, dq_len, qinv_len;
  int len = keylen / 16;
  CK_BBOOL dec_capability = CK_TRUE;

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                                       {CKA_KEY_TYPE, &kt, sizeof(kt)},
                                       {CKA_ID, &id, sizeof(id)},
                                       {CKA_DECRYPT, &dec_capability,
                                        sizeof(dec_capability)},
                                       {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
                                       {CKA_PRIME_1, p, (keylen / 16)},
                                       {CKA_PRIME_2, q, (keylen / 16)},
                                       {CKA_EXPONENT_1, dp, (keylen / 16)},
                                       {CKA_EXPONENT_2, dq, (keylen / 16)},
                                       {CKA_COEFFICIENT, qinv, (keylen / 16)}};
  int len_correct = 0;

  e_bn = BN_bin2bn(e, 3, NULL);
  if (e_bn == NULL)
    exit(EXIT_FAILURE);

  do {
    assert(RSA_generate_key_ex(*rsak, keylen, e_bn, NULL) == 1);

    RSA_get0_factors(*rsak, &bp, &bq);
    RSA_get0_crt_params(*rsak, &bdmp1, &bdmq1, &biqmp);
    p_len = BN_bn2bin(bp, p);
    q_len = BN_bn2bin(bq, q);
    dp_len = BN_bn2bin(bdmp1, dp);
    dq_len = BN_bn2bin(bdmq1, dq);
    qinv_len = BN_bn2bin(biqmp, qinv);
    len_correct = p_len == len && q_len == len && dp_len == len &&
                  dq_len == len && qinv_len == len;
  } while (!len_correct);

  if (EVP_PKEY_set1_RSA(*evp, *rsak) == 0)
    exit(EXIT_FAILURE);

  assert(p11->C_CreateObject(session, privateKeyTemplate, 10, keyid) == CKR_OK);

  BN_free(e_bn);
  free(p);
  free(q);
  free(dp);
  free(dq);
  free(qinv);
}

static void test_rsa_encrypt(CK_OBJECT_HANDLE keyid, RSA *rsak,
                             CK_MECHANISM_TYPE mech_type, int padding,
                             CK_ULONG expected_enc_len) {
  CK_BYTE data[32] = {0};
  CK_ULONG data_len = sizeof(data);
  CK_BYTE enc[1024] = {0};
  CK_ULONG enc_len;
  CK_BYTE dec[512] = {0};
  CK_BYTE dec_internal[512] = {0};
  CK_ULONG dec_internal_len;

  CK_RSA_PKCS_OAEP_PARAMS params = {CKM_SHA_1, CKG_MGF1_SHA1, 0, 0, 0};
  CK_MECHANISM mech = {mech_type, &params, sizeof(params)};
  if (mech_type == CKM_RSA_PKCS) {
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
  }

  if (RAND_bytes(data, data_len) <= 0)
    exit(EXIT_FAILURE);

  // Encrypt
  assert(p11->C_EncryptInit(session, &mech, keyid) == CKR_OK);
  enc_len = 0;
  assert(p11->C_Encrypt(session, data, data_len, NULL, &enc_len) == CKR_OK);
  assert(enc_len == expected_enc_len);
  assert(p11->C_Encrypt(session, data, data_len, enc, &enc_len) == CKR_OK);
  assert(enc_len == expected_enc_len);

  CK_ULONG err;
  CK_ULONG dec_len =
    (CK_ULONG) RSA_private_decrypt((int) enc_len, (unsigned char *) enc,
                                   (unsigned char *) dec, rsak, padding);
  if ((err = ERR_get_error())) {
    ERR_load_crypto_strings();
    fprintf(stderr, "RSA_private_decrypt:[%lu](%s)\n", err,
            ERR_error_string(err, NULL));
  }
  assert(dec_len == data_len);
  assert(memcmp(dec, data, data_len) == 0);

  assert(p11->C_DecryptInit(session, &mech, keyid) == CKR_OK);
  dec_internal_len = 0;
  assert(p11->C_Decrypt(session, enc, enc_len, NULL, &dec_internal_len) ==
         CKR_OK);
  assert(p11->C_Decrypt(session, enc, enc_len, dec_internal,
                        &dec_internal_len) == CKR_OK);
  assert(dec_internal_len == data_len);
  assert(memcmp(dec_internal, data, data_len) == 0);

  // Encrypt Update
  assert(p11->C_EncryptInit(session, &mech, keyid) == CKR_OK);
  enc_len = 0;
  assert(p11->C_EncryptUpdate(session, data, 10, NULL, &enc_len) == CKR_OK);
  assert(p11->C_EncryptUpdate(session, data, 10, enc, &enc_len) == CKR_OK);
  enc_len = 0;
  assert(p11->C_EncryptUpdate(session, data + 10, 22, NULL, &enc_len) ==
         CKR_OK);
  assert(p11->C_EncryptUpdate(session, data + 10, 22, enc, &enc_len) == CKR_OK);
  enc_len = 0;
  assert(p11->C_EncryptFinal(session, NULL, &enc_len) == CKR_OK);
  assert(enc_len == expected_enc_len);
  assert(p11->C_EncryptFinal(session, enc, &enc_len) == CKR_OK);
  assert(enc_len == expected_enc_len);

  dec_len = (CK_ULONG) RSA_private_decrypt(enc_len, enc, dec, rsak, padding);
  if ((err = ERR_get_error())) {
    ERR_load_crypto_strings();
    fprintf(stderr, "RSA_private_decrypt:[%lu](%s)\n", err,
            ERR_error_string(err, NULL));
  }
  assert(dec_len == data_len);
  assert(memcmp(dec, data, data_len) == 0);

  // Decrypt Update
  assert(p11->C_DecryptInit(session, &mech, keyid) == CKR_OK);
  dec_internal_len = sizeof(dec_internal);
  assert(p11->C_DecryptUpdate(session, enc, 10, dec_internal,
                              &dec_internal_len) == CKR_OK);
  assert(dec_internal_len == 0);
  dec_internal_len = sizeof(dec_internal);
  assert(p11->C_DecryptUpdate(session, enc + 10, enc_len - 10, dec_internal,
                              &dec_internal_len) == CKR_OK);
  assert(dec_internal_len == 0);
  dec_internal_len = sizeof(dec_internal);
  assert(p11->C_DecryptFinal(session, dec_internal, &dec_internal_len) ==
         CKR_OK);
  assert(dec_internal_len == data_len);
  assert(memcmp(dec_internal, data, data_len) == 0);
}

static void test_encrypt_RSA(int keysize, CK_ULONG expected_enc_len) {
  EVP_PKEY *evp = EVP_PKEY_new();
  RSA *rsak = RSA_new();
  CK_OBJECT_HANDLE keyid;

  import_rsa_key(keysize, &evp, &rsak, &keyid);
  if (evp == NULL || rsak == NULL)
    exit(EXIT_FAILURE);

  printf("RSA %d : RSA_PKCS1_PADDING\n", keysize);
  test_rsa_encrypt(keyid, rsak, CKM_RSA_PKCS, RSA_PKCS1_PADDING,
                   expected_enc_len);

  printf("RSA %d : RSA_PKCS1_OAEP_PADDING\n", keysize);
  test_rsa_encrypt(keyid, rsak, CKM_RSA_PKCS_OAEP, RSA_PKCS1_OAEP_PADDING,
                   expected_enc_len);

  RSA_free(rsak);
  EVP_PKEY_free(evp);
  destroy_object(keyid);
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "usage: /path/to/yubihsm_pkcs11/module\n");
    exit(EXIT_FAILURE);
  }

  get_function_list(argv);
  open_session();
  print_session_state();

  test_encrypt_RSA(2048, 256);
  test_encrypt_RSA(3072, 384);
  test_encrypt_RSA(4096, 512);

  close_session();
  return (EXIT_SUCCESS);
}
