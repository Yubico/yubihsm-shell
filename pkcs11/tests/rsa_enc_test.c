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
#include <openssl/rand.h>
#include <openssl/err.h>

#include "../pkcs11.h"
#include "common.h"

#define BUFSIZE 1024

static CK_FUNCTION_LIST_PTR p11;
static CK_SESSION_HANDLE session;

static void import_rsa_key(int keylen, EVP_PKEY **evp, RSA **rsak,
                           CK_OBJECT_HANDLE_PTR keyid) {
  CK_BYTE e[] = {0x01, 0x00, 0x01};
  CK_BYTE *p, *q, *dp, *dq, *qinv;
  int len = keylen / 16;
  p = malloc(len);
  q = malloc(len);
  dp = malloc(len);
  dq = malloc(len);
  qinv = malloc(len);

  BIGNUM *e_bn;
  CK_ULONG class_k = CKO_PRIVATE_KEY;
  CK_ULONG kt = CKK_RSA;
  CK_BYTE id[] = {0, 0};
  const BIGNUM *bp, *bq, *biqmp, *bdmp1, *bdmq1;

  // unsigned char  *px;
  CK_BBOOL dec_capability = CK_TRUE;

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                                       {CKA_KEY_TYPE, &kt, sizeof(kt)},
                                       {CKA_ID, &id, sizeof(id)},
                                       {CKA_DECRYPT, &dec_capability,
                                        sizeof(dec_capability)},
                                       {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
                                       {CKA_PRIME_1, p, len},
                                       {CKA_PRIME_2, q, len},
                                       {CKA_EXPONENT_1, dp, len},
                                       {CKA_EXPONENT_2, dq, len},
                                       {CKA_COEFFICIENT, qinv, len}};
  e_bn = BN_bin2bn(e, 3, NULL);
  if (e_bn == NULL)
    exit(EXIT_FAILURE);

  assert(RSA_generate_key_ex(*rsak, keylen, e_bn, NULL) == 1);

  RSA_get0_factors(*rsak, &bp, &bq);
  RSA_get0_crt_params(*rsak, &bdmp1, &bdmq1, &biqmp);
  BN_bn2binpad(bp, p, len);
  BN_bn2binpad(bq, q, len);
  BN_bn2binpad(bdmp1, dp, len);
  BN_bn2binpad(bdmq1, dq, len);
  BN_bn2binpad(biqmp, qinv, len);

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

static void test_rsa_encrypt(CK_OBJECT_HANDLE privkey, CK_OBJECT_HANDLE pubkey, RSA *rsak,
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
  assert(p11->C_EncryptInit(session, &mech, pubkey) == CKR_OK);
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

  assert(p11->C_DecryptInit(session, &mech, privkey) == CKR_OK);
  dec_internal_len = 0;
  assert(p11->C_Decrypt(session, enc, enc_len, NULL, &dec_internal_len) ==
         CKR_OK);
  assert(p11->C_Decrypt(session, enc, enc_len, dec_internal,
                        &dec_internal_len) == CKR_OK);
  assert(dec_internal_len == data_len);
  assert(memcmp(dec_internal, data, data_len) == 0);

  // Encrypt Update
  assert(p11->C_EncryptInit(session, &mech, pubkey) == CKR_OK);
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
  assert(p11->C_DecryptInit(session, &mech, privkey) == CKR_OK);
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

  CK_BYTE id[] = {0, 0};
  CK_MECHANISM_TYPE mechs[32];

  CK_ATTRIBUTE attrs[] = {
    {CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs)},
    {CKA_ID, &id, sizeof(id)}
  };

  assert(p11->C_GetAttributeValue(session, keyid, attrs, 2) == CKR_OK);
  assert(attrs[0].ulValueLen == 2 * sizeof(CK_MECHANISM_TYPE));
  assert(mechs[0] == CKM_RSA_PKCS);
  assert(mechs[1] == CKM_RSA_PKCS_OAEP);

  CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;

  CK_ATTRIBUTE findKeyTemplate[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                                       {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                                       {CKA_ID, &id, sizeof(id)}};

  CK_OBJECT_HANDLE objs[1];
  CK_ULONG n_objs = 0;
  assert(p11->C_FindObjectsInit(session, findKeyTemplate, 3) == CKR_OK);
  assert(p11->C_FindObjects(session, objs, 1, &n_objs) == CKR_OK);
  assert(p11->C_FindObjectsFinal(session) == CKR_OK);

  assert(n_objs == 1);

  printf("RSA %d : RSA_PKCS1_PADDING\n", keysize);
  test_rsa_encrypt(keyid, objs[0], rsak, CKM_RSA_PKCS, RSA_PKCS1_PADDING,
                   expected_enc_len);

  printf("RSA %d : RSA_PKCS1_OAEP_PADDING\n", keysize);
  test_rsa_encrypt(keyid, objs[0], rsak, CKM_RSA_PKCS_OAEP, RSA_PKCS1_OAEP_PADDING,
                   expected_enc_len);

  RSA_free(rsak);
  EVP_PKEY_free(evp);
  destroy_object(p11, session, keyid);
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

  test_encrypt_RSA(2048, 256);
  test_encrypt_RSA(3072, 384);
  test_encrypt_RSA(4096, 512);

  close_session(p11, session);
  close_module(handle);
  return (EXIT_SUCCESS);
}
