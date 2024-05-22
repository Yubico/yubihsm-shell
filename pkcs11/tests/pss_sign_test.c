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

#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include "../pkcs11y.h"
#include "common.h"

#define BUFSIZE 1024

static CK_FUNCTION_LIST_3_0_PTR p11;
static CK_SESSION_HANDLE session;

static void import_rsa_key(int keylen, RSA *rsak,
                           CK_OBJECT_HANDLE_PTR keyid) {
  CK_BYTE e[] = {0x01, 0x00, 0x01};
  CK_BYTE *p, *q, *dp, *dq, *qinv;
  int len = keylen / 16;
  p = malloc(len);
  q = malloc(len);
  dp = malloc(len);
  dq = malloc(len);
  qinv = malloc(len);

  CK_ULONG class_k = CKO_PRIVATE_KEY;
  CK_ULONG kt = CKK_RSA;
  CK_BYTE id[] = {0, 0};
  CK_BBOOL sign_capability = CK_TRUE;

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                                       {CKA_KEY_TYPE, &kt, sizeof(kt)},
                                       {CKA_ID, &id, sizeof(id)},
                                       {CKA_SIGN, &sign_capability,
                                        sizeof(sign_capability)},
                                       {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
                                       {CKA_PRIME_1, p, len},
                                       {CKA_PRIME_2, q, len},
                                       {CKA_EXPONENT_1, dp, len},
                                       {CKA_EXPONENT_2, dq, len},
                                       {CKA_COEFFICIENT, qinv, len}};
  BIGNUM *e_bn = BN_bin2bn(e, 3, NULL);
  if (e_bn == NULL)
    exit(EXIT_FAILURE);

  assert(RSA_generate_key_ex(rsak, keylen, e_bn, NULL) == 1);

  const BIGNUM *bp, *bq, *biqmp, *bdmp1, *bdmq1;
  RSA_get0_factors(rsak, &bp, &bq);
  RSA_get0_crt_params(rsak, &bdmp1, &bdmq1, &biqmp);
  BN_bn2binpad(bp, p, len);
  BN_bn2binpad(bq, q, len);
  BN_bn2binpad(bdmp1, dp, len);
  BN_bn2binpad(bdmq1, dq, len);
  BN_bn2binpad(biqmp, qinv, len);

  assert(p11->C_CreateObject(session, privateKeyTemplate, 10, keyid) == CKR_OK);

  BN_free(e_bn);
  free(p);
  free(q);
  free(dp);
  free(dq);
  free(qinv);
}

static CK_MECHANISM_TYPE get_hash_mechanism(CK_MECHANISM_TYPE mech) {
  switch (mech) {
    case CKM_SHA1_RSA_PKCS_PSS:
      return CKM_SHA_1;
    case CKM_SHA256_RSA_PKCS_PSS:
      return CKM_SHA256;
    case CKM_SHA384_RSA_PKCS_PSS:
      return CKM_SHA384;
    case CKM_SHA512_RSA_PKCS_PSS:
      return CKM_SHA512;
    default:
      return 0;
  }
}

static CK_RSA_PKCS_MGF_TYPE get_mgf_algo(CK_MECHANISM_TYPE mech) {
  switch (mech) {
    case CKM_SHA1_RSA_PKCS_PSS:
      return CKG_MGF1_SHA1;
    case CKM_SHA256_RSA_PKCS_PSS:
      return CKG_MGF1_SHA256;
    case CKM_SHA384_RSA_PKCS_PSS:
      return CKG_MGF1_SHA384;
    case CKM_SHA512_RSA_PKCS_PSS:
      return CKG_MGF1_SHA512;
    default:
      return 0;
  }
}

static const EVP_MD *get_md_type(CK_MECHANISM_TYPE mech) {
  switch (mech) {
    case CKM_SHA_1:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKG_MGF1_SHA1:
      return EVP_sha1();
    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKG_MGF1_SHA256:
      return EVP_sha256();
    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKG_MGF1_SHA384:
      return EVP_sha384();
    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKG_MGF1_SHA512:
      return EVP_sha512();
    default:
      return NULL;
  }
}

static void test_sign_pss(CK_OBJECT_HANDLE keyid, CK_MECHANISM_TYPE mech_type,
                          RSA *rsak) {
  CK_RSA_PKCS_PSS_PARAMS pss_params = {get_hash_mechanism(mech_type),
                                       get_mgf_algo(mech_type),
                                       EVP_MD_size(get_md_type(mech_type))};
  CK_MECHANISM mech = {mech_type, &pss_params, sizeof(pss_params)};
  CK_BYTE *data = malloc(pss_params.sLen);

  if (RAND_bytes(data, pss_params.sLen) <= 0) {
    exit(EXIT_FAILURE);
  }

  // Sign
  assert(p11->C_SignInit(session, &mech, keyid) == CKR_OK);
  CK_ULONG sig_len = 0;
  assert(p11->C_Sign(session, data, pss_params.sLen, NULL, &sig_len) == CKR_OK);
  CK_BYTE *sig = malloc(sig_len);
  assert(p11->C_Sign(session, data, pss_params.sLen, sig, &sig_len) == CKR_OK);

  // Verify signature
  if (rsak != NULL) {
    CK_BYTE *pss_buf = malloc(sig_len);
    assert((CK_ULONG) RSA_public_decrypt(sig_len, sig, pss_buf, rsak,
                                         RSA_NO_PADDING) == sig_len);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    assert(EVP_DigestInit_ex(md_ctx, get_md_type(mech_type), NULL) == 1);
    assert(EVP_DigestUpdate(md_ctx, data, pss_params.sLen) == 1);
    CK_BYTE digest_data[256] = {0};
    unsigned int digest_data_len = sizeof(digest_data);
    assert(EVP_DigestFinal_ex(md_ctx, digest_data, &digest_data_len) == 1);
    EVP_MD_CTX_destroy(md_ctx);

    assert(RSA_verify_PKCS1_PSS_mgf1(rsak, digest_data,
                                     get_md_type(pss_params.hashAlg),
                                     get_md_type(pss_params.mgf), pss_buf,
                                     pss_params.sLen) == 1);
    free(pss_buf);
  }
  free(sig);
  free(data);
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

  int keysizes[3] = {2048, 3072, 4096};

  for (int i = 0; i < 3; i++) {

    RSA *rsak = RSA_new();
    CK_OBJECT_HANDLE keyid;

    import_rsa_key(keysizes[i], rsak, &keyid);
    if (keyid == 0) {
      exit(EXIT_FAILURE);
    }

    test_sign_pss(keyid, CKM_SHA1_RSA_PKCS_PSS, rsak);
    test_sign_pss(keyid, CKM_SHA256_RSA_PKCS_PSS, rsak);
    test_sign_pss(keyid, CKM_SHA384_RSA_PKCS_PSS, rsak);
    test_sign_pss(keyid, CKM_SHA512_RSA_PKCS_PSS, rsak);

    RSA_free(rsak);
    destroy_object(p11, session, keyid);
  }
  printf("OK!\n");

  close_session(p11, session);
  close_module(handle);
  return (EXIT_SUCCESS);
}
