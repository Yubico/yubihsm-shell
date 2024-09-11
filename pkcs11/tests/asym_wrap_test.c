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

#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "../pkcs11y.h"
#include "../lib/yubihsm.h"
#include "common.h"
#include "../common/util.h"

const char rsa2048[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEA1mA5mATDvo4dN7gTNyXMr+Sen2vkTaYY2vDY6B59ZuQp7si9\n"
  "H4sjjZjXm0/+CCuwmi287mu8zrqDYsi+cVtw+KsVdMp7EmaHUelael0JzUy+pbJs\n"
  "4+PT8kZ/ytx2640j5P1H7mt/LJKcJCq7U0N4WUGx5YEyPUPGJxCgYgnXx8CSxCst\n"
  "A3leSfVEnPu9kA7hztMREfyrSIyLoDcNY3y0n7yHL/uHlNAIMvOT1+RAqYHm1mxQ\n"
  "sKZtDNtRBACRh4j1wKZSjK+0Wt0h15RJ4fp0i+smNR5rU0UpvpjfbeEe14DBxxE5\n"
  "v0W64hsIoedJh5GD9vWARa1wF8+pi+KDHny5KwIDAQABAoIBAG4o4k+g2yl3g8IX\n"
  "ICCtluIn++72FUpleM5BB2U4Db6qrnWax7yG1k0z5k9UKrjuIoEH0dc+m7Yrl8pS\n"
  "V7KOh53w5ESwq8+Hyi+oVysb1iaeMjWZW2U7tLUBzzdiVOW0EGbiVG1K5f30lLHt\n"
  "F3ew6w4KuSyzWCqtQgze+VuHrU9iT/jllv/KFxxaIFQeUOL0sR0CeE7gji7QE4C1\n"
  "2WjYjGYb7+N+3R+nmWq3NOXBarj4vSQ42UngzO2eH6d04KsCWJzOQ/2ymCzoai+v\n"
  "AaiACdrOrZFscJw8E8jyrNHDEBXvqY6j3S4444FshKiXij5gLoZZ22rY2lWcc3s+\n"
  "qOPK9MkCgYEA7wVV3ON+nmS+GZKRa+RlQ0Ooh/VlYw2NJBxmPrYVTN/YQAzE2hoA\n"
  "OVrXOjfuF4g/YgxvvbKcImSxUvAoemUPO0v/9NA0L1u8ehP/S+RrmvTk4IG2OlGs\n"
  "LqAzpUp1t4OONKzulISmJ0LNRblwbA2ORgugVo5/X495XIwJZ5V2cX0CgYEA5Zq2\n"
  "scXFMmcl99OgH5DwPtlYLlKjub4lhiyEEWghcCMDriLlbT/oqi3cJlJejsqHhI+u\n"
  "pWH8WBfoVc2xNvaqzqzCJtKHxjjrEhwpjFO7e+idxwbKCB6blpBwayClVjd3UURz\n"
  "TNBWPPvx0a1cMyufF1g1Nw8DwpjfTeA7WZdsVccCgYAhW0NCUlVHUZPeCcBVqEgh\n"
  "fP22C58clbWOxo/WTJ7oXYzWU3HdZieF2ZGTxF5r1k3SJx4pARYdDqRYiL99ZUEc\n"
  "61xLFAtUWJ8TAltsgfIqa+bNFg0SUnePAjhy5tNKywc7fq7E90Yg0IfJJTn1OmcS\n"
  "i2jS64wHEATFz504YXloGQKBgQCntZCI3YqivFExanTlWbsCTUNp4pcQz2EdVlrJ\n"
  "VCRIgmrnwTmPyUSrOYA6xaOn7St7mm/ZAW+O8TeVpP8yxI4TFIFkVhcypNSfj86R\n"
  "X3/sjAbjH4Rm1eST38EdnuTlyvHufG8zxmGXffguTdCw18YHCTkllGQMuhkyCv2O\n"
  "/Vn2dQKBgQDI1dM1/jCLg6mh51np0ZB8BgTv8mEIOvgdlD21lTpWaCeAWFJZOqWY\n"
  "Oo/dNh3YcbW0I6kTpriukDSxXJ095BhcBAG8jGNxw2293A/lKeyQyGKCYOX2Foh/\n"
  "dBVLu4zKddTSxwy7p5iu5fTf4m0T/BJIea16hiyWfL01UxfiS+ybRg==\n"
  "-----END RSA PRIVATE KEY-----";

const char rsa3072[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "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\n"
  "-----END RSA PRIVATE KEY-----";

const char rsa4096[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "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\n"
  "-----END RSA PRIVATE KEY-----";

#define BUFSIZE 1024

static CK_FUNCTION_LIST_3_0_PTR p11;
static CK_SESSION_HANDLE session;

static void generate_ec_keys(CK_OBJECT_HANDLE_PTR pubkey,
                             CK_OBJECT_HANDLE_PTR pvtkey) {
  CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                         0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_ULONG class_k = CKO_PRIVATE_KEY;
  CK_ULONG class_c = CKO_PUBLIC_KEY;
  CK_ULONG kt = CKK_EC;
  CK_BBOOL exportable_capability = CK_TRUE;
  CK_BBOOL sign_capability = CK_TRUE;
  char *label = "eckey";

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                                       {CKA_KEY_TYPE, &kt, sizeof(kt)},
                                       {CKA_LABEL, label, strlen(label)},
                                       {CKA_EXTRACTABLE, &exportable_capability,
                                        sizeof(exportable_capability)},
                                       {CKA_SIGN, &sign_capability,
                                        sizeof(sign_capability)}};

  CK_ATTRIBUTE publicKeyTemplate[] = {{CKA_CLASS, &class_c, sizeof(class_c)},
                                      {CKA_EC_PARAMS, ec_params,
                                       sizeof(ec_params)}};

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

  assert(p11->C_GenerateKeyPair(session, &mech, publicKeyTemplate, 2,
                                privateKeyTemplate, 5, pubkey,
                                pvtkey) == CKR_OK);
  fprintf(stdout, "Generated EC key. Handle 0x%06lx\n", *pvtkey);
}

static void generate_aes_key(CK_OBJECT_HANDLE_PTR key) {
  CK_OBJECT_CLASS class = CKO_SECRET_KEY;
  CK_KEY_TYPE type = CKK_AES;
  CK_ULONG key_len = 32;
  CK_BBOOL exportable_capability = CK_TRUE;
  CK_BBOOL encrypt_capability = CK_TRUE;
  CK_BBOOL decrypt_capability = CK_TRUE;
  CK_ATTRIBUTE templ[] =
    {{CKA_CLASS, &class, sizeof(class)},
     {CKA_KEY_TYPE, &type, sizeof(type)},
     {CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)},
     {CKA_EXTRACTABLE, &exportable_capability, sizeof(exportable_capability)},
     {CKA_ENCRYPT, &encrypt_capability, sizeof(encrypt_capability)},
     {CKA_DECRYPT, &decrypt_capability, sizeof(decrypt_capability)}};
  CK_MECHANISM  mech = {CKM_AES_KEY_GEN, NULL, 0};

  assert(p11->C_GenerateKey(session, &mech, templ, 6, key) == CKR_OK);
  fprintf(stdout, "Generated AES key. Handle 0x%06lx\n", *key);
}

static void import_rsa_wrapkey(const char *key, int keylen,
                               CK_OBJECT_HANDLE_PTR keyid) {
  CK_BYTE e[] = {0x01, 0x00, 0x01};
  CK_BYTE *p, *q, *dp, *dq, *qinv;
  int len = keylen / 16;
  p = malloc(len);
  q = malloc(len);
  dp = malloc(len);
  dq = malloc(len);
  qinv = malloc(len);

  BIO *bio = BIO_new_mem_buf((void *) key, strlen(key));
  RSA *rsak = PEM_read_bio_RSAPrivateKey(bio, 0, 0, 0);

  const BIGNUM *bp, *bq, *biqmp, *bdmp1, *bdmq1;
  RSA_get0_factors(rsak, &bp, &bq);
  RSA_get0_crt_params(rsak, &bdmp1, &bdmq1, &biqmp);
  BN_bn2binpad(bp, p, len);
  BN_bn2binpad(bq, q, len);
  BN_bn2binpad(bdmp1, dp, len);
  BN_bn2binpad(bdmq1, dq, len);
  BN_bn2binpad(biqmp, qinv, len);

  CK_ULONG class_k = CKO_PRIVATE_KEY;
  CK_ULONG kt = CKK_RSA;
  CK_BYTE id[] = {0, 0};
  CK_BBOOL wrap_capability = CK_TRUE;
  CK_BBOOL sign_capability = CK_TRUE;
  char *label = "rsa_wrap";
  CK_ATTRIBUTE keyTemplate[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                                {CKA_KEY_TYPE, &kt, sizeof(kt)},
                                {CKA_ID, &id, sizeof(id)},
                                {CKA_LABEL, label, strlen(label)},
                                {CKA_UNWRAP, &wrap_capability,
                                 sizeof(wrap_capability)},
                                {CKA_SIGN, &sign_capability,
                                 sizeof(sign_capability)},
                                {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
                                {CKA_PRIME_1, p, len},
                                {CKA_PRIME_2, q, len},
                                {CKA_EXPONENT_1, dp, len},
                                {CKA_EXPONENT_2, dq, len},
                                {CKA_COEFFICIENT, qinv, len}};
  assert(p11->C_CreateObject(session, keyTemplate, 12, keyid) == CKR_OK);
  fprintf(stdout, "Imorted RSA wrap key. Size %d. Handle 0x%06lx\n", keylen,
          *keyid);

  free(p);
  free(q);
  free(dp);
  free(dq);
  free(qinv);
}

static CK_OBJECT_HANDLE import_rsa_pub_wrapkey(uint8_t *pubkey,
                                               size_t pubkey_len) {

  CK_OBJECT_HANDLE pubkey_handle;

  CK_ULONG class_k = CKO_PUBLIC_KEY;
  CK_BBOOL wrap_capability = CK_TRUE;
  char *label = "pub_rsa_wrap";
  CK_ULONG kt = CKK_RSA;

  CK_ATTRIBUTE template[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                             {CKA_KEY_TYPE, &kt, sizeof(kt)},
                             {CKA_LABEL, label, strlen(label)},
                             {CKA_WRAP, &wrap_capability,
                              sizeof(wrap_capability)},
                             {CKA_VALUE, pubkey, pubkey_len}};
  assert(p11->C_CreateObject(session, template, 5, &pubkey_handle) == CKR_OK);
  return pubkey_handle;
}

static void generate_rsa_wrapkey(int keylen, CK_OBJECT_HANDLE_PTR keyid) {
  CK_ULONG class_k = CKO_PRIVATE_KEY;
  CK_ULONG class_c = CKO_PUBLIC_KEY;
  CK_ULONG kt = CKK_RSA;
  CK_BYTE id[] = {0, 0};
  char *label = "rsa_wrap";
  CK_BBOOL wrap_capability = CK_TRUE;
  CK_BBOOL sign_capability = CK_TRUE;
  CK_ULONG key_len = keylen;
  CK_OBJECT_HANDLE pub_keyid;

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                                       {CKA_KEY_TYPE, &kt, sizeof(kt)},
                                       {CKA_ID, &id, sizeof(id)},
                                       {CKA_LABEL, label, strlen(label)},
                                       {CKA_UNWRAP, &wrap_capability,
                                        sizeof(wrap_capability)},
                                       {CKA_SIGN, &sign_capability,
                                        sizeof(sign_capability)}};

  CK_ATTRIBUTE publicKeyTemplate[] = {{CKA_CLASS, &class_c, sizeof(class_c)},
                                      {CKA_MODULUS_BITS, &key_len,
                                       sizeof(key_len)}};

  assert(p11->C_GenerateKeyPair(session, &mech, publicKeyTemplate, 2,
                                privateKeyTemplate, 6, &pub_keyid,
                                keyid) == CKR_OK);
  fprintf(stdout, "Generated RSA wrap key. Size %lu. Handle 0x%06lx\n", key_len,
          *keyid);
}

static void get_pub_wrapkey(CK_OBJECT_HANDLE rsa_wrapkeyid, uint8_t *pubkey,
                            size_t *pubkey_len) {
  CK_ATTRIBUTE template[] = {
    {CKA_MODULUS, pubkey, *pubkey_len},
  };
  assert(p11->C_GetAttributeValue(session, rsa_wrapkeyid, template, 1) ==
         CKR_OK);
  *pubkey_len = template[0].ulValueLen;
}

static void get_wrapped_data(CK_OBJECT_HANDLE wrapping_keyid,
                             CK_OBJECT_HANDLE keyid, uint8_t *wrapped_obj,
                             size_t *wrapped_obj_len, bool only_key) {
  CK_RSA_PKCS_OAEP_PARAMS oaep_params = {CKM_SHA256, CKG_MGF1_SHA256, 0, NULL, 0};
  CK_RSA_AES_KEY_WRAP_PARAMS params = {256, &oaep_params};
  CK_MECHANISM mech = {0, &params, sizeof(params)};
  CK_ULONG wrapped_len = *wrapped_obj_len;

  if (only_key) {
    mech.mechanism = CKM_RSA_AES_KEY_WRAP;
  } else {
    mech.mechanism = CKM_YUBICO_RSA_WRAP;
  }
  assert(p11->C_WrapKey(session, &mech, wrapping_keyid, keyid, wrapped_obj,
                        &wrapped_len) == CKR_OK);
  *wrapped_obj_len = wrapped_len;
}

static CK_OBJECT_HANDLE import_wrapped_data(CK_OBJECT_HANDLE wrapping_keyid,
                                            uint8_t *wrapped_obj,
                                            size_t wrapped_obj_len,
                                            bool only_key, CK_ULONG key_type) {

  CK_RSA_PKCS_OAEP_PARAMS oaep_params = {CKM_SHA256, CKG_MGF1_SHA256, 0, NULL, 0};
  CK_RSA_AES_KEY_WRAP_PARAMS params = {256, &oaep_params};
  CK_MECHANISM mech = {0, &params, sizeof(params)};
  if (only_key) {
    mech.mechanism = CKM_RSA_AES_KEY_WRAP;
  } else {
    mech.mechanism = CKM_YUBICO_RSA_WRAP;
  }

  CK_OBJECT_HANDLE imported_keyhandle;
  CK_ULONG kt = key_type;
  CK_ULONG class_k = kt == CKK_EC ? CKO_PRIVATE_KEY : CKO_SECRET_KEY;

  if (kt == CKK_EC) {
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                           0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_BBOOL sign_capability = CK_TRUE;
    CK_ATTRIBUTE template[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                               {CKA_KEY_TYPE, &kt, sizeof(kt)},
                               {CKA_SIGN, &sign_capability,
                                sizeof(sign_capability)},
                               {CKA_EC_PARAMS, ec_params, sizeof(ec_params)}};

    assert(p11->C_UnwrapKey(session, &mech, wrapping_keyid, wrapped_obj,
                            wrapped_obj_len, template, 4,
                            &imported_keyhandle) == CKR_OK);
  } else {
    CK_ULONG keylen = 32;
    CK_BBOOL encrypt_capability = CK_TRUE;
    CK_BBOOL decrypt_capability = CK_TRUE;
    CK_ATTRIBUTE template[] = {{CKA_CLASS, &class_k, sizeof(class_k)},
                               {CKA_KEY_TYPE, &kt, sizeof(kt)},
                               {CKA_DECRYPT, &decrypt_capability,
                                sizeof(decrypt_capability)},
                               {CKA_ENCRYPT, &encrypt_capability,
                                sizeof(encrypt_capability)},
                               {CKA_VALUE_LEN, &keylen, sizeof(keylen)}};

    assert(p11->C_UnwrapKey(session, &mech, wrapping_keyid, wrapped_obj,
                            wrapped_obj_len, template, 5,
                            &imported_keyhandle) == CKR_OK);
  }
  return imported_keyhandle;
}

static void find_rsa_wrapkey(CK_OBJECT_HANDLE keyid, size_t key_size) {
  CK_BBOOL wrap_capability = CK_TRUE;
  char *label = "rsa_wrap";
  CK_ATTRIBUTE template[] = {{CKA_LABEL, label, strlen(label)},
                             {CKA_UNWRAP, &wrap_capability,
                              sizeof(wrap_capability)}};

  CK_OBJECT_HANDLE objects[10] = {0};
  CK_ULONG n_objects = 0;
  assert(p11->C_FindObjectsInit(session, template, 2) == CKR_OK);
  assert(p11->C_FindObjects(session, objects, 10, &n_objects) == CKR_OK);
  assert(p11->C_FindObjectsFinal(session) == CKR_OK);
  assert(n_objects == 1);
  assert(objects[0] == keyid);

  CK_ULONG mod_bits = 0;
  CK_ATTRIBUTE value_template[] = {
    {CKA_MODULUS_BITS, &mod_bits, sizeof(CK_ULONG)}};
  assert(p11->C_GetAttributeValue(session, objects[0], value_template, 1) ==
         CKR_OK);
  assert(mod_bits == key_size);
}

static void find_pub_rsa_wrapkey(CK_OBJECT_HANDLE keyid, size_t key_size) {
  CK_BBOOL wrap_capability = CK_TRUE;
  char *label = "pub_rsa_wrap";
  CK_ATTRIBUTE template[] = {{CKA_LABEL, label, strlen(label)},
                             {CKA_WRAP, &wrap_capability,
                              sizeof(wrap_capability)}};

  CK_OBJECT_HANDLE objects[10] = {0};
  CK_ULONG n_objects = 0;
  assert(p11->C_FindObjectsInit(session, template, 2) == CKR_OK);
  assert(p11->C_FindObjects(session, objects, 10, &n_objects) == CKR_OK);
  assert(p11->C_FindObjectsFinal(session) == CKR_OK);
  assert(n_objects == 1);
  assert(objects[0] == keyid);

  CK_ULONG mod_bits = 0;
  CK_ULONG key_type = 0;
  CK_ATTRIBUTE value_template[] = {{CKA_MODULUS_BITS, &mod_bits,
                                    sizeof(CK_ULONG)},
                                   {CKA_KEY_TYPE, &key_type, sizeof(CK_ULONG)}};
  assert(p11->C_GetAttributeValue(session, objects[0], value_template, 2) ==
         CKR_OK);
  assert(mod_bits == key_size);
  assert(key_type == CKK_RSA);
}

static CK_OBJECT_HANDLE get_public_key_handle(CK_OBJECT_HANDLE privkey) {
  CK_OBJECT_HANDLE found_obj[10] = {0};
  CK_ULONG n_found_obj = 0;
  CK_ULONG class_pub = CKO_PUBLIC_KEY;
  uint16_t ckaid = 0;

  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_pub, sizeof(class_pub)}
  };

  assert(p11->C_GetAttributeValue(session, privkey, idTemplate, 1) == CKR_OK);
  assert(p11->C_FindObjectsInit(session, idClassTemplate, 2) == CKR_OK);
  assert(p11->C_FindObjects(session, found_obj, 10, &n_found_obj) == CKR_OK);
  assert(n_found_obj == 1);
  assert(p11->C_FindObjectsFinal(session) == CKR_OK);
  return found_obj[0];
}

static void do_ecdsa_sign(CK_OBJECT_HANDLE eckey) {
  CK_MECHANISM mech = {CKM_ECDSA_SHA1, NULL, 0};
  CK_BYTE sig[64] = {0};
  CK_ULONG sig_len = sizeof(sig);

  CK_BYTE data[16] = {0};
  CK_ULONG data_len = sizeof(data);
  assert((RAND_bytes(data, data_len) > 0));
  assert(p11->C_SignInit(session, &mech, eckey) == CKR_OK);
  assert(p11->C_Sign(session, data, sizeof(data), sig, &sig_len) == CKR_OK);
  CK_OBJECT_HANDLE eckey_pub = get_public_key_handle(eckey);
  assert(p11->C_VerifyInit(session, &mech, eckey_pub) == CKR_OK);
  assert(p11->C_Verify(session, data, sizeof(data), sig, sig_len) == CKR_OK);
}

static void do_aesecb_encryption(CK_OBJECT_HANDLE aeskey) {
  CK_MECHANISM mech = {CKM_AES_ECB, NULL, 0};
  CK_BYTE enc[16] = {0};
  CK_ULONG enc_len = sizeof(enc);
  CK_BYTE dec[16] = {0};
  CK_ULONG dec_len = sizeof(dec);

  CK_BYTE data[16] = {0};
  CK_ULONG data_len = sizeof(data);
  assert((RAND_bytes(data, data_len) > 0));

  assert(p11->C_EncryptInit(session, &mech, aeskey) == CKR_OK);
  assert(p11->C_Encrypt(session, data, sizeof(data), enc, &enc_len) == CKR_OK);
  assert(p11->C_DecryptInit(session, &mech, aeskey) == CKR_OK);
  assert(p11->C_Decrypt(session, enc, enc_len, dec, &dec_len) == CKR_OK);
  assert(dec_len == 16);
  assert(memcmp(data, dec, dec_len) == 0);
}

static void test_asym_wrapkey(CK_OBJECT_HANDLE_PTR eckey,
                              CK_OBJECT_HANDLE_PTR aeskey,
                              CK_OBJECT_HANDLE wrapkey, size_t keysize) {
  CK_OBJECT_HANDLE pub_wrapkey, imported_eckey, imported_aeskey;

  find_rsa_wrapkey(wrapkey, keysize);

  // Get public key of RSA wrap key: C_GetAttributeValue(CKA_MODULUS)
  uint8_t pubkey[2048] = {0};
  size_t pubkey_len = sizeof(pubkey);
  get_pub_wrapkey(wrapkey, pubkey, &pubkey_len);
  fprintf(stdout, "Got public key for RSA wrap key 0x%06lx. OK!\n", wrapkey);

  // Import the public key of the RSA wrap key as a public wrap key
  // C_CreateObject(RSA Public Key)
  pub_wrapkey = import_rsa_pub_wrapkey(pubkey, pubkey_len);
  fprintf(stdout,
          "Imported RSA public wrap key of size %zu. ID 0x%06lx OK!\n",
          keysize, pub_wrapkey);
  find_pub_rsa_wrapkey(pub_wrapkey, keysize);

  // Wrap EC key material then import it again as an RSA wrapped key
  // C_WrapKey, C_UnwrapKey
  uint8_t wrapped_key[2048] = {0};
  size_t wrapped_key_len = sizeof(wrapped_key);
  get_wrapped_data(pub_wrapkey, *eckey, wrapped_key, &wrapped_key_len, true);
  fprintf(stdout, "Got wrapped EC key material. %zu bytes. OK!\n", wrapped_key_len);
  imported_eckey =
    import_wrapped_data(wrapkey, wrapped_key, wrapped_key_len, true, CKK_EC);
  fprintf(stdout, "Imported unwrapped EC key material. 0x%06lx. OK!\n",
          imported_eckey);
  do_ecdsa_sign(imported_eckey);
  fprintf(stdout, "Signed using imported EC key. OK!\n");

  // Wrap EC key object then import it again as an RSA wrapped object
  // C_WrapKey, C_UnwrapKey
  memset(wrapped_key, 0, sizeof(wrapped_key));
  wrapped_key_len = sizeof(wrapped_key);
  get_wrapped_data(pub_wrapkey, *eckey, wrapped_key, &wrapped_key_len, false);
  fprintf(stdout, "Got wrapped EC key object. %zu bytes. OK!\n", wrapped_key_len);
  destroy_object(p11, session, *eckey);
  fprintf(stdout, "Removed EC key object. OK!\n");
  *eckey =
    import_wrapped_data(wrapkey, wrapped_key, wrapped_key_len, false, CKK_EC);
  fprintf(stdout, "Imported unwrapped EC key object. OK!\n");
  do_ecdsa_sign(*eckey);
  fprintf(stdout, "Signed using imported EC object. OK!\n");

  // Wrap AES key material then import it again as an RSA wrapped key
  // C_WrapKey, C_UnwrapKey
  memset(wrapped_key, 0, sizeof(wrapped_key));
  wrapped_key_len = sizeof(wrapped_key);
  get_wrapped_data(pub_wrapkey, *aeskey, wrapped_key, &wrapped_key_len, true);
  fprintf(stdout, "Got wrapped AES key material. %zu bytes. OK!\n", wrapped_key_len);
  imported_aeskey =
    import_wrapped_data(wrapkey, wrapped_key, wrapped_key_len, true, CKK_AES);
  fprintf(stdout, "Imported unwrapped AES key material. 0x%06lx. OK!\n",
          imported_aeskey);
  do_aesecb_encryption(imported_aeskey);
  fprintf(stdout, "Encrypted using imported AES key. OK!\n");

  // Wrap AES key object then import it again as an RSA wrapped object
  // C_WrapKey, C_UnwrapKey
  memset(wrapped_key, 0, sizeof(wrapped_key));
  wrapped_key_len = sizeof(wrapped_key);
  get_wrapped_data(pub_wrapkey, *aeskey, wrapped_key, &wrapped_key_len, false);
  fprintf(stdout, "Got wrapped AES key object. %zu bytes. OK!\n", wrapped_key_len);
  destroy_object(p11, session, *aeskey);
  fprintf(stdout, "Removed AES key object. OK!\n");
  *aeskey =
    import_wrapped_data(wrapkey, wrapped_key, wrapped_key_len, false, CKK_AES);
  fprintf(stdout, "Imported unwrapped AES key object. OK!\n");
  do_aesecb_encryption(*aeskey);
  fprintf(stdout, "Signed using imported AES object. OK!\n");

  // Delete test keys
  destroy_object(p11, session, imported_eckey);
  destroy_object(p11, session, imported_aeskey);
  destroy_object(p11, session, pub_wrapkey);

}

static bool is_asymwrap_supported(void) {
  CK_SESSION_INFO info;
  CK_RV r;

  if ((r = p11->C_GetSessionInfo(session, &info)) != CKR_OK) {
    fprintf(stderr, "C_GetSessionInfo (r = %lu)\n", r);
    return CKR_FUNCTION_FAILED;
  }

  CK_MECHANISM_TYPE m[128];
  CK_ULONG n = sizeof(m) / sizeof(m[0]);
  if ((r = p11->C_GetMechanismList(info.slotID, m, &n)) != CKR_OK) {
    fprintf(stderr, "C_GetMechanismList (r = %lu)\n", r);
    return CKR_FUNCTION_FAILED;
  }

  for (CK_ULONG i = 0; i < n; i++) {
    if (m[i] == CKM_YUBICO_RSA_WRAP) {
      return true;
    }
  }
  return false;
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

  if (!is_asymwrap_supported()) {
    goto clean;
  }

  const char *keys[] = {rsa2048, rsa3072, rsa4096};
  size_t keysizes[] = {2048, 3072, 4096};

//   Generate EC key to wrap
  CK_OBJECT_HANDLE ec_pubkey, ec_privkey, aes_key;
  generate_ec_keys(&ec_pubkey, &ec_privkey);
  generate_aes_key(&aes_key);

  for (int i = 0; i < 3; i++) {
    CK_OBJECT_HANDLE wrapkey;

    generate_rsa_wrapkey(keysizes[i], &wrapkey);
    assert(wrapkey != 0);
    test_asym_wrapkey(&ec_privkey, &aes_key, wrapkey, keysizes[i]);
    destroy_object(p11, session, wrapkey);

    wrapkey = 0;
    import_rsa_wrapkey(keys[i], keysizes[i], &wrapkey);
    assert(wrapkey != 0);
    test_asym_wrapkey(&ec_privkey, &aes_key, wrapkey, keysizes[i]);
    destroy_object(p11, session, wrapkey);
  }
  destroy_object(p11, session, ec_privkey);
  printf("OK!\n");

clean:
  close_session(p11, session);
  close_module(handle);
  return (EXIT_SUCCESS);
}
