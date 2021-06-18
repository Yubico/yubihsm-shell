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

#include <pkcs11y.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: p11 /path/to/yubihsm_pkcs11/module\n");
    exit(EXIT_FAILURE);
  }

  CK_C_GetFunctionList fn;
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
  assert(handle != NULL);

  *(void **) (&fn) = dlsym(handle, "C_GetFunctionList");
  assert(fn != NULL);

  CK_FUNCTION_LIST_PTR p11;
  CK_RV rv = fn(&p11);
  assert(rv == CKR_OK);

  rv = p11->C_Initialize(NULL_PTR);
  assert(rv == CKR_OK);

  CK_SESSION_HANDLE session;
  rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
                          &session);
  assert(rv == CKR_OK);

  char password[] = "0001password";
  rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) password,
                    (CK_ULONG) strlen(password));
  assert(rv == CKR_OK);

  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_ULONG modulus = 2048;
  CK_BYTE exponent[] = {0x00, 0x1, 0x0, 0x1}; // 65537
  CK_BYTE id[] = {0};
  CK_BBOOL ck_true = CK_TRUE;
  CK_BBOOL ck_false = CK_FALSE;

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
    {CKA_DECRYPT, &ck_false, sizeof(ck_false)},
    {CKA_SIGN, &ck_false, sizeof(ck_false)},
    {CKA_VERIFY, &ck_true, sizeof(ck_true)},
    {CKA_WRAP, &ck_true, sizeof(ck_true)},
    {CKA_UNWRAP, &ck_false, sizeof(ck_false)},
    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
    {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
    {CKA_MODIFIABLE, &ck_false, sizeof(ck_false)},
    {CKA_COPYABLE, &ck_false, sizeof(ck_false)},
    {CKA_DESTROYABLE, &ck_true, sizeof(ck_true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_MODULUS_BITS, &modulus, sizeof(modulus)},
    {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
  };
  CK_ULONG publicKeyAttributeCount =
    sizeof(publicKeyTemplate) / sizeof(publicKeyTemplate[0]);

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_ENCRYPT, &ck_false, sizeof(ck_false)},
    {CKA_DECRYPT, &ck_true, sizeof(ck_true)},
    {CKA_SIGN, &ck_true, sizeof(ck_true)},
    {CKA_VERIFY, &ck_false, sizeof(ck_false)},
    {CKA_WRAP, &ck_false, sizeof(ck_false)},
    {CKA_UNWRAP, &ck_true, sizeof(ck_true)},
    {CKA_TOKEN, &ck_true, sizeof(ck_true)},
    {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
    {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
    {CKA_MODIFIABLE, &ck_false, sizeof(ck_false)},
    {CKA_COPYABLE, &ck_false, sizeof(ck_false)},
    {CKA_DESTROYABLE, &ck_true, sizeof(ck_true)},
    {CKA_ID, id, sizeof(id)},
  };
  CK_ULONG privateKeyAttributeCount =
    sizeof(privateKeyTemplate) / sizeof(privateKeyTemplate[0]);

  CK_OBJECT_HANDLE publicKey, privateKey;
  rv =
    p11->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate,
                           publicKeyAttributeCount, privateKeyTemplate,
                           privateKeyAttributeCount, &publicKey, &privateKey);
  assert(rv == CKR_OK);

  rv = p11->C_Logout(session);
  assert(rv == CKR_OK);

  rv = p11->C_CloseSession(session);
  assert(rv == CKR_OK);

  rv = p11->C_Finalize(NULL);
  assert(rv == CKR_OK);

  dlclose(handle);

  return 0;
}
