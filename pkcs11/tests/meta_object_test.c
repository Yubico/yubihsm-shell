/*
 * Copyright 2023 Yubico AB
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

#include "../pkcs11.h"
#include "common.h"

CK_BYTE P384_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};

static CK_FUNCTION_LIST_PTR p11;
static CK_SESSION_HANDLE session;

static void fail(const char *message) { printf("%s. FAIL!\n", message); }

static void generate_keypair(CK_BYTE *curve, CK_ULONG curve_len,
                             CK_OBJECT_HANDLE_PTR publicKeyPtr,
                             CK_OBJECT_HANDLE_PTR privateKeyPtr,
                             char *label_public, char *label_private) {
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

  CK_BBOOL ck_true = CK_TRUE;

  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;

  CK_ATTRIBUTE publicKeyTemplate[] =
    {{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
     {CKA_VERIFY, &ck_true, sizeof(ck_true)},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
     {CKA_LABEL, label_public, strlen(label_public)},
     {CKA_EC_PARAMS, curve, curve_len}};

  CK_ATTRIBUTE privateKeyTemplate[] = {{CKA_CLASS, &privkey_class,
                                        sizeof(privkey_class)},
                                       {CKA_LABEL, label_private,
                                        strlen(label_private)},
                                       {CKA_DERIVE, &ck_true, sizeof(ck_true)}};

  if ((p11->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, 5,
                              privateKeyTemplate, 3, publicKeyPtr,
                              privateKeyPtr)) != CKR_OK) {
    fail("Failed to generate EC key pair on YubiHSM");
    exit(EXIT_FAILURE);
  }
}

static void get_stored_label(CK_OBJECT_HANDLE object, char *label) {
  CK_ATTRIBUTE template[] = {{CKA_LABEL, label, 255}};
  if ((p11->C_GetAttributeValue(session, object, template, 1)) != CKR_OK) {
    printf("Failed C_GetAttributeValue. 0x%lx\n", object);
  }
}

static void set_label(CK_OBJECT_HANDLE object, char *new_label) {
  CK_ATTRIBUTE new_label_template[] = {
    {CKA_LABEL, new_label, strlen(new_label)}};
  if ((p11->C_SetAttributeValue(session, object, new_label_template, 1)) !=
      CKR_OK) {
    fail("Failed to generate EC key pair on YubiHSM");
    exit(EXIT_FAILURE);
  }
}

static void run_label_test(CK_OBJECT_HANDLE object, char *old_label,
                           char *new_label) {
  char label[255] = {0};
  get_stored_label(object, label);
  if (strcmp(label, old_label) != 0) {
    printf("Label does not match what's on the device. Expected: %s. Found: "
           "%s. FAIL!\n",
           old_label, label);
    exit(EXIT_FAILURE);
  }
  set_label(object, new_label);
  memset(label, 0, 255);

  get_stored_label(object, label);
  if (strcmp(label, new_label) != 0) {
    printf("Label does not match what's on the device. Expected: %s. Found: "
           "%s. FAIL!\n",
           new_label, label);
    exit(EXIT_FAILURE);
  }

  printf("Label changed on YubiHSM From '%s' to '%s'. OK!\n", old_label,
         new_label);
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
  printf("Generating key pair with privateKey label 'label' and publicKey "
         "label 'label'... \n");
  generate_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey, &yh_privkey,
                   "label", "label");
  run_label_test(yh_privkey, "label", "new_label");
  run_label_test(yh_pubkey, "label", "new_label");
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");
  /*
    printf("Generating key pair with privateKey label 'label_private' and
    publicKey label 'label_public'... \n"); generate_keypair(CURVE_PARAMS[2],
    CURVE_LENS[2], &yh_pubkey, &yh_privkey, "label_public", "label_private");
    run_label_test(yh_privkey, "label_private", "new_label");
    run_label_test(yh_pubkey, "label_public", "new_label");
    destroy_object(p11, session, yh_privkey);
    printf("OK!\n");
  */

  printf("Generating key pair with privateKey label "
         "'label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00' and publicKey "
         "label 'label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00'... \n");
  generate_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey, &yh_privkey,
                   "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                   "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  run_label_test(yh_privkey,
                 "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_label_0123456789012345678901234567890123456789");
  run_label_test(yh_pubkey,
                 "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_label");
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");

  printf("Generating key pair with privateKey label "
         "'label_private_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00' and "
         "publicKey label "
         "'label_public_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00'... \n");
  generate_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey, &yh_privkey,
                   "label_public_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                   "label_private_"
                   "5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  run_label_test(yh_privkey,
                 "label_private_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_nice_label_0123456789012345678901234567890123456789");
  run_label_test(yh_pubkey,
                 "label_public_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_nice_label_0123456789012345678901234567890123456789");
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");

  close_session(p11, session);
  close_module(handle);
  return (exit_status);
}
