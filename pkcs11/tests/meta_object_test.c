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
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "../pkcs11.h"
#include "common.h"
#include "yubihsm.h"

CK_BYTE P384_PARAMS[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
CK_BYTE KEYID[2] = {0x64, 0x64};

static CK_FUNCTION_LIST_PTR p11;
static CK_SESSION_HANDLE session;

static void fail(const char *message) { printf("%s. FAIL!\n", message); }

static void print_byte_array_no_new_line(const char *tag, uint8_t *data,
                                         uint16_t data_len) {
  printf("%s: ", tag);
  for (uint16_t i = 0; i < data_len; i++) {
    printf("%x ", data[i]);
  }
}

static void print_byte_array(const char *tag, uint8_t *data,
                             uint16_t data_len) {
  print_byte_array_no_new_line(tag, data, data_len);
  printf("\n");
}

static CK_SESSION_HANDLE open_test_session(char *password) {
  CK_SESSION_HANDLE tmp_session;
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

  p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
                     &tmp_session);
  assert(rv == CKR_OK);

  p11->C_Login(tmp_session, CKU_USER, (CK_UTF8CHAR_PTR) password,
               (CK_ULONG) strlen(password));
  assert(rv == CKR_OK);
  return tmp_session;
}

static void generate_ec_keypair(
  CK_BYTE *curve, CK_ULONG curve_len, CK_OBJECT_HANDLE_PTR publicKeyPtr,
  CK_OBJECT_HANDLE_PTR privateKeyPtr, CK_BYTE *ckaid_public,
  CK_ULONG ckaid_public_len, CK_BYTE *ckaid_private, CK_ULONG ckaid_private_len,
  char *label_public, char *label_private) {
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};

  CK_BBOOL ck_true = CK_TRUE;

  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;

  CK_ATTRIBUTE publicKeyTemplate[] =
    {{CKA_ID, ckaid_public, ckaid_public_len},
     {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
     {CKA_VERIFY, &ck_true, sizeof(ck_true)},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
     {CKA_LABEL, label_public, strlen(label_public)},
     {CKA_EC_PARAMS, curve, curve_len}};

  CK_ATTRIBUTE privateKeyTemplate[] =
    {{CKA_ID, ckaid_private, ckaid_private_len},
     {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
     {CKA_LABEL, label_private, strlen(label_private)},
     {CKA_DERIVE, &ck_true, sizeof(ck_true)}};

  CK_RV rv =
    p11->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, 6,
                           privateKeyTemplate, 4, publicKeyPtr, privateKeyPtr);
  assert(rv == CKR_OK);
}

static void generate_rsa_keypair(
  CK_OBJECT_HANDLE_PTR publicKeyPtr, CK_OBJECT_HANDLE_PTR privateKeyPtr,
  CK_BYTE *ckaid_public, CK_ULONG ckaid_public_len, CK_BYTE *ckaid_private,
  CK_ULONG ckaid_private_len, char *label_public, char *label_private) {
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};

  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_BYTE e[] = {0x01, 0x00, 0x01};
  CK_ULONG key_size = 2048;

  CK_ATTRIBUTE publicKeyTemplate[] =
    {{CKA_ID, ckaid_public, ckaid_public_len},
     {CKA_LABEL, label_public, strlen(label_public)},
     {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
     {CKA_MODULUS_BITS, &key_size, sizeof(key_size)},
     {CKA_PUBLIC_EXPONENT, e, sizeof(e)}};

  CK_ATTRIBUTE privateKeyTemplate[] =
    {{CKA_ID, ckaid_private, ckaid_private_len},
     {CKA_LABEL, label_private, strlen(label_private)},
     {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
     {CKA_KEY_TYPE, &key_type, sizeof(key_type)}};

  CK_RV rv =
    p11->C_GenerateKeyPair(session, &mechanism, publicKeyTemplate, 5,
                           privateKeyTemplate, 4, publicKeyPtr, privateKeyPtr);
  assert(rv == CKR_OK);
}

static void generate_hmac_key(CK_OBJECT_HANDLE_PTR key_handle, CK_BYTE *ckaid,
                              CK_ULONG ckaid_len, char *label) {
  CK_MECHANISM mechanism = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};

  CK_OBJECT_CLASS class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_SHA_1_HMAC;

  CK_ATTRIBUTE keyTemplate[] = {{CKA_ID, ckaid, ckaid_len},
                                {CKA_LABEL, label, strlen(label)},
                                {CKA_CLASS, &class, sizeof(class)},
                                {CKA_KEY_TYPE, &key_type, sizeof(key_type)}};

  CK_RV rv =
    p11->C_GenerateKey(session, &mechanism, keyTemplate, 4, key_handle);
  assert(rv == CKR_OK);
}

static void get_stored_id(CK_OBJECT_HANDLE object, uint8_t *id) {
  CK_ATTRIBUTE template[] = {{CKA_ID, id, 255}};
  CK_RV rv = p11->C_GetAttributeValue(session, object, template, 1);
  assert(rv == CKR_OK);
}

static void get_stored_label(CK_OBJECT_HANDLE object, char *label) {
  CK_ATTRIBUTE template[] = {{CKA_LABEL, label, 255}};
  CK_RV rv = p11->C_GetAttributeValue(session, object, template, 1);
  assert(rv == CKR_OK);
}

static void set_id(CK_OBJECT_HANDLE object, uint8_t *new_id,
                   uint16_t new_id_len) {
  CK_ATTRIBUTE template[] = {{CKA_ID, new_id, new_id_len}};
  CK_RV rv = p11->C_SetAttributeValue(session, object, template, 1);
  assert(rv == CKR_OK);
}

static void set_label(CK_OBJECT_HANDLE object, char *new_label) {
  CK_ATTRIBUTE template[] = {{CKA_LABEL, new_label, strlen(new_label)}};
  CK_RV rv = p11->C_SetAttributeValue(session, object, template, 1);
  assert(rv == CKR_OK);
}

static void run_id_test(CK_OBJECT_HANDLE object, uint8_t *old_id,
                        uint16_t old_id_len, uint8_t *new_id,
                        uint16_t new_id_len) {
  uint8_t id[255] = {0};
  get_stored_id(object, id);
  if (memcmp(id, old_id, old_id_len) != 0) {
    printf("ID does not match what's on the device.FAIL!\n");
    print_byte_array("Expected CKA_ID", old_id, old_id_len);
    print_byte_array("Found CKA_ID", id, sizeof(id));
    exit(EXIT_FAILURE);
  }
  set_id(object, new_id, new_id_len);
  memset(id, 0, 255);

  get_stored_id(object, id);
  if (memcmp(id, new_id, new_id_len) != 0) {
    printf("ID does not match what's on the device. FAIL!\n");
    print_byte_array("Expected CKA_ID", new_id, new_id_len);
    print_byte_array("Found CKA_ID", id, sizeof(id));
    exit(EXIT_FAILURE);
  }

  printf("ID changed on YubiHSM. ");
  print_byte_array_no_new_line("Old CKA_ID", old_id, old_id_len);
  print_byte_array_no_new_line(". New CKA_ID", new_id, new_id_len);
  printf(". OK!\n");
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

static void test_keypair_metadata(int is_rsa) {
  CK_BYTE data[64] = {0};
  CK_ULONG data_len = sizeof(data);
  int ret = RAND_bytes(data, data_len);
  assert(ret > 0);

  CK_OBJECT_HANDLE yh_pubkey, yh_privkey;
  printf("Generating key pair with privateKey label 'label' and publicKey "
         "label 'label'... \n");
  if (is_rsa) {
    generate_rsa_keypair(&yh_pubkey, &yh_privkey, KEYID, sizeof(KEYID), KEYID,
                         sizeof(KEYID), "label", "label");
  } else {
    generate_ec_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey,
                        &yh_privkey, KEYID, sizeof(KEYID), KEYID, sizeof(KEYID),
                        "label", "label");
  }
  run_label_test(yh_privkey, "label", "new_label");
  run_label_test(yh_pubkey, "label", "new_label");
  run_id_test(yh_privkey, KEYID, sizeof(KEYID), data, 32);
  run_id_test(yh_pubkey, KEYID, sizeof(KEYID), data, 32);
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");

  printf("Generating key pair with privateKey label 'label_private' and "
         "publicKey label 'label_public' and different CKA_ID of size 2... \n");
  if (is_rsa) {
    generate_rsa_keypair(&yh_pubkey, &yh_privkey, KEYID, sizeof(KEYID), data,
                         sizeof(KEYID), "label_public", "label_private");
  } else {
    generate_ec_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey,
                        &yh_privkey, KEYID, sizeof(KEYID), data, sizeof(KEYID),
                        "label_public", "label_private");
  }
  run_label_test(yh_privkey, "label_private", "new_label");
  run_label_test(yh_pubkey, "label_public", "new_label");
  run_id_test(yh_privkey, data, sizeof(KEYID), data + 10, sizeof(KEYID));
  run_id_test(yh_pubkey, KEYID, sizeof(KEYID), data + 6, sizeof(KEYID));
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");

  printf("Generating key pair with privateKey label "
         "'label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00' and publicKey "
         "label 'label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00' and "
         "similar 32 bytes CKA_ID... \n");
  if (is_rsa) {
    generate_rsa_keypair(&yh_pubkey, &yh_privkey, data, 32, data + 32, 32,
                         "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                         "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  } else {
    generate_ec_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey,
                        &yh_privkey, data, 32, data + 32, 32,
                        "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                        "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  }
  run_label_test(yh_privkey,
                 "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_label_0123456789012345678901234567890123456789");
  run_label_test(yh_pubkey,
                 "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_label");
  run_id_test(yh_privkey, data + 32, 32, data, 32);
  run_id_test(yh_pubkey, data, 32, data + 6, sizeof(KEYID));
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");

  printf("Generating key pair with privateKey label "
         "'label_private_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00' and "
         "publicKey label "
         "'label_public_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00'... \n");
  if (is_rsa) {
    generate_rsa_keypair(&yh_pubkey, &yh_privkey, KEYID, sizeof(KEYID), KEYID,
                         sizeof(KEYID),
                         "label_public_"
                         "5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                         "label_private_"
                         "5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  } else {
    generate_ec_keypair(P384_PARAMS, sizeof(P384_PARAMS), &yh_pubkey,
                        &yh_privkey, KEYID, sizeof(KEYID), KEYID, sizeof(KEYID),
                        "label_public_"
                        "5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                        "label_private_"
                        "5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  }
  run_label_test(yh_privkey,
                 "label_private_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_nice_label_0123456789012345678901234567890123456789");
  run_label_test(yh_pubkey,
                 "label_public_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_nice_label_0123456789012345678901234567890123456789");
  destroy_object(p11, session, yh_privkey);
  printf("OK!\n");
}

static void test_secretkey_metadata(void) {
  CK_BYTE data[64] = {0};
  CK_ULONG data_len = sizeof(data);
  int ret = RAND_bytes(data, data_len);
  assert(ret > 0);

  CK_OBJECT_HANDLE yh_key;

  printf("Generating HMAC key with label 'label' and default CKA_ID... \n");
  generate_hmac_key(&yh_key, KEYID, sizeof(KEYID), "label");
  run_label_test(yh_key, "label", "new_label");
  run_id_test(yh_key, KEYID, sizeof(KEYID), data, 32);
  destroy_object(p11, session, yh_key);
  printf("OK!\n");

  printf("Generating HMAC key with label "
         "'label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00' and a 32 bytes "
         "CKA_ID... \n");
  generate_hmac_key(&yh_key, data, 32,
                    "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00");
  run_label_test(yh_key, "label_5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
                 "new_label_0123456789012345678901234567890123456789");
  run_id_test(yh_key, data, 32, data + 6, sizeof(KEYID));
  destroy_object(p11, session, yh_key);
  printf("OK!\n");
}

static yh_session *get_device_session(void) {
  yh_connector *connector = NULL;
  yh_session *device_session = NULL;

  uint16_t authkey = 1;
  const uint8_t password1[] = "password";

  const char *connector_url;

  connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }

  yh_rc yrc = yh_init();
  assert(yrc == YHR_SUCCESS);

  yrc = yh_init_connector(connector_url, &connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_connect(connector, 0);
  assert(yrc == YHR_SUCCESS);

  yrc =
    yh_create_session_derived(connector, authkey, password1,
                              sizeof(password1) - 1, false, &device_session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(device_session, &session_id);
  assert(yrc == YHR_SUCCESS);

  return device_session;
}

static void import_authkey(yh_session *device_session, uint16_t keyid,
                           char *domains_str, char *password) {
  yh_capabilities capabilities = {{0}};
  yh_rc yrc = yh_string_to_capabilities("all", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domains = 0;
  yrc = yh_string_to_domains(domains_str, &domains);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_import_authentication_key_derived(device_session, &keyid,
                                                  "pkca11test_authkey", domains,
                                                  &capabilities, &capabilities,
                                                  (CK_UTF8CHAR_PTR) password,
                                                  strlen(password));
  printf("yh_util_import_authentication_key_derived returned: %d "
         "   keyid: 0x%x\n",
         yrc, keyid);
  assert(yrc == YHR_SUCCESS);
}

static void test_domain(void) {

  char password2[] = "foobar123";
  char p11_password2[] = "0002foobar123";
  char password3[] = "foo123bar";
  char p11_password3[] = "0003foo123bar";
  char password4[] = "123foobar";
  char p11_password4[] = "0004123foobar";
  char password5[] = "foofoobar";
  char p11_password5[] = "0005foofoobar";

  close_session(p11, session);
  yh_session *device_session = get_device_session();

  // Create authentication keys with different domains access to test with
  import_authkey(device_session, 2, "3,4,5", password2);
  import_authkey(device_session, 3, "5,6,7", password3);
  import_authkey(device_session, 4, "7,8,9", password4);
  import_authkey(device_session, 5, "1,2,3,4,5", password5);

  session = open_test_session(p11_password2);

  CK_OBJECT_HANDLE key_handle;

  // Generate key with domains: 3,4,5
  printf("Generate key with domains: 3,4,5\n");
  CK_MECHANISM mechanism = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};
  CK_OBJECT_CLASS class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_SHA_1_HMAC;
  char *label = "labellabel5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00";
  CK_ATTRIBUTE keyTemplate[] = {{CKA_LABEL, label, strlen(label)},
                                {CKA_CLASS, &class, sizeof(class)},
                                {CKA_KEY_TYPE, &key_type, sizeof(key_type)}};
  CK_RV rv =
    p11->C_GenerateKey(session, &mechanism, keyTemplate, 3, &key_handle);
  assert(rv == CKR_OK);
  close_session(p11, session);

  char stored_label[255] = {0};
  CK_ATTRIBUTE get_label_template[] = {{CKA_LABEL, stored_label, 255}};
  char *new_label = "new_label";
  CK_ATTRIBUTE new_label_template[] = {
    {CKA_LABEL, new_label, strlen(new_label)}};

  // Read meta data using authkey with domains: 5,6,7
  printf("Read meta data using authkey with domains: 5,6,7. ");
  session = open_test_session(p11_password3);
  get_stored_label(key_handle, stored_label);
  if (strcmp(stored_label,
             "labellabel5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00") != 0) {
    printf("Label does not match what's on the device, probably because "
           "meta_object was not read. Expected: %s. Found: "
           "%s. FAIL!\n",
           "labellabel5fc17f953e7c97dafabe60b1d5769c2b629c9b198bf00",
           stored_label);
    exit(EXIT_FAILURE);
  }
  printf("OK!\n");

  // Overwrite existing meta_data using authkey with domains: 5,6,7. Should fail
  printf("Overwrite existing meta_data using authkey with domains: 5,6,7 "
         "(Expected to fail). ");
  if ((p11->C_SetAttributeValue(session, key_handle, new_label_template, 1)) !=
      CKR_FUNCTION_REJECTED) {
    memset(stored_label, 0, 255);
    get_stored_label(key_handle, stored_label);
    printf("After C_SetAttribute: label: %s\n", stored_label);
    if (strcmp(stored_label, new_label) == 0) {
      fail("Succeeded to set CKA_LABEL attribute, which should fail due to "
           "domain mismatch");
      exit(EXIT_FAILURE);
    }
  }
  printf("OK!\n");
  close_session(p11, session);

  // Read meta_data using authkey with domains: 7,8,9. Should fail
  printf(
    "Read meta_data using authkey with domains: 7,8,9 (Expected to fail). ");
  session = open_test_session(p11_password4);
  memset(stored_label, 0, 255);
  rv = p11->C_GetAttributeValue(session, key_handle, get_label_template, 1);
  assert(rv == CKR_OBJECT_HANDLE_INVALID);
  printf("OK!\n");
  close_session(p11, session);

  // Modify meta_object using authkey with superset domains
  printf("Modify meta_object using authkey with superset domains. ");
  session = open_test_session(p11_password5);
  if ((p11->C_SetAttributeValue(session, key_handle, new_label_template, 1)) !=
      CKR_OK) {
    memset(stored_label, 0, 255);
    get_stored_label(key_handle, stored_label);
    printf("Failed to set attribute. Stored label expected: %s. Found: %s\n",
           new_label, stored_label);
    exit(EXIT_FAILURE);
  }
  close_session(p11, session);

  // Find meta_object ObjectID
  uint16_t target_id = key_handle & 0xffff;
  uint8_t target_type = (key_handle >> 16);
  uint8_t target_sequence = key_handle >> 24;
  char metaobject_label[YH_OBJ_LABEL_LEN] = {0};
  sprintf(metaobject_label, "Meta object for 0x%02x%02x%04x", target_sequence,
          target_type, target_id);
  yh_object_descriptor meta_objects[10] = {0};
  size_t meta_ojbects_len = 10;
  yh_capabilities capabilities = {{0}};
  yh_rc yrc =
    yh_util_list_objects(device_session, 0, YH_OPAQUE, 0xffff, &capabilities,
                         YH_ALGO_OPAQUE_DATA, metaobject_label, meta_objects,
                         &meta_ojbects_len);
  assert(yrc == YHR_SUCCESS);
  if (meta_ojbects_len == 0) {
    fail("No meta_objects were found. There should be 1");
    exit(EXIT_FAILURE);
  } else if (meta_ojbects_len > 1) {
    printf("There are more than 1 meta_object for the target_object. Expected: "
           "1. Found: %ld\n",
           meta_ojbects_len);
    exit(EXIT_FAILURE);
  }

  // Check meta_object domains
  yrc = yh_util_get_object_info(device_session, meta_objects[0].id, YH_OPAQUE,
                                &meta_objects[0]);
  assert(yrc == YHR_SUCCESS);
  if (meta_objects[0].domains != 28) { // domains 3,4,5
    printf("Meta object was overwritten with other domains than original "
           "object. Expected: 28. Found %d\n",
           meta_objects[0].domains);
    exit(EXIT_FAILURE);
  }
  printf("OK!\n");

  // Clear the HSM after the test
  yh_util_delete_object(device_session, 2, YH_AUTHENTICATION_KEY);
  yh_util_delete_object(device_session, 3, YH_AUTHENTICATION_KEY);
  yh_util_delete_object(device_session, 4, YH_AUTHENTICATION_KEY);
  yh_util_delete_object(device_session, 5, YH_AUTHENTICATION_KEY);
  yh_util_delete_object(device_session, target_id, YH_HMAC_KEY);
  yh_util_delete_object(device_session, meta_objects[0].id, YH_OPAQUE);

  yh_util_close_session(device_session);

  printf("OK!\n");
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "usage: /path/to/yubihsm_pkcs11/module\n");
    exit(EXIT_FAILURE);
  }

  void *handle = open_module(argv[1]);
  p11 = get_function_list(handle);
  session = open_test_session("0001password");
  print_session_state(p11, session);

  int exit_status = EXIT_SUCCESS;

  test_keypair_metadata(0);
  printf("\n\n");
  test_keypair_metadata(1);
  test_secretkey_metadata();
  printf("\n\n");
  test_domain();

  close_module(handle);
  return (exit_status);
}
