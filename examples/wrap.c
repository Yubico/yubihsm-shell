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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char *key_label = "label";
const uint8_t password[] = "password";

int main(void) {
  yh_connector *connector = NULL;
  yh_session *session = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;

  uint16_t authkey = 1;

  const char *connector_url;

  connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }

  yrc = yh_init();
  assert(yrc == YHR_SUCCESS);

  yrc = yh_init_connector(connector_url, &connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_connect(connector, 0);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_create_session_derived(connector, authkey, password,
                                  sizeof(password), false, &session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_authenticate_session(session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);

  yh_capabilities capabilities = {{0}};
  yrc =
    yh_string_to_capabilities("export-wrapped:import-wrapped", &capabilities);
  assert(yrc == YHR_SUCCESS);

  yh_capabilities delegated_capabilities = {{0}};
  yrc = yh_string_to_capabilities("sign-ecdsa:exportable-under-wrap",
                                  &delegated_capabilities); // delegated
                                                            // capabilities has
                                                            // to match the
                                                            // capabilities of
                                                            // the object we
                                                            // want to export
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t wrapping_key_id = 0; // ID 0 lets the device generate an ID
  yrc =
    yh_util_generate_wrap_key(session, &wrapping_key_id, key_label, domain_five,
                              &capabilities, YH_ALGO_AES256_CCM_WRAP,
                              &delegated_capabilities);
  assert(yrc == YHR_SUCCESS);

  printf("Generated wrapping key with ID %04x\n", wrapping_key_id);

  memset(capabilities.capabilities, 0, YH_CAPABILITIES_LEN);
  yrc = yh_string_to_capabilities("sign-ecdsa:exportable-under-wrap",
                                  &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id_before = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_ec_key(session, &key_id_before, key_label, domain_five,
                                &capabilities, YH_ALGO_EC_P256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated ec key with ID %04x\n", key_id_before);

  uint8_t public_key_before[512];
  size_t public_key_before_len = sizeof(public_key_before);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_before,
                               &public_key_before_len, NULL);
  assert(yrc == YHR_SUCCESS);

  printf("Public key before (%zu bytes) is:", public_key_before_len);
  for (unsigned int i = 0; i < public_key_before_len; i++) {
    printf(" %02x", public_key_before[i]);
  }
  printf("\n");

  uint8_t wrapped_object[512];
  size_t wrapped_object_len = sizeof(wrapped_object);
  yh_object_type object_type_after;
  yrc =
    yh_util_export_wrapped(session, wrapping_key_id, YH_ASYMMETRIC_KEY,
                           key_id_before, wrapped_object, &wrapped_object_len);
  assert(yrc == YHR_SUCCESS);

  printf("Wrapped object (%zu bytes) is:", wrapped_object_len);
  for (unsigned int i = 0; i < wrapped_object_len; i++) {
    printf(" %02x", wrapped_object[i]);
  }
  printf("\n");

  yrc = yh_util_delete_object(session, key_id_before, YH_ASYMMETRIC_KEY);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully deleted ec key with ID %04x\n", key_id_before);

  uint8_t public_key_after[512];
  size_t public_key_after_len = sizeof(public_key_after);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_after,
                               &public_key_after_len, NULL);
  assert(yrc == YHR_DEVICE_OBJECT_NOT_FOUND);

  printf("Unable to get public key for ec key with ID %04x\n", key_id_before);

  uint16_t key_id_after;
  yrc = yh_util_import_wrapped(session, wrapping_key_id, wrapped_object,
                               wrapped_object_len, &object_type_after,
                               &key_id_after);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully imported wrapped object with ID %04x\n", key_id_after);

  if (object_type_after != YH_ASYMMETRIC_KEY) {
    printf("Unexpected odbject type\n");
    exit(EXIT_FAILURE);
  }

  if (key_id_before != key_id_after) {
    printf("ID %04x and %04x do not match\n", key_id_before, key_id_after);
    exit(EXIT_FAILURE);
  } else {
    printf("ID %04x and %04x match\n", key_id_before, key_id_after);
  }

  yrc = yh_util_get_public_key(session, key_id_after, public_key_after,
                               &public_key_after_len, NULL);
  assert(yrc == YHR_SUCCESS);

  printf("Public key after (%zu bytes) is:", public_key_after_len);
  for (unsigned int i = 0; i < public_key_after_len; i++) {
    printf(" %02x", public_key_after[i]);
  }
  printf("\n");

  if (public_key_before_len != public_key_after_len ||
      memcmp(public_key_before, public_key_after, public_key_before_len) != 0) {
    printf("Public key before and after do not match\n");
    exit(EXIT_FAILURE);
  } else {
    printf("Public key before and after match\n");
  }

  yh_object_descriptor object;

  yrc =
    yh_util_get_object_info(session, key_id_after, YH_ASYMMETRIC_KEY, &object);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yh_disconnect(connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return 0;
}
