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

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <yubihsm.h>

#include "util.h"
#include "openssl-compat.h"

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
                                  sizeof(password) - 1, false, &session);
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
  yrc = yh_string_to_capabilities("sign-ecdsa:sign-eddsa:sign-pkcs:sign-pss:exportable-under-wrap",
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

  const char data[] = "This is the data to sign"; 

  uint8_t hashed_data[32];
  unsigned int hashed_data_len = sizeof(hashed_data);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  assert(mdctx != NULL);
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, data, sizeof(data) - 1);
  EVP_DigestFinal_ex(mdctx, hashed_data, &hashed_data_len);
  EVP_MD_CTX_destroy(mdctx);

  uint16_t wrapping_key_id = 0; // ID 0 lets the device generate an ID
  yrc =
    yh_util_generate_wrap_key(session, &wrapping_key_id, key_label, domain_five,
                              &capabilities, YH_ALGO_AES256_CCM_WRAP,
                              &delegated_capabilities);
  assert(yrc == YHR_SUCCESS);

  printf("Generated wrapping key with ID %04x\n", wrapping_key_id);

  memset(capabilities.capabilities, 0, YH_CAPABILITIES_LEN);
  yrc = yh_string_to_capabilities("sign-ecdsa:sign-eddsa:sign-pkcs:sign-pss:exportable-under-wrap",
                                  &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t key_id_before = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_ec_key(session, &key_id_before, key_label, domain_five,
                                &capabilities, YH_ALGO_EC_P256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated ec key with ID %04x\n", key_id_before);

  uint8_t public_key_before[1024];
  size_t public_key_before_len = sizeof(public_key_before);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_before,
                               &public_key_before_len, NULL);
  assert(yrc == YHR_SUCCESS);

  memmove(public_key_before + 1, public_key_before, public_key_before_len);
  public_key_before[0] = 0x04; // hack to make it a valid ec pubkey..
  public_key_before_len++;

  printf("Public ec key before (%zu bytes) is:", public_key_before_len);
  for (unsigned int i = 0; i < public_key_before_len; i++) {
    printf(" %02x", public_key_before[i]);
  }
  printf("\n");

  uint8_t signature_before[512];
  size_t signature_before_len = sizeof(signature_before);
  yrc = yh_util_sign_ecdsa(session, key_id_before, hashed_data, hashed_data_len, signature_before,
                           &signature_before_len);
  assert(yrc == YHR_SUCCESS);

  printf("ECDSA signature before (%zu bytes) is:", signature_before_len);
  for (unsigned int i = 0; i < signature_before_len; i++) {
    printf(" %02x", signature_before[i]);
  }
  printf("\n");

  int nid = algo2nid(YH_ALGO_EC_P256);
  EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
  assert(group != NULL);
  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

  EC_POINT *point = EC_POINT_new(group);
  EC_POINT_oct2point(group, point, public_key_before, public_key_before_len, NULL);

  EC_KEY *eckey = EC_KEY_new();
  EC_KEY_set_group(eckey, group);
  EC_KEY_set_public_key(eckey, point);

  assert(ECDSA_verify(0, hashed_data, hashed_data_len, signature_before, signature_before_len, eckey) == 1);
  
  printf("ECDSA Signature before successfully verified\n");

  EC_POINT_free(point);
  EC_KEY_free(eckey);

  uint8_t wrapped_object[2048];
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

  uint8_t public_key_after[1024];
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

  memmove(public_key_after + 1, public_key_after, public_key_after_len);
  public_key_after[0] = 0x04; // hack to make it a valid ec pubkey..
  public_key_after_len++;

  printf("Public ec key after (%zu bytes) is:", public_key_after_len);
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

  uint8_t signature_after[512];
  size_t signature_after_len = sizeof(signature_after);
  yrc = yh_util_sign_ecdsa(session, key_id_after, hashed_data, hashed_data_len, signature_after,
                           &signature_after_len);
  assert(yrc == YHR_SUCCESS);

  printf("\nECDSA signature after (%zu bytes) is:", signature_after_len);
  for (unsigned int i = 0; i < signature_after_len; i++) {
    printf(" %02x", signature_after[i]);
  }
  printf("\n");

  point = EC_POINT_new(group);
  EC_POINT_oct2point(group, point, public_key_after, public_key_after_len, NULL);

  eckey = EC_KEY_new();
  EC_KEY_set_group(eckey, group);
  EC_KEY_set_public_key(eckey, point);

  assert(ECDSA_verify(0, hashed_data, hashed_data_len, signature_after, signature_after_len, eckey) == 1);
  
  printf("ECDSA Signature after successfully verified\n");

  EC_POINT_free(point);
  EC_KEY_free(eckey);
  EC_GROUP_free(group);

  yh_object_descriptor object;

  yrc =
    yh_util_get_object_info(session, key_id_after, YH_ASYMMETRIC_KEY, &object);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_delete_object(session, key_id_after, YH_ASYMMETRIC_KEY);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully deleted ec key with ID %04x\n", key_id_after);

  key_id_before = 0;
  yrc = yh_util_generate_ed_key(session, &key_id_before, key_label, domain_five,
                                &capabilities, YH_ALGO_EC_ED25519);
  assert(yrc == YHR_SUCCESS);

  printf("Generated ed25519 key with ID %04x\n", key_id_before);

  public_key_before_len = sizeof(public_key_before);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_before,
                               &public_key_before_len, NULL);
  assert(yrc == YHR_SUCCESS);

  printf("Public ed25519 key before (%zu bytes) is:", public_key_before_len);
  for (unsigned int i = 0; i < public_key_before_len; i++) {
    printf(" %02x", public_key_before[i]);
  }
  printf("\n");

  signature_before_len = sizeof(signature_before);
  yrc = yh_util_sign_eddsa(session, key_id_before, hashed_data, hashed_data_len, signature_before,
                           &signature_before_len);
  assert(yrc == YHR_SUCCESS);

  printf("Signature (%zu bytes) is:", signature_before_len);
  for (unsigned int i = 0; i < signature_before_len; i++) {
    printf(" %02x", signature_before[i]);
  }
  printf("\n");

  assert(signature_before_len == 64);
  
  wrapped_object_len = sizeof(wrapped_object);
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

  printf("Successfully deleted ed25519 key with ID %04x\n", key_id_before);

  public_key_after_len = sizeof(public_key_after);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_after,
                               &public_key_after_len, NULL);
  assert(yrc == YHR_DEVICE_OBJECT_NOT_FOUND);

  printf("Unable to get public key for ed25519 key with ID %04x\n", key_id_before);

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

  printf("Public ed25519 key after (%zu bytes) is:", public_key_after_len);
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

  signature_after_len = sizeof(signature_after);
  yrc = yh_util_sign_eddsa(session, key_id_after, hashed_data, hashed_data_len, signature_after,
                           &signature_after_len);
  assert(yrc == YHR_SUCCESS);

  printf("Signature (%zu bytes) is:", signature_after_len);
  for (unsigned int i = 0; i < signature_after_len; i++) {
    printf(" %02x", signature_after[i]);
  }
  printf("\n");

  assert(signature_after_len == 64);

  if (signature_before_len != signature_after_len ||
      memcmp(signature_before, signature_after, signature_before_len) != 0) {
    printf("Signature before and after do not match\n");
    exit(EXIT_FAILURE);
  } else {
    printf("Signature before and after match\n");
  }

  yrc =
    yh_util_get_object_info(session, key_id_after, YH_ASYMMETRIC_KEY, &object);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_delete_object(session, key_id_after, YH_ASYMMETRIC_KEY);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully deleted ed25519 key with ID %04x\n", key_id_after);

  key_id_before = 0;
  yrc = yh_util_generate_rsa_key(session, &key_id_before, key_label, domain_five,
                                &capabilities, YH_ALGO_RSA_2048);
  assert(yrc == YHR_SUCCESS);

  printf("Generated 2048 bit RSA key with ID %04x\n", key_id_before);

  public_key_before_len = sizeof(public_key_before);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_before,
                               &public_key_before_len, NULL);
  assert(yrc == YHR_SUCCESS);

  printf("Public RSA key before (%zu bytes) is:", public_key_before_len);
  for (unsigned int i = 0; i < public_key_before_len; i++) {
    printf(" %02x", public_key_before[i]);
  }
  printf("\n");

  signature_before_len = sizeof(signature_before);
  yrc = yh_util_sign_pkcs1v1_5(session, key_id_before, true, hashed_data, hashed_data_len, signature_before,
                           &signature_before_len);
  assert(yrc == YHR_SUCCESS);

  printf("Signature (%zu bytes) is:", signature_before_len);
  for (unsigned int i = 0; i < signature_before_len; i++) {
    printf(" %02x", signature_before[i]);
  }
  printf("\n");

  BIGNUM *n = BN_bin2bn(public_key_before, public_key_before_len, NULL);
  assert(n != NULL);

  BIGNUM *e = BN_bin2bn((const unsigned char *) "\x01\x00\x01", 3, NULL);
  assert(e != NULL);

  RSA *rsa = RSA_new();
  assert(RSA_set0_key(rsa, n, e, NULL) != 0);

  assert(RSA_verify(EVP_MD_type(EVP_sha256()), hashed_data, hashed_data_len,
                 signature_before, signature_before_len, rsa) == 1);
  
  printf("RSA signature before successfully verified\n");

  RSA_free(rsa);

  wrapped_object_len = sizeof(wrapped_object);
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

  printf("Successfully deleted RSA key with ID %04x\n", key_id_before);

  public_key_after_len = sizeof(public_key_after);
  yrc = yh_util_get_public_key(session, key_id_before, public_key_after,
                               &public_key_after_len, NULL);
  assert(yrc == YHR_DEVICE_OBJECT_NOT_FOUND);

  printf("Unable to get public key for RSA key with ID %04x\n", key_id_before);

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

  printf("Public RSA key after (%zu bytes) is:", public_key_after_len);
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

  signature_after_len = sizeof(signature_after);
  yrc = yh_util_sign_pkcs1v1_5(session, key_id_before, true, hashed_data, hashed_data_len, signature_after,
                           &signature_after_len);
  assert(yrc == YHR_SUCCESS);

  printf("Signature (%zu bytes) is:", signature_after_len);
  for (unsigned int i = 0; i < signature_after_len; i++) {
    printf(" %02x", signature_after[i]);
  }
  printf("\n");

  n = BN_bin2bn(public_key_after, public_key_after_len, NULL);
  assert(n != NULL);

  e = BN_bin2bn((const unsigned char *) "\x01\x00\x01", 3, NULL);
  assert(e != NULL);

  rsa = RSA_new();
  assert(RSA_set0_key(rsa, n, e, NULL) != 0);

  assert(RSA_verify(EVP_MD_type(EVP_sha256()), hashed_data, hashed_data_len,
                 signature_after, signature_after_len, rsa) == 1);
  
  printf("RSA signature after successfully verified\n");

  RSA_free(rsa);

  yrc =
    yh_util_get_object_info(session, key_id_after, YH_ASYMMETRIC_KEY, &object);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_delete_object(session, key_id_after, YH_ASYMMETRIC_KEY);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully deleted RSA key with ID %04x\n", key_id_after);

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
