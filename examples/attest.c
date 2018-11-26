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

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <yubihsm.h>

#include "openssl-compat.h"

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char attestation_template_file[] = "attestation_template.pem";
const char *key_label = "label";
const uint8_t password[] = "password";

static void print_extension(X509_EXTENSION *extension) {
  // Quick and dirty solution for printing extensions

  const uint8_t version[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                             0x01, 0x82, 0xc4, 0x0a, 0x04, 0x01};
  const uint8_t serial[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                            0x01, 0x82, 0xc4, 0x0a, 0x04, 0x02};
  const uint8_t origin[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                            0x01, 0x82, 0xc4, 0x0a, 0x04, 0x03};
  const uint8_t domains[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                             0x01, 0x82, 0xc4, 0x0a, 0x04, 0x04};
  const uint8_t capabilities[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                                  0x01, 0x82, 0xc4, 0x0a, 0x04, 0x05};
  const uint8_t id[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                        0x01, 0x82, 0xc4, 0x0a, 0x04, 0x06};
  const uint8_t label[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
                           0x01, 0x82, 0xc4, 0x0a, 0x04, 0x09};

  ASN1_OBJECT *a_object = X509_EXTENSION_get_object(extension);
  ASN1_OCTET_STRING *a_value = X509_EXTENSION_get_data(extension);
  uint8_t object[1024];
  uint8_t *ptr = object;
  if (i2d_ASN1_OBJECT(a_object, NULL) > 1024) {
    printf("Extension to long.\n");
    return;
  }
  unsigned int object_len = i2d_ASN1_OBJECT(a_object, &ptr);

  uint8_t value[1024];
  ptr = value;
  if (i2d_ASN1_OCTET_STRING(a_value, NULL) > 1024) {
    printf("Extension value to long.\n");
    return;
  }
  unsigned int value_len = i2d_ASN1_OCTET_STRING(a_value, &ptr);

  if (object_len == sizeof(version) &&
      memcmp(object, version, sizeof(version)) == 0) {
    printf("Version:");
  } else if (object_len == sizeof(serial) &&
             memcmp(object, serial, sizeof(serial)) == 0) {
    printf("Serial:");
  } else if (object_len == sizeof(origin) &&
             memcmp(object, origin, sizeof(origin)) == 0) {
    printf("Origin:");
  } else if (object_len == sizeof(domains) &&
             memcmp(object, domains, sizeof(domains)) == 0) {
    printf("Domains:");
  } else if (object_len == sizeof(capabilities) &&
             memcmp(object, capabilities, sizeof(capabilities)) == 0) {
    printf("Capabilities:");
  } else if (object_len == sizeof(id) && memcmp(object, id, sizeof(id)) == 0) {
    printf("ID:");
  } else if (object_len == sizeof(label) &&
             memcmp(object, label, sizeof(label)) == 0) {
    printf("Label:");
  } else {
    printf("Unknown:");
  }

  for (unsigned int i = 0; i < value_len; i++) {
    printf(" %02x", value[i]);
  }
  printf("\n");
}

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
    yh_string_to_capabilities("sign-attestation-certificate", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t attesting_key_id = 0; // ID 0 lets the device generate an ID

  yrc = yh_util_generate_ec_key(session, &attesting_key_id, key_label,
                                domain_five, &capabilities, YH_ALGO_EC_P256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated attesting key with ID %04x\n", attesting_key_id);

  FILE *fp = fopen(attestation_template_file, "rb");
  assert(fp != NULL);

  X509 *attestation_template = PEM_read_X509(fp, NULL, NULL, NULL);
  assert(attestation_template != NULL);

  uint8_t attestation_template_buffer[3072];
  uint16_t attestation_template_buffer_len =
    i2d_X509(attestation_template, NULL);
  assert(sizeof(attestation_template_buffer) >=
         attestation_template_buffer_len);

  unsigned char *certptr = attestation_template_buffer;

  i2d_X509(attestation_template, &certptr);

  memset(capabilities.capabilities, 0, YH_CAPABILITIES_LEN);
  yrc =
    yh_util_import_opaque(session, &attesting_key_id, key_label, domain_five,
                          &capabilities, YH_ALGO_OPAQUE_X509_CERTIFICATE,
                          attestation_template_buffer,
                          attestation_template_buffer_len);
  assert(yrc == YHR_SUCCESS);

  uint8_t tmpbuf[3072];
  size_t tmpbuf_len = sizeof(tmpbuf);
  yrc = yh_util_get_opaque(session, attesting_key_id, tmpbuf, &tmpbuf_len);
  assert(yrc == YHR_SUCCESS);
  assert(tmpbuf_len == attestation_template_buffer_len);
  assert(memcmp(attestation_template_buffer, tmpbuf, tmpbuf_len) == 0);

  memset(capabilities.capabilities, 0, YH_CAPABILITIES_LEN);
  yrc = yh_string_to_capabilities("sign-ecdsa", &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t attested_key_id = 0; // ID 0 lets the device generate an ID
  yrc = yh_util_generate_ec_key(session, &attested_key_id, key_label,
                                domain_five, &capabilities, YH_ALGO_EC_P256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated attested key with ID %04x\n", attested_key_id);

  uint8_t attestation[2048];
  size_t attestation_len = sizeof(attestation);

  yrc = yh_util_sign_attestation_certificate(session, attested_key_id,
                                             attesting_key_id, attestation,
                                             &attestation_len);
  assert(yrc == YHR_SUCCESS);

  X509 *x509 = X509_new();
  const unsigned char *ptr = attestation;
  assert(x509 != NULL);

  x509 = d2i_X509(NULL, &ptr, attestation_len);
  assert(x509 != NULL);

  BIO *STDout = BIO_new_fp(stdout, BIO_NOCLOSE);

  X509_print_ex(STDout, x509, 0, 0);

  BIO_free(STDout);

  const STACK_OF(X509_EXTENSION) *extensions_list = X509_get0_extensions(x509);
  assert(sk_X509_EXTENSION_num(extensions_list) >= 6);

  for (int i = 0; i < sk_X509_EXTENSION_num(extensions_list); i++) {
    X509_EXTENSION *extension;

    extension = sk_X509_EXTENSION_value(extensions_list, i);

    print_extension(extension);
  }

  X509_free(x509);

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
