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

#include <ctype.h>
#include <yubihsm.h>
#include <pkcs11y.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#ifdef __WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "util_pkcs11.h"
#include "debug_p11.h"
#include "../common/util.h"
#include "../common/openssl-compat.h"

#define ASN1_OID 0x06
static const uint8_t oid_secp224r1[] = {ASN1_OID, 0x05, 0x2b, 0x81,
                                        0x04,     0x00, 0x21};
static const uint8_t oid_secp256r1[] = {ASN1_OID, 0x08, 0x2a, 0x86, 0x48,
                                        0xce,     0x3d, 0x03, 0x01, 0x07};
static const uint8_t oid_secp384r1[] = {ASN1_OID, 0x05, 0x2b, 0x81,
                                        0x04,     0x00, 0x22};
static const uint8_t oid_secp521r1[] = {ASN1_OID, 0x05, 0x2b, 0x81,
                                        0x04,     0x00, 0x23};
static const uint8_t oid_secp256k1[] = {ASN1_OID, 0x05, 0x2b, 0x81,
                                        0x04,     0x00, 0x0a};
static const uint8_t oid_brainpool256r1[] = {ASN1_OID, 0x09, 0x2b, 0x24,
                                             0x03,     0x03, 0x02, 0x08,
                                             0x01,     0x01, 0x07};
static const uint8_t oid_brainpool384r1[] = {ASN1_OID, 0x09, 0x2b, 0x24,
                                             0x03,     0x03, 0x02, 0x08,
                                             0x01,     0x01, 0x0b};
static const uint8_t oid_brainpool512r1[] = {ASN1_OID, 0x09, 0x2b, 0x24,
                                             0x03,     0x03, 0x02, 0x08,
                                             0x01,     0x01, 0x0d};

static void add_mech(CK_MECHANISM_TYPE *buf, CK_ULONG_PTR count,
                     CK_MECHANISM_TYPE item) {
  for (CK_ULONG i = 0; i < *count; i++) {
    if (buf[i] == item) {
      return;
    }
  }
  buf[*count] = item;
  *count = *count + 1;
}

CK_RV get_mechanism_list(yubihsm_pkcs11_slot *slot,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR count) {

  if (slot->n_algorithms == 0) {
    slot->n_algorithms = sizeof(slot->algorithms) / sizeof(slot->algorithms[0]);
    yh_rc yrc =
      yh_util_get_device_info(slot->connector, NULL, NULL, NULL, NULL, NULL,
                              NULL, slot->algorithms, &slot->n_algorithms);
    if (yrc != YHR_SUCCESS) {
      return CKR_FUNCTION_FAILED;
    }
  }

  CK_MECHANISM_TYPE buffer[128]; // NOTE: this is a bit hardcoded, but much more
  // than what we might add below.
  CK_ULONG items = 0;

  for (size_t i = 0; i < slot->n_algorithms; i++) {
    switch (slot->algorithms[i]) {
      case YH_ALGO_RSA_PKCS1_SHA1:
        add_mech(buffer, &items, CKM_RSA_PKCS);
        add_mech(buffer, &items, CKM_SHA1_RSA_PKCS);
        break;

      case YH_ALGO_RSA_PKCS1_SHA256:
        add_mech(buffer, &items, CKM_RSA_PKCS);
        add_mech(buffer, &items, CKM_SHA256_RSA_PKCS);
        break;

      case YH_ALGO_RSA_PKCS1_SHA384:
        add_mech(buffer, &items, CKM_RSA_PKCS);
        add_mech(buffer, &items, CKM_SHA384_RSA_PKCS);
        break;

      case YH_ALGO_RSA_PKCS1_SHA512:
        add_mech(buffer, &items, CKM_RSA_PKCS);
        add_mech(buffer, &items, CKM_SHA512_RSA_PKCS);
        break;

      case YH_ALGO_RSA_PSS_SHA1:
        add_mech(buffer, &items, CKM_RSA_PKCS_PSS);
        add_mech(buffer, &items, CKM_SHA1_RSA_PKCS_PSS);
        break;

      case YH_ALGO_RSA_PSS_SHA256:
        add_mech(buffer, &items, CKM_RSA_PKCS_PSS);
        add_mech(buffer, &items, CKM_SHA256_RSA_PKCS_PSS);
        break;

      case YH_ALGO_RSA_PSS_SHA384:
        add_mech(buffer, &items, CKM_RSA_PKCS_PSS);
        add_mech(buffer, &items, CKM_SHA384_RSA_PKCS_PSS);
        break;

      case YH_ALGO_RSA_PSS_SHA512:
        add_mech(buffer, &items, CKM_RSA_PKCS_PSS);
        add_mech(buffer, &items, CKM_SHA512_RSA_PKCS_PSS);
        break;

      case YH_ALGO_RSA_2048:
      case YH_ALGO_RSA_3072:
      case YH_ALGO_RSA_4096:
        add_mech(buffer, &items, CKM_RSA_PKCS_KEY_PAIR_GEN);
        break;

      case YH_ALGO_EC_P224:
      case YH_ALGO_EC_P256:
      case YH_ALGO_EC_P384:
      case YH_ALGO_EC_P521:
      case YH_ALGO_EC_K256:
      case YH_ALGO_EC_BP256:
      case YH_ALGO_EC_BP384:
      case YH_ALGO_EC_BP512:
        add_mech(buffer, &items, CKM_EC_KEY_PAIR_GEN);
        break;

      case YH_ALGO_HMAC_SHA1:
        add_mech(buffer, &items, CKM_SHA_1_HMAC);
        add_mech(buffer, &items, CKM_GENERIC_SECRET_KEY_GEN);
        break;

      case YH_ALGO_HMAC_SHA256:
        add_mech(buffer, &items, CKM_SHA256_HMAC);
        add_mech(buffer, &items, CKM_GENERIC_SECRET_KEY_GEN);
        break;

      case YH_ALGO_HMAC_SHA384:
        add_mech(buffer, &items, CKM_SHA384_HMAC);
        add_mech(buffer, &items, CKM_GENERIC_SECRET_KEY_GEN);
        break;

      case YH_ALGO_HMAC_SHA512:
        add_mech(buffer, &items, CKM_SHA512_HMAC);
        add_mech(buffer, &items, CKM_GENERIC_SECRET_KEY_GEN);
        break;

      case YH_ALGO_EC_ECDSA_SHA1:
        add_mech(buffer, &items, CKM_ECDSA);
        add_mech(buffer, &items, CKM_ECDSA_SHA1);
        break;

      case YH_ALGO_EC_ECDSA_SHA256:
        add_mech(buffer, &items, CKM_ECDSA);
        add_mech(buffer, &items, CKM_ECDSA_SHA256);
        break;

      case YH_ALGO_EC_ECDSA_SHA384:
        add_mech(buffer, &items, CKM_ECDSA);
        add_mech(buffer, &items, CKM_ECDSA_SHA384);
        break;

      case YH_ALGO_EC_ECDSA_SHA512:
        add_mech(buffer, &items, CKM_ECDSA);
        add_mech(buffer, &items, CKM_ECDSA_SHA512);
        break;

      case YH_ALGO_EC_ECDH:
        add_mech(buffer, &items, CKM_ECDH1_DERIVE);
        break;

      case YH_ALGO_RSA_OAEP_SHA1:
      case YH_ALGO_RSA_OAEP_SHA256:
      case YH_ALGO_RSA_OAEP_SHA384:
      case YH_ALGO_RSA_OAEP_SHA512:
        add_mech(buffer, &items, CKM_RSA_PKCS_OAEP);
        break;

      case YH_ALGO_AES128_CCM_WRAP:
      case YH_ALGO_AES192_CCM_WRAP:
      case YH_ALGO_AES256_CCM_WRAP:
        add_mech(buffer, &items, CKM_YUBICO_AES_CCM_WRAP);
        add_mech(buffer, &items, CKM_GENERIC_SECRET_KEY_GEN);
        break;

        // NOTE: there are algorithms don't have corresponding mechanisms
      default:
        break;
    }
  }

  // NOTE(adma): manually add digest mechanisms
  add_mech(buffer, &items, CKM_SHA_1);
  add_mech(buffer, &items, CKM_SHA256);
  add_mech(buffer, &items, CKM_SHA384);
  add_mech(buffer, &items, CKM_SHA512);

  if (pMechanismList != NULL) {
    if (items > *count) {
      *count = items;

      return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pMechanismList, buffer, sizeof(CK_MECHANISM_TYPE) * items);
  }

  *count = items;

  return CKR_OK;
}

static void find_minmax_rsa_key_length_in_bits(yh_algorithm *algorithms,
                                               size_t n_algorithms,
                                               CK_ULONG *min, CK_ULONG *max) {

  *min = 0;
  *max = 0;

  for (size_t i = 0; i < n_algorithms; i++) {
    CK_ULONG size;

    switch (algorithms[i]) {
      case YH_ALGO_RSA_2048:
        size = 2048;
        break;
      case YH_ALGO_RSA_3072:
        size = 3072;
        break;
      case YH_ALGO_RSA_4096:
        size = 4096;
        break;
      default:
        size = 0;
    }
    if (size == 0) {
      continue;
    }
    if (*min == 0 || *min > size) {
      *min = size;
    }
    if (size > *max) {
      *max = size;
    }
  }
}

static void find_minmax_ec_key_length_in_bits(yh_algorithm *algorithms,
                                              size_t n_algorithms,
                                              CK_ULONG *min, CK_ULONG *max) {

  *min = 0;
  *max = 0;

  for (size_t i = 0; i < n_algorithms; i++) {
    CK_ULONG size;
    switch (algorithms[i]) {
      case YH_ALGO_EC_P224:
        size = 224;
        break;
      case YH_ALGO_EC_P256:
      case YH_ALGO_EC_K256:
      case YH_ALGO_EC_BP256:
        size = 256;
        break;
      case YH_ALGO_EC_P384:
      case YH_ALGO_EC_BP384:
        size = 384;
        break;
      case YH_ALGO_EC_BP512:
        size = 512;
        break;
      case YH_ALGO_EC_P521:
        size = 521;
        break;
      default:
        size = 0;
    }
    if (size == 0) {
      continue;
    }
    if (*min == 0 || *min > size) {
      *min = size;
    }
    if (size > *max) {
      *max = size;
    }
  }
}

bool get_mechanism_info(yubihsm_pkcs11_slot *slot, CK_MECHANISM_TYPE type,
                        CK_MECHANISM_INFO_PTR pInfo) {

  if (slot->n_algorithms == 0) {
    slot->n_algorithms = sizeof(slot->algorithms) / sizeof(slot->algorithms[0]);
    yh_rc yrc =
      yh_util_get_device_info(slot->connector, NULL, NULL, NULL, NULL, NULL,
                              NULL, slot->algorithms, &slot->n_algorithms);
    if (yrc != YHR_SUCCESS) {
      return false;
    }
  }

  pInfo->flags = 0;
  switch (type) {
    case CKM_RSA_PKCS:
      pInfo->flags = CKF_DECRYPT;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags |= CKF_HW | CKF_SIGN;
      break;

    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_SIGN;
      break;

    case CKM_RSA_PKCS_OAEP:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_DECRYPT;
      break;

    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
      break;

    case CKM_EC_KEY_PAIR_GEN:
      find_minmax_ec_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                        &pInfo->ulMinKeySize,
                                        &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P |
                     CKF_EC_ECPARAMETERS | CKF_EC_UNCOMPRESS;
      break;

    case CKM_SHA_1_HMAC:
      pInfo->ulMaxKeySize = 64 * 8;
      pInfo->ulMinKeySize = 1;
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
      break;

    case CKM_SHA256_HMAC:
      pInfo->ulMaxKeySize = 64 * 8;
      pInfo->ulMinKeySize = 1;
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
      break;

    case CKM_SHA384_HMAC:
      pInfo->ulMaxKeySize = 128 * 8;
      pInfo->ulMinKeySize = 1;
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
      break;

    case CKM_SHA512_HMAC:
      pInfo->ulMaxKeySize = 128 * 8;
      pInfo->ulMinKeySize = 1;
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
      break;

    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
      // should all ecdsa mechanisms have all keylengths? or should they be
      // bounded to length of hash?
      find_minmax_ec_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                        &pInfo->ulMinKeySize,
                                        &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_EC_F_P | CKF_EC_ECPARAMETERS |
                     CKF_EC_UNCOMPRESS;
      break;

    case CKM_ECDH1_DERIVE:
      find_minmax_ec_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                        &pInfo->ulMinKeySize,
                                        &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_ECPARAMETERS |
                     CKF_EC_UNCOMPRESS;
      break;

    case CKM_SHA_1:
      pInfo->ulMaxKeySize = 0; // NOTE(adma): ignored
      pInfo->ulMinKeySize = 0; // NOTE(adma): ignored
      pInfo->flags = CKF_DIGEST;
      break;

    case CKM_SHA256:
      pInfo->ulMaxKeySize = 0; // NOTE(adma): ignored
      pInfo->ulMinKeySize = 0; // NOTE(adma): ignored
      pInfo->flags = CKF_DIGEST;
      break;

    case CKM_SHA384:
      pInfo->ulMaxKeySize = 0; // NOTE(adma): ignored
      pInfo->ulMinKeySize = 0; // NOTE(adma): ignored
      pInfo->flags = CKF_DIGEST;
      break;

    case CKM_SHA512:
      pInfo->ulMaxKeySize = 0; // NOTE(adma): ignored
      pInfo->ulMinKeySize = 0; // NOTE(adma): ignored
      pInfo->flags = CKF_DIGEST;
      break;

    case CKM_YUBICO_AES_CCM_WRAP:
      pInfo->ulMaxKeySize = 256;
      pInfo->ulMinKeySize = 128;
      pInfo->flags = CKF_HW | CKF_WRAP | CKF_UNWRAP | CKF_ENCRYPT | CKF_DECRYPT;
      break;

    case CKM_GENERIC_SECRET_KEY_GEN:
      pInfo->ulMaxKeySize =
        128 * 8; // NOTE: 128*8 is max key size for sha512-hmac keys
      pInfo->ulMinKeySize = 1;
      pInfo->flags = CKF_HW | CKF_GENERATE;
      break;

    default:
      return false;
  }

  return true;
}

bool parse_hex(CK_UTF8CHAR_PTR hex, CK_ULONG hex_len, uint8_t *parsed) {

  int j = 0;

  for (CK_ULONG i = 0; i < hex_len; i += 2) {
    if (isxdigit(hex[i]) == 0 || isxdigit(hex[i + 1]) == 0) {
      return false;
    }

    if (isdigit(hex[i])) {
      parsed[j] = (hex[i] - '0') << 4;
    } else {
      parsed[j] = (tolower(hex[i]) - 'a' + 10) << 4;
    }

    if (isdigit(hex[i + 1])) {
      parsed[j] |= (hex[i + 1] - '0');
    } else {
      parsed[j] |= (tolower(hex[i + 1]) - 'a' + 10);
    }

    j++;
  }

  return true;
}

bool create_session(yubihsm_pkcs11_slot *slot, CK_FLAGS flags,
                    CK_SESSION_HANDLE_PTR phSession) {

  bool authed = false;
  yubihsm_pkcs11_session session;
  memset(&session, 0, sizeof(session));
  if (slot->pkcs11_sessions.head) {
    yubihsm_pkcs11_session *s =
      (yubihsm_pkcs11_session *) slot->pkcs11_sessions.head->data;
    if (s->session_state & SESSION_AUTHENTICATED) {
      authed = true;
    }
  }
  if (flags & CKF_RW_SESSION) {
    session.session_state =
      authed ? SESSION_AUTHENTICATED_RW : SESSION_RESERVED_RW;
  } else {
    session.session_state =
      authed ? SESSION_AUTHENTICATED_RO : SESSION_RESERVED_RO;
  }
  session.id = slot->max_session_id++;
  session.slot = slot;
  list_create(&session.ecdh_session_keys, sizeof(ecdh_session_key), NULL);
  *phSession = (slot->id << 16) + session.id;
  return list_append(&slot->pkcs11_sessions, (void *) &session);
}

static void get_label_attribute(yh_object_descriptor *object, CK_VOID_PTR value,
                                CK_ULONG_PTR length) {

  *length = strlen(object->label);
  memcpy(value, object->label, *length);
  // NOTE(adma): we have seen some weird behvior with different
  // PKCS#11 tools. We decided not to add '\0' for now. This *seems*
  // to be a good solution ...
}

static void get_id_attribute(yh_object_descriptor *object, CK_VOID_PTR value,
                             CK_ULONG_PTR length) {
  uint16_t *ptr = value;
  *ptr = ntohs(object->id);
  *length = sizeof(uint16_t);
}

static void get_capability_attribute(yh_object_descriptor *object,
                                     const char *capability, bool val,
                                     CK_VOID_PTR value, CK_ULONG_PTR length,
                                     yh_object_type *type) {

  if ((type == NULL &&
       yh_check_capability(&object->capabilities, capability) == val) ||
      (type != NULL && *type == object->type &&
       yh_check_capability(&object->capabilities, capability) == val)) {

    *((CK_BBOOL *) value) = CK_TRUE;
  } else {
    *((CK_BBOOL *) value) = CK_FALSE;
  }
  *length = sizeof(CK_BBOOL);
}

static CK_RV get_attribute_opaque(CK_ATTRIBUTE_TYPE type,
                                  yh_object_descriptor *object,
                                  CK_VOID_PTR value, CK_ULONG_PTR length,
                                  yh_session *session) {

  if (object->type != YH_OPAQUE) {
    return CKR_FUNCTION_FAILED;
  }

  switch (type) {
    case CKA_CLASS:
      if (object->algorithm == YH_ALGO_OPAQUE_X509_CERTIFICATE) {
        *((CK_OBJECT_CLASS *) value) = CKO_CERTIFICATE;
      } else {
        *((CK_OBJECT_CLASS *) value) = CKO_DATA;
      }
      *length = sizeof(CK_OBJECT_CLASS);
      break;

      // NOTE(adma): Storage Objects attributes

    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_DESTROYABLE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LABEL:
      get_label_attribute(object, value, length);
      break;

    case CKA_ID:
      get_id_attribute(object, value, length);
      break;

      // NOTE(adma): Data Objects attributes

    case CKA_APPLICATION: {
      char *str = "Opaque object";
      strcpy((char *) value, str);
      *length = strlen(str);
    } break;

    case CKA_OBJECT_ID:
      *((CK_BYTE_PTR *) value) = NULL;
      *length = 0;
      break;

    case CKA_VALUE:
      if (yh_util_get_opaque(session, object->id, value, (size_t *) length) !=
          YHR_SUCCESS) {
        *length = CK_UNAVAILABLE_INFORMATION;
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_CERTIFICATE_TYPE:
      if (object->algorithm == YH_ALGO_OPAQUE_X509_CERTIFICATE) {
        *((CK_CERTIFICATE_TYPE *) value) = CKC_X_509;
        *length = sizeof(CK_CERTIFICATE_TYPE);
      } else {
        *length = CK_UNAVAILABLE_INFORMATION;
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    default:
      *length = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV get_attribute_secret_key(CK_ATTRIBUTE_TYPE type,
                                      yh_object_descriptor *object,
                                      CK_VOID_PTR value, CK_ULONG_PTR length) {
  yh_object_type objtype;
  switch (type) {
    case CKA_CLASS:
      *((CK_OBJECT_CLASS *) value) = CKO_SECRET_KEY;
      *length = sizeof(CK_OBJECT_CLASS);
      break;

      // NOTE(adma): Storage Objects attributes

    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_DESTROYABLE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LABEL:
      get_label_attribute(object, value, length);
      break;

      // NOTE(adma): Key Objects attributes

    case CKA_KEY_TYPE:
      if (object->type == YH_WRAP_KEY) {
        switch (object->algorithm) {
          case YH_ALGO_AES128_CCM_WRAP:
            *((CK_KEY_TYPE *) value) = CKK_YUBICO_AES128_CCM_WRAP;
            break;

          case YH_ALGO_AES192_CCM_WRAP:
            *((CK_KEY_TYPE *) value) = CKK_YUBICO_AES192_CCM_WRAP;
            break;

          case YH_ALGO_AES256_CCM_WRAP:
            *((CK_KEY_TYPE *) value) = CKK_YUBICO_AES256_CCM_WRAP;
            break;

          default:
            return CKR_FUNCTION_FAILED;
        }
      } else if (object->type == YH_HMAC_KEY) {
        switch (object->algorithm) {
          case YH_ALGO_HMAC_SHA1:
            *((CK_KEY_TYPE *) value) = CKK_SHA_1_HMAC;
            break;

          case YH_ALGO_HMAC_SHA256:
            *((CK_KEY_TYPE *) value) = CKK_SHA256_HMAC;
            break;

          case YH_ALGO_HMAC_SHA384:
            *((CK_KEY_TYPE *) value) = CKK_SHA384_HMAC;
            break;

          case YH_ALGO_HMAC_SHA512:
            *((CK_KEY_TYPE *) value) = CKK_SHA512_HMAC;
            break;

          default:
            return CKR_FUNCTION_FAILED;
        }
      } else {
        return CKR_FUNCTION_FAILED;
      }
      *length = sizeof(CK_KEY_TYPE);
      break;

    case CKA_ID:
      get_id_attribute(object, value, length);
      break;

      // case CKA_START_DATE:
      // case CKA_END_DATE:

    case CKA_DERIVE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LOCAL:
      if (object->origin == YH_ORIGIN_GENERATED) {
        *((CK_BBOOL *) value) = CK_TRUE;
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
      }
      *length = sizeof(CK_BBOOL);
      break;

      // case CKA_KEY_GEN_MECHANISM:
      // case CKA_ALLOWED_MECHANISMS:

      // NOTE(adma): Secret Key Objects attributes

    case CKA_SENSITIVE:
    case CKA_ALWAYS_SENSITIVE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_SIGN:
      objtype = YH_HMAC_KEY;
      get_capability_attribute(object, "sign-hmac", true, value, length,
                               &objtype);
      break;

    case CKA_VERIFY:
      objtype = YH_HMAC_KEY;
      get_capability_attribute(object, "verify-hmac", true, value, length,
                               &objtype);
      break;

    case CKA_DECRYPT:
      objtype = YH_WRAP_KEY;
      get_capability_attribute(object, "unwrap-data", true, value, length,
                               &objtype);
      break;

    case CKA_ENCRYPT:
      objtype = YH_WRAP_KEY;
      get_capability_attribute(object, "wrap-data", true, value, length,
                               &objtype);
      break;

    case CKA_TRUSTED:
    case CKA_WRAP_WITH_TRUSTED:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_WRAP:
      objtype = YH_WRAP_KEY;
      get_capability_attribute(object, "export-wrapped", true, value, length,
                               &objtype);
      break;

    case CKA_UNWRAP:
      objtype = YH_WRAP_KEY;
      get_capability_attribute(object, "import-wrapped", true, value, length,
                               &objtype);
      break;

    case CKA_EXTRACTABLE:
      get_capability_attribute(object, "exportable-under-wrap", true, value,
                               length, NULL);
      break;

    case CKA_NEVER_EXTRACTABLE:
      get_capability_attribute(object, "exportable-under-wrap", false, value,
                               length, NULL);
      break;

    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
      *((CK_ATTRIBUTE_PTR *) value) = NULL;
      *length = 0;
      break;

    default:
      *length = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV get_attribute_private_key(CK_ATTRIBUTE_TYPE type,
                                       yh_object_descriptor *object,
                                       CK_VOID_PTR value, CK_ULONG_PTR length,
                                       yh_session *session) {
  switch (type) {
    case CKA_CLASS:
      *((CK_OBJECT_CLASS *) value) = CKO_PRIVATE_KEY;
      *length = sizeof(CK_OBJECT_CLASS);
      break;

      // NOTE(adma): Storage Objects attributes

    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_DESTROYABLE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LABEL:
      get_label_attribute(object, value, length);
      break;

      // NOTE(adma): Key Objects attributes

    case CKA_KEY_TYPE:
      if (object->type == YH_ASYMMETRIC_KEY) {
        if (yh_is_rsa(object->algorithm)) {
          *((CK_KEY_TYPE *) value) = CKK_RSA;
        } else {
          *((CK_KEY_TYPE *) value) = CKK_EC;
        }

        *length = sizeof(CK_KEY_TYPE);
      } else {
        return CKR_FUNCTION_FAILED;
      }
      break;

    case CKA_ID:
      get_id_attribute(object, value, length);
      break;

      // case CKA_START_DATE:
      // case CKA_END_DATE:

    case CKA_DERIVE:
      if (object->type == YH_ASYMMETRIC_KEY &&
          yh_is_rsa(object->algorithm) == false &&
          yh_check_capability(&object->capabilities, "derive-ecdh") == true) {

        *((CK_BBOOL *) value) = CK_TRUE;
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
      }
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LOCAL:
      if (object->origin == YH_ORIGIN_GENERATED) {
        *((CK_BBOOL *) value) = CK_TRUE;
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
      }
      *length = sizeof(CK_BBOOL);
      break;

      // case CKA_KEY_GEN_MECHANISM:
      // case CKA_ALLOWED_MECHANISMS:

      // NOTE(adma): Key Objects attributes

    case CKA_SUBJECT:
    case CKA_PUBLIC_KEY_INFO:
      *((CK_BYTE_PTR *) value) = NULL;
      *length = 0;
      break;

    case CKA_SENSITIVE:
    case CKA_ALWAYS_SENSITIVE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_DECRYPT:
      if (object->type == YH_ASYMMETRIC_KEY && yh_is_rsa(object->algorithm)) {
        get_capability_attribute(object, "decrypt-pkcs,decrypt-oaep", true,
                                 value, length, NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_SIGN:
      if (object->type == YH_ASYMMETRIC_KEY &&
          yh_is_rsa(object->algorithm) == true) {
        get_capability_attribute(object, "sign-pkcs,sign-pss", true, value,
                                 length, NULL);
      } else if (object->type == YH_ASYMMETRIC_KEY &&
                 yh_is_ec(object->algorithm) == true) {
        get_capability_attribute(object, "sign-ecdsa", true, value, length,
                                 NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_ALWAYS_AUTHENTICATE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_EXTRACTABLE:
      get_capability_attribute(object, "exportable-under-wrap", true, value,
                               length, NULL);
      break;

    case CKA_NEVER_EXTRACTABLE:
      get_capability_attribute(object, "exportable-under-wrap", false, value,
                               length, NULL);
      break;

    case CKA_UNWRAP_TEMPLATE:
      *((CK_ATTRIBUTE_PTR *) value) = NULL;
      *length = 0;
      break;

    case CKA_EC_PARAMS: {
      const uint8_t *oid;
      switch (object->algorithm) {
        case YH_ALGO_EC_P224:
          oid = oid_secp224r1;
          *length = sizeof(oid_secp224r1);
          break;
        case YH_ALGO_EC_P256:
          oid = oid_secp256r1;
          *length = sizeof(oid_secp256r1);
          break;
        case YH_ALGO_EC_P384:
          oid = oid_secp384r1;
          *length = sizeof(oid_secp384r1);
          break;
        case YH_ALGO_EC_P521:
          oid = oid_secp521r1;
          *length = sizeof(oid_secp521r1);
          break;
        case YH_ALGO_EC_K256:
          oid = oid_secp256k1;
          *length = sizeof(oid_secp256k1);
          break;
        case YH_ALGO_EC_BP256:
          oid = oid_brainpool256r1;
          *length = sizeof(oid_brainpool256r1);
          break;
        case YH_ALGO_EC_BP384:
          oid = oid_brainpool384r1;
          *length = sizeof(oid_brainpool384r1);
          break;
        case YH_ALGO_EC_BP512:
          oid = oid_brainpool512r1;
          *length = sizeof(oid_brainpool512r1);
          break;
        default:
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      memcpy(value, oid, *length);
    } break;

    case CKA_MODULUS: {
      switch (object->algorithm) {
        case YH_ALGO_RSA_2048:
        case YH_ALGO_RSA_3072:
        case YH_ALGO_RSA_4096: {
          uint8_t resp[2048];
          size_t resp_len = sizeof(resp);

          if (yh_util_get_public_key(session, object->id, resp, &resp_len,
                                     NULL) != YHR_SUCCESS) {
            *length = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_TYPE_INVALID;
          }

          *length = resp_len;
          memcpy(value, resp, *length);

        } break;

        default:
          *length = CK_UNAVAILABLE_INFORMATION;
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;
    }

    case CKA_PUBLIC_EXPONENT:
      switch (object->algorithm) {
        case YH_ALGO_RSA_2048:
        case YH_ALGO_RSA_3072:
        case YH_ALGO_RSA_4096: {
          uint8_t *p = (uint8_t *) value;
          p[0] = 0x01;
          p[1] = 0x00;
          p[2] = 0x01;
          *length = 3;
          break;
        }
        default:
          *length = CK_UNAVAILABLE_INFORMATION;
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_VALUE:            // CKK_EC has the private values in CKA_VALUE
    case CKA_PRIVATE_EXPONENT: // CKK_RSA has the private exponent in
      // CKA_PRIVATE_EXPONENT
      *length = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_SENSITIVE;

    default:
      *length = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static bool load_public_key(yh_session *session, uint16_t id, EVP_PKEY *key) {

  uint8_t data[1024];
  size_t data_len = sizeof(data) - 1;

  RSA *rsa = NULL;
  BIGNUM *e = NULL;
  BIGNUM *n = NULL;
  EC_KEY *ec_key = NULL;
  EC_GROUP *ec_group = NULL;
  EC_POINT *ec_point = NULL;
  yh_algorithm algo;

  yh_rc yrc = yh_util_get_public_key(session, id, data + 1, &data_len, &algo);
  if (yrc != YHR_SUCCESS) {
    return false;
  }

  if (yh_is_rsa(algo)) {
    rsa = RSA_new();
    e = BN_new();
    if (rsa == NULL || e == NULL) {
      goto l_p_k_failure;
    }

    if (BN_hex2bn(&e, "10001") == 0) {
      goto l_p_k_failure;
    }

    n = BN_bin2bn(data + 1, data_len, NULL);
    if (n == NULL) {
      goto l_p_k_failure;
    }

    if (RSA_set0_key(rsa, n, e, NULL) == 0) {
      goto l_p_k_failure;
    }

    if (EVP_PKEY_assign_RSA(key, rsa) == 0) {
      goto l_p_k_failure;
    }
  } else {
    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
      goto l_p_k_failure;
    }

    ec_group = EC_GROUP_new_by_curve_name(algo2nid(algo));
    if (ec_group == NULL) {
      goto l_p_k_failure;
    }

    // NOTE: this call is important since it makes it a named curve instead of
    // encoded parameters
    EC_GROUP_set_asn1_flag(ec_group, algo2nid(algo));

    if (EC_KEY_set_group(ec_key, ec_group) == 0) {
      goto l_p_k_failure;
    }

    ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
      goto l_p_k_failure;
    }

    data[0] = 0x04;
    data_len++;
    if (EC_POINT_oct2point(ec_group, ec_point, data, data_len, NULL) == 0) {
      goto l_p_k_failure;
    }

    if (EC_KEY_set_public_key(ec_key, ec_point) == 0) {
      goto l_p_k_failure;
    }

    if (EVP_PKEY_assign_EC_KEY(key, ec_key) == 0) {
      goto l_p_k_failure;
    }
  }

  return true;

l_p_k_failure:
  if (ec_point != NULL) {
    EC_POINT_free(ec_point);
  }

  if (ec_group != NULL) {
    EC_GROUP_free(ec_group);
  }

  if (ec_key != NULL) {
    EC_KEY_free(ec_key);
  }

  if (rsa != NULL) {
    RSA_free(rsa);
  }

  if (key != NULL) {
    EVP_PKEY_free(key);
  }

  return false;
}

static CK_RV get_attribute_public_key(CK_ATTRIBUTE_TYPE type,
                                      yh_object_descriptor *object,
                                      CK_VOID_PTR value, CK_ULONG_PTR length,
                                      yh_session *session) {
  switch (type) {
    case CKA_CLASS:
      *((CK_OBJECT_CLASS *) value) = CKO_PUBLIC_KEY;
      *length = sizeof(CK_OBJECT_CLASS);
      break;

      // NOTE(adma): Storage Objects attributes

    case CKA_TOKEN:
    case CKA_DESTROYABLE:
    case CKA_EXTRACTABLE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_DERIVE:
    case CKA_SENSITIVE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
    case CKA_WRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_NEVER_EXTRACTABLE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_ENCRYPT:
      if (object->type == (0x80 | YH_ASYMMETRIC_KEY) &&
          yh_is_rsa(object->algorithm)) {
        get_capability_attribute(object, "decrypt-pkcs,decrypt-oaep", true,
                                 value, length, NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_VERIFY:
      if (object->type == (0x80 | YH_ASYMMETRIC_KEY) &&
          yh_is_rsa(object->algorithm) == true) {
        get_capability_attribute(object, "sign-pkcs,sign-pss", true, value,
                                 length, NULL);
      } else if (object->type == (0x80 | YH_ASYMMETRIC_KEY) &&
                 yh_is_ec(object->algorithm) == true) {
        get_capability_attribute(object, "sign-ecdsa", true, value, length,
                                 NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_LABEL:
      get_label_attribute(object, value, length);
      break;

      // NOTE(adma): Key Objects attributes

    case CKA_KEY_TYPE:
      if (object->type == (0x80 | YH_ASYMMETRIC_KEY)) {
        switch (object->algorithm) {
          case YH_ALGO_RSA_2048:
          case YH_ALGO_RSA_3072:
          case YH_ALGO_RSA_4096:
            *((CK_KEY_TYPE *) value) = CKK_RSA;
            break;

          case YH_ALGO_EC_P224:
          case YH_ALGO_EC_K256:
          case YH_ALGO_EC_P256:
          case YH_ALGO_EC_P384:
          case YH_ALGO_EC_P521:
          case YH_ALGO_EC_BP256:
          case YH_ALGO_EC_BP384:
          case YH_ALGO_EC_BP512:
            *((CK_KEY_TYPE *) value) = CKK_EC;
            break;

          default:
            *((CK_KEY_TYPE *) value) = CKK_VENDOR_DEFINED; // TODO: argh
        }

        *length = sizeof(CK_KEY_TYPE);
      } else if (object->type == YH_HMAC_KEY) {
        switch (object->algorithm) {
          case YH_ALGO_HMAC_SHA1:
            *((CK_KEY_TYPE *) value) = CKK_SHA_1_HMAC;
            break;

          case YH_ALGO_HMAC_SHA256:
            *((CK_KEY_TYPE *) value) = CKK_SHA256_HMAC;
            break;

          case YH_ALGO_HMAC_SHA384:
            *((CK_KEY_TYPE *) value) = CKK_SHA384_HMAC;
            break;

          case YH_ALGO_HMAC_SHA512:
            *((CK_KEY_TYPE *) value) = CKK_SHA512_HMAC;
            break;

          default:
            *((CK_KEY_TYPE *) value) = CKK_VENDOR_DEFINED; // TODO: argh
        }
        *length = sizeof(CK_KEY_TYPE);
      } else {
        return CKR_FUNCTION_FAILED;
      }
      break;

    case CKA_ID:
      get_id_attribute(object, value, length);
      break;

      // case CKA_START_DATE:
      // case CKA_END_DATE:

    case CKA_LOCAL:
      if (object->origin == YH_ORIGIN_GENERATED) {
        *((CK_BBOOL *) value) = CK_TRUE;
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
      }
      *length = sizeof(CK_BBOOL);
      break;

      // case CKA_KEY_GEN_MECHANISM:
      // case CKA_ALLOWED_MECHANISMS:

      // NOTE(adma): Key Objects attributes

    case CKA_SUBJECT:
    case CKA_PUBLIC_KEY_INFO:
    case CKA_UNWRAP_TEMPLATE:
      *((CK_BYTE_PTR *) value) = NULL;
      *length = 0;
      break;

    case CKA_MODULUS_BITS:
      switch (object->algorithm) {
        case YH_ALGO_RSA_2048:
          *((CK_ULONG *) value) = 2048;
          break;

        case YH_ALGO_RSA_3072:
          *((CK_ULONG *) value) = 3072;
          break;

        case YH_ALGO_RSA_4096:
          *((CK_ULONG *) value) = 4096;
          break;

        default:
          *((CK_ULONG *) value) = 0;
      }
      *length = sizeof(CK_ULONG);
      break;

    case CKA_EC_PARAMS: {
      const uint8_t *oid;
      switch (object->algorithm) {
        case YH_ALGO_EC_P224:
          oid = oid_secp224r1;
          *length = sizeof(oid_secp224r1);
          break;
        case YH_ALGO_EC_P256:
          oid = oid_secp256r1;
          *length = sizeof(oid_secp256r1);
          break;
        case YH_ALGO_EC_P384:
          oid = oid_secp384r1;
          *length = sizeof(oid_secp384r1);
          break;
        case YH_ALGO_EC_P521:
          oid = oid_secp521r1;
          *length = sizeof(oid_secp521r1);
          break;
        case YH_ALGO_EC_K256:
          oid = oid_secp256k1;
          *length = sizeof(oid_secp256k1);
          break;
        case YH_ALGO_EC_BP256:
          oid = oid_brainpool256r1;
          *length = sizeof(oid_brainpool256r1);
          break;
        case YH_ALGO_EC_BP384:
          oid = oid_brainpool384r1;
          *length = sizeof(oid_brainpool384r1);
          break;
        case YH_ALGO_EC_BP512:
          oid = oid_brainpool512r1;
          *length = sizeof(oid_brainpool512r1);
          break;
        default:
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      memcpy(value, oid, *length);
      break;
    }

    case CKA_EC_POINT: {
      uint8_t resp[2048];
      size_t resplen = sizeof(resp);

      if (yh_util_get_public_key(session, object->id, resp, &resplen, NULL) ==
          YHR_SUCCESS) {
        uint8_t *p = value;
        *p++ = 0x04;
        if (resplen + 1 >= 0x80) {
          *p++ = 0x81;
        }
        *p++ = resplen + 1;
        *p++ = 0x04;
        memcpy(p, resp, resplen);
        p += resplen;
        *length = p - (uint8_t *) value;
      } else {
        *length = CK_UNAVAILABLE_INFORMATION;
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;
    }

    case CKA_MODULUS: {
      switch (object->algorithm) {
        case YH_ALGO_RSA_2048:
        case YH_ALGO_RSA_3072:
        case YH_ALGO_RSA_4096: {
          uint8_t resp[2048];
          size_t resp_len = sizeof(resp);

          if (yh_util_get_public_key(session, object->id, resp, &resp_len,
                                     NULL) != YHR_SUCCESS) {
            *length = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_TYPE_INVALID;
          }

          *length = resp_len;
          memcpy(value, resp, *length);

        } break;

        default:
          *length = CK_UNAVAILABLE_INFORMATION;
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;
    }

    case CKA_PUBLIC_EXPONENT:
      switch (object->algorithm) {
        case YH_ALGO_RSA_2048:
        case YH_ALGO_RSA_3072:
        case YH_ALGO_RSA_4096: {
          uint8_t *p = (uint8_t *) value;
          p[0] = 0x01;
          p[1] = 0x00;
          p[2] = 0x01;
          *length = 3;
          break;
        }
        default:
          *length = CK_UNAVAILABLE_INFORMATION;
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_VALUE: {
      EVP_PKEY *pkey = EVP_PKEY_new();
      if (pkey == NULL) {
        *length = CK_UNAVAILABLE_INFORMATION;
        return CKR_FUNCTION_FAILED;
      }

      if (load_public_key(session, object->id, pkey) == false) {
        EVP_PKEY_free(pkey);
        *length = CK_UNAVAILABLE_INFORMATION;
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }

      *length = i2d_PUBKEY(pkey, (unsigned char **) &value);
      EVP_PKEY_free(pkey);
    } break;

    default:
      *length = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

CK_RV get_attribute(CK_ATTRIBUTE_TYPE type, yh_object_descriptor *object,
                    CK_VOID_PTR value, CK_ULONG_PTR length,
                    yh_session *session) {

  CK_BYTE tmp[2048];
  CK_VOID_PTR ptr;
  if (value == NULL) {
    // NOTE(adma): we just need the length, use a scratchpad for the data
    ptr = tmp;
    *length = sizeof(tmp);
  } else {
    // NOTE(adma): otherwise actually save the data
    ptr = value;
  }

  switch (object->type) {
    case YH_OPAQUE:
      return get_attribute_opaque(type, object, ptr, length, session);

    case YH_WRAP_KEY:
    case YH_HMAC_KEY:
      return get_attribute_secret_key(type, object, ptr, length);

    case YH_ASYMMETRIC_KEY:
      return get_attribute_private_key(type, object, ptr, length, session);
    case 0x80 | YH_ASYMMETRIC_KEY:
      return get_attribute_public_key(type, object, ptr, length, session);

    case YH_TEMPLATE:
    case YH_AUTHENTICATION_KEY:
    case YH_OTP_AEAD_KEY:
      // TODO: do something good here.
      break;
  } // TODO(adma): try to check common attributes in some convenience function

  return CKR_OK;
}

CK_RV get_attribute_ecsession_key(CK_ATTRIBUTE_TYPE type, ecdh_session_key *key,
                                  CK_VOID_PTR value, CK_ULONG_PTR length) {

  CK_BYTE tmp[2048];
  CK_VOID_PTR ptr;
  if (value == NULL) {
    ptr = tmp;
    *length = sizeof(tmp);
  } else {
    ptr = value;
  }

  switch (type) {
    case CKA_CLASS:
      *((CK_OBJECT_CLASS *) ptr) = CKO_SECRET_KEY;
      *length = sizeof(CK_OBJECT_CLASS);
      break;

    case CKA_KEY_TYPE:
      *((CK_KEY_TYPE *) ptr) = CKK_GENERIC_SECRET;
      *length = sizeof(CK_KEY_TYPE);
      break;

    case CKA_ID: {
      CK_OBJECT_HANDLE *id = ptr;
      *id = key->id;
      *length = sizeof(CK_OBJECT_HANDLE);
      break;
    }

    case CKA_LABEL:
      *length = strlen(key->label);
      memcpy(ptr, key->label, *length);
      break;

    case CKA_LOCAL:
    case CKA_TOKEN:
      *((CK_BBOOL *) ptr) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_DESTROYABLE:
    case CKA_EXTRACTABLE:
      *((CK_BBOOL *) ptr) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_DERIVE:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_SENSITIVE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_UNWRAP:
    case CKA_WRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_VERIFY:
    case CKA_ENCRYPT:
      *((CK_BBOOL *) ptr) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_VALUE:
      memcpy(ptr, key->ecdh_key, key->len);
      *length = key->len;
      break;

    default:
      *length = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

void delete_object_from_cache(yubihsm_pkcs11_object_desc *objects,
                              CK_OBJECT_HANDLE objHandle) {
  uint16_t id = objHandle & 0xffff;
  uint8_t type = objHandle >> 16;
  uint8_t sequence = objHandle >> 24;

  for (uint16_t i = 0; i < YH_MAX_ITEMS_COUNT; i++) {
    if (objects[i].object.id == id &&
        (objects[i].object.type & 0x7f) == (type & 0x7f) &&
        objects[i].object.sequence == sequence) {
      memset(&objects[i], 0, sizeof(yubihsm_pkcs11_object_desc));
      return;
    }
  }
}

yubihsm_pkcs11_object_desc *get_object_desc(yh_session *session,
                                            yubihsm_pkcs11_object_desc *objects,
                                            CK_OBJECT_HANDLE objHandle) {

  yubihsm_pkcs11_object_desc *object = NULL;
  uint16_t id = objHandle & 0xffff;
  uint8_t type = objHandle >> 16;
  uint8_t sequence = objHandle >> 24;

  for (uint16_t i = 0; i < YH_MAX_ITEMS_COUNT; i++) {
    if (objects[i].object.id == id &&
        (objects[i].object.type & 0x7f) == (type & 0x7f) &&
        objects[i].object.sequence == sequence) {
      object = &objects[i];
      break;
    }
  }

  if (!object) {
    uint16_t low;
    struct timeval *low_time = NULL;

    for (uint16_t i = 0; i < YH_MAX_ITEMS_COUNT; i++) {
      if (objects[i].tv.tv_sec == 0) {
        low = i;
        low_time = &objects[i].tv;
        break;
      } else {
        if (!low_time || objects[i].tv.tv_sec < low_time->tv_sec ||
            (objects[i].tv.tv_sec == low_time->tv_sec &&
             objects[i].tv.tv_usec < low_time->tv_usec)) {

          low_time = &objects[i].tv;
          low = i;
        }
      }
    }
    object = &objects[low];
    memset(object, 0, sizeof(yubihsm_pkcs11_object_desc));
  }

  if (!object->filled) {
    uint16_t real_type =
      type & ~0x80; // NOTE(adma): public key are not real objects
    yh_rc rc = yh_util_get_object_info(session, id, real_type, &object->object);
    if (rc != YHR_SUCCESS) {
      return NULL;
    }

    object->filled = true;
  }

  object->object.type = type;

  gettimeofday(&object->tv, NULL);

  return object;
}

bool check_sign_mechanism(yubihsm_pkcs11_slot *slot,
                          CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128];
  CK_ULONG count = 128;

  if (is_RSA_sign_mechanism(pMechanism->mechanism) == false &&
      is_ECDSA_sign_mechanism(pMechanism->mechanism) == false &&
      is_HMAC_sign_mechanism(pMechanism->mechanism) == false) {

    return false;
  }

  if (get_mechanism_list(slot, mechanisms, &count) != CKR_OK) {
    return false;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return true;
    }
  }

  return false;
}

bool check_verify_mechanism(yubihsm_pkcs11_slot *slot,
                            CK_MECHANISM_PTR pMechanism) {

  return check_sign_mechanism(slot, pMechanism);
}

bool check_decrypt_mechanism(yubihsm_pkcs11_slot *slot,
                             CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128];
  CK_ULONG count = 128;

  if (is_RSA_decrypt_mechanism(pMechanism->mechanism) == false &&
      pMechanism->mechanism != CKM_YUBICO_AES_CCM_WRAP) {
    return false;
  }

  if (get_mechanism_list(slot, mechanisms, &count) != CKR_OK) {
    return false;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return true;
    }
  }

  return false;
}

bool check_encrypt_mechanism(yubihsm_pkcs11_slot *slot,
                             CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128];
  CK_ULONG count = 128;

  if (pMechanism->mechanism != CKM_YUBICO_AES_CCM_WRAP) {
    return false;
  }

  if (get_mechanism_list(slot, mechanisms, &count) != CKR_OK) {
    return false;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return true;
    }
  }

  return false;
}

bool check_digest_mechanism(CK_MECHANISM_PTR pMechanism) {

  switch (pMechanism->mechanism) {
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      break;
    default:
      return false;
  }

  return true;
}

bool check_wrap_mechanism(yubihsm_pkcs11_slot *slot,
                          CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128];
  CK_ULONG count = 128;

  if (pMechanism->mechanism != CKM_YUBICO_AES_CCM_WRAP) {
    return false;
  }

  if (get_mechanism_list(slot, mechanisms, &count) != CKR_OK) {
    return false;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return true;
    }
  }

  return false;
}

CK_RV apply_sign_mechanism_init(yubihsm_pkcs11_op_info *op_info) {

  const EVP_MD *md = NULL;

  op_info->buffer_length = 0;

  switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_ECDSA:
    case CKM_SHA_1_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
      // NOTE(adma): no hash required for these mechanisms
      op_info->op.sign.md_ctx = NULL;
      return CKR_OK;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
      md = EVP_sha1();
      break;

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
      md = EVP_sha256();
      break;

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
      md = EVP_sha384();
      break;

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  op_info->op.sign.md_ctx = EVP_MD_CTX_create();

  if (EVP_DigestInit_ex(op_info->op.sign.md_ctx, md, NULL) == 0) {
    EVP_MD_CTX_destroy(op_info->op.sign.md_ctx);
    op_info->op.sign.md_ctx = NULL;
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_verify_mechanism_init(yubihsm_pkcs11_op_info *op_info) {

  const EVP_MD *md = NULL;

  op_info->buffer_length = 0;
  op_info->op.verify.padding = 0;
  op_info->op.verify.saltLen = 0;
  op_info->op.verify.mgf1md = NULL;
  op_info->op.verify.md = NULL;
  op_info->op.verify.md_ctx = NULL;

  switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_ECDSA:
    case CKM_SHA_1_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
      // NOTE(adma): no hash required for these mechanisms
      return CKR_OK;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
      md = EVP_sha1();
      break;

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
      md = EVP_sha256();
      break;

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
      md = EVP_sha384();
      break;

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  op_info->op.verify.md = md;
  op_info->op.verify.md_ctx = EVP_MD_CTX_create();
  if (op_info->op.verify.md_ctx == NULL) {
    return CKR_FUNCTION_FAILED;
  }
  if (EVP_DigestInit(op_info->op.verify.md_ctx, md) == 0) {
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_decrypt_mechanism_init(yubihsm_pkcs11_op_info *op_info) {

  op_info->buffer_length = 0;
  op_info->op.decrypt.finalized = false;

  switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_YUBICO_AES_CCM_WRAP:
      return CKR_OK;
    default:
      DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV apply_digest_mechanism_init(yubihsm_pkcs11_op_info *op_info) {

  const EVP_MD *md = NULL;

  op_info->buffer_length = 0;

  switch (op_info->mechanism.mechanism) {
    case CKM_SHA_1:
      md = EVP_sha1();
      break;

    case CKM_SHA256:
      md = EVP_sha256();
      break;

    case CKM_SHA384:
      md = EVP_sha384();
      break;

    case CKM_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  op_info->op.digest.md_ctx = EVP_MD_CTX_create();

  op_info->op.digest.is_multipart = false;

  if (EVP_DigestInit_ex(op_info->op.digest.md_ctx, md, NULL) == 0) {
    EVP_MD_CTX_destroy(op_info->op.digest.md_ctx);
    op_info->op.digest.md_ctx = NULL;
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_sign_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                  CK_BYTE_PTR in, CK_ULONG in_len) {

  switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
      // NOTE(adma): Specs say there should be enough space for PKCS#1 padding
      if (op_info->buffer_length + in_len >
          (op_info->op.sign.key_len + 7) / 8 - 11) {
        return CKR_DATA_LEN_RANGE;
      }

      memcpy(op_info->buffer + op_info->buffer_length, in, in_len);
      op_info->buffer_length += in_len;
      break;

    case CKM_ECDSA:
      if (op_info->buffer_length + in_len > 128) {
        // NOTE(adma): Specs say ECDSA only supports data up to 1024 bit
        return CKR_DATA_LEN_RANGE;
      }

      memcpy(op_info->buffer + op_info->buffer_length, in, in_len);
      op_info->buffer_length += in_len;
      break;

    case CKM_RSA_PKCS_PSS:
    case CKM_SHA_1_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
      if (op_info->buffer_length + in_len > sizeof(op_info->buffer)) {
        return CKR_DATA_LEN_RANGE;
      }

      memcpy(op_info->buffer + op_info->buffer_length, in, in_len);
      op_info->buffer_length += in_len;
      break;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
      if (EVP_DigestUpdate(op_info->op.sign.md_ctx, in, in_len) != 1) {
        EVP_MD_CTX_destroy(op_info->op.sign.md_ctx);
        op_info->op.sign.md_ctx = NULL;
        return CKR_FUNCTION_FAILED;
      }
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_verify_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                    CK_BYTE_PTR in, CK_ULONG in_len) {

  switch (op_info->mechanism.mechanism) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_ECDSA:
      // NOTE(adma): no hash required for these mechanisms
      if (op_info->buffer_length + in_len > sizeof(op_info->buffer)) {
        return CKR_DATA_LEN_RANGE;
      }

      memcpy(op_info->buffer + op_info->buffer_length, in, in_len);
      op_info->buffer_length += in_len;
      break;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
      if (EVP_DigestUpdate(op_info->op.verify.md_ctx, in, in_len) != 1) {
        EVP_MD_CTX_destroy(op_info->op.verify.md_ctx);
        op_info->op.sign.md_ctx = NULL;
        return CKR_FUNCTION_FAILED;
      }
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_decrypt_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                     CK_BYTE_PTR in, CK_ULONG in_len) {

  switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_YUBICO_AES_CCM_WRAP:
      if (op_info->buffer_length + in_len > sizeof(op_info->buffer)) {
        return CKR_DATA_LEN_RANGE;
      }

      memcpy(op_info->buffer + op_info->buffer_length, in, in_len);
      op_info->buffer_length += in_len;
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_encrypt_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                     CK_BYTE_PTR in, CK_ULONG in_len) {

  switch (op_info->mechanism.mechanism) {
    case CKM_YUBICO_AES_CCM_WRAP:
      if (op_info->buffer_length + in_len > sizeof(op_info->buffer)) {
        return CKR_DATA_LEN_RANGE;
      }

      memcpy(op_info->buffer + op_info->buffer_length, in, in_len);
      op_info->buffer_length += in_len;
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_digest_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                    CK_BYTE_PTR in, CK_ULONG in_len) {

  switch (op_info->mechanism.mechanism) {
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      if (EVP_DigestUpdate(op_info->op.digest.md_ctx, in, in_len) != 1) {
        EVP_MD_CTX_destroy(op_info->op.digest.md_ctx);
        op_info->op.digest.md_ctx = NULL;
        return CKR_FUNCTION_FAILED;
      }
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV apply_sign_mechanism_finalize(yubihsm_pkcs11_op_info *op_info) {

  if (is_hashed_mechanism(op_info->mechanism.mechanism)) {
    int ret;
    ret = EVP_DigestFinal_ex(op_info->op.sign.md_ctx, op_info->buffer,
                             &op_info->buffer_length);

    EVP_MD_CTX_destroy(op_info->op.sign.md_ctx);
    op_info->op.sign.md_ctx = NULL;

    if (ret != 1) {
      return CKR_FUNCTION_FAILED;
    }
  }

  if (is_ECDSA_sign_mechanism(op_info->mechanism.mechanism)) {
    if (op_info->buffer_length < op_info->op.sign.sig_len / 2) {
      uint16_t padding =
        (op_info->op.sign.sig_len / 2) - op_info->buffer_length;
      memmove(op_info->buffer + padding, op_info->buffer,
              op_info->buffer_length);
      memset(op_info->buffer, 0, padding);
      op_info->buffer_length += padding;
    } else if (op_info->buffer_length > op_info->op.sign.sig_len / 2) {
      op_info->buffer_length = op_info->op.sign.sig_len / 2;
    }
  }

  // TODO(adma): check if more steps are need for PSS or ECDSA

  return CKR_OK;
}

CK_RV apply_verify_mechanism_finalize(yubihsm_pkcs11_op_info *op_info
                                      __attribute((unused))) {

  return CKR_OK;
}

CK_RV apply_decrypt_mechanism_finalize(yubihsm_pkcs11_op_info *op_info
                                       __attribute((unused))) {

  op_info->op.decrypt.finalized = true;
  return CKR_OK;
}

CK_RV apply_digest_mechanism_finalize(yubihsm_pkcs11_op_info *op_info) {

  int ret;
  ret = EVP_DigestFinal_ex(op_info->op.digest.md_ctx, op_info->buffer,
                           &op_info->buffer_length);

  EVP_MD_CTX_destroy(op_info->op.digest.md_ctx);
  op_info->op.digest.md_ctx = NULL;

  if (ret != 1) {
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

static bool apply_DER_encoding_to_ECSIG(uint8_t *signature,
                                        uint16_t *signature_len) {
  ECDSA_SIG *sig = ECDSA_SIG_new();
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  bool ret = false;

  if (sig == NULL) {
    return false;
  }

  r = BN_bin2bn(signature, *signature_len / 2, NULL);
  s = BN_bin2bn(signature + *signature_len / 2, *signature_len / 2, NULL);
  if (r == NULL || s == NULL) {
    goto adete_out;
  }

  if (ECDSA_SIG_set0(sig, r, s) == 0) {
    goto adete_out;
  }

  r = s = NULL;

  unsigned char *pp = signature;
  *signature_len = i2d_ECDSA_SIG(sig, &pp);

  if (*signature_len == 0) {
    goto adete_out;
  } else {
    ret = true;
  }

adete_out:
  if (sig != NULL) {
    ECDSA_SIG_free(sig);
  }
  if (r != NULL) {
    BN_free(r);
  }
  if (s != NULL) {
    BN_free(s);
  }

  return ret;
}

CK_RV perform_verify(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                     uint8_t *signature, uint16_t signature_len) {

  if (is_HMAC_sign_mechanism(op_info->mechanism.mechanism)) {
    yh_rc yrc;
    bool verified = false;

    yrc = yh_util_verify_hmac(session, op_info->op.verify.key_id, signature,
                              signature_len, op_info->buffer,
                              op_info->buffer_length, &verified);

    if (yrc != YHR_SUCCESS) {
      return CKR_FUNCTION_FAILED;
    }

    if (verified == false) {
      return CKR_SIGNATURE_INVALID;
    }

    return CKR_OK;
  } else {
    CK_RV rv;
    EVP_PKEY *key = EVP_PKEY_new();
    uint8_t md_data[EVP_MAX_MD_SIZE];
    uint8_t *md = md_data;
    unsigned int md_len = sizeof(md_data);
    EVP_PKEY_CTX *ctx = NULL;

    if (key == NULL) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }

    if (load_public_key(session, op_info->op.verify.key_id, key) == false) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }

    int res;
    unsigned char data[2048];
    if (is_hashed_mechanism(op_info->mechanism.mechanism)) {
      if (EVP_DigestFinal_ex(op_info->op.verify.md_ctx, md, &md_len) <= 0) {
        rv = CKR_FUNCTION_FAILED;
        goto pv_failure;
      }
    } else if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
      const EVP_MD *md_type;
      int di_len;

      if (op_info->mechanism.mechanism == CKM_RSA_PKCS_PSS) {
        md = op_info->buffer;
        md_len = op_info->buffer_length;
      } else {
        parse_NID(op_info->buffer, op_info->buffer_length, &md_type, &di_len);
        if (md_type == EVP_md_null()) {
          rv = CKR_DATA_INVALID;
          goto pv_failure;
        }

        op_info->op.verify.md = md_type;
        md = op_info->buffer + di_len;
        md_len = op_info->buffer_length - di_len;
      }
    } else if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
      md = op_info->buffer;
      md_len = op_info->buffer_length;
      if (md_len == 20) {
        op_info->op.verify.md = EVP_sha1();
      } else if (md_len == 32) {
        op_info->op.verify.md = EVP_sha256();
      } else if (md_len == 48) {
        op_info->op.verify.md = EVP_sha384();
      } else if (md_len == 64) {
        op_info->op.verify.md = EVP_sha512();
      } else {
        rv = CKR_FUNCTION_FAILED;
        goto pv_failure;
      }
    } else {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, op_info->op.verify.md) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }
    if (op_info->op.verify.padding) {
      if (EVP_PKEY_CTX_set_rsa_padding(ctx, op_info->op.verify.padding) <= 0) {
        rv = CKR_FUNCTION_FAILED;
        goto pv_failure;
      }
      if (op_info->op.verify.padding == RSA_PKCS1_PSS_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, op_info->op.verify.saltLen) <=
            0) {
          rv = CKR_FUNCTION_FAILED;
          goto pv_failure;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, op_info->op.verify.mgf1md) <= 0) {
          rv = CKR_FUNCTION_FAILED;
          goto pv_failure;
        }
      }
    }
    if (is_ECDSA_sign_mechanism(op_info->mechanism.mechanism)) {
      memcpy(data, signature, signature_len);
      signature = data;
      if (apply_DER_encoding_to_ECSIG(signature, &signature_len) == false) {
        DBG_ERR("Failed to apply DER encoding to ECDSA signature");
        rv = CKR_FUNCTION_FAILED;
        goto pv_failure;
      }
    }
    res = EVP_PKEY_verify(ctx, signature, signature_len, md, md_len);

    if (res == 1) {
      rv = CKR_OK;
    } else if (res == 0) {
      rv = CKR_SIGNATURE_INVALID;
    } else {
      rv = CKR_FUNCTION_FAILED;
    }

  pv_failure:
    if (ctx != NULL) {
      EVP_PKEY_CTX_free(ctx);
      ctx = NULL;
    }

    if (key != NULL) {
      EVP_PKEY_free(key);
      key = NULL;
    }

    return rv;
  }

  return CKR_FUNCTION_FAILED;
}

static bool strip_DER_encoding_from_ECSIG(uint8_t *signature,
                                          size_t *signature_len,
                                          size_t sig_len) {

  ECDSA_SIG *sig;
  const unsigned char *pp = (const unsigned char *) signature;
  int r_len, s_len;
  const BIGNUM *r, *s;

  sig = ECDSA_SIG_new();
  if (sig == NULL) {
    return false;
  }

  if (d2i_ECDSA_SIG(&sig, &pp, *signature_len) == NULL) {
    ECDSA_SIG_free(sig);
    return false;
  }

  // since we're going to copy the data out again in signature we need to clear
  // it
  memset(signature, 0, *signature_len);

  ECDSA_SIG_get0(sig, &r, &s);

  r_len = BN_num_bytes(r);
  s_len = BN_num_bytes(s);
  BN_bn2bin(r, signature + sig_len / 2 - r_len);
  BN_bn2bin(s, signature + sig_len - s_len);

  *signature_len = sig_len;

  ECDSA_SIG_free(sig);
  return true;
}

CK_RV perform_signature(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                        uint8_t *signature, uint16_t *signature_len) {

  yh_rc yrc;
  size_t outlen = sizeof(op_info->buffer);

  if (is_RSA_sign_mechanism(op_info->mechanism.mechanism)) {
    if (is_PSS_sign_mechanism(op_info->mechanism.mechanism)) {
      yrc = yh_util_sign_pss(session, op_info->op.sign.key_id, op_info->buffer,
                             op_info->buffer_length, op_info->buffer, &outlen,
                             op_info->mechanism.pss.salt_len,
                             op_info->mechanism.pss.mgf1Algo);
    } else {
      yrc = yh_util_sign_pkcs1v1_5(session, op_info->op.sign.key_id,
                                   is_hashed_mechanism(
                                     op_info->mechanism.mechanism),
                                   op_info->buffer, op_info->buffer_length,
                                   op_info->buffer, &outlen);
    }
  } else if (is_ECDSA_sign_mechanism(op_info->mechanism.mechanism)) {
    yrc = yh_util_sign_ecdsa(session, op_info->op.sign.key_id, op_info->buffer,
                             op_info->buffer_length, op_info->buffer, &outlen);
  } else if (is_HMAC_sign_mechanism(op_info->mechanism.mechanism)) {
    yrc = yh_util_sign_hmac(session, op_info->op.sign.key_id, op_info->buffer,
                            op_info->buffer_length, op_info->buffer, &outlen);

  } else {
    DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
    return CKR_MECHANISM_INVALID;
  }

  if (yrc != YHR_SUCCESS) {
    return CKR_FUNCTION_FAILED;
  }

  if (is_ECDSA_sign_mechanism(op_info->mechanism.mechanism)) {
    // NOTE(adma): ECDSA, we must remove the DER encoding and only
    // return R,S as required by the specs
    if (strip_DER_encoding_from_ECSIG(op_info->buffer, &outlen,
                                      op_info->op.sign.sig_len) == false) {
      return CKR_FUNCTION_FAILED;
    }
  }

  if (outlen > *signature_len) {
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(signature, op_info->buffer, outlen);
  *signature_len = outlen;

  return CKR_OK;
}

CK_RV perform_decrypt(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                      uint8_t *data, uint16_t *data_len) {

  yh_rc yrc;
  size_t outlen = sizeof(op_info->buffer);

  if (op_info->mechanism.mechanism == CKM_RSA_PKCS) {
    yrc = yh_util_decrypt_pkcs1v1_5(session, op_info->op.decrypt.key_id,
                                    op_info->buffer, op_info->buffer_length,
                                    op_info->buffer, &outlen);
  } else if (op_info->mechanism.mechanism == CKM_RSA_PKCS_OAEP) {
    yrc =
      yh_util_decrypt_oaep(session, op_info->op.decrypt.key_id, op_info->buffer,
                           op_info->buffer_length, op_info->buffer, &outlen,
                           op_info->mechanism.oaep.label,
                           op_info->mechanism.oaep.label_len,
                           op_info->mechanism.oaep.mgf1Algo);
  } else if (op_info->mechanism.mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    yrc =
      yh_util_unwrap_data(session, op_info->op.decrypt.key_id, op_info->buffer,
                          op_info->buffer_length, op_info->buffer, &outlen);
  } else {
    DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
    return CKR_MECHANISM_INVALID;
  }

  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Decryption failed: %s", yh_strerror(yrc));
    return CKR_FUNCTION_FAILED;
  }

  if (outlen > *data_len) {
    DBG_ERR("Data won't fit in buffer %zu > %d", outlen, *data_len);
    *data_len = outlen;
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(data, op_info->buffer, outlen);
  *data_len = outlen;

  return CKR_OK;
}

CK_RV perform_encrypt(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                      uint8_t *data, uint16_t *data_len) {

  yh_rc yrc;
  size_t outlen = sizeof(op_info->buffer);

  if (op_info->mechanism.mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    yrc =
      yh_util_wrap_data(session, op_info->op.decrypt.key_id, op_info->buffer,
                        op_info->buffer_length, op_info->buffer, &outlen);
  } else {
    DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
    return CKR_MECHANISM_INVALID;
  }

  if (yrc != YHR_SUCCESS) {
    return CKR_FUNCTION_FAILED;
  }

  if (outlen > *data_len) {
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(data, op_info->buffer, outlen);
  *data_len = outlen;

  return CKR_OK;
}

CK_RV perform_digest(yubihsm_pkcs11_op_info *op_info, uint8_t *digest,
                     uint16_t *digest_len) {

  if (op_info->buffer_length > *digest_len) {
    return CKR_BUFFER_TOO_SMALL;
  }

  memcpy(digest, op_info->buffer, op_info->buffer_length);
  *digest_len = op_info->buffer_length;

  return CKR_OK;
}

bool sign_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  if (op_info->op.sign.md_ctx != NULL) {
    EVP_MD_CTX_destroy(op_info->op.sign.md_ctx);
    op_info->op.sign.md_ctx = NULL;
  }

  return true;
}

bool verify_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  if (op_info->op.verify.md_ctx != NULL) {
    EVP_MD_CTX_destroy(op_info->op.verify.md_ctx);
    op_info->op.verify.md_ctx = NULL;
  }

  return true;
}

bool decrypt_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  (void) op_info;

  return true;
}

bool digest_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  if (op_info->op.digest.md_ctx != NULL) {
    EVP_MD_CTX_destroy(op_info->op.digest.md_ctx);
    op_info->op.digest.md_ctx = NULL;
  }

  return true;
}

CK_ULONG get_digest_bytelength(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_SHA_1:
      return 20;

    case CKM_SHA256:
      return 32;

    case CKM_SHA384:
      return 48;

    case CKM_SHA512:
      return 64;

    default:
      break;
  }

  return 0;
}

bool is_RSA_sign_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
      return true;

    default:
      break;
  }

  return false;
}

bool is_RSA_decrypt_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
      return true;

    default:
      break;
  }

  return false;
}

bool is_hashed_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      return true;

    default:
      break;
  }

  return false;
}

bool is_PKCS1v1_5_sign_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      return true;

    default:
      break;
  }

  return false;
}

bool is_ECDSA_sign_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
      return true;

    default:
      break;
  }

  return false;
}

bool is_PSS_sign_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return true;

    default:
      break;
  }

  return false;
}

bool is_HMAC_sign_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
      return true;

    default:
      break;
  }

  return false;
}

static void free_pkcs11_slot(void *data) {
  yubihsm_pkcs11_slot *slot = (yubihsm_pkcs11_slot *) data;
  free(slot->connector_name);
  if (slot->device_session) {
    if (yh_destroy_session(&slot->device_session) != YHR_SUCCESS) {
      DBG_ERR("Failed destroying session");
    }
  }
  if (slot->connector) {
    yh_disconnect(slot->connector);
  }
  list_destroy(&slot->pkcs11_sessions);
}

static bool compare_slot(void *data, void *item) {
  uint16_t *a = data;
  uint16_t b = ((yubihsm_pkcs11_slot *) item)->id;
  return *a == b;
}

static bool compare_session(void *data, void *item) {
  uint16_t *a = data;
  uint16_t b = ((yubihsm_pkcs11_session *) item)->id;
  return *a == b;
}

yubihsm_pkcs11_slot *get_slot(yubihsm_pkcs11_context *ctx, CK_ULONG id) {

  ListItem *item = list_get(&ctx->slots, &id, compare_slot);
  if (item) {
    yubihsm_pkcs11_slot *slot = (yubihsm_pkcs11_slot *) item->data;
    if (slot->mutex != NULL) {
      if (ctx->lock_mutex(slot->mutex) != CKR_OK) {
        return NULL;
      }
    }
    return slot;
  }

  return NULL;
}

void release_slot(yubihsm_pkcs11_context *ctx, yubihsm_pkcs11_slot *slot) {

  if (slot->mutex != NULL) {
    ctx->unlock_mutex(slot->mutex);
  }
}

CK_RV get_session(yubihsm_pkcs11_context *ctx, CK_SESSION_HANDLE hSession,
                  yubihsm_pkcs11_session **session, int session_state) {
  uint16_t slot_id = hSession >> 16;
  uint16_t session_id = hSession & 0xffff;

  yubihsm_pkcs11_slot *slot = get_slot(ctx, slot_id);
  if (slot == NULL) {
    DBG_ERR("Slot %d doesn't exist", slot_id);
    return CKR_SESSION_HANDLE_INVALID;
  }

  ListItem *item =
    list_get(&slot->pkcs11_sessions, &session_id, compare_session);
  if (item == NULL) {
    release_slot(ctx, slot);
    DBG_ERR("Session %d doesn't exist", session_id);
    return CKR_SESSION_HANDLE_INVALID;
  }

  *session = (yubihsm_pkcs11_session *) item->data;
  int state = (int) (*session)->session_state;
  if (session_state == 0 || ((session_state & state) == state)) {
    // NOTE(thorduri): slot is locked.
    return CKR_OK;
  }

  CK_RV rv = CKR_SESSION_HANDLE_INVALID;
  if (session_state == SESSION_AUTHENTICATED) {
    rv = CKR_USER_NOT_LOGGED_IN;
    DBG_ERR("Session user not logged in");
  } else if (session_state == SESSION_AUTHENTICATED_RW) {
    rv = CKR_SESSION_READ_ONLY;
    DBG_ERR("Session read only");
  } else if (session_state == SESSION_NOT_AUTHENTICATED) {
    rv = CKR_USER_ALREADY_LOGGED_IN;
    DBG_ERR("Session user already logged in");
  }

  release_slot(ctx, slot);
  return rv;
}

bool delete_session(yubihsm_pkcs11_context *ctx,
                    CK_SESSION_HANDLE_PTR phSession) {
  uint16_t slot_id = *phSession >> 16;
  uint16_t session_id = *phSession & 0xffff;
  yubihsm_pkcs11_slot *slot = get_slot(ctx, slot_id);
  bool ret = false;

  if (slot) {
    ListItem *item =
      list_get(&slot->pkcs11_sessions, &session_id, compare_session);
    if (item) {
      list_delete(&slot->pkcs11_sessions, item);
      ret = true;
    }
    release_slot(ctx, slot);
  }
  return ret;
}

void release_session(yubihsm_pkcs11_context *ctx,
                     yubihsm_pkcs11_session *session) {

  release_slot(ctx, session->slot);
}

static CK_RV native_create_mutex(void **mutex) {

#ifdef __WIN32
  CRITICAL_SECTION *mtx = calloc(1, sizeof(CRITICAL_SECTION));
  if (mtx == NULL) {
    return CKR_GENERAL_ERROR;
  }
  InitializeCriticalSection(mtx);
#else
  pthread_mutex_t *mtx = calloc(1, sizeof(pthread_mutex_t));
  if (mtx == NULL) {
    return CKR_GENERAL_ERROR;
  }

  pthread_mutex_init(mtx, NULL);
#endif

  *mutex = mtx;
  return CKR_OK;
}

static CK_RV native_destroy_mutex(void *mutex) {

#ifdef __WIN32
  DeleteCriticalSection(mutex);
#else
  pthread_mutex_destroy(mutex);
#endif

  free(mutex);

  return CKR_OK;
}

static CK_RV native_lock_mutex(void *mutex) {

#ifdef __WIN32
  EnterCriticalSection(mutex);
#else
  if (pthread_mutex_lock(mutex) != 0) {
    return CKR_GENERAL_ERROR;
  }
#endif

  return CKR_OK;
}

static CK_RV native_unlock_mutex(void *mutex) {

#ifdef __WIN32
  LeaveCriticalSection(mutex);
#else
  if (pthread_mutex_unlock(mutex) != 0) {
    return CKR_GENERAL_ERROR;
  }
#endif

  return CKR_OK;
}

void set_native_locking(yubihsm_pkcs11_context *ctx) {

  ctx->create_mutex = native_create_mutex;
  ctx->destroy_mutex = native_destroy_mutex;
  ctx->lock_mutex = native_lock_mutex;
  ctx->unlock_mutex = native_unlock_mutex;
}

bool add_connectors(yubihsm_pkcs11_context *ctx, int n_connectors,
                    char **connector_names, yh_connector **connectors) {
  if (ctx->slots.head == NULL) {
    list_create(&ctx->slots, sizeof(yubihsm_pkcs11_slot), free_pkcs11_slot);
  }

  for (int i = 0; i < n_connectors; i++) {
    yubihsm_pkcs11_slot slot;
    memset(&slot, 0, sizeof(yubihsm_pkcs11_slot));
    slot.id = i;
    slot.connector_name = strdup(connector_names[i]);
    slot.max_session_id = 1;
    if (!slot.connector_name) {
      return false;
    }
    slot.connector = connectors[i];
    if (ctx->create_mutex != NULL) {
      if (ctx->create_mutex(&slot.mutex) != CKR_OK) {
        return false;
      }
    }
    list_create(&slot.pkcs11_sessions, sizeof(yubihsm_pkcs11_session), NULL);
    if (list_append(&ctx->slots, (void *) &slot) != true) {
      return false;
    }
  }
  return true;
}

CK_RV set_template_attribute(yubihsm_pkcs11_attribute *attribute, void *value) {
  if (*attribute == ATTRIBUTE_NOT_SET) {
    if ((*(CK_BBOOL *) value) == true) {
      *attribute = ATTRIBUTE_TRUE;
    } else {
      *attribute = ATTRIBUTE_FALSE;
    }
    return CKR_OK;
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

static CK_RV check_bool_attribute(void *value, bool check) {
  CK_BBOOL b_val = *(CK_BBOOL *) value;
  if (check == true && b_val == CK_TRUE) {
    return CKR_OK;
  } else if (check == false && b_val == CK_FALSE) {
    return CKR_OK;
  }
  return CKR_ATTRIBUTE_VALUE_INVALID;
}

CK_RV parse_rsa_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         yubihsm_pkcs11_object_template *template) {

  uint8_t *e = NULL;
  uint16_t primelen = 0;
  CK_RV rv;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_PRIME_1:
        if (template->obj.rsa.p == NULL) {
          template->obj.rsa.p = (CK_BYTE_PTR) pTemplate[i].pValue;
          if (pTemplate[i].ulValueLen % 2 != 0) {
            pTemplate[i].ulValueLen--;
            template->obj.rsa.p++;
          }
          if (primelen == 0 || primelen == pTemplate[i].ulValueLen) {
            primelen = pTemplate[i].ulValueLen;
          } else {
            return CKR_TEMPLATE_INCONSISTENT;
          }
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_PRIME_2:
        if (template->obj.rsa.q == NULL) {
          template->obj.rsa.q = (CK_BYTE_PTR) pTemplate[i].pValue;
          if (pTemplate[i].ulValueLen % 2 != 0) {
            pTemplate[i].ulValueLen--;
            template->obj.rsa.q++;
          }
          if (primelen == 0 || primelen == pTemplate[i].ulValueLen) {
            primelen = pTemplate[i].ulValueLen;
          } else {
            return CKR_TEMPLATE_INCONSISTENT;
          }
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_PUBLIC_EXPONENT:
        if (e == NULL) {
          e = (CK_BYTE_PTR) pTemplate[i].pValue;
          if (pTemplate[i].ulValueLen != 3 ||
              memcmp(e, "\x01\x00\x01", 3) != 0) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_DECRYPT:
        if ((rv = set_template_attribute(&template->decrypt,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_MODULUS:
      case CKA_PRIVATE_EXPONENT:
      case CKA_EXPONENT_1:
      case CKA_EXPONENT_2:
      case CKA_COEFFICIENT:
      case CKA_CLASS:
      case CKA_KEY_TYPE:
      case CKA_SUBJECT:
      case CKA_ID:
      case CKA_LABEL:
      case CKA_EXTRACTABLE:
        break;

      default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (e && template->obj.rsa.p && template->obj.rsa.q) {
    template->objlen = primelen;
    switch (primelen) {
      case 128:
        template->algorithm = YH_ALGO_RSA_2048;
        break;
      case 192:
        template->algorithm = YH_ALGO_RSA_3072;
        break;
      case 256:
        template->algorithm = YH_ALGO_RSA_4096;
        break;
      default:
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }

  return CKR_OK;
}

static CK_RV parse_ecparams(uint8_t *ecparams, uint16_t ecparams_len,
                            yh_algorithm *algorithm, uint16_t *key_len) {
  EC_GROUP *group = EC_GROUP_new(EC_GFp_simple_method());
  const uint8_t *param_ptr = ecparams;
  int curve = 0;
  if (group == NULL) {
    return CKR_FUNCTION_FAILED;
  }
  if (d2i_ECPKParameters(&group, &param_ptr, ecparams_len) != NULL) {
    curve = EC_GROUP_get_curve_name(group);
  }
  EC_GROUP_free(group);
  switch (curve) {
    case NID_secp224r1:
      *algorithm = YH_ALGO_EC_P224;
      *key_len = 28;
      break;
    case NID_X9_62_prime256v1:
      *algorithm = YH_ALGO_EC_P256;
      *key_len = 32;
      break;
    case NID_secp384r1:
      *algorithm = YH_ALGO_EC_P384;
      *key_len = 48;
      break;
    case NID_secp521r1:
      *algorithm = YH_ALGO_EC_P521;
      *key_len = 66;
      break;
    case NID_secp256k1:
      *algorithm = YH_ALGO_EC_K256;
      *key_len = 32;
      break;
#ifdef NID_brainpoolP256r1
    case NID_brainpoolP256r1:
      *algorithm = YH_ALGO_EC_BP256;
      *key_len = 32;
      break;
#endif
#ifdef NID_brainpoolP384r1
    case NID_brainpoolP384r1:
      *algorithm = YH_ALGO_EC_BP384;
      *key_len = 48;
      break;
#endif
#ifdef NID_brainpoolP512r1
    case NID_brainpoolP512r1:
      *algorithm = YH_ALGO_EC_BP512;
      *key_len = 64;
      break;
#endif
    default:
      return CKR_CURVE_NOT_SUPPORTED;
  }
  return CKR_OK;
}

CK_RV parse_ec_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        yubihsm_pkcs11_object_template *template) {

  uint8_t *ecparams = NULL;
  uint16_t ecparams_len;
  CK_RV rv;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_VALUE:
        if (template->obj.buf == NULL) {
          template->obj.buf = (CK_BYTE_PTR) pTemplate[i].pValue;
          template->objlen = pTemplate[i].ulValueLen;
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_EC_PARAMS:
        if (ecparams == NULL) {
          ecparams = (CK_BYTE_PTR) pTemplate[i].pValue;
          ecparams_len = pTemplate[i].ulValueLen;
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_DERIVE:
        if ((rv = set_template_attribute(&template->derive,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_CLASS:
      case CKA_KEY_TYPE:
      case CKA_SUBJECT:
      case CKA_ID:
      case CKA_LABEL:
      case CKA_EXTRACTABLE:
        break;

      default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (ecparams && template->obj.buf) {
    uint16_t key_len;
    CK_RV rv =
      parse_ecparams(ecparams, ecparams_len, &template->algorithm, &key_len);
    if (rv != CKR_OK) {
      return rv;
    }
    if (key_len != template->objlen) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }

  return CKR_OK;
}

CK_RV parse_hmac_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          yubihsm_pkcs11_object_template *template,
                          bool generate) {

  CK_RV rv;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_VALUE:
        if (generate == false && template->obj.buf == NULL) {
          // TODO: consider hanshing the key here if it's longer than blocklen
          template->obj.buf = (CK_BYTE_PTR) pTemplate[i].pValue;
          template->objlen = pTemplate[i].ulValueLen;
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_VERIFY:
        if ((rv = set_template_attribute(&template->verify,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_KEY_TYPE:
        switch (*((CK_ULONG_PTR) pTemplate[i].pValue)) {
          case CKK_SHA_1_HMAC:
            template->algorithm = YH_ALGO_HMAC_SHA1;
            break;
          case CKK_SHA256_HMAC:
            template->algorithm = YH_ALGO_HMAC_SHA256;
            break;
          case CKK_SHA384_HMAC:
            template->algorithm = YH_ALGO_HMAC_SHA384;
            break;
          case CKK_SHA512_HMAC:
            template->algorithm = YH_ALGO_HMAC_SHA512;
            break;
          default:
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_TOKEN:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_CLASS:
      case CKA_SUBJECT:
      case CKA_ID:
      case CKA_LABEL:
      case CKA_EXTRACTABLE:
        break;

      default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (template->algorithm && (generate == true || template->obj.buf)) {
    return CKR_OK;
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

CK_RV parse_rsa_generate_template(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                  CK_ULONG ulPublicKeyAttributeCount,
                                  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                  CK_ULONG ulPrivateKeyAttributeCount,
                                  yubihsm_pkcs11_object_template *template) {

  uint8_t *e = NULL;
  bool label_set = FALSE;
  CK_RV rv;

  memset(template->label, 0, sizeof(template->label));

  for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch (pPublicKeyTemplate[i].type) {
      case CKA_CLASS:
        if (*((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue) != CKO_PUBLIC_KEY) {
          DBG_ERR("CKA_CLASS inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_KEY_TYPE:
        if (*((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue) != CKK_RSA) {
          DBG_ERR("CKA_KEY_TYPE inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_ID:
        if (template->id == 0) {
          int id = parse_id_value(pPublicKeyTemplate[i].pValue,
                                  pPublicKeyTemplate[i].ulValueLen);
          if (id == -1) {
            DBG_ERR("CKA_ID invalid in PublicKeyTemplate");
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
          template->id = id;
        } else {
          DBG_ERR("CKA_ID inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_PUBLIC_EXPONENT:
        if (e == NULL) {
          e = (CK_BYTE_PTR) pPublicKeyTemplate[i].pValue;
          if (!((pPublicKeyTemplate[i].ulValueLen == 3 &&
                 memcmp(e, "\x01\x00\x01", 3) == 0) ||
                (pPublicKeyTemplate[i].ulValueLen == 4 &&
                 memcmp(e, "\x00\x01\x00\x01", 4) == 0))) {
            DBG_ERR("CKA_PUBLIC_EXPONENT invalid in PublicKeyTemplate");
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          DBG_ERR("CKA_PUBLIC_EXPONENT inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_MODULUS_BITS:
        switch (*((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue)) {
          case 2048:
            template->algorithm = YH_ALGO_RSA_2048;
            break;

          case 3072:
            template->algorithm = YH_ALGO_RSA_3072;
            break;

          case 4096:
            template->algorithm = YH_ALGO_RSA_4096;
            break;

          default:
            DBG_ERR("CKA_MODULUS_BITS wrong length in PublicKeyTemplate (%lu)",
                    *((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;

      case CKA_LABEL:
        if (pPublicKeyTemplate[i].ulValueLen > YH_OBJ_LABEL_LEN) {
          DBG_ERR("CKA_LABEL invalid in PublicKeyTemplate");
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        memcpy(template->label, pPublicKeyTemplate[i].pValue,
               pPublicKeyTemplate[i].ulValueLen);

        label_set = TRUE;

        break;

      case CKA_TOKEN:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_MODIFIABLE:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_UNWRAP:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_WRAP:
      case CKA_VERIFY:
      case CKA_ENCRYPT:
      case CKA_EXTRACTABLE:
      case CKA_PRIVATE:
      case CKA_COPYABLE:
      case CKA_DESTROYABLE:
        break;

      default:
        DBG_ERR("invalid attribute type in PublicKeyTemplate: 0x%lx",
                pPublicKeyTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
    switch (pPrivateKeyTemplate[i].type) {
      case CKA_CLASS:
        if (*((CK_ULONG_PTR) pPrivateKeyTemplate[i].pValue) !=
            CKO_PRIVATE_KEY) {
          DBG_ERR("CKA_CLASS inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_KEY_TYPE:
        if (*((CK_ULONG_PTR) pPrivateKeyTemplate[i].pValue) != CKK_RSA) {
          DBG_ERR("CKA_KEY_TYPE inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_ID: {
        int id = parse_id_value(pPrivateKeyTemplate[i].pValue,
                                pPrivateKeyTemplate[i].ulValueLen);
        if (id == -1) {
          DBG_ERR("CKA_ID invalid in PrivateKeyTemplate");
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (template->id != 0 && template->id != id) {
          DBG_ERR("CKA_ID inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        } else {
          template->id = id;
        }
      } break;

      case CKA_DECRYPT:
        if ((rv = set_template_attribute(&template->decrypt,
                                         pPrivateKeyTemplate[i].pValue)) !=
            CKR_OK) {
          DBG_ERR("CKA_DECRYPT inconsistent in PrivateKeyTemplate");
          return rv;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pPrivateKeyTemplate[i].pValue)) !=
            CKR_OK) {
          DBG_ERR("CKA_SIGN inconsistent in PrivateKeyTemplate");
          return rv;
        }
        break;

      case CKA_EXTRACTABLE:
        if ((rv = set_template_attribute(&template->exportable,
                                         pPrivateKeyTemplate[i].pValue)) !=
            CKR_OK) {
          DBG_ERR("CKA_EXTRACTABLE inconsistent in PrivateKeyTemplate");
          return rv;
        }
        break;

      case CKA_LABEL:
        if (pPrivateKeyTemplate[i].ulValueLen > YH_OBJ_LABEL_LEN) {
          DBG_ERR("CKA_LABEL invalid in PrivateKeyTemplate");
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (label_set == TRUE) {
          if (memcmp(template->label, pPrivateKeyTemplate[i].pValue,
                     pPrivateKeyTemplate[i].ulValueLen) != 0) {
            DBG_ERR("CKA_LABEL inconsistent in PrivateKeyTemplate");
            return CKR_TEMPLATE_INCONSISTENT;
          }
        } else {
          memcpy(template->label, pPrivateKeyTemplate[i].pValue,
                 pPrivateKeyTemplate[i].ulValueLen);
        }
        break;

      case CKA_TOKEN:
      case CKA_SENSITIVE:
      case CKA_PRIVATE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_WRAP:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_UNWRAP:
      case CKA_SUBJECT:
        break;

      default:
        DBG_ERR("invalid attribute type in PrivateKeyTemplate: 0x%lx",
                pPrivateKeyTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (template->algorithm == 0) {
    DBG_ERR("No RSA bitlength set");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  return CKR_OK;
}

int parse_id_value(void *value, CK_ULONG len) {
  switch (len) {
    case 0:
      return 0;
    case 1:
      return *(uint8_t *) value;
    case 2:
      return ntohs(*(uint16_t *) value);
    default:
      DBG_INFO("Supplied id is long, truncating it (was %lu bytes)", len);
      return ntohs(*(uint16_t *) value);
  }
}

CK_RV parse_ec_generate_template(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_ULONG ulPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_ULONG ulPrivateKeyAttributeCount,
                                 yubihsm_pkcs11_object_template *template) {

  uint8_t *ecparams = NULL;
  uint16_t ecparams_len = 0;
  bool label_set = FALSE;
  CK_RV rv;

  memset(template->label, 0, sizeof(template->label));

  for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch (pPublicKeyTemplate[i].type) {
      case CKA_CLASS:
        if (*((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue) != CKO_PUBLIC_KEY) {
          DBG_ERR("CKA_CLASS inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_KEY_TYPE:
        if (*((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue) != CKK_EC) {
          DBG_ERR("CKA_KEY_TYPE inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_ID:
        if (template->id == 0) {
          int id = parse_id_value(pPublicKeyTemplate[i].pValue,
                                  pPublicKeyTemplate[i].ulValueLen);
          if (id == -1) {
            DBG_ERR("CKA_ID invalid in PublicKeyTemplate");
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
          template->id = id;
        } else {
          DBG_ERR("CKA_ID inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_EC_PARAMS:
        if (ecparams == NULL) {
          ecparams = (CK_BYTE_PTR) pPublicKeyTemplate[i].pValue;
          ecparams_len = pPublicKeyTemplate[i].ulValueLen;
        } else {
          DBG_ERR("CKA_PUBLIC_EXPONENT inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_LABEL:
        if (pPublicKeyTemplate[i].ulValueLen > YH_OBJ_LABEL_LEN) {
          DBG_ERR("CKA_LABEL invalid in PublicKeyTemplate");
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        memcpy(template->label, pPublicKeyTemplate[i].pValue,
               pPublicKeyTemplate[i].ulValueLen);

        label_set = TRUE;

        break;

      case CKA_TOKEN:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_MODIFIABLE:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_WRAP:
      case CKA_UNWRAP:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_VERIFY:
      case CKA_ENCRYPT:
      case CKA_COPYABLE:
      case CKA_PRIVATE:
      case CKA_EXTRACTABLE:
      case CKA_DERIVE:
        break;

      default:
        DBG_ERR("invalid attribute type in PublicKeyTemplate: 0x%lx\n",
                pPublicKeyTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
    switch (pPrivateKeyTemplate[i].type) {
      case CKA_CLASS:
        if (*((CK_ULONG_PTR) pPrivateKeyTemplate[i].pValue) !=
            CKO_PRIVATE_KEY) {
          DBG_ERR("CKA_CLASS inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_KEY_TYPE:
        if (*((CK_ULONG_PTR) pPrivateKeyTemplate[i].pValue) != CKK_EC) {
          DBG_ERR("CKA_KEY_TYPE inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_ID: {
        int id = parse_id_value(pPrivateKeyTemplate[i].pValue,
                                pPrivateKeyTemplate[i].ulValueLen);
        if (id == -1) {
          DBG_ERR("CKA_ID invalid in PrivateKeyTemplate");
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (template->id != 0 && template->id != id) {
          DBG_ERR("CKA_ID inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        } else {
          template->id = id;
        }
      } break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pPrivateKeyTemplate[i].pValue)) !=
            CKR_OK) {
          DBG_ERR("CKA_SIGN inconsistent in PrivateKeyTemplate");
          return rv;
        }
        break;

      case CKA_EXTRACTABLE:
        if ((rv = set_template_attribute(&template->exportable,
                                         pPrivateKeyTemplate[i].pValue)) !=
            CKR_OK) {
          DBG_ERR("CKA_EXTRACTABLE inconsistent in PrivateKeyTemplate");
          return rv;
        }
        break;

      case CKA_DERIVE:
        if ((rv = set_template_attribute(&template->derive,
                                         pPrivateKeyTemplate[i].pValue)) !=
            CKR_OK) {
          DBG_ERR("CKA_DERIVE inconsistent in PrivateKeyTemplate");
          return rv;
        }
        break;

      case CKA_LABEL:
        if (pPrivateKeyTemplate[i].ulValueLen > YH_OBJ_LABEL_LEN) {
          DBG_ERR("CKA_LABEL invalid in PrivateKeyTemplate");
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (label_set == TRUE) {
          if (memcmp(template->label, pPrivateKeyTemplate[i].pValue,
                     pPrivateKeyTemplate[i].ulValueLen) != 0) {
            DBG_ERR("CKA_LABEL inconsistent in PrivateKeyTemplate");
            return CKR_TEMPLATE_INCONSISTENT;
          }
        } else {
          memcpy(template->label, pPrivateKeyTemplate[i].pValue,
                 pPrivateKeyTemplate[i].ulValueLen);
        }
        break;

      case CKA_TOKEN:
      case CKA_SENSITIVE:
      case CKA_PRIVATE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_UNWRAP:
      case CKA_WRAP:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SUBJECT:
      case CKA_DECRYPT:
        break;

      default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (ecparams == NULL) {
    DBG_ERR("CKA_ECPARAMS not set");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  uint16_t key_len;
  rv = parse_ecparams(ecparams, ecparams_len, &template->algorithm, &key_len);
  if (rv != CKR_OK) {
    DBG_ERR("Failed to parse CKA_ECPARAMS");
    return rv;
  }

  return CKR_OK;
}

CK_RV parse_wrap_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          yubihsm_pkcs11_object_template *template,
                          bool generate) {

  CK_RV rv;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_VALUE:
        if (generate == false && template->obj.buf == NULL) {
          template->obj.buf = (CK_BYTE_PTR) pTemplate[i].pValue;
          template->objlen = pTemplate[i].ulValueLen;
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_WRAP:
        if ((rv = set_template_attribute(&template->wrap,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_UNWRAP:
        if ((rv = set_template_attribute(&template->unwrap,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_ENCRYPT:
        if ((rv = set_template_attribute(&template->encrypt,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_DECRYPT:
        if ((rv = set_template_attribute(&template->decrypt,
                                         pTemplate[i].pValue)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_TOKEN:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_KEY_TYPE:
      case CKA_CLASS:
      case CKA_SUBJECT:
      case CKA_ID:
      case CKA_LABEL:
      case CKA_EXTRACTABLE:
        break;

      default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (generate == true || template->obj.buf) {
    return CKR_OK;
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

CK_RV populate_template(int type, void *object, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount, yh_session *session) {

  CK_RV rv = CKR_OK;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    DBG_INFO("Getting attribute 0x%lx", pTemplate[i].type);

    CK_VOID_PTR object_ptr;
    if (pTemplate[i].pValue == NULL) {
      // NOTE(adma): just asking for the length
      object_ptr = NULL;
      DBG_INFO("Retrieving length");
    } else {
      // NOTE(adma): actually get the attribute
      object_ptr = pTemplate[i].pValue;
      DBG_INFO("Retrieving attribute");
    }

    CK_RV attribute_rc;
    if (type == ECDH_KEY_TYPE) {
      ecdh_session_key *key = object;
      attribute_rc =
        get_attribute_ecsession_key(pTemplate[i].type, key, object_ptr,
                                    &pTemplate[i].ulValueLen);
    } else {
      yubihsm_pkcs11_object_desc *desc = object;
      attribute_rc = get_attribute(pTemplate[i].type, &desc->object, object_ptr,
                                   &pTemplate[i].ulValueLen, session);
    }

    if (attribute_rc != CKR_OK) {
      rv = attribute_rc;
      if (attribute_rc == CKR_ATTRIBUTE_TYPE_INVALID) {
        DBG_ERR("Unable to get attribute");
      } else if (attribute_rc == CKR_BUFFER_TOO_SMALL) {
        DBG_ERR("Skipping attribute because buffer is too small");
      } else {
        DBG_ERR("Get attribute failed. %s", yh_strerror(attribute_rc));
      }
    } else {
      DBG_INFO("Attribute/length successfully returned with length %lu",
               pTemplate[i].ulValueLen);
    }

    // NOTE(adma): Array of attributes like CKA_WRAP_TEMPLATE are special
    // cases.
    /* In the special case of an attribute whose value is an array of
     * attributes, for example CKA_WRAP_TEMPLATE, where it is passed in with
     * pValue not NULL, then if the pValue of elements within the array is
     * NULL_PTR then the ulValueLen of elements within the array will be set
     * to the required length. If the pValue of elements within the array is
     * not NULL_PTR, then the ulValueLen element of attributes within the
     * array MUST reflect the space that the corresponding pValue points to,
     * and pValue is filled in if there is sufficient room. Therefore it is
     * important to initialize the contents of a buffer before calling
     * C_GetAttributeValue to get such an array value. If any ulValueLen
     * within the array isn't large enough, it will be set to
     * CK_UNAVAILABLE_INFORMATION and the function will return
     * CKR_BUFFER_TOO_SMALL, as it does if an attribute in the pTemplate
     * argument has ulValueLen too small. Note that any attribute whose value
     * is an array of attributes is identifiable by virtue of the attribute
     * type having the CKF_ARRAY_ATTRIBUTE bit set.*/
  }

  return rv;
}

CK_RV validate_derive_key_attribute(CK_ATTRIBUTE_TYPE type, void *value) {
  switch (type) {
    case CKA_TOKEN:
      if (*((CK_BBOOL *) value) == CK_TRUE) {
        DBG_ERR("Derived key can only be a session object");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;

    case CKA_CLASS:
      if (*((CK_ULONG_PTR) value) != CKO_SECRET_KEY) {
        DBG_ERR("Derived key class is unsupported");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;

    case CKA_KEY_TYPE:
      if (*((CK_ULONG_PTR) value) != CKK_GENERIC_SECRET) {
        DBG_ERR("Derived key type is unsupported");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;

    case CKA_EXTRACTABLE:
      if (*((CK_BBOOL *) value) == CK_FALSE) {
        DBG_ERR("The derived key will be extractable");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;

    default:
      DBG_WARN("ECDH key derive template contains the ignored attribute: %lx",
               type);
      break;
  }

  return CKR_OK;
}
