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
#include "../common/platform-config.h"
#include "../common/util.h"
#include "../common/time_win.h"
#include "../common/hash.h"

#ifdef __WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#include <pthread.h>
#endif

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "util_pkcs11.h"
#include "debug_p11.h"
#include "../common/openssl-compat.h"
#include "../common/insecure_memzero.h"

#define UNUSED(x) (void) (x)
#define ASN1_OCTET_STRING 0x04
#define ASN1_OID 0x06
#define ASN1_PRINTABLE_STRING 0x13
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
static const uint8_t oid_ed25519[] = {ASN1_PRINTABLE_STRING,
                                      0x0c,
                                      0x65,
                                      0x64,
                                      0x77,
                                      0x61,
                                      0x72,
                                      0x64,
                                      0x73,
                                      0x32,
                                      0x35,
                                      0x35,
                                      0x31,
                                      0x39};

CK_RV yrc_to_rv(yh_rc rc) {
  switch (rc) {
    case YHR_SUCCESS:
      return CKR_OK;
    case YHR_MEMORY_ERROR:
      return CKR_HOST_MEMORY;
    case YHR_INIT_ERROR:
      return CKR_GENERAL_ERROR;
    case YHR_CONNECTION_ERROR:
      return CKR_DEVICE_REMOVED;
    case YHR_CONNECTOR_NOT_FOUND:
      return CKR_TOKEN_NOT_PRESENT;
    case YHR_INVALID_PARAMETERS:
      return CKR_ARGUMENTS_BAD;
    case YHR_WRONG_LENGTH:
      return CKR_DATA_LEN_RANGE;
    case YHR_BUFFER_TOO_SMALL:
      return CKR_BUFFER_TOO_SMALL;
    case YHR_CRYPTOGRAM_MISMATCH:
      return CKR_ENCRYPTED_DATA_INVALID;
    case YHR_SESSION_AUTHENTICATION_FAILED:
      return CKR_ENCRYPTED_DATA_INVALID;
    case YHR_MAC_MISMATCH:
      return CKR_ENCRYPTED_DATA_INVALID;
    case YHR_DEVICE_OK:
      return CKR_OK;
    case YHR_DEVICE_INVALID_COMMAND:
      return CKR_DEVICE_ERROR;
    case YHR_DEVICE_INVALID_DATA:
      return CKR_DEVICE_ERROR;
    case YHR_DEVICE_INVALID_SESSION:
      return CKR_SESSION_CLOSED;
    case YHR_DEVICE_AUTHENTICATION_FAILED:
      return CKR_DEVICE_ERROR;
    case YHR_DEVICE_SESSIONS_FULL:
      return CKR_SESSION_COUNT;
    case YHR_DEVICE_SESSION_FAILED:
      return CKR_DEVICE_ERROR;
    case YHR_DEVICE_STORAGE_FAILED:
      return CKR_DEVICE_MEMORY;
    case YHR_DEVICE_WRONG_LENGTH:
      return CKR_DATA_LEN_RANGE;
    case YHR_DEVICE_INSUFFICIENT_PERMISSIONS:
      return CKR_FUNCTION_REJECTED;
    case YHR_DEVICE_LOG_FULL:
      return CKR_DEVICE_MEMORY;
    case YHR_DEVICE_OBJECT_NOT_FOUND:
      return CKR_OBJECT_HANDLE_INVALID;
    case YHR_DEVICE_INVALID_ID:
      return CKR_OBJECT_HANDLE_INVALID;
    case YHR_DEVICE_INVALID_OTP:
      return CKR_DEVICE_ERROR;
    case YHR_DEVICE_DEMO_MODE:
      return CKR_FUNCTION_REJECTED;
    case YHR_DEVICE_COMMAND_UNEXECUTED:
      return CKR_DEVICE_ERROR;
    case YHR_GENERIC_ERROR:
      return CKR_FUNCTION_FAILED;
    case YHR_DEVICE_OBJECT_EXISTS:
      return CKR_ATTRIBUTE_VALUE_INVALID;
    case YHR_CONNECTOR_ERROR:
      return CKR_DEVICE_REMOVED;
    case YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION:
      return CKR_FUNCTION_REJECTED;
    case YHR_DEVICE_ALGORITHM_DISABLED:
      return CKR_FUNCTION_REJECTED;
    default:
      return CKR_GENERAL_ERROR;
  }
}

static CK_ULONG encode_length(CK_BYTE_PTR buffer, CK_ULONG length) {
  if (length < 0x80) {
    *buffer++ = length;
    return 1;
  } else if (length < 0x100) {
    *buffer++ = 0x81;
    *buffer++ = length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = length & 0xff;
    return 3;
  }
}

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

CK_RV set_operation_part(yubihsm_pkcs11_op_info *op_info,
                         yubihsm_pkcs11_part_type part) {
  if (part == PART_INIT || op_info->part == PART_INIT ||
      op_info->part == part) {
    op_info->part = part;
    return CKR_OK;
  }

  return CKR_OPERATION_ACTIVE;
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
      return yrc_to_rv(yrc);
    }
  }

  CK_MECHANISM_TYPE buffer[128] = {
    0}; // NOTE: this is a bit hardcoded, but much more
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

      case YH_ALGO_EC_ED25519:
        add_mech(buffer, &items, CKM_EDDSA);
        add_mech(buffer, &items, CKM_EC_EDWARDS_KEY_PAIR_GEN);
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

      case YH_ALGO_AES128:
      case YH_ALGO_AES192:
      case YH_ALGO_AES256:
        add_mech(buffer, &items, CKM_AES_KEY_GEN);
        break;

      case YH_ALGO_AES_ECB:
        add_mech(buffer, &items, CKM_AES_ECB);
        break;

      case YH_ALGO_AES_CBC:
        add_mech(buffer, &items, CKM_AES_CBC);
        add_mech(buffer, &items, CKM_AES_CBC_PAD);
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

static void find_minmax_aes_key_length_in_bytes(yh_algorithm *algorithms,
                                                size_t n_algorithms,
                                                CK_ULONG *min, CK_ULONG *max) {
  *min = 0;
  *max = 0;

  for (size_t i = 0; i < n_algorithms; i++) {
    CK_ULONG size;
    switch (algorithms[i]) {
      case YH_ALGO_AES128:
        size = 16;
        break;
      case YH_ALGO_AES192:
        size = 24;
        break;
      case YH_ALGO_AES256:
        size = 32;
        break;
      default:
        size = 0;
        break;
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

CK_RV get_mechanism_info(yubihsm_pkcs11_slot *slot, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo) {

  if (slot->n_algorithms == 0) {
    slot->n_algorithms = sizeof(slot->algorithms) / sizeof(slot->algorithms[0]);
    yh_rc yrc =
      yh_util_get_device_info(slot->connector, NULL, NULL, NULL, NULL, NULL,
                              NULL, slot->algorithms, &slot->n_algorithms);
    if (yrc != YHR_SUCCESS) {
      return yrc_to_rv(yrc);
    }
  }

  pInfo->flags = 0;
  switch (type) {
    case CKM_RSA_PKCS:
      pInfo->flags = CKF_DECRYPT | CKF_ENCRYPT;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags |= CKF_HW | CKF_SIGN | CKF_VERIFY;
      break;

    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
      break;

    case CKM_RSA_PKCS_OAEP:
      find_minmax_rsa_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                         &pInfo->ulMinKeySize,
                                         &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_DECRYPT | CKF_ENCRYPT;
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
                     CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
      break;

    case CKM_EC_EDWARDS_KEY_PAIR_GEN:
      pInfo->ulMaxKeySize = 255;
      pInfo->ulMinKeySize = 255;
      pInfo->flags = CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P |
                     CKF_EC_NAMEDCURVE | CKF_EC_COMPRESS;
      break;

    case CKM_EDDSA:
      pInfo->ulMaxKeySize = 255;
      pInfo->ulMinKeySize = 255;
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
                     CKF_EC_NAMEDCURVE | CKF_EC_COMPRESS;
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
      pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
                     CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
      break;

    case CKM_ECDH1_DERIVE:
      find_minmax_ec_key_length_in_bits(slot->algorithms, slot->n_algorithms,
                                        &pInfo->ulMinKeySize,
                                        &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE |
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

    case CKM_AES_KEY_GEN:
      find_minmax_aes_key_length_in_bytes(slot->algorithms, slot->n_algorithms,
                                          &pInfo->ulMinKeySize,
                                          &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_GENERATE;
      break;

    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      find_minmax_aes_key_length_in_bytes(slot->algorithms, slot->n_algorithms,
                                          &pInfo->ulMinKeySize,
                                          &pInfo->ulMaxKeySize);
      pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT;
      break;

    default:
      DBG_ERR("Invalid mechanism %lu", type);
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

#define PKCS11_ID_TAG 1
#define PKCS11_LABEL_TAG 2
#define PKCS11_PUBKEY_ID_TAG 3
#define PKCS11_PUBKEY_LABEL_TAG 4
const char META_OBJECT_VERSION[4] = "MDB1";

static uint16_t write_meta_item(uint8_t *target_value, uint8_t tag,
                                cka_meta_item *meta_item) {
  if (meta_item->len == 0) {
    return 0;
  }
  uint8_t *p = target_value;
  *p++ = tag;
  *(uint16_t *) p = htons(meta_item->len);
  p += 2;
  memcpy(p, &meta_item->value, meta_item->len);
  return meta_item->len + 3;
}

static uint16_t read_meta_item(uint8_t *value, cka_meta_item *meta_item) {
  uint8_t *p = value;
  meta_item->len = ntohs(*(uint16_t *) p);
  if (meta_item->len > CKA_ATTRIBUTE_VALUE_SIZE) {
    DBG_ERR("Parsed meta item length is too long");
    return 0;
  }
  p += 2;
  memcpy(&meta_item->value, p, meta_item->len);
  return meta_item->len + 2;
}

/*
 * Meta object value structure:
 * byte 0-3 : META_OBJECT_VERSION (always present)
 * byte 4: Original object type (always present)
 * byte 5 and 6: Original object ID (always present)
 * byte 7: original object sequence
 * byte 8 and onward: TLV tripplets
 */
static CK_RV read_meta_object(yubihsm_pkcs11_slot *slot, uint16_t opaque_id,
                              pkcs11_meta_object *meta_object) {

  uint8_t opaque_value[YH_MSG_BUF_SIZE] = {0};
  size_t opaque_value_len = sizeof(opaque_value);
  yh_rc yrc = yh_util_get_opaque(slot->device_session, opaque_id, opaque_value,
                                 &opaque_value_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to read meta object 0x%x from device", opaque_id);
    return yrc_to_rv(yrc);
  }

  // 4 (version) + 1 (object type) + 2 (id) + 1 (sequence)
  if (opaque_value_len < 8) {
    DBG_ERR("Opaque value to import is too small to be a meta obeject data");
    return CKR_DATA_INVALID;
  }

  uint8_t *p = opaque_value;
  if (memcmp(p, META_OBJECT_VERSION, sizeof(META_OBJECT_VERSION)) != 0) {
    DBG_ERR("Meta object value has unexpected version");
    return CKR_DATA_INVALID;
  }
  p += sizeof(META_OBJECT_VERSION);

  meta_object->target_type = *p++;

  meta_object->target_id = ntohs(*(uint16_t *) p);
  p += 2;

  meta_object->target_sequence = *p++;

  while (p < opaque_value + opaque_value_len) {
    uint16_t len = 0;
    switch (*p++) {
      case PKCS11_ID_TAG:
        len = read_meta_item(p, &meta_object->cka_id);
        break;
      case PKCS11_LABEL_TAG:
        len = read_meta_item(p, &meta_object->cka_label);
        break;
      case PKCS11_PUBKEY_ID_TAG:
        len = read_meta_item(p, &meta_object->cka_id_pubkey);
        break;
      case PKCS11_PUBKEY_LABEL_TAG:
        len = read_meta_item(p, &meta_object->cka_label_pubkey);
        break;
      default:
        DBG_ERR("Unknown tag in value of opaque PKCS11 object");
        return CKR_DATA_INVALID;
    }
    if (len == 0) {
      return CKR_DATA_INVALID;
    }
    p += len;
  }
  return CKR_OK;
}

yubihsm_pkcs11_object_desc *_get_object_desc(yubihsm_pkcs11_slot *slot,
                                             uint16_t id, uint8_t type,
                                             uint16_t sequence) {

  yubihsm_pkcs11_object_desc *object = NULL;
  for (uint16_t i = 0; i < YH_MAX_ITEMS_COUNT; i++) {
    if (slot->objects[i].object.id == id &&
        (slot->objects[i].object.type & 0x7f) == (type & 0x7f)) {
      object = &slot->objects[i];
      if (sequence != 0xffff &&
          object->object.sequence !=
            sequence) { // Force refresh if cache entry has wrong sequence
        memset(object, 0, sizeof(yubihsm_pkcs11_object_desc));
      }
      break;
    }
  }

  if (!object) {
    uint16_t low = 0;
    struct timeval *low_time = NULL;

    for (uint16_t i = 0; i < YH_MAX_ITEMS_COUNT; i++) {
      if (slot->objects[i].tv.tv_sec == 0) {
        low = i;
        low_time = &slot->objects[i].tv;
        break;
      } else {
        if (!low_time || slot->objects[i].tv.tv_sec < low_time->tv_sec ||
            (slot->objects[i].tv.tv_sec == low_time->tv_sec &&
             slot->objects[i].tv.tv_usec < low_time->tv_usec)) {

          low_time = &slot->objects[i].tv;
          low = i;
        }
      }
    }
    object = &slot->objects[low];
    memset(object, 0, sizeof(yubihsm_pkcs11_object_desc));
  }

  if (object->tv.tv_sec == 0) {
    yh_rc yrc = yh_util_get_object_info(slot->device_session, id, type & 0x7f,
                                        &object->object);
    if (yrc != YHR_SUCCESS) {
      return NULL;
    }

    if (is_meta_object(&object->object)) {
      // fill in the meta_object value
      CK_RV rv =
        read_meta_object(slot, object->object.id, &object->meta_object);
      if (rv != CKR_OK) {
        DBG_ERR("Failed to refresh meta object 0x%x", object->object.id);
        return NULL;
      }
    }
  }

  object->object.type = type;
  gettimeofday(&object->tv, NULL);

  if (sequence != 0xffff && object->object.sequence != sequence) {
    return NULL; // Only return for correct sequence
  }
  return object;
}

yubihsm_pkcs11_object_desc *get_object_desc(yubihsm_pkcs11_slot *slot,
                                            CK_OBJECT_HANDLE objHandle) {
  uint16_t id = objHandle & 0xffff;
  uint8_t type = (objHandle >> 16);
  uint8_t sequence = objHandle >> 24;
  return _get_object_desc(slot, id, type, sequence);
}

static bool check_domains(uint16_t subset_domains, uint16_t domains) {
  for (uint16_t i = 0; i < YH_MAX_DOMAINS; i++) {
    if ((subset_domains & (1 << i)) && !(domains & (1 << i))) {
      return false;
    }
  }
  return true;
}

CK_RV write_meta_object(yubihsm_pkcs11_slot *slot,
                        pkcs11_meta_object *meta_object,
                        yh_capabilities *target_capabilities,
                        uint16_t target_domains, bool replace) {

  if (!check_domains(target_domains, slot->authkey_domains)) {
    DBG_ERR(
      "Current user's domain access does not match target_object domains.");
    return CKR_FUNCTION_REJECTED;
  }

  size_t opaque_value_len =
    8 /* 4 version + 1 original type + 2 original ID 1 opaque sequence */ +
    (meta_object->cka_id.len == 0 ? 0 : 3 + meta_object->cka_id.len) +
    (meta_object->cka_label.len == 0 ? 0 : 3 + meta_object->cka_label.len) +
    (meta_object->cka_id_pubkey.len == 0 ? 0
                                         : 3 + meta_object->cka_id_pubkey.len) +
    (meta_object->cka_label_pubkey.len == 0
       ? 0
       : 3 + meta_object->cka_label_pubkey.len);
  // 3: 1 tag + 2 value length

  if (opaque_value_len > (YH_MSG_BUF_SIZE - 20)) {
    DBG_ERR("Failed to write meta object to device. Meta object too large.");
    return CKR_DATA_INVALID;
  }

  uint8_t opaque_value[YH_MSG_BUF_SIZE] = {0};
  uint8_t *p = opaque_value;

  memcpy(p, META_OBJECT_VERSION, sizeof(META_OBJECT_VERSION));
  p += sizeof(META_OBJECT_VERSION);

  *p++ = meta_object->target_type;

  *(uint16_t *) p = htons(meta_object->target_id);
  p += 2;

  *p++ = meta_object->target_sequence;

  p += write_meta_item(p, PKCS11_ID_TAG, &meta_object->cka_id);
  p += write_meta_item(p, PKCS11_LABEL_TAG, &meta_object->cka_label);
  p += write_meta_item(p, PKCS11_PUBKEY_ID_TAG, &meta_object->cka_id_pubkey);
  p +=
    write_meta_item(p, PKCS11_PUBKEY_LABEL_TAG, &meta_object->cka_label_pubkey);

  char opaque_label[YH_OBJ_LABEL_LEN] = {0};
  snprintf(opaque_label, sizeof(opaque_label), "Meta object for 0x%02x%02x%04x",
          meta_object->target_sequence, meta_object->target_type,
          meta_object->target_id);

  yh_rc rc = YHR_SUCCESS;
  uint16_t meta_object_id = 0;
  if (replace) {
    yubihsm_pkcs11_object_desc *meta_desc =
      find_meta_object_by_target(slot, meta_object->target_id,
                                 meta_object->target_type,
                                 meta_object->target_sequence, target_domains);
    if (meta_desc != NULL) {
      meta_object_id = meta_desc->object.id;
      rc =
        yh_util_delete_object(slot->device_session, meta_object_id, YH_OPAQUE);
      if (rc != YHR_SUCCESS) {
        DBG_INFO("Failed to delete opaque object 0x%x", meta_object_id);
      } else {
        DBG_INFO("Removed opaque object 0x%x with label %s", meta_object_id,
                 opaque_label);
      }
      memset(meta_desc, 0, sizeof(yubihsm_pkcs11_object_desc));
    }
  }
  yh_capabilities capabilities = {{0}};
  if (yh_check_capability(target_capabilities, "exportable-under-wrap")) {
    rc = yh_string_to_capabilities("exportable-under-wrap", &capabilities);
    if (rc != YHR_SUCCESS) {
      DBG_ERR("Failed to set meta object capabilities");
      return yrc_to_rv(rc);
    }
  }
  rc =
    yh_util_import_opaque(slot->device_session, &meta_object_id, opaque_label,
                          target_domains, &capabilities, YH_ALGO_OPAQUE_DATA,
                          opaque_value, opaque_value_len);

  if (rc != YHR_SUCCESS) {
    DBG_ERR("Failed to import opaque meta object for object 0x%x",
            meta_object->target_id);
    return yrc_to_rv(rc);
  }
  DBG_INFO("Successfully imported opaque object 0x%x with label: %s",
           meta_object_id, opaque_label);

  _get_object_desc(slot, meta_object_id, YH_OPAQUE, 0xffff);

  return CKR_OK;
}

bool is_meta_object(yh_object_descriptor *object) {
  return (object->type == YH_OPAQUE &&
          object->algorithm == YH_ALGO_OPAQUE_DATA &&
          strncmp(object->label, "Meta object", strlen("Meta object")) == 0);
}

bool match_byte_array(uint8_t *a, uint16_t a_len, uint8_t *b, uint16_t b_len) {
  return a_len == b_len && memcmp(a, b, a_len) == 0;
}

CK_RV populate_cache_with_data_opaques(yubihsm_pkcs11_slot *slot) {
  if (slot == NULL || slot->device_session == NULL) {
    DBG_INFO("No device session available");
    return CKR_OK;
  }

  if (slot->objects[0].object.id != 0) {
    DBG_INFO("Cache already populated");
    return CKR_OK;
  }

  yh_rc rc = YHR_SUCCESS;
  yh_object_descriptor opaques[YH_MAX_ITEMS_COUNT] = {0};
  size_t n_opaques = YH_MAX_ITEMS_COUNT;
  yh_capabilities capabilities = {{0}};

  rc =
    yh_util_list_objects(slot->device_session, 0, YH_OPAQUE, 0, &capabilities,
                         YH_ALGO_OPAQUE_DATA, NULL, opaques, &n_opaques);
  if (rc != YHR_SUCCESS) {
    DBG_ERR("Failed to get object list");
    return yrc_to_rv(rc);
  }
  for (size_t i = 0; i < n_opaques; i++) {
    _get_object_desc(slot, opaques[i].id, opaques[i].type, opaques[i].sequence);
  }
  return CKR_OK;
}

yubihsm_pkcs11_object_desc *
find_meta_object_by_target(yubihsm_pkcs11_slot *slot, uint16_t target_id,
                           uint8_t target_type, uint8_t target_sequence,
                           uint16_t target_domains) {
  for (int i = 0; i < YH_MAX_ITEMS_COUNT; i++) {
    pkcs11_meta_object *current_meta = &slot->objects[i].meta_object;
    if (target_domains == slot->objects[i].object.domains &&
        current_meta->target_id == target_id &&
        current_meta->target_type == target_type &&
        current_meta->target_sequence == target_sequence) {
      return &slot->objects[i];
    }
  }
  return NULL;
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
  return list_append(&slot->pkcs11_sessions, &session);
}

static void get_label_attribute(yh_object_descriptor *object, bool public,
                                pkcs11_meta_object *meta_object,
                                CK_VOID_PTR value, CK_ULONG_PTR length) {
  if (meta_object != NULL && !public && meta_object->cka_label.len > 0) {
    *length = meta_object->cka_label.len;
    memcpy(value, meta_object->cka_label.value, *length);
  } else if (meta_object != NULL && public &&
             meta_object->cka_label_pubkey.len > 0) {
    *length = meta_object->cka_label_pubkey.len;
    memcpy(value, meta_object->cka_label_pubkey.value, *length);
  } else {
    *length = strlen(object->label);
    memcpy(value, object->label, *length);
    // NOTE(adma): we have seen some weird behvior with different
    // PKCS#11 tools. We decided not to add '\0' for now. This *seems*
    // to be a good solution ...
  }
}

static void get_id_attribute(yh_object_descriptor *object, bool public,
                             pkcs11_meta_object *meta_object, CK_VOID_PTR value,
                             CK_ULONG_PTR length) {
  if (meta_object != NULL && !public && meta_object->cka_id.len > 0) {
    *length = meta_object->cka_id.len;
    memcpy(value, meta_object->cka_id.value, *length);
  } else if (meta_object != NULL && public &&
             meta_object->cka_id_pubkey.len > 0) {
    *length = meta_object->cka_id_pubkey.len;
    memcpy(value, meta_object->cka_id_pubkey.value, *length);
  } else {
    uint16_t *ptr = value;
    *ptr = ntohs(object->id);
    *length = sizeof(uint16_t);
  }
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

static CK_RV add_mech_type(CK_BYTE_PTR value, CK_ULONG max, CK_ULONG_PTR length,
                           CK_MECHANISM_TYPE mech) {
  for (CK_ULONG i = 0; i < *length; i += sizeof(CK_MECHANISM_TYPE)) {
    if (*(CK_MECHANISM_TYPE_PTR)(value + i) == mech)
      return CKR_OK;
  }
  if (*length + sizeof(CK_MECHANISM_TYPE) > max)
    return CKR_BUFFER_TOO_SMALL;
  *(CK_MECHANISM_TYPE_PTR)(value + *length) = mech;
  *length += sizeof(CK_MECHANISM_TYPE);
  return CKR_OK;
}

static int compare_mechs(const void *p1, const void *p2) {
  return *(const CK_MECHANISM_TYPE *) p1 - *(const CK_MECHANISM_TYPE *) p2;
}

static CK_RV get_allowed_mechs(yh_object_descriptor *object, CK_BYTE_PTR value,
                               CK_ULONG_PTR length) {
  CK_ULONG max = *length;
  *length = 0;
  CK_RV rv;
  if (yh_is_rsa(object->algorithm)) {
    if (yh_check_capability(&object->capabilities, "sign-pkcs")) {
      rv = add_mech_type(value, max, length, CKM_RSA_PKCS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA1_RSA_PKCS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA256_RSA_PKCS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA384_RSA_PKCS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA512_RSA_PKCS);
      if (rv != CKR_OK)
        return rv;
    }
    if (yh_check_capability(&object->capabilities, "sign-pss")) {
      rv = add_mech_type(value, max, length, CKM_RSA_PKCS_PSS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA1_RSA_PKCS_PSS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA256_RSA_PKCS_PSS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA384_RSA_PKCS_PSS);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_SHA512_RSA_PKCS_PSS);
      if (rv != CKR_OK)
        return rv;
    }
    if (yh_check_capability(&object->capabilities, "decrypt-pkcs")) {
      rv = add_mech_type(value, max, length, CKM_RSA_PKCS);
      if (rv != CKR_OK)
        return rv;
    }
    if (yh_check_capability(&object->capabilities, "decrypt-oaep")) {
      rv = add_mech_type(value, max, length, CKM_RSA_PKCS_OAEP);
      if (rv != CKR_OK)
        return rv;
    }
  } else if (yh_is_ec(object->algorithm)) {
    if (yh_check_capability(&object->capabilities, "sign-ecdsa")) {
      rv = add_mech_type(value, max, length, CKM_ECDSA);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_ECDSA_SHA1);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_ECDSA_SHA256);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_ECDSA_SHA384);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_ECDSA_SHA512);
      if (rv != CKR_OK)
        return rv;
    }
    if (yh_check_capability(&object->capabilities, "derive-ecdh")) {
      rv = add_mech_type(value, max, length, CKM_ECDH1_DERIVE);
      if (rv != CKR_OK)
        return rv;
    }
  } else if (yh_is_aes(object->algorithm)) {
    if (yh_check_capability(&object->capabilities, "aes-ecb")) {
      rv = add_mech_type(value, max, length, CKM_AES_ECB);
      if (rv != CKR_OK)
        return rv;
    }
    if (yh_check_capability(&object->capabilities, "aes-cbc")) {
      rv = add_mech_type(value, max, length, CKM_AES_CBC);
      if (rv != CKR_OK)
        return rv;
      rv = add_mech_type(value, max, length, CKM_AES_CBC_PAD);
      if (rv != CKR_OK)
        return rv;
    }
  } else {
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }
  qsort(value, *length / sizeof(CK_MECHANISM_TYPE), sizeof(CK_MECHANISM_TYPE),
        compare_mechs);
  return CKR_OK;
}

static CK_RV get_attribute_opaque(CK_ATTRIBUTE_TYPE type,
                                  yh_object_descriptor *object,
                                  pkcs11_meta_object *meta_object,
                                  CK_VOID_PTR value, CK_ULONG_PTR length,
                                  yubihsm_pkcs11_session *session) {

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
    case CKA_DESTROYABLE:
      *((CK_BBOOL *) value) = CK_TRUE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_PRIVATE:
    case CKA_SENSITIVE:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
    case CKA_TRUSTED:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LABEL:
      get_label_attribute(object, false, meta_object, value, length);
      break;

    case CKA_ID:
      get_id_attribute(object, false, meta_object, value, length);
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

    case CKA_VALUE: {
      size_t len = *length;
      yh_rc yrc = yh_util_get_opaque(session->slot->device_session, object->id,
                                     value, &len);
      if (yrc != YHR_SUCCESS) {
        return yrc_to_rv(yrc);
      }
      *length = len;
    } break;

    case CKA_CERTIFICATE_TYPE:
      if (object->algorithm == YH_ALGO_OPAQUE_X509_CERTIFICATE) {
        *((CK_CERTIFICATE_TYPE *) value) = CKC_X_509;
        *length = sizeof(CK_CERTIFICATE_TYPE);
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_SUBJECT:
    case CKA_ISSUER:
    case CKA_SERIAL_NUMBER:
      *((CK_BYTE_PTR *) value) = NULL;
      *length = 0;
      break;

    default:
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV get_attribute_secret_key(CK_ATTRIBUTE_TYPE type,
                                      yh_object_descriptor *object,
                                      pkcs11_meta_object *meta_object,
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
    case CKA_ALWAYS_AUTHENTICATE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LABEL:
      get_label_attribute(object, false, meta_object, value, length);
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
      } else if (object->type == YH_SYMMETRIC_KEY) {
        switch (object->algorithm) {
          case YH_ALGO_AES128:
          case YH_ALGO_AES192:
          case YH_ALGO_AES256:
            *((CK_KEY_TYPE *) value) = CKK_AES;
            break;
          default:
            return CKR_FUNCTION_FAILED;
        }
      } else {
        return CKR_FUNCTION_FAILED;
      }
      *length = sizeof(CK_KEY_TYPE);
      break;

    case CKA_VALUE_LEN:
      if (object->type == YH_WRAP_KEY || object->type == YH_SYMMETRIC_KEY) {
        size_t key_length = 0;
        yh_rc yrc = yh_get_key_bitlength(object->algorithm, &key_length);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }
        *(CK_ULONG_PTR) value = (key_length + 7) / 8;
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      *length = sizeof(CK_ULONG);
      break;

    case CKA_ID:
      get_id_attribute(object, false, meta_object, value, length);
      break;

      // case CKA_START_DATE:
      // case CKA_END_DATE:

    case CKA_DERIVE:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY_RECOVER:
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
    case CKA_ALLOWED_MECHANISMS:
      return get_allowed_mechs(object, value, length);

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
      if (object->type == YH_WRAP_KEY) {
        get_capability_attribute(object, "unwrap-data", true, value, length,
                                 NULL);
      } else if (object->type == YH_SYMMETRIC_KEY) {
        get_capability_attribute(object, "decrypt-cbc,decrypt-ecb", true, value,
                                 length, NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_ENCRYPT:
      if (object->type == YH_WRAP_KEY) {
        get_capability_attribute(object, "wrap-data", true, value, length,
                                 NULL);
      } else if (object->type == YH_SYMMETRIC_KEY) {
        get_capability_attribute(object, "encrypt-cbc,encrypt-ecb", true, value,
                                 length, NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
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
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV get_attribute_private_key(CK_ATTRIBUTE_TYPE type,
                                       yh_object_descriptor *object,
                                       pkcs11_meta_object *meta_object,
                                       CK_VOID_PTR value, CK_ULONG_PTR length,
                                       yubihsm_pkcs11_session *session) {
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

    case CKA_ENCRYPT:
    case CKA_MODIFIABLE:
    case CKA_COPYABLE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_LABEL:
      get_label_attribute(object, false, meta_object, value, length);
      break;

      // NOTE(adma): Key Objects attributes

    case CKA_KEY_TYPE:
      if (object->type == YH_ASYMMETRIC_KEY) {
        if (yh_is_rsa(object->algorithm)) {
          *((CK_KEY_TYPE *) value) = CKK_RSA;
        } else if (yh_is_ed(object->algorithm)) {
          *((CK_KEY_TYPE *) value) = CKK_EC_EDWARDS;
        } else {
          *((CK_KEY_TYPE *) value) = CKK_EC;
        }

        *length = sizeof(CK_KEY_TYPE);
      } else {
        return CKR_FUNCTION_FAILED;
      }
      break;

    case CKA_ID:
      get_id_attribute(object, false, meta_object, value, length);
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
    case CKA_ALLOWED_MECHANISMS:
      return get_allowed_mechs(object, value, length);

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
      } else if (object->type == YH_ASYMMETRIC_KEY &&
                 yh_is_ed(object->algorithm) == true) {
        get_capability_attribute(object, "sign-eddsa", true, value, length,
                                 NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_SIGN_RECOVER:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
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
        case YH_ALGO_EC_ED25519:
          oid = oid_ed25519;
          *length = sizeof(oid_ed25519);
          break;
        default:
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      memcpy(value, oid, *length);
    } break;

    case CKA_EC_POINT:
      if (yh_is_ec(object->algorithm)) {
        uint8_t resp[2048] = {0};
        size_t resplen = sizeof(resp);
        yh_rc yrc = yh_util_get_public_key(session->slot->device_session,
                                           object->id, resp, &resplen, NULL);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }

        uint8_t *p = value;
        *p++ = ASN1_OCTET_STRING;
        p += encode_length(p, resplen + 1);
        *p++ = 0x04; // UNCOMPRESSED POINT
        memcpy(p, resp, resplen);
        p += resplen;
        *length = p - (uint8_t *) value;
      } else if (yh_is_ed(object->algorithm)) {
        uint8_t resp[2048];
        size_t resplen = sizeof(resp);

        yh_rc yrc =
          yh_util_get_public_key(session->slot->device_session, object->id, resp, &resplen, NULL);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }

        uint8_t *p = value;
        *p++ = ASN1_OCTET_STRING;
        p += encode_length(p, resplen);
        memcpy(p, resp, resplen);
        p += resplen;
        *length = p - (uint8_t *) value;
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_MODULUS_BITS:
      if (yh_is_rsa(object->algorithm)) {
        size_t key_length = 0;
        yh_rc yrc = yh_get_key_bitlength(object->algorithm, &key_length);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }
        *(CK_ULONG *) value = key_length;
        *length = sizeof(CK_ULONG);
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_MODULUS:
      if (yh_is_rsa(object->algorithm)) {
        uint8_t resp[2048] = {0};
        size_t resp_len = sizeof(resp);

        yh_rc yrc = yh_util_get_public_key(session->slot->device_session,
                                           object->id, resp, &resp_len, NULL);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }

        *length = resp_len;
        memcpy(value, resp, *length);
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_PUBLIC_EXPONENT:
      if (yh_is_rsa(object->algorithm)) {
        uint8_t *p = (uint8_t *) value;
        p[0] = 0x01;
        p[1] = 0x00;
        p[2] = 0x01;
        *length = 3;
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_VALUE:            // CKK_EC has the private values in CKA_VALUE
    case CKA_PRIVATE_EXPONENT: // CKK_RSA has the private exponent in
      // CKA_PRIVATE_EXPONENT
      return CKR_ATTRIBUTE_SENSITIVE;

    default:
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV load_public_key(yh_session *session, uint16_t id, EVP_PKEY **key) {

  uint8_t data[1024] = {0};
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
    return yrc_to_rv(yrc);
  }

  if (yh_is_rsa(algo)) {
    rsa = RSA_new();
    e = BN_new();
    if (rsa == NULL || e == NULL) {
      goto l_p_k_failure;
    }

    BN_set_word(e, 0x010001);

    n = BN_bin2bn(data + 1, data_len, NULL);
    if (n == NULL) {
      goto l_p_k_failure;
    }

    if (RSA_set0_key(rsa, n, e, NULL) == 0) {
      goto l_p_k_failure;
    }

    n = NULL;
    e = NULL;

    *key = EVP_PKEY_new();
    if (*key == NULL) {
      goto l_p_k_failure;
    }

    if (EVP_PKEY_assign_RSA(*key, rsa) == 0) {
      goto l_p_k_failure;
    }
  } else if (yh_is_ec(algo)) {
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
    EC_GROUP_set_asn1_flag(ec_group, OPENSSL_EC_NAMED_CURVE);

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

    *key = EVP_PKEY_new();
    if (*key == NULL) {
      goto l_p_k_failure;
    }

    if (EVP_PKEY_assign_EC_KEY(*key, ec_key) == 0) {
      goto l_p_k_failure;
    }

    EC_POINT_free(ec_point);
    EC_GROUP_free(ec_group);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  } else if (yh_is_ed(algo)) {
    *key =
      EVP_PKEY_new_raw_public_key(algo2nid(algo), NULL, data + 1, data_len);
    if (*key == NULL) {
      goto l_p_k_failure;
    }
#endif
  } else {
    DBG_ERR("Unsupported key algorithm");
    goto l_p_k_failure;
  }

  return CKR_OK;

l_p_k_failure:
  EC_POINT_free(ec_point);
  EC_GROUP_free(ec_group);
  EC_KEY_free(ec_key);
  RSA_free(rsa);
  BN_free(n);
  BN_free(e);

  return CKR_FUNCTION_FAILED;
}

static CK_RV get_attribute_public_key(CK_ATTRIBUTE_TYPE type,
                                      yh_object_descriptor *object,
                                      pkcs11_meta_object *meta_object,
                                      CK_VOID_PTR value, CK_ULONG_PTR length,
                                      yubihsm_pkcs11_session *session) {
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
    case CKA_DECRYPT:
    case CKA_DERIVE:
    case CKA_SENSITIVE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY_RECOVER:
    case CKA_UNWRAP:
    case CKA_WRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_NEVER_EXTRACTABLE:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_ENCRYPT:
      if (object->type == YH_PUBLIC_KEY && yh_is_rsa(object->algorithm)) {
        get_capability_attribute(object, "decrypt-pkcs,decrypt-oaep", true,
                                 value, length, NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_VERIFY:
      if (object->type == YH_PUBLIC_KEY &&
          yh_is_rsa(object->algorithm) == true) {
        get_capability_attribute(object, "sign-pkcs,sign-pss", true, value,
                                 length, NULL);
      } else if (object->type == YH_PUBLIC_KEY &&
                 yh_is_ec(object->algorithm) == true) {
        get_capability_attribute(object, "sign-ecdsa", true, value, length,
                                 NULL);
      } else if (object->type == (0x80 | YH_ASYMMETRIC_KEY) &&
                 yh_is_ed(object->algorithm) == true) {
        get_capability_attribute(object, "sign-eddsa", true, value, length,
                                 NULL);
      } else {
        *((CK_BBOOL *) value) = CK_FALSE;
        *length = sizeof(CK_BBOOL);
      }
      break;

    case CKA_LABEL:
      get_label_attribute(object, true, meta_object, value, length);
      break;

      // NOTE(adma): Key Objects attributes

    case CKA_KEY_TYPE:
      if (object->type == YH_PUBLIC_KEY) {
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

          case YH_ALGO_EC_ED25519:
            *((CK_KEY_TYPE *) value) = CKK_EC_EDWARDS;
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
      get_id_attribute(object, true, meta_object, value, length);
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
    case CKA_ALLOWED_MECHANISMS:
      return get_allowed_mechs(object, value, length);

      // NOTE(adma): Key Objects attributes

    case CKA_SUBJECT:
    case CKA_PUBLIC_KEY_INFO:
    case CKA_UNWRAP_TEMPLATE:
      *((CK_BYTE_PTR *) value) = NULL;
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
        case YH_ALGO_EC_ED25519:
          oid = oid_ed25519;
          *length = sizeof(oid_ed25519);
          break;
        default:
          return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      memcpy(value, oid, *length);
      break;
    }

    case CKA_EC_POINT:
      if (yh_is_ec(object->algorithm)) {
        uint8_t resp[2048] = {0};
        size_t resplen = sizeof(resp);

        yh_rc yrc = yh_util_get_public_key(session->slot->device_session,
                                           object->id, resp, &resplen, NULL);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }

        uint8_t *p = value;
        *p++ = ASN1_OCTET_STRING;
        p += encode_length(p, resplen + 1);
        *p++ = 0x04; // UNCOMPRESSED POINT
        memcpy(p, resp, resplen);
        p += resplen;
        *length = p - (uint8_t *) value;
      } else if (yh_is_ed(object->algorithm)) {
        uint8_t resp[2048];
        size_t resplen = sizeof(resp);

        yh_rc yrc =
          yh_util_get_public_key(session->slot->device_session, object->id, resp, &resplen, NULL);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }

        uint8_t *p = value;
        *p++ = ASN1_OCTET_STRING;
        p += encode_length(p, resplen);
        memcpy(p, resp, resplen);
        p += resplen;
        *length = p - (uint8_t *) value;
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_MODULUS_BITS:
      if (yh_is_rsa(object->algorithm)) {
        size_t key_length = 0;
        yh_rc yrc = yh_get_key_bitlength(object->algorithm, &key_length);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }
        *(CK_ULONG *) value = key_length;
        *length = sizeof(CK_ULONG);
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_MODULUS:
      if (yh_is_rsa(object->algorithm)) {
        uint8_t resp[2048] = {0};
        size_t resp_len = sizeof(resp);

        yh_rc yrc = yh_util_get_public_key(session->slot->device_session,
                                           object->id, resp, &resp_len, NULL);
        if (yrc != YHR_SUCCESS) {
          return yrc_to_rv(yrc);
        }

        *length = resp_len;
        memcpy(value, resp, *length);
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_PUBLIC_EXPONENT:
      if (yh_is_rsa(object->algorithm)) {
        uint8_t *p = (uint8_t *) value;
        p[0] = 0x01;
        p[1] = 0x00;
        p[2] = 0x01;
        *length = 3;
      } else {
        return CKR_ATTRIBUTE_TYPE_INVALID;
      }
      break;

    case CKA_VALUE: {
      EVP_PKEY *pkey = NULL;

      CK_RV rv =
        load_public_key(session->slot->device_session, object->id, &pkey);
      if (rv != CKR_OK) {
        EVP_PKEY_free(pkey);
        return rv;
      }

      *length = i2d_PUBKEY(pkey, (unsigned char **) &value);
      EVP_PKEY_free(pkey);
    } break;

    default:
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV get_attribute(CK_ATTRIBUTE_TYPE type, yh_object_descriptor *object,
                           CK_BYTE_PTR value, CK_ULONG_PTR length,
                           yubihsm_pkcs11_session *session) {

  yubihsm_pkcs11_object_desc *meta_desc =
    find_meta_object_by_target(session->slot, object->id, (object->type & 0x7f),
                               object->sequence, object->domains);
  pkcs11_meta_object *meta_object = meta_desc ? &meta_desc->meta_object : NULL;

  switch (object->type) {
    case YH_OPAQUE:
      return get_attribute_opaque(type, object, meta_object, value, length,
                                  session);

    case YH_WRAP_KEY:
    case YH_HMAC_KEY:
    case YH_SYMMETRIC_KEY:
      return get_attribute_secret_key(type, object, meta_object, value, length);

    case YH_ASYMMETRIC_KEY:
      return get_attribute_private_key(type, object, meta_object, value, length,
                                       session);
    case YH_PUBLIC_KEY:
      return get_attribute_public_key(type, object, meta_object, value, length,
                                      session);

    case YH_TEMPLATE:
    case YH_AUTHENTICATION_KEY:
    case YH_OTP_AEAD_KEY:
      // TODO: do something good here.
      break;
  } // TODO(adma): try to check common attributes in some convenience function

  return CKR_OK;
}

static CK_RV get_attribute_ecsession_key(CK_ATTRIBUTE_TYPE type,
                                         ecdh_session_key *key,
                                         CK_BYTE_PTR value,
                                         CK_ULONG_PTR length) {

  switch (type) {
    case CKA_CLASS:
      *((CK_OBJECT_CLASS *) value) = CKO_SECRET_KEY;
      *length = sizeof(CK_OBJECT_CLASS);
      break;

    case CKA_KEY_TYPE:
      *((CK_KEY_TYPE *) value) = CKK_GENERIC_SECRET;
      *length = sizeof(CK_KEY_TYPE);
      break;

    case CKA_ID: {
      CK_OBJECT_HANDLE *id = (CK_OBJECT_HANDLE *) value;
      *id = key->id;
      *length = sizeof(CK_OBJECT_HANDLE);
      break;
    }

    case CKA_LABEL:
      *length = strlen(key->label);
      memcpy(value, key->label, *length);
      break;

    case CKA_LOCAL:
    case CKA_TOKEN:
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_DESTROYABLE:
    case CKA_EXTRACTABLE:
      *((CK_BBOOL *) value) = CK_TRUE;
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
      *((CK_BBOOL *) value) = CK_FALSE;
      *length = sizeof(CK_BBOOL);
      break;

    case CKA_VALUE:
      memcpy(value, key->ecdh_key, key->len);
      *length = key->len;
      break;

    default:
      return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

CK_RV check_sign_mechanism(yubihsm_pkcs11_slot *slot,
                           CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128] = {0};
  CK_ULONG count = 128;

  if (!is_RSA_sign_mechanism(pMechanism->mechanism) &&
      !is_ECDSA_sign_mechanism(pMechanism->mechanism) &&
      !is_EDDSA_sign_mechanism(pMechanism->mechanism) &&
      !is_HMAC_sign_mechanism(pMechanism->mechanism)) {

    return CKR_MECHANISM_INVALID;
  }

  CK_RV rv = get_mechanism_list(slot, mechanisms, &count);
  if (rv != CKR_OK) {
    return rv;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return CKR_OK;
    }
  }

  return CKR_MECHANISM_INVALID;
}

CK_RV check_decrypt_mechanism(yubihsm_pkcs11_slot *slot,
                              CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128] = {0};
  CK_ULONG count = 128;

  if (is_RSA_decrypt_mechanism(pMechanism->mechanism) == false &&
      pMechanism->mechanism != CKM_YUBICO_AES_CCM_WRAP &&
      pMechanism->mechanism != CKM_AES_ECB &&
      pMechanism->mechanism != CKM_AES_CBC &&
      pMechanism->mechanism != CKM_AES_CBC_PAD) {
    return CKR_MECHANISM_INVALID;
  }

  CK_RV rv = get_mechanism_list(slot, mechanisms, &count);
  if (rv != CKR_OK) {
    return rv;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return CKR_OK;
    }
  }

  return CKR_MECHANISM_INVALID;
}

CK_RV check_digest_mechanism(CK_MECHANISM_PTR pMechanism) {

  switch (pMechanism->mechanism) {
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV check_wrap_mechanism(yubihsm_pkcs11_slot *slot,
                           CK_MECHANISM_PTR pMechanism) {

  CK_MECHANISM_TYPE mechanisms[128] = {0};
  CK_ULONG count = 128;

  if (pMechanism->mechanism != CKM_YUBICO_AES_CCM_WRAP) {
    return CKR_MECHANISM_INVALID;
  }

  CK_RV rv = get_mechanism_list(slot, mechanisms, &count);
  if (rv != CKR_OK) {
    return rv;
  }

  for (CK_ULONG i = 0; i < count; i++) {
    if (pMechanism->mechanism == mechanisms[i]) {
      return CKR_OK;
    }
  }

  return CKR_MECHANISM_INVALID;
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
    case CKM_EDDSA:
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
  if (op_info->op.sign.md_ctx == NULL) {
    return CKR_HOST_MEMORY;
  }
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
    case CKM_EDDSA:
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
    return CKR_HOST_MEMORY;
  }
  if (EVP_DigestInit(op_info->op.verify.md_ctx, md) == 0) {
    EVP_MD_CTX_destroy(op_info->op.verify.md_ctx);
    op_info->op.verify.md_ctx = NULL;
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
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      return CKR_OK;
    default:
      DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }
}

CK_RV apply_encrypt_mechanism_init(yubihsm_pkcs11_session *session,
                                   CK_MECHANISM_PTR pMechanism,
                                   CK_OBJECT_HANDLE hKey) {

  int type = hKey >> 16;
  if (type == ECDH_KEY_TYPE) {
    DBG_ERR("Wrong key type");
    return CKR_KEY_TYPE_INCONSISTENT;
  }

  yubihsm_pkcs11_object_desc *object = get_object_desc(session->slot, hKey);

  if (object == NULL) {
    DBG_ERR("Unable to retrieve object");
    return CKR_KEY_HANDLE_INVALID;
  }

  session->operation.op.encrypt.oaep_label = NULL;
  session->operation.op.encrypt.oaep_md = NULL;
  session->operation.op.encrypt.mgf1_md = NULL;
  session->operation.op.encrypt.key_len = 0;

  size_t key_length;
  if (yh_get_key_bitlength(object->object.algorithm, &key_length) !=
      YHR_SUCCESS) {
    DBG_ERR("Unable to get key length");
    return CKR_FUNCTION_FAILED;
  }
  session->operation.op.encrypt.key_len = key_length;

  if (pMechanism->mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    if (object->object.type != YH_WRAP_KEY) {
      DBG_ERR("Wrong key type or algorithm");
      return CKR_KEY_TYPE_INCONSISTENT;
    }
  } else if (pMechanism->mechanism == CKM_RSA_PKCS) {
    if (object->object.type != YH_PUBLIC_KEY ||
        !yh_is_rsa(object->object.algorithm)) {
      DBG_ERR("Wrong key type for algorithm");
      return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (pMechanism->pParameter != NULL) {
      DBG_ERR("Expecting NULL mechanism parameter for CKM_RSA_PKCS");
      return CKR_MECHANISM_PARAM_INVALID;
    }
    session->operation.op.encrypt.padding = RSA_PKCS1_PADDING;
  } else if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
    if (object->object.type != YH_PUBLIC_KEY ||
        !yh_is_rsa(object->object.algorithm)) {
      DBG_ERR("Wrong key type for algorithm");
      return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (pMechanism->pParameter == NULL) {
      DBG_ERR("Mechanism parameter for CKM_RSA_PKCS_OAEP is NULL");
      return CKR_MECHANISM_PARAM_INVALID;
    }
    session->operation.op.encrypt.padding = RSA_PKCS1_OAEP_PADDING;

    if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
      DBG_ERR("Length of mechanism parameters does not match expected value: "
              "found %lu, expected %zu",
              pMechanism->ulParameterLen, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
      return CKR_MECHANISM_PARAM_INVALID;
    }

    CK_RSA_PKCS_OAEP_PARAMS *params = pMechanism->pParameter;

    if (params->source == 0 && params->ulSourceDataLen != 0) {
      DBG_ERR("Source parameter empty but sourceDataLen != 0");
      return CKR_MECHANISM_PARAM_INVALID;
    } else if (params->source != 0 && params->source != CKZ_DATA_SPECIFIED) {
      DBG_ERR("Unknown value in parameter source");
      return CKR_MECHANISM_PARAM_INVALID;
    }

    DBG_INFO("OAEP params : hashAlg 0x%lx mgf 0x%lx source 0x%lx pSourceData "
             "%p ulSourceDataLen %lu",
             params->hashAlg, params->mgf, params->source, params->pSourceData,
             params->ulSourceDataLen);

    const EVP_MD *md = NULL;
    switch (params->hashAlg) {
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
        md = NULL;
    }
    session->operation.op.encrypt.oaep_md = md;

    switch (params->mgf) {
      case CKG_MGF1_SHA1:
        session->operation.op.encrypt.mgf1_md = EVP_sha1();
        break;
      case CKG_MGF1_SHA256:
        session->operation.op.encrypt.mgf1_md = EVP_sha256();
        break;
      case CKG_MGF1_SHA384:
        session->operation.op.encrypt.mgf1_md = EVP_sha384();
        break;
      case CKG_MGF1_SHA512:
        session->operation.op.encrypt.mgf1_md = EVP_sha512();
        break;
      default:
        session->operation.op.encrypt.mgf1_md = NULL;
    }

    if (params->source == CKZ_DATA_SPECIFIED && params->pSourceData) {
      session->operation.op.encrypt.oaep_label =
        malloc(params->ulSourceDataLen);
      if (session->operation.op.encrypt.oaep_label == NULL) {
        DBG_INFO("Unable to allocate memory for %lu byte OAEP label",
                 params->ulSourceDataLen);
        return CKR_HOST_MEMORY;
      }
      memcpy(session->operation.op.encrypt.oaep_label, params->pSourceData,
             params->ulSourceDataLen);
      session->operation.op.encrypt.oaep_label_len = params->ulSourceDataLen;
    } else {
      session->operation.op.encrypt.oaep_label = NULL;
      session->operation.op.encrypt.oaep_label_len = 0;
    }
  } else if (pMechanism->mechanism == CKM_AES_ECB) {
    if (object->object.type != YH_SYMMETRIC_KEY ||
        !yh_is_aes(object->object.algorithm)) {
      DBG_ERR("Wrong key type for algorithm");
      return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0) {
      return CKR_MECHANISM_PARAM_INVALID;
    }
  } else if (pMechanism->mechanism == CKM_AES_CBC ||
             pMechanism->mechanism == CKM_AES_CBC_PAD) {
    if (object->object.type != YH_SYMMETRIC_KEY ||
        !yh_is_aes(object->object.algorithm)) {
      DBG_ERR("Wrong key type for algorithm");
      return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (pMechanism->pParameter == NULL ||
        pMechanism->ulParameterLen !=
          sizeof(session->operation.mechanism.cbc.iv)) {
      DBG_ERR("IV invalid");
      return CKR_MECHANISM_PARAM_INVALID;
    }
    memcpy(session->operation.mechanism.cbc.iv, pMechanism->pParameter,
           sizeof(session->operation.mechanism.cbc.iv));
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
  if (op_info->op.digest.md_ctx == NULL) {
    return CKR_HOST_MEMORY;
  }

  if (EVP_DigestInit_ex(op_info->op.digest.md_ctx, md, NULL) == 0) {
    EVP_MD_CTX_destroy(op_info->op.digest.md_ctx);
    op_info->op.digest.md_ctx = NULL;
    return CKR_FUNCTION_FAILED;
  }

  set_operation_part(op_info, PART_INIT);

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
    case CKM_EDDSA:
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
    case CKM_EDDSA:
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

static CK_RV op_info_buffer_append(yubihsm_pkcs11_op_info *op_info,
                                   CK_BYTE_PTR ptr, CK_ULONG len) {
  if (op_info->buffer_length > sizeof(op_info->buffer) ||
      sizeof(op_info->buffer) - op_info->buffer_length < len) {
    return CKR_DATA_LEN_RANGE;
  }

  memcpy(op_info->buffer + op_info->buffer_length, ptr, len);
  op_info->buffer_length += len;

  return CKR_OK;
}

static CK_RV do_aes_encdec(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                           const uint8_t *in, size_t in_len, uint8_t *out,
                           size_t *out_len, bool final) {
  yh_rc yhr = YHR_GENERIC_ERROR;
  bool encrypt = op_info->type == OPERATION_ENCRYPT;

  if (in_len < AES_BLOCK_SIZE) {
    // This function should only be called internally when there is
    // enough data to encrypt/decrypt at least one block. This is
    // required for correct IV handling.
    return CKR_FUNCTION_FAILED;
  }

  switch (op_info->mechanism.mechanism) {
    case CKM_AES_ECB:
      yhr = encrypt
              ? yh_util_encrypt_aes_ecb(session, op_info->op.encrypt.key_id, in,
                                        in_len, out, out_len)
              : yh_util_decrypt_aes_ecb(session, op_info->op.decrypt.key_id, in,
                                        in_len, out, out_len);
      break;
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      if (encrypt) {
        if ((yhr = yh_util_encrypt_aes_cbc(session, op_info->op.encrypt.key_id,
                                           op_info->mechanism.cbc.iv, in,
                                           in_len, out, out_len)) ==
              YHR_SUCCESS &&
            !final) {
          memcpy(op_info->mechanism.cbc.iv, out + *out_len - AES_BLOCK_SIZE,
                 AES_BLOCK_SIZE);
        }
      } else {
        // `in` and `out` may overlap.
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        memcpy(iv, in + in_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        if ((yhr = yh_util_decrypt_aes_cbc(session, op_info->op.encrypt.key_id,
                                           op_info->mechanism.cbc.iv, in,
                                           in_len, out, out_len)) ==
              YHR_SUCCESS &&
            !final) {
          memcpy(op_info->mechanism.cbc.iv, iv, AES_BLOCK_SIZE);
        }
      }
      break;
    default:
      return CKR_FUNCTION_FAILED;
  }

  return yrc_to_rv(yhr);
}

static CK_RV perform_aes_update(yh_session *session,
                                yubihsm_pkcs11_op_info *op_info, CK_BYTE_PTR in,
                                CK_ULONG in_len, CK_BYTE_PTR out,
                                CK_ULONG_PTR out_len) {
  size_t prev = op_info->buffer_length;
  if (SIZE_MAX - prev < in_len) {
    return CKR_DATA_LEN_RANGE;
  }
  size_t size = prev + in_len;
  size_t next = size % AES_BLOCK_SIZE;

  // We may have to hold off an entire block.
  if (size && !next && op_info->type == OPERATION_DECRYPT &&
      op_info->mechanism.mechanism == CKM_AES_CBC_PAD) {
    next = 16;
  }

  // Block-align the data.
  size -= next;

  if (out == NULL) {
    DBG_INFO("User querying output size, returning %zu bytes", size);
    *out_len = size;
    return CKR_OK;
  }

  if (size > *out_len) {
    DBG_ERR("Provided buffer is too small (%lu < %zu)", *out_len, size);
    *out_len = size;
    return CKR_BUFFER_TOO_SMALL;
  }

  if (!size) {
    DBG_INFO("Nothing to do for this update, buffering all input");
    *out_len = 0;
    return op_info_buffer_append(op_info, in, in_len);
  }

  // Temporarily store next remainder.
  uint8_t tmp[AES_BLOCK_SIZE] = {0};
  memcpy(tmp, in + in_len - next, next);
  // Move input into place (may overlap).
  memmove(out + prev, in, size - prev);
  // Move previous remainder into place.
  memcpy(out, op_info->buffer, prev);
  // Store the next remainder.
  memcpy(op_info->buffer, tmp, next);
  insecure_memzero(tmp, sizeof(tmp));
  op_info->buffer_length = next;

  CK_RV rv;
  if ((rv = do_aes_encdec(session, op_info, out, size, out, &size, false)) !=
      CKR_OK) {
    DBG_ERR("Failed to encrypt/decrypt data");
    return rv;
  }

  DBG_INFO("Returning %zu bytes (buffered %zu bytes)", size, next);
  *out_len = size;

  return CKR_OK;
}

static CK_RV perform_aes_final(yh_session *session,
                               yubihsm_pkcs11_op_info *op_info, CK_BYTE_PTR out,
                               CK_ULONG_PTR out_len) {
  size_t len = op_info->buffer_length;
  uint8_t last[AES_BLOCK_SIZE * 2] = {0};

  if (op_info->mechanism.mechanism != CKM_AES_CBC_PAD) {
    if (len != 0) {
      DBG_ERR("Data not a multiple of block size");
      return op_info->type == OPERATION_ENCRYPT ? CKR_DATA_LEN_RANGE
                                                : CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    // Nothing to do for mechanisms that have no padding.
    *out_len = 0;
    return CKR_OK;
  }

  CK_RV rv;
  memcpy(last, op_info->buffer, len);
  if (op_info->type == OPERATION_ENCRYPT &&
      yh_util_pad_pkcs7(last, &len, sizeof(last), AES_BLOCK_SIZE) !=
        YHR_SUCCESS) {
    DBG_ERR("Could not pad remainder");
    rv = CKR_FUNCTION_FAILED;
    goto daf_out;
  }

  if (do_aes_encdec(session, op_info, last, len, last, &len, true) != CKR_OK) {
    DBG_ERR("Could not %s remainder",
            op_info->type == OPERATION_ENCRYPT ? "encrypt" : "decrypt");
    rv = CKR_FUNCTION_FAILED;
    goto daf_out;
  }

  if (op_info->type == OPERATION_DECRYPT &&
      yh_util_unpad_pkcs7(last, &len, AES_BLOCK_SIZE) != YHR_SUCCESS) {
    DBG_ERR("Could not unpad remainder");
    rv = CKR_ENCRYPTED_DATA_INVALID;
    goto daf_out;
  }

  // For single part encryption; reaching this point means the
  // internal IV may have been modified by an earlier call to
  // `perform_aes_update()` (used internally). Restore the original
  // IV so that the user can try again for return values that do not
  // terminate the operation.
  if (op_info->part == PART_SINGLE) {
    memcpy(op_info->mechanism.cbc.iv, op_info->mechanism.cbc.orig,
           sizeof(op_info->mechanism.cbc.iv));
  }

  if (out == NULL) {
    *out_len = len;
    rv = CKR_OK;
    goto daf_out;
  }

  if (*out_len < len) {
    *out_len = len;
    rv = CKR_BUFFER_TOO_SMALL;
    goto daf_out;
  }

  memcpy(out, last, len);
  op_info->buffer_length = 0;
  *out_len = len;
  rv = CKR_OK;

daf_out:
  insecure_memzero(last, sizeof(last));
  return rv;
}

CK_RV apply_decrypt_mechanism_update(yh_session *session,
                                     yubihsm_pkcs11_op_info *op_info,
                                     CK_BYTE_PTR pEncryptedPart,
                                     CK_ULONG ulEncryptedPartLen,
                                     CK_BYTE_PTR pPart,
                                     CK_ULONG_PTR pulPartLen) {
  switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_YUBICO_AES_CCM_WRAP:
      *pulPartLen = 0;
      // Only append to the buffer if the user has provided an output
      // buffer. Otherwise, they're just querying the output size.
      return pPart ? op_info_buffer_append(op_info, pEncryptedPart,
                                           ulEncryptedPartLen)
                   : CKR_OK;

    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      return perform_aes_update(session, op_info, pEncryptedPart,
                                ulEncryptedPartLen, pPart, pulPartLen);

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

CK_RV apply_verify_mechanism_finalize(yubihsm_pkcs11_op_info *op_info,
                                      CK_ULONG sig_len) {
  CK_ULONG siglen = 0;
  if (is_HMAC_sign_mechanism(op_info->mechanism.mechanism) == true) {
    switch (op_info->mechanism.mechanism) {
      case CKM_SHA_1_HMAC:
        siglen = 20;
        break;

      case CKM_SHA256_HMAC:
        siglen = 32;
        break;

      case CKM_SHA384_HMAC:
        siglen = 48;
        break;

      case CKM_SHA512_HMAC:
        siglen = 64;
        break;
      default:
        return CKR_MECHANISM_INVALID;
    }
  } else if (is_RSA_sign_mechanism(op_info->mechanism.mechanism)) {
    siglen = (op_info->op.verify.key_len + 7) / 8;
  } else if (is_ECDSA_sign_mechanism(op_info->mechanism.mechanism) ||
             is_EDDSA_sign_mechanism(op_info->mechanism.mechanism)) {
    siglen = ((op_info->op.verify.key_len + 7) / 8) * 2;
  } else {
    return CKR_MECHANISM_INVALID;
  }

  if (sig_len != siglen) {
    DBG_ERR("Wrong signature length, expected %lu, got %lu", siglen, sig_len);
    return CKR_SIGNATURE_LEN_RANGE;
  }
  return CKR_OK;
}

CK_RV apply_decrypt_mechanism_finalize(yh_session *session,
                                       yubihsm_pkcs11_op_info *op_info,
                                       CK_BYTE_PTR pData,
                                       CK_ULONG_PTR pulDataLen) {
  yh_rc yrc;
  size_t outlen = *pulDataLen;

  if (op_info->mechanism.mechanism == CKM_RSA_PKCS) {
    yrc = yh_util_decrypt_pkcs1v1_5(session, op_info->op.decrypt.key_id,
                                    op_info->buffer, op_info->buffer_length,
                                    pData, &outlen);
  } else if (op_info->mechanism.mechanism == CKM_RSA_PKCS_OAEP) {
    yrc = yh_util_decrypt_oaep(session, op_info->op.decrypt.key_id,
                               op_info->buffer, op_info->buffer_length, pData,
                               &outlen, op_info->mechanism.oaep.label,
                               op_info->mechanism.oaep.label_len,
                               op_info->mechanism.oaep.mgf1Algo);
  } else if (op_info->mechanism.mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    yrc =
      yh_util_unwrap_data(session, op_info->op.decrypt.key_id, op_info->buffer,
                          op_info->buffer_length, pData, &outlen);
  } else if (op_info->mechanism.mechanism == CKM_AES_ECB ||
             op_info->mechanism.mechanism == CKM_AES_CBC ||
             op_info->mechanism.mechanism == CKM_AES_CBC_PAD) {
    return perform_aes_final(session, op_info, pData, pulDataLen);
  } else {
    DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
    return CKR_MECHANISM_INVALID;
  }

  if (yrc != YHR_SUCCESS && yrc != YHR_BUFFER_TOO_SMALL) {
    DBG_ERR("Decryption failed: %s", yh_strerror(yrc));
    return yrc_to_rv(yrc);
  }

  if (yrc == YHR_BUFFER_TOO_SMALL || outlen > *pulDataLen) {
    *pulDataLen = outlen;
    return CKR_BUFFER_TOO_SMALL;
  }

  *pulDataLen = outlen;
  return CKR_OK;
}

CK_RV apply_encrypt_mechanism_finalize(yh_session *session,
                                       yubihsm_pkcs11_op_info *op_info,
                                       CK_BYTE_PTR pEncryptedData,
                                       CK_ULONG_PTR pulEncryptedDataLen) {

  CK_RV rv = CKR_MECHANISM_INVALID;
  if (op_info->mechanism.mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    rv = perform_wrap_encrypt(session, op_info, pEncryptedData,
                              (uint16_t *) pulEncryptedDataLen);
    if (rv != CKR_OK) {
      DBG_ERR("Unable to AES wrap data");
    }
  } else if (op_info->mechanism.mechanism == CKM_RSA_PKCS ||
             op_info->mechanism.mechanism == CKM_RSA_PKCS_OAEP) {

    rv = perform_rsa_encrypt(session, op_info, op_info->buffer,
                             op_info->buffer_length, pEncryptedData,
                             pulEncryptedDataLen);
    if (rv != CKR_OK) {
      DBG_ERR("Unable to RSA encrypt data");
    }
  } else if (op_info->mechanism.mechanism == CKM_AES_ECB ||
             op_info->mechanism.mechanism == CKM_AES_CBC ||
             op_info->mechanism.mechanism == CKM_AES_CBC_PAD) {
    return perform_aes_final(session, op_info, pEncryptedData,
                             pulEncryptedDataLen);
  }

  return rv;
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
    bool verified = false;

    yh_rc yrc = yh_util_verify_hmac(session, op_info->op.verify.key_id,
                                    signature, signature_len, op_info->buffer,
                                    op_info->buffer_length, &verified);

    if (yrc != YHR_SUCCESS) {
      return yrc_to_rv(yrc);
    }

    if (verified == false) {
      return CKR_SIGNATURE_INVALID;
    }

    return CKR_OK;
  } else {
    CK_RV rv;
    EVP_PKEY *key = EVP_PKEY_new();
    uint8_t md_data[EVP_MAX_MD_SIZE] = {0};
    uint8_t *md = md_data;
    unsigned int md_len = sizeof(md_data);
    EVP_PKEY_CTX *ctx = NULL;

    rv = load_public_key(session, op_info->op.verify.key_id, &key);
    if (rv != CKR_OK) {
      goto pv_failure;
    }

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    if (EVP_PKEY_base_id(key) == EVP_PKEY_ED25519) {
      EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
      int rc = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, key);
      if (rc <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return CKR_FUNCTION_FAILED;
      }
      rc = EVP_DigestVerify(md_ctx, signature, signature_len, op_info->buffer,
                            op_info->buffer_length);
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(key);
      if (rc == 1) {
        return CKR_OK;
      } else if (rc == 0) {
        return CKR_SIGNATURE_INVALID;
      } else {
        return CKR_FUNCTION_FAILED;
      }
    }
#endif

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL) {
      rv = CKR_HOST_MEMORY;
      goto pv_failure;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }

    unsigned char data[2048] = {0};
    if (is_hashed_mechanism(op_info->mechanism.mechanism)) {
      if (EVP_DigestFinal_ex(op_info->op.verify.md_ctx, md, &md_len) <= 0) {
        rv = CKR_FUNCTION_FAILED;
        goto pv_failure;
      }
    } else if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
      if (op_info->mechanism.mechanism == CKM_RSA_PKCS_PSS) {
        md = op_info->buffer;
        md_len = op_info->buffer_length;
      } else {
        int di_len = parse_NID(op_info->buffer, op_info->buffer_length,
                               &op_info->op.verify.md);
        if (di_len == 0) {
          rv = CKR_DATA_INVALID;
          goto pv_failure;
        }

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

    int res = EVP_PKEY_verify(ctx, signature, signature_len, md, md_len);

    if (res == 1) {
      rv = CKR_OK;
    } else if (res == 0) {
      rv = CKR_SIGNATURE_INVALID;
    } else {
      rv = CKR_FUNCTION_FAILED;
    }

  pv_failure:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return rv;
  }

  return CKR_FUNCTION_FAILED;
}

static bool strip_DER_encoding_from_ECSIG(uint8_t *signature,
                                          size_t *signature_len,
                                          size_t sig_len) {

  ECDSA_SIG *sig;
  const unsigned char *pp = (const unsigned char *) signature;
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

  BN_bn2binpad(r, signature, sig_len / 2);
  BN_bn2binpad(s, signature + sig_len / 2, sig_len / 2);

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
  } else if (is_EDDSA_sign_mechanism(op_info->mechanism.mechanism)) {
    yrc = yh_util_sign_eddsa(session, op_info->op.sign.key_id, op_info->buffer,
                             op_info->buffer_length, op_info->buffer, &outlen);
  } else if (is_ECDSA_sign_mechanism(op_info->mechanism.mechanism)) {
    yrc = yh_util_sign_ecdsa(session, op_info->op.sign.key_id, op_info->buffer,
                             op_info->buffer_length, op_info->buffer, &outlen);
    if (yrc == YHR_SUCCESS) {
      // NOTE(adma): ECDSA, we must remove the DER encoding and only
      // return R,S as required by the specs
      if (strip_DER_encoding_from_ECSIG(op_info->buffer, &outlen,
                                        op_info->op.sign.sig_len) == false) {
        return CKR_FUNCTION_FAILED;
      }
    }
  } else if (is_HMAC_sign_mechanism(op_info->mechanism.mechanism)) {
    yrc = yh_util_sign_hmac(session, op_info->op.sign.key_id, op_info->buffer,
                            op_info->buffer_length, op_info->buffer, &outlen);
  } else {
    DBG_ERR("Mechanism %lu not supported", op_info->mechanism.mechanism);
    return CKR_MECHANISM_INVALID;
  }

  if (yrc != YHR_SUCCESS) {
    return yrc_to_rv(yrc);
  }

  if (outlen > *signature_len) {
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(signature, op_info->buffer, outlen);
  *signature_len = outlen;

  return CKR_OK;
}

CK_RV perform_wrap_encrypt(yh_session *session, yubihsm_pkcs11_op_info *op_info,
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
    return yrc_to_rv(yrc);
  }

  if (outlen > *data_len) {
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(data, op_info->buffer, outlen);
  *data_len = outlen;

  return CKR_OK;
}

CK_RV perform_rsa_encrypt(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                          CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc,
                          CK_ULONG_PTR enc_len) {

  if (data == NULL) {
    DBG_ERR("data is null");
    return CKR_ARGUMENTS_BAD;
  }

  EVP_PKEY *public_key = NULL;
  EVP_PKEY_CTX *ctx = NULL;

  CK_RV rv = load_public_key(session, op_info->op.encrypt.key_id, &public_key);
  if (rv != CKR_OK) {
    DBG_ERR("Failed to load public key");
    goto rsa_enc_cleanup;
  }

  ctx = EVP_PKEY_CTX_new(public_key, NULL);
  if (ctx == NULL) {
    DBG_ERR("Failed to create EVP_PKEY_CTX object for public key");
    rv = CKR_HOST_MEMORY;
    goto rsa_enc_cleanup;
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    rv = CKR_FUNCTION_FAILED;
    goto rsa_enc_cleanup;
  }

  CK_ULONG padding = op_info->op.encrypt.padding;
  if (padding == RSA_NO_PADDING) {
    DBG_ERR("Unsupported padding RSA_NO_PADDING");
    rv = CKR_FUNCTION_REJECTED;
    goto rsa_enc_cleanup;
  } else {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }
  }

  if (op_info->op.encrypt.oaep_md != NULL &&
      op_info->op.encrypt.mgf1_md != NULL &&
      op_info->op.encrypt.oaep_label != NULL) {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_MD_meth_dup(
                                            op_info->op.encrypt.oaep_md)) >=
        0) {
#else
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, op_info->op.encrypt.oaep_md) >= 0) {
#endif
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_MD_meth_dup(
                                            op_info->op.encrypt.mgf1_md)) >=
        0) {
#else
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, op_info->op.encrypt.mgf1_md) >= 0) {

#endif
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }

    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, op_info->op.encrypt.oaep_label,
                                         op_info->op.encrypt.oaep_label_len) >=
        0) {
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }
  }
  size_t cbLen = *enc_len;
  if (EVP_PKEY_encrypt(ctx, enc, &cbLen, data, data_len) <= 0) {
    rv = CKR_FUNCTION_FAILED;
    goto rsa_enc_cleanup;
  }
  *enc_len = cbLen;
  rv = CKR_OK;

rsa_enc_cleanup:
  if (rv != CKR_OK) {
    free(op_info->op.encrypt.oaep_label);
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(public_key);
  return rv;
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

void sign_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  if (op_info->op.sign.md_ctx != NULL) {
    EVP_MD_CTX_destroy(op_info->op.sign.md_ctx);
    op_info->op.sign.md_ctx = NULL;
  }
}

void verify_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  if (op_info->op.verify.md_ctx != NULL) {
    EVP_MD_CTX_destroy(op_info->op.verify.md_ctx);
    op_info->op.verify.md_ctx = NULL;
  }
}

void decrypt_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  (void) op_info;
}

void digest_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info) {

  if (op_info->op.digest.md_ctx != NULL) {
    EVP_MD_CTX_destroy(op_info->op.digest.md_ctx);
    op_info->op.digest.md_ctx = NULL;
  }
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

bool is_EDDSA_sign_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
    case CKM_EDDSA:
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

CK_RV add_connectors(yubihsm_pkcs11_context *ctx, int n_connectors,
                     char **connector_names, yh_connector **connectors) {
  list_create(&ctx->slots, sizeof(yubihsm_pkcs11_slot), free_pkcs11_slot);
  for (int i = 0; i < n_connectors; i++) {
    yubihsm_pkcs11_slot slot;
    memset(&slot, 0, sizeof(yubihsm_pkcs11_slot));
    slot.id = i;
    slot.connector_name = strdup(connector_names[i]);
    slot.max_session_id = 1;
    if (!slot.connector_name) {
      return CKR_HOST_MEMORY;
    }
    slot.connector = connectors[i];
    if (ctx->create_mutex != NULL) {
      CK_RV rv = ctx->create_mutex(&slot.mutex);
      if (rv != CKR_OK) {
        return rv;
      }
    }
    list_create(&slot.pkcs11_sessions, sizeof(yubihsm_pkcs11_session), NULL);
    if (list_append(&ctx->slots, &slot) != true) {
      return CKR_HOST_MEMORY;
    }
  }
  return CKR_OK;
}

CK_RV set_template_attribute(yubihsm_pkcs11_attribute *attribute,
                             CK_BBOOL *value) {
  if (*attribute == ATTRIBUTE_NOT_SET) {
    if (*value == CK_TRUE) {
      *attribute = ATTRIBUTE_TRUE;
    } else {
      *attribute = ATTRIBUTE_FALSE;
    }
    return CKR_OK;
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

CK_RV check_bool_attribute(CK_BBOOL *value, bool check) {
  if (check == true && *value == CK_TRUE) {
    return CKR_OK;
  } else if (check == false && *value == CK_FALSE) {
    return CKR_OK;
  }
  return CKR_ATTRIBUTE_VALUE_INVALID;
}

static int BN_cmp_f4(BIGNUM *bn) {
  BIGNUM *f4 = BN_new();
  BN_set_word(f4, 0x010001);
  int cmp = BN_cmp(bn, f4);
  BN_free(f4);
  return cmp;
}

CK_RV parse_rsa_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         yubihsm_pkcs11_object_template *template) {
  BIGNUM *e = NULL;
  CK_RV rv;
  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_PRIME_1:
        if (template->obj.rsa.p == NULL) {
          template->obj.rsa.p =
            BN_bin2bn(pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
        } else {
          DBG_ERR("CKA_PRIME_1 inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_PRIME_2:
        if (template->obj.rsa.q == NULL) {
          template->obj.rsa.q =
            BN_bin2bn(pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
        } else {
          DBG_ERR("CKA_PRIME_2 inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_PUBLIC_EXPONENT:
        if (e == NULL) {
          e = BN_bin2bn(pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
          if (e == NULL || BN_cmp_f4(e)) {
            DBG_ERR("CKA_PUBLIC_EXPONENT invalid in template");
            BN_free(e);
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
          BN_free(e);
        } else {
          DBG_ERR("CKA_PUBLIC_EXPONENT inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_SIGN inconsistent in template");
          return rv;
        }
        break;

      case CKA_DECRYPT:
        if ((rv = set_template_attribute(&template->decrypt,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_DECRYPT inconsistent in template");
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pTemplate[i].type);
          return rv;
        }
        break;

      case CKA_WRAP:
      case CKA_DERIVE:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_ALWAYS_AUTHENTICATE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, false)) != CKR_OK) {
          return rv;
        }
        break;

      case CKA_SIGN_RECOVER:
      case CKA_UNWRAP: {
        CK_BBOOL b_val = *(CK_BBOOL *) pTemplate[i].pValue;
        if (b_val != CK_FALSE) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx. This will "
                  "be ignored",
                  pTemplate[i].type);
        }
      } break;

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
        DBG_ERR("Invalid attribute type in key template: 0x%lx\n",
                pTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (template->obj.rsa.p && template->obj.rsa.q) {
    template->objlen = (BN_num_bits(template->obj.rsa.p) + 7) / 8;
    if ((BN_num_bits(template->obj.rsa.q) + 7) / 8 != template->objlen) {
      DBG_ERR("Inconsistent prime sizes in template");
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    switch (template->objlen) {
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
        DBG_ERR("Invalid %u bit primes in template", template->objlen * 8);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
  } else {
    DBG_ERR("Iconsistent RSA template");
    return CKR_TEMPLATE_INCONSISTENT;
  }
  return CKR_OK;
}

static CK_RV parse_ecparams(const uint8_t *ecparams, uint16_t ecparams_len,
                            yh_algorithm *algorithm, uint16_t *key_len) {
  EC_GROUP *group = EC_GROUP_new(EC_GFp_simple_method());
  int curve = 0;
  if (group == NULL) {
    return CKR_HOST_MEMORY;
  }
  if (d2i_ECPKParameters(&group, &ecparams, ecparams_len) != NULL) {
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

static CK_RV parse_edparams(uint8_t *ecparams, uint16_t ecparams_len,
                            yh_algorithm *algorithm, uint16_t *key_len) {
  if (ecparams_len != sizeof(oid_ed25519) ||
      memcmp(ecparams, oid_ed25519, sizeof(oid_ed25519))) {
    return CKR_CURVE_NOT_SUPPORTED;
  }
  *algorithm = YH_ALGO_EC_ED25519;
  *key_len = 32;
  return CKR_OK;
}

CK_RV parse_ec_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        yubihsm_pkcs11_object_template *template) {

  CK_RV rv;
  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_VALUE:
        if (template->obj.ec.d == NULL) {
          template->obj.ec.d =
            BN_bin2bn(pTemplate[i].pValue, pTemplate[i].ulValueLen, NULL);
        } else {
          DBG_ERR("CKA_VALUE inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_EC_PARAMS:
        if (template->objlen == 0) {
          rv = parse_ecparams(pTemplate[i].pValue, pTemplate[i].ulValueLen,
                              &template->algorithm, &template->objlen);
          if (rv != CKR_OK) {
            DBG_ERR("Invalid EC parameters in template");
            return rv;
          }
        } else {
          DBG_ERR("CKA_EC_PARAMS inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_SIGN inconsistent in template");
          return rv;
        }
        break;

      case CKA_DERIVE:
        if ((rv = set_template_attribute(&template->derive,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_DERIVE inconsistent in template");
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pTemplate[i].type);
          return rv;
        }
        break;

      case CKA_VERIFY:
      case CKA_WRAP:
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_VERIFY_RECOVER:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_ALWAYS_AUTHENTICATE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, false)) != CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx.",
                  pTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SIGN_RECOVER:
      case CKA_UNWRAP: {
        CK_BBOOL b_val = *(CK_BBOOL *) pTemplate[i].pValue;
        if (b_val != CK_FALSE) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx. This will "
                  "be ignored",
                  pTemplate[i].type);
        }
      } break;

      case CKA_CLASS:
      case CKA_KEY_TYPE:
      case CKA_SUBJECT:
      case CKA_ID:
      case CKA_LABEL:
      case CKA_EXTRACTABLE:
        break;

      default:
        DBG_ERR("Invalid attribute type in key template: 0x%lx\n",
                pTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (template->obj.ec.d == NULL || template->objlen == 0) {
    DBG_ERR("Inconsistent EC template");
    return CKR_TEMPLATE_INCONSISTENT;
  }
  return CKR_OK;
}

CK_RV parse_ed_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        yubihsm_pkcs11_object_template *template) {

  uint8_t *ecparams = NULL;
  uint16_t ecparams_len = 0;
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
      case CKA_DERIVE:
        break;

      default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (ecparams && template->obj.buf) {
    uint16_t key_len;
    rv = parse_edparams(ecparams, ecparams_len, &template->algorithm, &key_len);
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
          // TODO: consider hashing the key here if it's longer than blocklen
          template->obj.buf = pTemplate[i].pValue;
          template->objlen = pTemplate[i].ulValueLen;
        } else {
          DBG_ERR("CKA_VALUE inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_SIGN:
        if ((rv = set_template_attribute(&template->sign,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_SIGN inconsistent in template");
          return rv;
        }
        break;

      case CKA_VERIFY:
        if ((rv = set_template_attribute(&template->verify,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_VERIFY inconsistent in template");
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
            DBG_ERR("CKA_KEY_TYPE inconsistent in template");
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_DESTROYABLE:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_TOKEN:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pTemplate[i].type);
          return rv;
        }
        break;

      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_WRAP:
      case CKA_UNWRAP:
      case CKA_DERIVE:
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY_RECOVER:
      case CKA_ALWAYS_AUTHENTICATE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, false)) != CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pTemplate[i].type);
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
        DBG_ERR("Invalid attribute type in key template: 0x%lx\n",
                pTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (template->algorithm && (generate == true || template->obj.buf)) {
    return CKR_OK;
  } else {
    DBG_ERR("Inconsistent HMAC template");
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

CK_RV parse_meta_id_template(yubihsm_pkcs11_object_template *template,
                             pkcs11_meta_object *pkcs11meta, bool pubkey,
                             uint8_t *value, size_t value_len) {
  if (value_len > CKA_ATTRIBUTE_VALUE_SIZE) {
    DBG_ERR("Failed to parse too large CKA_ID");
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }
  if (pubkey) {
    // Store pubkey metadata
    pkcs11meta->cka_id_pubkey.len = value_len;
    memcpy(pkcs11meta->cka_id_pubkey.value, value, value_len);
  } else {
    // Check if it is a valid regular id
    if (value_len == 2) {
      // Parse the id for backwards compat
      template->id = parse_id_value(value, value_len);
      // Check if both ids are the same
      if (pkcs11meta->cka_id_pubkey.len == value_len &&
          memcmp(pkcs11meta->cka_id_pubkey.value, value, value_len) == 0) {
        // Remove metadata
        pkcs11meta->cka_id_pubkey.len = 0;
      }
    } else {
      // Store privkey metadata
      pkcs11meta->cka_id.len = value_len;
      memcpy(pkcs11meta->cka_id.value, value, value_len);
      // Use random id for invalid length
      template->id = 0;
    }
  }
  return CKR_OK;
}

CK_RV parse_meta_label_template(yubihsm_pkcs11_object_template *template,
                                pkcs11_meta_object *pkcs11meta, bool pubkey,
                                uint8_t *value, size_t value_len) {
  if (value_len > CKA_ATTRIBUTE_VALUE_SIZE) {
    DBG_ERR("Failed to parse too large CKA_LABEL");
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }
  if (pubkey) {
    // Store pubkey metadata
    pkcs11meta->cka_label_pubkey.len = value_len;
    memcpy(pkcs11meta->cka_label_pubkey.value, value, value_len);
  } else {
    // Check if it can fit as regular label
    if (value_len <= YH_OBJ_LABEL_LEN) {
      // Store as regular label
      memcpy(template->label, value, value_len);
      // Check if both labels are the same
      if (pkcs11meta->cka_label_pubkey.len == value_len &&
          memcmp(pkcs11meta->cka_label_pubkey.value, value, value_len) == 0) {
        // Remove pubkey metadata
        pkcs11meta->cka_label_pubkey.len = 0;
      }
    } else {
      // Store privkey metadata
      pkcs11meta->cka_label.len = value_len;
      memcpy(pkcs11meta->cka_label.value, value, value_len);
      // Also store first part as regular label
      memcpy(template->label, value, YH_OBJ_LABEL_LEN);
    }
  }
  return CKR_OK;
}

CK_RV parse_rsa_generate_template(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                  CK_ULONG ulPublicKeyAttributeCount,
                                  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                  CK_ULONG ulPrivateKeyAttributeCount,
                                  yubihsm_pkcs11_object_template *template,
                                  pkcs11_meta_object *pkcs11meta) {

  uint8_t *e = NULL;
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
        rv = parse_meta_id_template(template, pkcs11meta, true,
                                    pPublicKeyTemplate[i].pValue,
                                    pPublicKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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
        rv = parse_meta_label_template(template, pkcs11meta, true,
                                       pPublicKeyTemplate[i].pValue,
                                       pPublicKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_EXTRACTABLE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_DERIVE:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY_RECOVER:
      case CKA_ALWAYS_AUTHENTICATE:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_WRAP:   // pkcs11-tool sets this on public keys
      case CKA_UNWRAP: // pkcs11-tool sets this on public keys
      case CKA_VERIFY:
      case CKA_ENCRYPT:
        break;

      default:
        DBG_ERR("Invalid attribute type in PublicKeyTemplate: 0x%lx",
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
        rv = parse_meta_id_template(template, pkcs11meta, false,
                                    pPrivateKeyTemplate[i].pValue,
                                    pPrivateKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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
        rv = parse_meta_label_template(template, pkcs11meta, false,
                                       pPrivateKeyTemplate[i].pValue,
                                       pPrivateKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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
      case CKA_DERIVE:
      case CKA_ENCRYPT:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_UNWRAP: // pkcs11-tool sets this on private keys
      case CKA_SUBJECT:
        break;

      default:
        DBG_ERR("Invalid attribute type in PrivateKeyTemplate: 0x%lx",
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

uint16_t parse_id_value(void *value, CK_ULONG len) {
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
                                 yubihsm_pkcs11_object_template *template,
                                 pkcs11_meta_object *pkcs11meta) {

  uint8_t *ecparams = NULL;
  uint16_t ecparams_len = 0;
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
        rv = parse_meta_id_template(template, pkcs11meta, true,
                                    pPublicKeyTemplate[i].pValue,
                                    pPublicKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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
        rv = parse_meta_label_template(template, pkcs11meta, true,
                                       pPublicKeyTemplate[i].pValue,
                                       pPublicKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_EXTRACTABLE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_WRAP:
      case CKA_UNWRAP:
      case CKA_SIGN:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY_RECOVER:
      case CKA_ALWAYS_AUTHENTICATE:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_VERIFY:
      case CKA_DERIVE: // pkcs11-tool sets this on public keys
        break;

      default:
        DBG_ERR("Invalid attribute type in PublicKeyTemplate: 0x%lx",
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
        rv = parse_meta_id_template(template, pkcs11meta, false,
                                    pPrivateKeyTemplate[i].pValue,
                                    pPrivateKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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
        rv = parse_meta_label_template(template, pkcs11meta, false,
                                       pPrivateKeyTemplate[i].pValue,
                                       pPrivateKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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

      case CKA_VERIFY:
      case CKA_WRAP:
      case CKA_UNWRAP:
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY_RECOVER:
      case CKA_MODIFIABLE:
      case CKA_COPYABLE:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SUBJECT:
        break;

      default:
        DBG_ERR("Invalid attribute type in PrivateKeyTemplate: 0x%lx",
                pPrivateKeyTemplate[i].type);
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

CK_RV parse_ed_generate_template(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_ULONG ulPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_ULONG ulPrivateKeyAttributeCount,
                                 yubihsm_pkcs11_object_template *template,
                                 pkcs11_meta_object *pkcs11meta) {

  uint8_t *ecparams = NULL;
  uint16_t ecparams_len = 0;
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
        if (*((CK_ULONG_PTR) pPublicKeyTemplate[i].pValue) != CKK_EC_EDWARDS) {
          DBG_ERR("CKA_KEY_TYPE inconsistent in PublicKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_ID:
        rv = parse_meta_id_template(template, pkcs11meta, true,
                                    pPublicKeyTemplate[i].pValue,
                                    pPublicKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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
        rv = parse_meta_label_template(template, pkcs11meta, true,
                                       pPublicKeyTemplate[i].pValue,
                                       pPublicKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_EXTRACTABLE:
      case CKA_DESTROYABLE:
      case CKA_VERIFY:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, true)) !=
            CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SENSITIVE:
      case CKA_PRIVATE:
      case CKA_COPYABLE:
      case CKA_MODIFIABLE:
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_SIGN_RECOVER:
      case CKA_WRAP:
      case CKA_WRAP_WITH_TRUSTED:
      case CKA_UNWRAP:
      case CKA_DERIVE:
      case CKA_VERIFY_RECOVER:
        if ((rv = check_bool_attribute(pPublicKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPublicKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SUBJECT:
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
        if (*((CK_ULONG_PTR) pPrivateKeyTemplate[i].pValue) != CKK_EC_EDWARDS) {
          DBG_ERR("CKA_KEY_TYPE inconsistent in PrivateKeyTemplate");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_ID: {
        rv = parse_meta_id_template(template, pkcs11meta, false,
                                    pPrivateKeyTemplate[i].pValue,
                                    pPrivateKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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

      case CKA_LABEL:
        rv = parse_meta_label_template(template, pkcs11meta, false,
                                       pPrivateKeyTemplate[i].pValue,
                                       pPrivateKeyTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
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

      case CKA_COPYABLE:
      case CKA_MODIFIABLE:
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_WRAP:
      case CKA_WRAP_WITH_TRUSTED:
      case CKA_UNWRAP:
      case CKA_DERIVE:
        if ((rv = check_bool_attribute(pPrivateKeyTemplate[i].pValue, false)) !=
            CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pPrivateKeyTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SUBJECT:
        break;

      default:
        DBG_ERR("invalid attribute type in PrivateKeyTemplate: 0x%lx\n",
                pPrivateKeyTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (ecparams == NULL) {
    DBG_ERR("CKA_ECPARAMS not set");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  uint16_t key_len;
  rv = parse_edparams(ecparams, ecparams_len, &template->algorithm, &key_len);
  if (rv != CKR_OK) {
    DBG_ERR("Failed to parse CKA_ECPARAMS");
    return rv;
  }

  return CKR_OK;
}

CK_RV parse_wrap_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          yubihsm_pkcs11_object_template *template,
                          yh_algorithm algorithm, bool generate) {

  CK_RV rv;
  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_VALUE:
        if (generate == false && template->obj.buf == NULL) {
          template->obj.buf = pTemplate[i].pValue;
          template->objlen = pTemplate[i].ulValueLen;
        } else {
          DBG_ERR("CKA_VALUE inconsistent in template");
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_VALUE_LEN:
        if (generate == true) {
          size_t key_length = 0;
          yh_rc yrc = yh_get_key_bitlength(algorithm, &key_length);
          if (yrc != YHR_SUCCESS) {
            return yrc_to_rv(yrc);
          }
          if ((key_length + 7) / 8 != *(CK_ULONG_PTR) pTemplate[i].pValue) {
            return CKR_TEMPLATE_INCONSISTENT;
          }
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_WRAP:
        if ((rv = set_template_attribute(&template->wrap,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_WRAP inconsistent in template");
          return rv;
        }
        break;

      case CKA_UNWRAP:
        if ((rv = set_template_attribute(&template->unwrap,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_UNWRAP inconsistent in template");
          return rv;
        }
        break;

      case CKA_ENCRYPT:
        if ((rv = set_template_attribute(&template->encrypt,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_ENCRYPT inconsistent in template");
          return rv;
        }
        break;

      case CKA_DECRYPT:
        if ((rv = set_template_attribute(&template->decrypt,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_DECRYPT inconsistent in template");
          return rv;
        }
        break;

      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_DESTROYABLE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pTemplate[i].type);
          return rv;
        }
        break;

      case CKA_SIGN:
      case CKA_VERIFY:
      case CKA_SIGN_RECOVER:
      case CKA_VERIFY_RECOVER:
      case CKA_DERIVE:
      case CKA_COPYABLE:
      case CKA_MODIFIABLE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, false)) != CKR_OK) {
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
        DBG_ERR("Invalid attribute type in key template: 0x%lx",
                pTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }
  if (generate == true || template->obj.buf) {
    return CKR_OK;
  } else {
    DBG_ERR("Inconsistent wrap key template");
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

CK_RV parse_aes_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         yubihsm_pkcs11_object_template *template,
                         bool generate) {

  CK_RV rv;
  CK_ULONG keylen = 0;

  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {

      case CKA_VALUE:
        if (generate == false && template->obj.buf == NULL) {
          template->obj.buf = pTemplate[i].pValue;
          template->objlen = keylen = pTemplate[i].ulValueLen;
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
        }
        break;

      case CKA_VALUE_LEN:
        if (generate == true && template->obj.buf == NULL) {
          keylen = *((CK_ULONG *) pTemplate[i].pValue);
        } else {
          return CKR_TEMPLATE_INCONSISTENT;
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
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) != CKR_OK) {
          DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                  pTemplate[i].type);
          return rv;
        }
        break;

      case CKA_WRAP:
      case CKA_UNWRAP:
      case CKA_DERIVE:
      case CKA_SIGN:
      case CKA_VERIFY:
      case CKA_COPYABLE:
      case CKA_MODIFIABLE:
        if ((rv = check_bool_attribute(pTemplate[i].pValue, false)) != CKR_OK) {
          DBG_ERR("Boolean false check failed for attribute 0x%lx",
                  pTemplate[i].type);
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
        DBG_ERR("unknown attribute 0x%lx", pTemplate[i].type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  switch (keylen) {
    case 16:
      template->algorithm = YH_ALGO_AES128;
      break;
    case 24:
      template->algorithm = YH_ALGO_AES192;
      break;
    case 32:
      template->algorithm = YH_ALGO_AES256;
      break;
    default:
      DBG_ERR("Invalid key length %lu", keylen);
      return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  if (generate == true || template->obj.buf) {
    return CKR_OK;
  } else {
    return CKR_TEMPLATE_INCONSISTENT;
  }
}

CK_RV populate_template(int type, void *object, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount, yubihsm_pkcs11_session *session) {

  CK_RV rv = CKR_OK;
  CK_BYTE tmp[8192] = {0};
  for (CK_ULONG i = 0; i < ulCount; i++) {
    DBG_INFO("Getting attribute 0x%lx", pTemplate[i].type);
    CK_ULONG len = sizeof(tmp);
    CK_RV attribute_rc;

    if (type == ECDH_KEY_TYPE) {
      ecdh_session_key *key = object;
      attribute_rc =
        get_attribute_ecsession_key(pTemplate[i].type, key, tmp, &len);
    } else {
      yubihsm_pkcs11_object_desc *desc = object;
      attribute_rc =
        get_attribute(pTemplate[i].type, &desc->object, tmp, &len, session);
    }

    if (attribute_rc == CKR_OK) {
      if (pTemplate[i].pValue == NULL) {
        DBG_INFO("Retrieving only length which is %lu", len);
        pTemplate[i].ulValueLen = len;
      } else if (len > pTemplate[i].ulValueLen) {
        DBG_WARN("Skipping attribute, buffer too small %lu > %lu", len,
                 pTemplate[i].ulValueLen);
        attribute_rc = CKR_BUFFER_TOO_SMALL;
      } else {
        DBG_INFO("Retrieving attribute value, length is %lu", len);
        memcpy(pTemplate[i].pValue, tmp, len);
        pTemplate[i].ulValueLen = len;
      }
    }

    // NOTE: this needs to be a separate if since attribute_rc might be changed
    // inside of the above if statement
    if (attribute_rc != CKR_OK) {
      pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;

      rv = attribute_rc;
      if (attribute_rc == CKR_ATTRIBUTE_TYPE_INVALID) {
        DBG_ERR("Unable to get attribute");
      } else if (attribute_rc == CKR_BUFFER_TOO_SMALL) {
        DBG_ERR("Skipping attribute because buffer is too small");
      } else {
        DBG_ERR("Get attribute failed.");
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

  insecure_memzero(tmp, sizeof(tmp));

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
        DBG_ERR("The derived key must be extractable");
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

bool match_meta_attributes(yubihsm_pkcs11_session *session,
                           yh_object_descriptor *object, uint8_t *cka_id,
                           uint16_t cka_id_len, uint8_t *cka_label,
                           uint16_t cka_label_len) {
  CK_RV rv = CKR_OK;
  CK_BYTE tmp[8192] = {0};
  CK_ULONG len = sizeof(tmp);

  if (cka_id_len > 0) {
    rv = get_attribute(CKA_ID, object, tmp, &len, session);
    if (rv != CKR_OK) {
      DBG_ERR("Failed to parse CKA_ID");
      return false;
    }

    if (!match_byte_array(tmp, len, cka_id, cka_id_len)) {
      return false;
    }
  }

  if (cka_label_len > 0) {
    memset(tmp, 0, len);
    len = sizeof(tmp);
    rv = get_attribute(CKA_LABEL, object, tmp, &len, session);
    if (rv != CKR_OK) {
      DBG_ERR("Failed to parse CKA_LABEL");
      return false;
    }
    if (!match_byte_array(tmp, len, cka_label, cka_label_len)) {
      return false;
    }
  }
  return true;
}

static void increment_ctr(uint8_t *ctr, size_t len) {
  while (len > 0) {
    if (++ctr[--len]) {
      break;
    }
  }
}

CK_RV ecdh_with_kdf(ecdh_session_key *shared_secret, uint8_t *fixed_info,
                    size_t fixed_len, CK_ULONG kdf, size_t value_len) {

  if (fixed_len > 0 && fixed_info == NULL) {
    return CKR_MECHANISM_PARAM_INVALID;
  }

  hash_ctx hash = NULL;
  switch (kdf) {
    case CKD_NULL:
      DBG_INFO("KDF is CKD_NULL");
      // Do nothing
      break;
    case CKD_SHA1_KDF_SP800:
      DBG_INFO("KDF is CKD_SHA1_KDF_SP800");
      hash_create(&hash, _SHA1);
      break;
    case CKD_SHA256_KDF_SP800:
      DBG_INFO("KDF is CKD_SHA256_KDF_SP800");
      hash_create(&hash, _SHA256);
      break;
    case CKD_SHA384_KDF_SP800:
      DBG_INFO("KDF is CKD_SHA384_KDF_SP800");
      hash_create(&hash, _SHA384);
      break;
    case CKD_SHA512_KDF_SP800:
      DBG_INFO("KDF is CKD_SHA512_KDF_SP800");
      hash_create(&hash, _SHA512);
      break;
  }

  if (hash) {
    uint8_t ctr[sizeof(uint32_t)] = {0};
    uint8_t res[ECDH_KEY_BUF_SIZE] = {0};
    size_t res_len = 0;

    do {
      increment_ctr(ctr, sizeof(ctr));
      hash_init(hash);
      hash_update(hash, ctr, sizeof(ctr));
      hash_update(hash, shared_secret->ecdh_key, shared_secret->len);
      hash_update(hash, fixed_info, fixed_len);
      size_t len = sizeof(res) - res_len;
      hash_final(hash, res + res_len, &len);
      res_len += len;
    } while (res_len < value_len);

    if (value_len == 0) {
      value_len = res_len;
    }

    memcpy(shared_secret->ecdh_key, res, value_len);
    memset(shared_secret->ecdh_key + value_len, 0,
           sizeof(shared_secret->ecdh_key) - value_len);
    shared_secret->len = value_len;
  } else if (kdf != CKD_NULL) {
    DBG_ERR("Unsupported KDF %lu", kdf);
    return CKR_MECHANISM_PARAM_INVALID;
  }

  return CKR_OK;
}
