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

#ifndef YUBIHSM_PKCS11_H
#define YUBIHSM_PKCS11_H

#include "pkcs11y.h"
#include "list.h"
#include <openssl/evp.h>
#include <sys/time.h>

#define YUBIHSM_PKCS11_OP_BUFSIZE 4096
#define MAX_ECDH_SESSION_KEYS 255
#define ECDH_KEY_BUF_SIZE 128
#define ECDH_KEY_TYPE 0x00FF

typedef enum {
  SESSION_RESERVED_RO = 1 << 0,
  SESSION_RESERVED_RW = 1 << 1,
  SESSION_AUTHENTICATED_RO = 1 << 2,
  SESSION_AUTHENTICATED_RW = 1 << 3,
} yubihsm_pkcs11_session_state;

#define SESSION_AUTHENTICATED                                                  \
  (SESSION_AUTHENTICATED_RO | SESSION_AUTHENTICATED_RW)
#define SESSION_NOT_AUTHENTICATED (SESSION_RESERVED_RO | SESSION_RESERVED_RW)

typedef struct {
  struct timeval tv;
  bool filled;
  yh_object_descriptor object;
} yubihsm_pkcs11_object_desc;

typedef enum {
  OPERATION_NOOP,
  OPERATION_FIND,
  OPERATION_GEN,
  OPERATION_SIGN,
  OPERATION_DIGEST,
  OPERATION_DECRYPT,
  OPERATION_VERIFY,
  OPERATION_ENCRYPT
} yubihsm_pkcs11_op_type;

typedef struct {
  yh_object_descriptor objects[YH_MAX_ITEMS_COUNT];
  uint16_t current_object;
  size_t n_objects;
  bool only_private;
} find_info;

typedef struct {
  EVP_MD_CTX *md_ctx; // Digest context
  uint16_t key_id;    // Key id
  CK_ULONG key_len;   // Length in bits
  uint16_t sig_len;   // Length in bytes
} sign_info;

typedef struct {
  EVP_MD_CTX *md_ctx;  // Digest context
  CK_ULONG digest_len; // Length in bits
  bool is_multipart;
} digest_info;

typedef struct {
  uint16_t key_id;  // Key id
  CK_ULONG key_len; // Length in bits
  bool finalized;
} decrypt_info;

typedef struct {
  uint16_t key_id;
} encrypt_info;

typedef struct {
  EVP_MD_CTX *md_ctx;    // running hash
  const EVP_MD *md;      // digest used
  int padding;           // padding in the rsa case
  unsigned long saltLen; // saltlen for rsa-pss
  const EVP_MD *mgf1md;  // mgf1 md used for rsa-pss
  uint16_t key_id;       // Key id
  CK_ULONG key_len;      // Length in bits
} verify_info;

typedef union {
  find_info find;
  sign_info sign;
  digest_info digest;
  verify_info verify;
  decrypt_info decrypt;
  encrypt_info encrypt;
} op;

typedef struct {
  CK_MECHANISM_TYPE mechanism;
  union {
    struct {
      uint8_t label[64];      // hash of OAEP label
      unsigned int label_len; // length of the hashed label
      yh_algorithm mgf1Algo;
    } oaep;
    struct {
      uint16_t salt_len;
      yh_algorithm mgf1Algo;
    } pss;
  };
} mechanism;

typedef struct {
  // The session key ID 0x00 ff 0001, 0x00 ff 0002, 0x00 ff 0003...etc
  CK_OBJECT_HANDLE id;
  /// The key itself
  uint8_t ecdh_key[ECDH_KEY_BUF_SIZE];
  /// The length of the key
  size_t len;
  /// Object label
  char label[YH_OBJ_LABEL_LEN + 1];
} ecdh_session_key;

typedef struct {
  yubihsm_pkcs11_op_type type;
  mechanism mechanism;
  op op;
  uint8_t buffer[YUBIHSM_PKCS11_OP_BUFSIZE];
  unsigned int buffer_length;
} yubihsm_pkcs11_op_info;

typedef struct {
  List slots;
  CK_CREATEMUTEX create_mutex;
  CK_DESTROYMUTEX destroy_mutex;
  CK_LOCKMUTEX lock_mutex;
  CK_UNLOCKMUTEX unlock_mutex;
  void *mutex;
} yubihsm_pkcs11_context;

typedef struct {
  uint16_t id;
  uint16_t max_session_id;
  char *connector_name;
  yh_connector *connector;
  yh_session *device_session;
  List pkcs11_sessions;
  yubihsm_pkcs11_object_desc objects[YH_MAX_ITEMS_COUNT];
  yh_algorithm algorithms[YH_MAX_ALGORITHM_COUNT];
  size_t n_algorithms;
  void *mutex;
} yubihsm_pkcs11_slot;

typedef struct {
  uint16_t id;
  yubihsm_pkcs11_op_info operation;
  yubihsm_pkcs11_session_state session_state;
  yubihsm_pkcs11_slot *slot;
  List ecdh_session_keys;
} yubihsm_pkcs11_session;

typedef enum {
  ATTRIBUTE_NOT_SET = 0,
  ATTRIBUTE_FALSE,
  ATTRIBUTE_TRUE,
} yubihsm_pkcs11_attribute;

typedef struct {
  yh_algorithm algorithm;
  uint16_t id;
  char label[YH_OBJ_LABEL_LEN + 1];
  yubihsm_pkcs11_attribute sign;
  yubihsm_pkcs11_attribute encrypt;
  yubihsm_pkcs11_attribute decrypt;
  yubihsm_pkcs11_attribute derive;
  yubihsm_pkcs11_attribute exportable;
  yubihsm_pkcs11_attribute verify;
  yubihsm_pkcs11_attribute wrap;
  yubihsm_pkcs11_attribute unwrap;
  uint16_t objlen;
  union {
    struct {
      uint8_t *p;
      uint8_t *q;
    } rsa;
    uint8_t *buf;
  } obj;
} yubihsm_pkcs11_object_template;

#endif
