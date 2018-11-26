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

#ifndef YKYH_H
#define YKYH_H

#include <stdint.h>
#include <stddef.h>

//#include <ykyh-version.h>

#ifdef __cplusplus
extern "C" {
#endif

// INS codes
#define YKYH_INS_PUT 0x01
#define YKYH_INS_DELETE 0x02
#define YKYH_INS_CALCULATE 0x03
#define YKYH_INS_GET_CHALLENGE 0x04
#define YKYH_INS_LIST 0x05
#define YKYH_INS_RESET 0x06
#define YKYH_INS_GET_VERSION 0x07

// P1 bytes
#define YKYH_P1_RESET 0xde

// P2 bytes
#define YKYH_P2_RESET 0xad

// Tag codes
#define YKYH_TAG_NAME 0x71
#define YKYH_TAG_NAME_LIST 0x72
#define YKYH_TAG_PW 0x73
#define YKYH_TAG_ALGO 0x74
#define YKYH_TAG_KEY_ENC 0x75
#define YKYH_TAG_KEY_MAC 0x76
#define YKYH_TAG_CONTEXT 0x77
#define YKYH_TAG_RESPONSE 0x78
#define YKYH_TAG_VERSION 0x79
#define YKYH_TAG_TOUCH 0x7a

// Algos
#define YKYH_SCP03_ALGO 38
#define YKYH_SCP11_ALGO 39

#define SW_SUCCESS 0x9000
#define SW_ERR_AUTHENTICATION_FAILED 0x63c0

// Lengths
#define YKYH_MIN_NAME_LEN 1
#define YKYH_MAX_NAME_LEN 64
#define YKYH_KEY_LEN 16
#define YKYH_PW_LEN 16
#define YKYH_CONTEXT_LEN 16

// PBKDF2 derivation parameters
#define YKYH_DEFAULT_SALT "Yubico"
#define YKYH_DEFAULT_ITERS 10000

typedef struct ykyh_state ykyh_state;

typedef enum {
  YKYHR_SUCCESS = 0,
  YKYHR_MEMORY_ERROR = -1,
  YKYHR_PCSC_ERROR = -2,
  YKYHR_GENERIC_ERROR = -3,
  YKYHR_WRONG_PW = -4,
  YKYHR_INVALID_PARAMS = -5,
  YKYHR_ENTRY_NOT_FOUND = -6,
} ykyh_rc;

typedef struct {
  uint8_t algo;
  char name[YKYH_MAX_NAME_LEN + 1];
  uint8_t ctr;
} ykyh_list_entry;

const char *ykyh_strerror(ykyh_rc err);
const char *ykyh_strerror_name(ykyh_rc err);

ykyh_rc ykyh_init(ykyh_state **state, int verbose);
ykyh_rc ykyh_done(ykyh_state *state);
ykyh_rc ykyh_connect(ykyh_state *state, const char *wanted);
ykyh_rc ykyh_list_readers(ykyh_state *state, char *readers, size_t *len);
ykyh_rc ykyh_disconnect(ykyh_state *state);

ykyh_rc ykyh_get_version(ykyh_state *state, char *version, size_t len);

ykyh_rc ykyh_put(ykyh_state *state, const char *name, const uint8_t *key_enc,
                 size_t key_enc_len, const uint8_t *key_mac, size_t key_mac_len,
                 const char *pw, const uint8_t touch_policy);

ykyh_rc ykyh_delete(ykyh_state *state, char *name);
ykyh_rc ykyh_calculate(ykyh_state *state, const char *name, uint8_t *context,
                       size_t context_len, const char *pw, uint8_t *key_s_enc,
                       size_t key_s_enc_len, uint8_t *key_s_mac,
                       size_t key_s_mac_len, uint8_t *key_s_rmac,
                       size_t key_s_rmac_len, uint8_t *retries);
ykyh_rc ykyh_reset(ykyh_state *state);
ykyh_rc ykyh_list_keys(ykyh_state *state, ykyh_list_entry *list,
                       size_t *list_items);
ykyh_rc ykyh_get_challenge(ykyh_state *state);

#ifdef __cplusplus
}
#endif

#endif
