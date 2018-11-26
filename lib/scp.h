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

#ifndef SCP_H
#define SCP_H

#include <stdint.h>
#include <stdbool.h>

// Data derivation constants
#define SCP_CARD_CRYPTOGRAM 0x00
#define SCP_HOST_CRYPTOGRAM 0x01

#define SCP_CARD_CHALLENGE 0x02

#define SCP_S_ENC_DERIVATION 0x04
#define SCP_S_MAC_DERIVATION 0x06
#define SCP_S_RMAC_DERIVATION 0x07

// Lengths
#define AES_128_KEY_LEN 16
#define AES_192_KEY_LEN 24
#define AES_256_KEY_LEN 32
#define SCP_KEY_LEN (AES_128_KEY_LEN)
#define SCP_PRF_LEN 16 // One AES block

#define SCP_CARD_CHAL_LEN 8
#define SCP_HOST_CHAL_LEN 8

#define SCP_CARD_CRYPTO_LEN 8
#define SCP_HOST_CRYPTO_LEN 8

#define SCP_MAC_LEN 8

#define SCP_CONTEXT_LEN 16

#define SCP_AUTHKEY_ID_LEN 2

#define SCP_MSG_BUF_SIZE 2048

// Message
#pragma pack(push, 1)
union _Msg {
  struct {
    uint8_t cmd;
    uint16_t len;
    uint8_t data[SCP_MSG_BUF_SIZE];
  } st;
  uint8_t raw[3 + SCP_MSG_BUF_SIZE];
};
#pragma pack(pop)

typedef union _Msg Msg;

typedef struct {
  uint8_t sid;
  uint8_t s_enc[SCP_KEY_LEN];
  uint8_t s_mac[SCP_KEY_LEN];
  uint8_t s_rmac[SCP_KEY_LEN];
  uint8_t mac_chaining_value[SCP_PRF_LEN];
  uint8_t ctr[SCP_PRF_LEN];
  bool in_use;
  bool authenticated;
} Scp_ctx;

#endif
