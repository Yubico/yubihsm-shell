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

#include "aes.h"

typedef struct {
  aes_context aes_ctx;
  uint8_t k1[AES_BLOCK_SIZE];
  uint8_t k2[AES_BLOCK_SIZE];
  uint8_t mac[AES_BLOCK_SIZE];
} aes_cmac_context_t;

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

uint8_t YH_INTERNAL aes_cmac_init(uint8_t *key, uint16_t key_len,
                                  aes_cmac_context_t *ctx);
void YH_INTERNAL aes_cmac_encrypt(const aes_cmac_context_t *ctx,
                                  const uint8_t *message,
                                  const uint16_t message_len, uint8_t *mac);
void YH_INTERNAL aes_cmac_destroy(aes_cmac_context_t *ctx);
