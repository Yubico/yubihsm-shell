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

// AES-CMAC implementation as defined in SP-800-38B
// AES key length can be one of 128, 192, 256
// Output length is one full block (16 bytes)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "aes_cmac.h"
#include "../common/insecure_memzero.h"

static const uint8_t zero[AES_BLOCK_SIZE] = {0};

static void do_pad(uint8_t *data, uint8_t len) {

  for (uint8_t i = len; i < AES_BLOCK_SIZE; i++)
    if (i == len)
      data[i] = 0x80;
    else
      data[i] = 0x00;
}

static void do_xor(const uint8_t *a, uint8_t *b) {

  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
    b[i] ^= a[i];
  }
}

static void do_shift_one_bit_left(const uint8_t *a, uint8_t *b,
                                  uint8_t *carry) {
  for (int8_t i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    b[i] = (a[i] << 1) | *carry;

    *carry = a[i] >> 7;
  }
}

static void cmac_generate_subkey(const uint8_t *key, uint8_t *subkey) {

  uint8_t carry = 0;

  do_shift_one_bit_left(key, subkey, &carry);

  subkey[AES_BLOCK_SIZE - 1] ^= 0x87 >> (8 - (carry * 8));
}

int aes_cmac_encrypt(aes_cmac_context_t *ctx, const uint8_t *message,
                     const uint16_t message_len, uint8_t *mac) {

  uint8_t M[AES_BLOCK_SIZE] = {0};
  const uint8_t *ptr = message;

  memcpy(mac, zero, AES_BLOCK_SIZE);

  uint8_t n_blocks;
  if (message_len == 0)
    n_blocks = 0;
  else
    n_blocks = (message_len + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE - 1;

  uint8_t remaining_bytes = (message_len % AES_BLOCK_SIZE);

  for (uint8_t i = 0; i < n_blocks; i++) {
    do_xor(ptr, mac);
    int rc = aes_encrypt(mac, mac, AES_BLOCK_SIZE, ctx->aes_ctx);
    if (rc) {
      return rc;
    }
    ptr += AES_BLOCK_SIZE;
  }

  if (remaining_bytes == 0) {
    if (message != NULL && message_len != 0) {
      memcpy(M, ptr, AES_BLOCK_SIZE);
      do_xor(ctx->k1, M);
    } else {
      do_pad(M, 0);
      do_xor(ctx->k2, M);
    }
  } else {
    memcpy(M, ptr, remaining_bytes);
    do_pad(M, remaining_bytes);
    do_xor(ctx->k2, M);
  }

  do_xor(M, mac);

  return aes_encrypt(mac, mac, AES_BLOCK_SIZE, ctx->aes_ctx);
}

int aes_cmac_init(aes_context *aes_ctx, aes_cmac_context_t *ctx) {

  uint8_t L[AES_BLOCK_SIZE] = {0};

  ctx->aes_ctx = aes_ctx;

  int rc = aes_encrypt(zero, L, AES_BLOCK_SIZE, ctx->aes_ctx);
  if (rc) {
    return rc;
  }

  cmac_generate_subkey(L, ctx->k1);
  cmac_generate_subkey(ctx->k1, ctx->k2);

  return aes_cmac_encrypt(ctx, zero, AES_BLOCK_SIZE, ctx->mac);
}

void aes_cmac_destroy(aes_cmac_context_t *ctx) {
  if (ctx) {
    insecure_memzero(ctx, sizeof(aes_cmac_context_t));
  }
}
