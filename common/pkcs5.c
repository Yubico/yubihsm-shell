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

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "pkcs5.h"
#include "hash.h"
#include "../lib/debug_lib.h"

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#else

#define MAX_HASH_BLOCK_LEN 128
#define MAX_HASH_DIGEST_LEN 64

static bool get_hash_sizes(hash_t hash, size_t *digest_len,
                           size_t *block_len) {
  switch (hash) {
    case _SHA1:
      *digest_len = 20;
      *block_len = 64;
      return true;

    case _SHA256:
      *digest_len = 32;
      *block_len = 64;
      return true;

    case _SHA384:
      *digest_len = 48;
      *block_len = 128;
      return true;

    case _SHA512:
      *digest_len = 64;
      *block_len = 128;
      return true;

    default:
      return false;
  }
}

static bool hmac_sha(hash_t hash, const uint8_t *key, size_t cb_key,
                     const uint8_t *data, size_t cb_data, uint8_t *out,
                     size_t *cb_out) {
  size_t digest_len = 0;
  size_t block_len = 0;
  uint8_t key_block[MAX_HASH_BLOCK_LEN];
  uint8_t ipad[MAX_HASH_BLOCK_LEN];
  uint8_t opad[MAX_HASH_BLOCK_LEN];
  uint8_t inner_digest[MAX_HASH_DIGEST_LEN];
  size_t len;
  hash_ctx ctx = NULL;
  bool res = false;

  if (!get_hash_sizes(hash, &digest_len, &block_len)) {
    return false;
  }

  if (*cb_out < digest_len) {
    return false;
  }

  memset(key_block, 0, sizeof(key_block));
  if (cb_key > block_len) {
    len = sizeof(key_block);
    if (!hash_bytes(key, cb_key, hash, key_block, &len)) {
      return false;
    }
  } else {
    memcpy(key_block, key, cb_key);
  }

  for (size_t i = 0; i < block_len; i++) {
    ipad[i] = (uint8_t)(key_block[i] ^ 0x36);
    opad[i] = (uint8_t)(key_block[i] ^ 0x5c);
  }

  len = sizeof(inner_digest);
  if (!hash_create(&ctx, hash)) {
    return false;
  }
  if (!hash_init(ctx) || !hash_update(ctx, ipad, block_len) ||
      !hash_update(ctx, data, cb_data) ||
      !hash_final(ctx, inner_digest, &len)) {
    hash_destroy(ctx);
    return false;
  }
  hash_destroy(ctx);
  ctx = NULL;

  if (!hash_create(&ctx, hash)) {
    return false;
  }
  len = *cb_out;
  if (!hash_init(ctx) || !hash_update(ctx, opad, block_len) ||
      !hash_update(ctx, inner_digest, digest_len) ||
      !hash_final(ctx, out, &len)) {
    goto cleanup;
  }

  *cb_out = len;
  res = true;

cleanup:
  hash_destroy(ctx);
  return res;
}

#endif

bool pkcs5_pbkdf2_hmac(const uint8_t *password, size_t cb_password,
                       const uint8_t *salt, size_t cb_salt, uint64_t iterations,
                       hash_t hash, uint8_t *key, size_t cb_key) {
  bool res = false;

#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
  LPCWSTR alg = NULL;
  BCRYPT_ALG_HANDLE hAlg = 0;

  if (!(alg = get_hash(hash))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(
        status = BCryptOpenAlgorithmProvider(&hAlg, alg, NULL,
                                             BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(
        status =
          BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR) password, (ULONG) cb_password,
                                (PUCHAR) salt, (ULONG) cb_salt, iterations, key,
                                (ULONG) cb_key, 0))) {
    goto cleanup;
  }

  res = true;

cleanup:

  if (hAlg) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
  }

#else
  /* PBKDF2 as defined in RFC 8018 section 5.2 */
  size_t digest_len = 0;
  size_t block_len = 0;
  uint8_t *salt_block = NULL;
  uint8_t u[MAX_HASH_DIGEST_LEN];
  uint8_t t[MAX_HASH_DIGEST_LEN];
  size_t cb_u;
  uint32_t num_blocks;

  if (iterations == 0 || cb_key == 0) {
    DBG_ERR("Invalid iterations or key length for PBKDF2");
    return false;
  }

  if (!get_hash_sizes(hash, &digest_len, &block_len)) {
    DBG_ERR("Unsupported hash for PBKDF2");
    return false;
  }

  num_blocks = (uint32_t)((cb_key + digest_len - 1) / digest_len);

  if (!(salt_block = malloc(cb_salt + 4))) {
    return false;
  }
  memcpy(salt_block, salt, cb_salt);

  for (uint32_t block_idx = 1; block_idx <= num_blocks; block_idx++) {
    size_t offset = (block_idx - 1) * digest_len;
    size_t cb_copy = digest_len;

    salt_block[cb_salt + 0] = (uint8_t)((block_idx >> 24) & 0xff);
    salt_block[cb_salt + 1] = (uint8_t)((block_idx >> 16) & 0xff);
    salt_block[cb_salt + 2] = (uint8_t)((block_idx >> 8) & 0xff);
    salt_block[cb_salt + 3] = (uint8_t)(block_idx & 0xff);

    cb_u = sizeof(u);
    if (!hmac_sha(hash, password, cb_password, salt_block, cb_salt + 4, u,
                 &cb_u)) {
      DBG_ERR("HMAC failed while computing PBKDF2 block %u", block_idx);
      goto cleanup;
    }
    memcpy(t, u, digest_len);

    for (uint64_t i = 1; i < iterations; i++) {
      cb_u = sizeof(u);
      if (!hmac_sha(hash, password, cb_password, u, digest_len, u, &cb_u)) {
        DBG_ERR("HMAC failed while computing PBKDF2 block %u", block_idx);
        goto cleanup;
      }
      for (size_t j = 0; j < digest_len; j++) {
        t[j] ^= u[j];
      }
    }

    if (offset + cb_copy > cb_key) {
      cb_copy = cb_key - offset;
    }
    memcpy(key + offset, t, cb_copy);
  }

  res = true;

cleanup:
  free(salt_block);

#endif
  return res;
}
