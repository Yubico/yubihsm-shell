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
#include "insecure_memzero.h"
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

/*
 * Holds the HMAC state that is invariant across all PBKDF2 iterations for a
 * given password: two contexts primed with Hash(ipad) / Hash(opad), and two
 * scratch contexts that get reset (via hash_copy) from those primed contexts
 * on every iteration. This avoids re-hashing the pad blocks and re-allocating
 * hash contexts on every one of the (typically thousands of) iterations.
 */
typedef struct {
  hash_ctx ipad_ctx;
  hash_ctx opad_ctx;
  hash_ctx work_inner;
  hash_ctx work_outer;
  size_t digest_len;
  size_t block_len;
} hmac_state_t;

static void hmac_destroy(hmac_state_t *st) {
  if (st->ipad_ctx) {
    hash_destroy(st->ipad_ctx);
  }
  if (st->opad_ctx) {
    hash_destroy(st->opad_ctx);
  }
  if (st->work_inner) {
    hash_destroy(st->work_inner);
  }
  if (st->work_outer) {
    hash_destroy(st->work_outer);
  }
  memset(st, 0, sizeof(*st));
}

static bool hmac_init(hmac_state_t *st, hash_t hash, const uint8_t *key,
                      size_t cb_key) {
  uint8_t key_block[MAX_HASH_BLOCK_LEN];
  uint8_t ipad[MAX_HASH_BLOCK_LEN];
  uint8_t opad[MAX_HASH_BLOCK_LEN];
  size_t len;
  bool res = false;

  memset(st, 0, sizeof(*st));

  if (!get_hash_sizes(hash, &st->digest_len, &st->block_len)) {
    return false;
  }

  if (st->digest_len > MAX_HASH_DIGEST_LEN ||
      st->block_len > MAX_HASH_BLOCK_LEN) {
    DBG_ERR("Hash sizes exceed HMAC scratch buffer capacity");
    return false;
  }

  memset(key_block, 0, sizeof(key_block));
  if (cb_key > st->block_len) {
    len = sizeof(key_block);
    if (!hash_bytes(key, cb_key, hash, key_block, &len)) {
      goto cleanup;
    }
  } else {
    memcpy(key_block, key, cb_key);
  }

  for (size_t i = 0; i < st->block_len; i++) {
    ipad[i] = (uint8_t)(key_block[i] ^ 0x36);
    opad[i] = (uint8_t)(key_block[i] ^ 0x5c);
  }

  if (!hash_create(&st->ipad_ctx, hash) || !hash_init(st->ipad_ctx) ||
      !hash_update(st->ipad_ctx, ipad, st->block_len)) {
    goto cleanup;
  }

  if (!hash_create(&st->opad_ctx, hash) || !hash_init(st->opad_ctx) ||
      !hash_update(st->opad_ctx, opad, st->block_len)) {
    goto cleanup;
  }

  /* scratch contexts: their state is fully overwritten by hash_copy on each
   * iteration, so they don't need hash_init here. */
  if (!hash_create(&st->work_inner, hash) || !hash_create(&st->work_outer, hash)) {
    goto cleanup;
  }

  res = true;

cleanup:
  insecure_memzero(key_block, sizeof(key_block));
  insecure_memzero(ipad, sizeof(ipad));
  insecure_memzero(opad, sizeof(opad));
  if (!res) {
    hmac_destroy(st);
  }
  return res;
}

static bool hmac_compute(hmac_state_t *st, const uint8_t *data, size_t cb_data,
                         uint8_t *out, size_t *cb_out) {
  uint8_t inner_digest[MAX_HASH_DIGEST_LEN];
  size_t len;
  bool res = false;

  if (*cb_out < st->digest_len) {
    return false;
  }

  len = sizeof(inner_digest);
  if (!hash_copy(st->work_inner, st->ipad_ctx) ||
      !hash_update(st->work_inner, data, cb_data) ||
      !hash_final(st->work_inner, inner_digest, &len)) {
    goto cleanup;
  }

  len = *cb_out;
  if (!hash_copy(st->work_outer, st->opad_ctx) ||
      !hash_update(st->work_outer, inner_digest, st->digest_len) ||
      !hash_final(st->work_outer, out, &len)) {
    goto cleanup;
  }

  *cb_out = len;
  res = true;

cleanup:
  insecure_memzero(inner_digest, sizeof(inner_digest));
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
  uint8_t *salt_block = NULL;
  uint8_t u[MAX_HASH_DIGEST_LEN];
  uint8_t t[MAX_HASH_DIGEST_LEN];
  size_t cb_u;
  uint32_t num_blocks;
  hmac_state_t hmac;
  bool hmac_ready = false;

  if (iterations == 0 || cb_key == 0) {
    DBG_ERR("Invalid iterations or key length for PBKDF2");
    return false;
  }

  if (cb_salt > SIZE_MAX - 4) {
    DBG_ERR("Salt too large for PBKDF2");
    return false;
  }

  /* Prime the HMAC pads once; every iteration below just resets the scratch
   * contexts from this primed state instead of recreating/re-hashing them. */
  if (!hmac_init(&hmac, hash, password, cb_password)) {
    DBG_ERR("Unsupported hash or failed to initialize PBKDF2 HMAC state");
    return false;
  }
  hmac_ready = true;
  digest_len = hmac.digest_len;

  /* ceil(cb_key / digest_len), computed via truncated division + remainder
   * check so the intermediate can't overflow the way (cb_key + digest_len -
   * 1) could. RFC 8018 5.2 caps the number of blocks at 2^32 - 1; reject
   * anything above that instead of silently truncating the uint32_t count
   * (which could wrap to 0 and return "success" having written nothing). */
  {
    size_t num_blocks_sz = cb_key / digest_len;
    if (cb_key % digest_len != 0) {
      num_blocks_sz++;
    }
    if (num_blocks_sz > UINT32_MAX) {
      DBG_ERR("Requested PBKDF2 output length exceeds the 2^32-1 block limit");
      goto cleanup;
    }
    num_blocks = (uint32_t) num_blocks_sz;
  }

  if (!(salt_block = malloc(cb_salt + 4))) {
    goto cleanup;
  }
  memcpy(salt_block, salt, cb_salt);

  /* block_idx64 is wider than num_blocks so that when num_blocks is the
   * maximum legal value (UINT32_MAX) the loop still terminates instead of
   * wrapping a uint32_t counter back through 0. */
  for (uint64_t block_idx64 = 1; block_idx64 <= num_blocks; block_idx64++) {
    uint32_t block_idx = (uint32_t) block_idx64;
    size_t offset = (block_idx - 1) * digest_len;
    size_t cb_copy = digest_len;

    salt_block[cb_salt + 0] = (uint8_t)((block_idx >> 24) & 0xff);
    salt_block[cb_salt + 1] = (uint8_t)((block_idx >> 16) & 0xff);
    salt_block[cb_salt + 2] = (uint8_t)((block_idx >> 8) & 0xff);
    salt_block[cb_salt + 3] = (uint8_t)(block_idx & 0xff);

    cb_u = sizeof(u);
    if (!hmac_compute(&hmac, salt_block, cb_salt + 4, u, &cb_u)) {
      DBG_ERR("HMAC failed while computing PBKDF2 block %u", block_idx);
      goto cleanup;
    }
    memcpy(t, u, digest_len);

    for (uint64_t i = 1; i < iterations; i++) {
      cb_u = sizeof(u);
      if (!hmac_compute(&hmac, u, digest_len, u, &cb_u)) {
        DBG_ERR("HMAC failed while computing PBKDF2 block %u", block_idx);
        goto cleanup;
      }
      for (size_t j = 0; j < digest_len; j++) {
        t[j] ^= u[j];
      }
    }

    if (cb_copy > cb_key - offset) {
      cb_copy = cb_key - offset;
    }
    memcpy(key + offset, t, cb_copy);
  }

  res = true;

cleanup:
  if (salt_block) {
    insecure_memzero(salt_block, cb_salt + 4);
    free(salt_block);
  }
  insecure_memzero(u, sizeof(u));
  insecure_memzero(t, sizeof(t));
  if (hmac_ready) {
    hmac_destroy(&hmac);
  }

#endif
  return res;
}
