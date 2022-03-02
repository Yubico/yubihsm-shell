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

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

#include <stdlib.h>

#include "hash.h"

typedef struct _hash_ctx {
#ifdef _WIN32_BCRYPT
  BCRYPT_HASH_HANDLE hHash;
  ULONG cbHash;
#else
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
#endif
} _hash_ctx, *hash_ctx;

#ifndef _WIN32_BCRYPT

const EVP_MD *get_hash(hash_t hash) {
  switch (hash) {
    case _NONE:
      return NULL;

    case _SHA1:
      return EVP_sha1();

    case _SHA256:
      return EVP_sha256();

    case _SHA384:
      return EVP_sha384();

    case _SHA512:
      return EVP_sha512();

    default:
      return NULL;
  }
}

#else

BCRYPT_ALG_HANDLE get_hash(hash_t hash, bool hmac) {
  switch (hash) {
    case _NONE:
      return NULL;

    case _SHA1:
      return hmac ? BCRYPT_HMAC_SHA1_ALG_HANDLE : BCRYPT_SHA1_ALG_HANDLE;

    case _SHA256:
      return hmac ? BCRYPT_HMAC_SHA256_ALG_HANDLE : BCRYPT_SHA256_ALG_HANDLE;

    case _SHA384:
      return hmac ? BCRYPT_HMAC_SHA384_ALG_HANDLE : BCRYPT_SHA384_ALG_HANDLE;

    case _SHA512:
      return hmac ? BCRYPT_HMAC_SHA512_ALG_HANDLE : BCRYPT_SHA512_ALG_HANDLE;

    default:
      return 0;
  }
}

#endif

bool hash_bytes(const uint8_t *in, size_t len, hash_t hash, uint8_t *out,
                size_t *out_len) {
  hash_ctx ctx = 0;
  if (!hash_create(&ctx, hash)) {
    return false;
  }
  if (!hash_init(ctx)) {
    hash_destroy(ctx);
    return false;
  }
  if (!hash_update(ctx, in, len)) {
    hash_destroy(ctx);
    return false;
  }
  if (!hash_final(ctx, out, out_len)) {
    hash_destroy(ctx);
    return false;
  }
  return hash_destroy(ctx);
}

bool hash_create(hash_ctx *ctx, hash_t hash) {
  bool res = false;
  hash_ctx ctx_temp = NULL;

#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
  BCRYPT_ALG_HANDLE hAlg = 0;
  ULONG cbData = 0;
#else
  const EVP_MD *md = NULL;
#endif

  if (!ctx) {
    return false;
  }

  if (*ctx) {
    return false;
  }

  if (!(ctx_temp = (hash_ctx) calloc(1, sizeof(_hash_ctx)))) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  if (!(hAlg = get_hash(hash, false))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                                 (PBYTE) &ctx_temp->cbHash,
                                                 sizeof(ctx_temp->cbHash),
                                                 &cbData, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptCreateHash(hAlg, &ctx_temp->hHash, NULL, 0, NULL,
                                         0, BCRYPT_HASH_REUSABLE_FLAG))) {
    goto cleanup;
  }

#else
  if (!(md = get_hash(hash))) {
    goto cleanup;
  }

  if (!(ctx_temp->mdctx = EVP_MD_CTX_create())) {
    goto cleanup;
  }

  ctx_temp->md = md;

#endif

  /* set output parameters */
  *ctx = ctx_temp;
  ctx_temp = NULL;
  res = true;

cleanup:

  if (ctx_temp) {
#ifdef _WIN32_BCRYPT
    if (ctx_temp->hHash) {
      BCryptDestroyHash(ctx_temp->hHash);
    }
#endif
    free(ctx_temp);
  }

  return res;
}

bool hash_init(hash_ctx ctx) {
  if (!ctx) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  if (!ctx->hHash) {
    return false;
  }
#else
  if (EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL) != 1) {
    return false;
  }
#endif

  return true;
}

bool hash_update(hash_ctx ctx, const uint8_t *in, size_t cb_in) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
#endif

  if (!ctx) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  if (!ctx->hHash) {
    return false;
  }

  if (!BCRYPT_SUCCESS(
        status = BCryptHashData(ctx->hHash, (PBYTE) in, (ULONG) cb_in, 0))) {
    return false;
  }

#else
  if (!(ctx->mdctx)) {
    return false;
  }

  if (EVP_DigestUpdate(ctx->mdctx, in, cb_in) != 1) {
    return false;
  }
#endif

  return true;
}

bool hash_final(hash_ctx ctx, uint8_t *out, size_t *pcb_out) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
#else
  uint32_t d_len = 0;
#endif

  if (!ctx) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  if (!(ctx->hHash)) {
    return false;
  }

  if (*pcb_out < ctx->cbHash) {
    return false;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptFinishHash(ctx->hHash, out, ctx->cbHash, 0))) {
    return false;
  }

  *pcb_out = ctx->cbHash;

#else
  if (EVP_DigestFinal_ex(ctx->mdctx, out, &d_len) != 1) {
    *pcb_out = 0;
    return false;
  }
  *pcb_out = d_len;

#endif

  return true;
}

bool hash_destroy(hash_ctx ctx) {
  if (!ctx) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  if (ctx->hHash) {
    BCryptDestroyHash(ctx->hHash);
  }
#else
  if (ctx->mdctx) {
    EVP_MD_CTX_destroy(ctx->mdctx);
  }
#endif

  free(ctx);

  return true;
}
