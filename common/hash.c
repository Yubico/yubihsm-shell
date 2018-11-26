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

#include "hash.h"
#include "insecure_memzero.h"

typedef struct _hash_ctx {
#ifdef _WIN32_BCRYPT
  BCRYPT_ALG_HANDLE hAlg;
  BCRYPT_HASH_HANDLE hHash;
  PBYTE pbHashObj;
  bool fFinal;
  size_t cbHash;
#else
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
#endif
} _hash_ctx, *hash_ctx;

#ifndef _WIN32_BCRYPT

const YH_INTERNAL EVP_MD *get_hash(hash_t hash) {
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

LPCWSTR YH_INTERNAL get_hash(hash_t hash) {
  switch (hash) {
    case _NONE:
      return NULL;

    case _SHA1:
      return BCRYPT_SHA1_ALGORITHM;

    case _SHA256:
      return BCRYPT_SHA256_ALGORITHM;

    case _SHA384:
      return BCRYPT_SHA384_ALGORITHM;

    case _SHA512:
      return BCRYPT_SHA512_ALGORITHM;

    default:
      return NULL;
  }
}

#endif

bool hash_bytes(const uint8_t *in, size_t len, hash_t hash, uint8_t *out,
                size_t *out_len) {
#ifndef _WIN32_BCRYPT

  const EVP_MD *md;

  uint32_t d_len;

  md = get_hash(hash);
  if (md == NULL) {
    return false;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, in, len);
  EVP_DigestFinal_ex(mdctx, out, &d_len);

  *out_len = (uint16_t) d_len;

  EVP_MD_CTX_destroy(mdctx);

  return true;

#else

  bool res = false;
  NTSTATUS status = 0;
  LPCWSTR alg = NULL;
  BCRYPT_ALG_HANDLE hAlg = 0;
  BCRYPT_HASH_HANDLE hHash = 0;
  DWORD cbHashObj = 0;
  DWORD cbHash = 0;
  DWORD cbData = 0;
  PBYTE pbHashObj = NULL;

  alg = get_hash(hash);
  if (alg == NULL) {
    return false;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptOpenAlgorithmProvider(&hAlg, alg, NULL, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                                 (PBYTE) &cbHashObj,
                                                 sizeof(DWORD), &cbData, 0))) {
    goto cleanup;
  }

  if (!(pbHashObj = (PBYTE) malloc(cbHashObj))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                                 (PBYTE) &cbHash, sizeof(DWORD),
                                                 &cbData, 0))) {
    goto cleanup;
  }

  if (*out_len < cbHash) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObj,
                                                cbHashObj, NULL, 0, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptHashData(hHash, (PBYTE) in, len, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptFinishHash(hHash, out, cbHash, 0))) {
    goto cleanup;
  }

  *out_len = cbHash;
  res = true;

cleanup:

  if (pbHashObj) {
    free(pbHashObj);
  }
  if (hHash) {
    BCryptDestroyHash(hHash);
  }
  if (hAlg) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
  }

  return res;

#endif
}

bool hash_create(_hash_ctx **ctx, hash_t hash) {
  bool res = false;
  _hash_ctx *ctx_temp = NULL;

#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
  LPCWSTR alg = NULL;
  DWORD cbHashObj = 0;
  DWORD cbHash = 0;
  DWORD cbData = 0;
#else
  const EVP_MD *md = NULL;
#endif

  if (!ctx) {
    return false;
  }

  if (*ctx) {
    return false;
  }

  if (!(ctx_temp = (_hash_ctx *) malloc(sizeof(_hash_ctx)))) {
    return false;
  }

  insecure_memzero(ctx_temp, sizeof(_hash_ctx));

#ifdef _WIN32_BCRYPT
  if (!(alg = get_hash(hash))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&(ctx_temp->hAlg),
                                                           alg, NULL, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptGetProperty(ctx_temp->hAlg, BCRYPT_OBJECT_LENGTH,
                                          (PBYTE) &cbHashObj, sizeof(DWORD),
                                          &cbData, 0))) {
    goto cleanup;
  }

  if (!(ctx_temp->pbHashObj = (PBYTE) malloc(cbHashObj))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptGetProperty(ctx_temp->hAlg, BCRYPT_HASH_LENGTH,
                                          (PBYTE) &cbHash, sizeof(DWORD),
                                          &cbData, 0))) {
    goto cleanup;
  }

  ctx_temp->cbHash = (size_t) cbHash;

  if (!BCRYPT_SUCCESS(status =
                        BCryptCreateHash(ctx_temp->hAlg, &(ctx_temp->hHash),
                                         ctx_temp->pbHashObj, cbHashObj, NULL,
                                         0, BCRYPT_HASH_REUSABLE_FLAG))) {
    goto cleanup;
  }

  ctx_temp->fFinal = true;

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
    if (ctx_temp->pbHashObj) {
      free(ctx_temp->pbHashObj);
    }
    if (ctx_temp->hAlg) {
      BCryptCloseAlgorithmProvider(ctx_temp->hAlg, 0);
    }
#endif
    free(ctx_temp);
  }

  return res;
}

bool hash_init(_hash_ctx *ctx) {
  if (!ctx) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  /* finalize the hash, it should be marked as reusable */
  if (!ctx->fFinal) {
    size_t cbHash = ctx->cbHash;
    uint8_t *temp = (uint8_t *) malloc(cbHash);

    if (temp) {
      bool res = hash_final(ctx, temp, &cbHash);
      free(temp);
      return res;
    }
  }

#else
  EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL);
#endif

  return true;
}

bool hash_update(_hash_ctx *ctx, const uint8_t *in, size_t cb_in) {
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

  ctx->fFinal = true;

  if (!BCRYPT_SUCCESS(status =
                        BCryptHashData(ctx->hHash, (PBYTE) in, cb_in, 0))) {
    return false;
  }

#else
  if (!(ctx->mdctx)) {
    return false;
  }

  EVP_DigestUpdate(ctx->mdctx, in, cb_in);
#endif

  return true;
}

bool hash_final(_hash_ctx *ctx, uint8_t *out, size_t *pcb_out) {
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
  EVP_DigestFinal_ex(ctx->mdctx, out, &d_len);
  *pcb_out = d_len;

#endif

  return true;
}

bool hash_destroy(_hash_ctx *ctx) {
  if (!ctx) {
    return false;
  }

#ifdef _WIN32_BCRYPT
  if (ctx->hHash) {
    BCryptDestroyHash(ctx->hHash);
  }
  if (ctx->pbHashObj) {
    free(ctx->pbHashObj);
  }
  if (ctx->hAlg) {
    BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
  }
#else
  if (ctx->mdctx) {
    EVP_MD_CTX_destroy(ctx->mdctx);
  }
#endif

  free(ctx);

  return true;
}
