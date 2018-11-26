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
#include "../common/insecure_memzero.h"

#include <string.h>
#include <assert.h>

#ifdef _WIN32_BCRYPT
#include <ntstatus.h>
#endif

#ifdef _WIN32_BCRYPT
static NTSTATUS init_ctx(aes_context *ctx) {
  NTSTATUS status = STATUS_SUCCESS;
  BCRYPT_ALG_HANDLE hAlgCBC = 0;
  BCRYPT_ALG_HANDLE hAlgECB = 0;
  DWORD cbKeyObj = 0;
  DWORD cbData = 0;

  if (!ctx) {
    return STATUS_INVALID_PARAMETER;
  }

  if (ctx->hAlgCBC) {
    return STATUS_SUCCESS;
  }

  /* clear the context, to "reset" */

  insecure_memzero(ctx, sizeof(aes_context));

  if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlgCBC,
                                                           BCRYPT_AES_ALGORITHM,
                                                           NULL, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptSetProperty(hAlgCBC, BCRYPT_CHAINING_MODE,
                                          (PBYTE) BCRYPT_CHAIN_MODE_CBC,
                                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlgECB,
                                                           BCRYPT_AES_ALGORITHM,
                                                           NULL, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptSetProperty(hAlgECB, BCRYPT_CHAINING_MODE,
                                          (PBYTE) BCRYPT_CHAIN_MODE_ECB,
                                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlgCBC, BCRYPT_OBJECT_LENGTH,
                                                 (PBYTE) &cbKeyObj,
                                                 sizeof(DWORD), &cbData, 0))) {
    goto cleanup;
  }

  ctx->hAlgCBC = hAlgCBC;
  hAlgCBC = 0;
  ctx->hAlgECB = hAlgECB;
  hAlgECB = 0;
  ctx->cbKeyObj = cbKeyObj;

cleanup:

  if (hAlgCBC) {
    BCryptCloseAlgorithmProvider(hAlgCBC, 0);
  }
  if (hAlgECB) {
    BCryptCloseAlgorithmProvider(hAlgECB, 0);
  }

  return status;
}

static NTSTATUS import_key(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE *phKey,
                           PBYTE *ppbKeyObj, DWORD cbKeyObj, const uint8_t *key,
                           size_t key_len) {
  NTSTATUS status = STATUS_SUCCESS;
  PBYTE pbKeyObj = NULL;
  BCRYPT_KEY_HANDLE hKey = 0;
  PBYTE pbKeyBlob = NULL;
  DWORD cbKeyBlob = 0;

  if (!phKey || !ppbKeyObj) {
    return STATUS_INVALID_PARAMETER;
  }

  /* close existing key first */
  if (*phKey) {
    BCryptDestroyKey(*phKey);
    *phKey = 0;
  }

  /* free existing key object */
  if (*ppbKeyObj) {
    free(*ppbKeyObj);
    *ppbKeyObj = NULL;
  }

  /* allocate new key object */
  if (!(pbKeyObj = (PBYTE) malloc(cbKeyObj))) {
    status = STATUS_NO_MEMORY;
    goto cleanup;
  }

  cbKeyBlob = (DWORD)(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key_len);

  if (!(pbKeyBlob = (PBYTE) malloc(cbKeyBlob))) {
    status = STATUS_NO_MEMORY;
    goto cleanup;
  }

  /* set up BCrypt Key Blob for import */
  ((BCRYPT_KEY_DATA_BLOB_HEADER *) pbKeyBlob)->dwMagic =
    BCRYPT_KEY_DATA_BLOB_MAGIC;
  ((BCRYPT_KEY_DATA_BLOB_HEADER *) pbKeyBlob)->dwVersion =
    BCRYPT_KEY_DATA_BLOB_VERSION1;
  ((BCRYPT_KEY_DATA_BLOB_HEADER *) pbKeyBlob)->cbKeyData = (DWORD) key_len;
  memcpy(pbKeyBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key, key_len);

  if (!BCRYPT_SUCCESS(status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB,
                                               &hKey, pbKeyObj, cbKeyObj,
                                               pbKeyBlob, cbKeyBlob, 0))) {
    goto cleanup;
  }

  /* set output params */
  *phKey = hKey;
  hKey = 0;
  *ppbKeyObj = pbKeyObj;
  pbKeyObj = 0;

cleanup:

  if (hKey) {
    BCryptDestroyKey(hKey);
  }
  if (pbKeyObj) {
    free(pbKeyObj);
  }
  if (pbKeyBlob) {
    free(pbKeyBlob);
  }

  return !BCRYPT_SUCCESS(status);
}

#endif

uint8_t aes_set_encrypt_key(uint8_t *key, uint16_t key_len, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;

  if (!BCRYPT_SUCCESS(status = init_ctx(ctx))) {
    return 1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgCBC, &(ctx->hKeyCBC),
                                          &(ctx->pbKeyCBCObj), ctx->cbKeyObj,
                                          key, key_len))) {
    return 1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgECB, &(ctx->hKeyECB),
                                          &(ctx->pbKeyECBObj), ctx->cbKeyObj,
                                          key, key_len))) {
    return 1;
  }

#else
  AES_set_encrypt_key(key, key_len * 8, &ctx->key);
  ctx->key_len = key_len;

#endif

  return 0;
}

uint8_t aes_set_decrypt_key(uint8_t *key, uint16_t key_len, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;

  if (!BCRYPT_SUCCESS(status = init_ctx(ctx))) {
    return 1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgCBC, &(ctx->hKeyCBC),
                                          &(ctx->pbKeyCBCObj), ctx->cbKeyObj,
                                          key, key_len))) {
    return 1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgECB, &(ctx->hKeyECB),
                                          &(ctx->pbKeyECBObj), ctx->cbKeyObj,
                                          key, key_len))) {
    return 1;
  }

#else
  AES_set_decrypt_key(key, key_len * 8, &ctx->key);
  ctx->key_len = key_len;

#endif
  return 0;
}

uint8_t aes_encrypt(uint8_t *in, uint8_t *out, const aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyECB, in, AES_BLOCK_SIZE,
                                             NULL, NULL, 0, out, AES_BLOCK_SIZE,
                                             &cbResult, 0))) {
    return -2;
  }

#else

  AES_ecb_encrypt(in, out, &ctx->key, AES_ENCRYPT);

#endif

  return 0;
}

uint8_t aes_decrypt(uint8_t *in, uint8_t *out, const aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(ctx->hKeyECB, in, AES_BLOCK_SIZE,
                                             NULL, NULL, 0, out, AES_BLOCK_SIZE,
                                             &cbResult, 0))) {
    return -1;
  }

  assert(cbResult == AES_BLOCK_SIZE);

#else

  AES_ecb_encrypt(in, out, &ctx->key, AES_DECRYPT);

#endif

  return 0;
}

uint8_t aes_cbc_encrypt(uint8_t *in, uint8_t *out, uint16_t len, uint8_t *iv,
                        aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyCBC, in, len, NULL, iv,
                                             AES_BLOCK_SIZE, out, len,
                                             &cbResult, 0))) {
    return -1;
  }

#else

  AES_cbc_encrypt(in, out, len, &ctx->key, iv, AES_ENCRYPT);

#endif

  return 0;
}

uint8_t aes_cbc_decrypt(uint8_t *in, uint8_t *out, uint16_t len, uint8_t *iv,
                        aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(ctx->hKeyCBC, in, len, NULL, iv,
                                             AES_BLOCK_SIZE, out, len,
                                             &cbResult, 0))) {
    return -1;
  }

#else

  AES_cbc_encrypt(in, out, len, &ctx->key, iv, AES_DECRYPT);

#endif

  return 0;
}

void aes_add_padding(uint8_t *in, uint16_t *len) {

  in[(*len)++] = 0x80;
  while ((*len) % AES_BLOCK_SIZE != 0) {
    in[(*len)++] = 0x00;
  }
}

void aes_remove_padding(uint8_t *in, uint16_t *len) {

  while (in[(*len) - 1] == 0) {
    (*len)--;
  }

  (*len)--;
}

void aes_destroy(aes_context *ctx) {
  if (!ctx) {
    return;
  }

#ifdef _WIN32_BCRYPT

  if (ctx->hKeyCBC) {
    BCryptDestroyKey(ctx->hKeyCBC);
  }
  if (ctx->pbKeyCBCObj) {
    free(ctx->pbKeyCBCObj);
  }
  if (ctx->hKeyECB) {
    BCryptDestroyKey(ctx->hKeyECB);
  }
  if (ctx->pbKeyECBObj) {
    free(ctx->pbKeyECBObj);
  }
  if (ctx->hAlgCBC) {
    BCryptCloseAlgorithmProvider(ctx->hAlgCBC, 0);
  }
  if (ctx->hAlgECB) {
    BCryptCloseAlgorithmProvider(ctx->hAlgECB, 0);
  }

#endif

  insecure_memzero(ctx, sizeof(aes_context));
}
