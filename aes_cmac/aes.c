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

#include "aes.h"
#include "debug_lib.h"
#include "../common/insecure_memzero.h"

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

  cbKeyBlob = (DWORD) (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key_len);

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

#else

/*
 * Use the low-level AES API (AES_set_encrypt_key / AES_ecb_encrypt /
 * AES_cbc_encrypt) instead of the EVP API.  The low-level functions
 * operate directly on an AES_KEY struct with pre-computed round keys
 * and do not depend on OpenSSL's global library context.  This means
 * they continue to work after OPENSSL_cleanup() has been called,
 * which is critical for SCP03 session close during application
 * teardown.
 */

#endif

int aes_set_key(const uint8_t *key, uint16_t key_len, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;

  if (!BCRYPT_SUCCESS(status = init_ctx(ctx))) {
    return -1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgCBC, &(ctx->hKeyCBC),
                                          &(ctx->pbKeyCBCObj), ctx->cbKeyObj,
                                          key, key_len))) {
    return -2;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgECB, &(ctx->hKeyECB),
                                          &(ctx->pbKeyECBObj), ctx->cbKeyObj,
                                          key, key_len))) {
    return -3;
  }

#else

  if (key == NULL || (key_len != 16 && key_len != 24 && key_len != 32)) {
    DBG_ERR("aes_set_key: invalid key or key_len %u", key_len);
    return -1;
  }
  if (AES_set_encrypt_key(key, key_len * 8, &ctx->enc_key) != 0) {
    DBG_ERR("AES_set_encrypt_key failed");
    return -2;
  }
  if (AES_set_decrypt_key(key, key_len * 8, &ctx->dec_key) != 0) {
    DBG_ERR("AES_set_decrypt_key failed");
    return -3;
  }

#endif

  return 0;
}

int aes_load_key(const char *key, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  (void) key;
  (void) ctx;
  return -1;
#else
  const uint8_t default_enc[] = {0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59,
                                 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c,
                                 0xc6, 0x55, 0xe4, 0x20};
  const uint8_t default_mac[] = {0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59,
                                 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
                                 0x05, 0xd2, 0xce, 0x0a};
  const uint8_t *k;

  if (key == NULL)
    return -1;
  if (!strcmp(key, "default_enc"))
    k = default_enc;
  else if (!strcmp(key, "default_mac"))
    k = default_mac;
  else
    return -1;

  return aes_set_key(k, sizeof(default_enc), ctx);
#endif
}

int aes_encrypt(const uint8_t *in, uint8_t *out, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyECB, (PUCHAR) in,
                                             AES_BLOCK_SIZE, NULL, NULL, 0, out,
                                             AES_BLOCK_SIZE, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != AES_BLOCK_SIZE) {
    return -2;
  }

  return 0;

#else

  AES_ecb_encrypt(in, out, &ctx->enc_key, AES_ENCRYPT);
  return 0;

#endif
}

int aes_decrypt(const uint8_t *in, uint8_t *out, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(ctx->hKeyECB, (PUCHAR) in,
                                             AES_BLOCK_SIZE, NULL, NULL, 0, out,
                                             AES_BLOCK_SIZE, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != AES_BLOCK_SIZE) {
    return -2;
  }

  return 0;

#else

  AES_ecb_encrypt(in, out, &ctx->dec_key, AES_DECRYPT);
  return 0;

#endif
}

int aes_cbc_encrypt(const uint8_t *in, uint8_t *out, uint16_t len,
                    const uint8_t *iv, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  UCHAR _iv[AES_BLOCK_SIZE];
  memcpy(_iv, iv, AES_BLOCK_SIZE);

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyCBC, (PUCHAR) in, len,
                                             NULL, _iv, AES_BLOCK_SIZE, out,
                                             len, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != len) {
    return -2;
  }

  return 0;

#else

  uint8_t _iv[AES_BLOCK_SIZE];
  memcpy(_iv, iv, AES_BLOCK_SIZE);
  AES_cbc_encrypt(in, out, len, &ctx->enc_key, _iv, AES_ENCRYPT);
  return 0;

#endif
}

int aes_cbc_decrypt(const uint8_t *in, uint8_t *out, uint16_t len,
                    const uint8_t *iv, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  UCHAR _iv[AES_BLOCK_SIZE];
  memcpy(_iv, iv, AES_BLOCK_SIZE);

  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(ctx->hKeyCBC, (PUCHAR) in, len,
                                             NULL, _iv, AES_BLOCK_SIZE, out,
                                             len, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != len) {
    return -2;
  }

  return 0;

#else

  uint8_t _iv[AES_BLOCK_SIZE];
  memcpy(_iv, iv, AES_BLOCK_SIZE);
  AES_cbc_encrypt(in, out, len, &ctx->dec_key, _iv, AES_DECRYPT);
  return 0;

#endif
}

int aes_add_padding(uint8_t *in, uint16_t max_len, uint16_t *len) {
  uint16_t new_len = *len;

  if (in) {
    if (new_len >= max_len) {
      return -1;
    }
    in[new_len] = 0x80;
  }
  new_len++;

  while (new_len % AES_BLOCK_SIZE != 0) {
    if (in) {
      if (new_len >= max_len) {
        return -2;
      }
      in[new_len] = 0x00;
    }
    new_len++;
  }

  *len = new_len;
  return 0;
}

void aes_remove_padding(uint8_t *in, uint16_t *len) {

  while ((*len) > 1 && in[(*len) - 1] == 0) {
    (*len)--;
  }

  if (*len > 0)
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

#else

  /* AES_KEY has no resources to free, just zero the key material */

#endif

  insecure_memzero(ctx, sizeof(aes_context));
}
