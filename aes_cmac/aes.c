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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define UNUSED(x) (void) (x)

#ifdef _WIN32_BCRYPT

void mserror(const char *str, int err);

void ncrypt_parse_name(wchar_t *name, const wchar_t **prov, const wchar_t **key,
                       DWORD *flags);

static SECURITY_STATUS import_aes_key(NCRYPT_PROV_HANDLE prov,
                                      NCRYPT_KEY_HANDLE *hkey, LPCWSTR name,
                                      const uint8_t *key, DWORD cb) {

  struct IMPORT_CIPHER_KEY_BLOB {
    NCRYPT_KEY_BLOB_HEADER nhdr;
    wchar_t algName[_countof(NCRYPT_AES_ALGORITHM)];
    BCRYPT_KEY_DATA_BLOB_HEADER bhdr;
    uint8_t keyData[32];
  } blob = {{sizeof(blob.nhdr), NCRYPT_CIPHER_KEY_BLOB_MAGIC,
             sizeof(blob.algName), sizeof(blob.bhdr) + cb},
            NCRYPT_AES_ALGORITHM,
            {BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, cb}};

  memcpy(blob.keyData, key, cb);

  DWORD tot = offsetof(struct IMPORT_CIPHER_KEY_BLOB, keyData) + cb;
  ULONG name_len = (ULONG) wcslen(name ? name : L"") + 1;
  NCryptBuffer cbuf = {name_len * sizeof(wchar_t), NCRYPTBUFFER_PKCS_KEY_NAME,
                       (PVOID) name};
  NCryptBufferDesc desc = {NCRYPTBUFFER_VERSION, 1, &cbuf};

  SECURITY_STATUS st =
    NCryptImportKey(prov, 0, NCRYPT_CIPHER_KEY_BLOB, name ? &desc : 0, hkey,
                    (PBYTE) &blob, tot,
                    NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG);
  if (st) {
    mserror("NCryptImportKey", st);
    return st;
  }
  DWORD length = cb * 8;
  st = NCryptSetProperty(*hkey, NCRYPT_LENGTH_PROPERTY, (PBYTE) &length,
                         sizeof(length), 0);
  if (st) {
    mserror("NCryptSetProperty", st);
    NCryptFreeObject(*hkey);
    return st;
  }
  st = NCryptFinalizeKey(*hkey, 0);
  if (st) {
    mserror("NCryptFinalizeKey", st);
    NCryptFreeObject(*hkey);
    return st;
  }
  return st;
}

#else

static const EVP_CIPHER *aes_ecb(uint32_t key_len) {
  switch (key_len) {
    case 16:
      return EVP_aes_128_ecb();
    case 24:
      return EVP_aes_192_ecb();
    case 32:
      return EVP_aes_256_ecb();
    default:
      return NULL;
  }
}

static const EVP_CIPHER *aes_cbc(uint32_t key_len) {
  switch (key_len) {
    case 16:
      return EVP_aes_128_cbc();
    case 24:
      return EVP_aes_192_cbc();
    case 32:
      return EVP_aes_256_cbc();
    default:
      return NULL;
  }
}

static int aes_cipher(const EVP_CIPHER *cipher, const uint8_t *in, uint8_t *out,
                      int len, const uint8_t *iv, int enc, aes_context *ctx) {
  if (EVP_CipherInit_ex(ctx->ctx, cipher, NULL, ctx->key, iv, enc) != 1) {
    return -1;
  }
  if (EVP_CIPHER_CTX_set_padding(ctx->ctx, 0) != 1) {
    return -2;
  }
  int update_len = len;
  if (EVP_CipherUpdate(ctx->ctx, out, &update_len, in, len) != 1) {
    return -3;
  }
  int final_len = len - update_len;
  if (EVP_CipherFinal_ex(ctx->ctx, out + update_len, &final_len) != 1) {
    return -4;
  }
  if (update_len + final_len != len) {
    return -5;
  }
  return 0;
}

#endif

int aes_set_key(const uint8_t *key, uint32_t key_len, aes_context *ctx) {
#ifdef _WIN32_BCRYPT

  SECURITY_STATUS st = 0;

  if (!ctx->hProvider) {
    st = NCryptOpenStorageProvider(&ctx->hProvider, MS_KEY_STORAGE_PROVIDER, 0);
    if (st) {
      mserror("NCryptOpenStorageProvider", st);
      return -1;
    }
  }

  if (ctx->hKeyCBC) {
    st = NCryptFreeObject(ctx->hKeyCBC);
    ctx->hKeyCBC = 0;
  }

  if (ctx->hKeyECB) {
    st = NCryptFreeObject(ctx->hKeyECB);
    ctx->hKeyECB = 0;
  }

  st = import_aes_key(ctx->hProvider, &ctx->hKeyCBC, NULL, key, key_len);
  if (st) {
    return -2;
  }

  st = NCryptSetProperty(ctx->hKeyCBC, NCRYPT_CHAINING_MODE_PROPERTY,
                         (PBYTE) BCRYPT_CHAIN_MODE_CBC,
                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (st) {
    mserror("NCryptSetProperty", st);
    return -3;
  }

  st = import_aes_key(ctx->hProvider, &ctx->hKeyECB, NULL, key, key_len);
  if (st) {
    return -4;
  }

  st = NCryptSetProperty(ctx->hKeyECB, NCRYPT_CHAINING_MODE_PROPERTY,
                         (PBYTE) BCRYPT_CHAIN_MODE_ECB,
                         sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
  if (st) {
    mserror("NCryptSetProperty", st);
    return -5;
  }

#else

  if (key == NULL || aes_ecb(key_len) == NULL) {
    return -1;
  }
  if (!ctx->ctx) {
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (!ctx->ctx) {
      return -2;
    }
  }
  ctx->key_len = key_len;
  memcpy(ctx->key, key, key_len);

#endif

  return 0;
}

int aes_load_key(const char *key, aes_context *ctx) {
#ifdef _WIN32_BCRYPT
  aes_destroy(ctx);

  size_t n = 0;
  DWORD flags = 0;
  wchar_t buf[2048] = {0}, *prov, *wkey;
  mbstowcs_s(&n, buf, _countof(buf), key, _TRUNCATE);
  ncrypt_parse_name(buf, &prov, &wkey, &flags);

  SECURITY_STATUS st = NCryptOpenStorageProvider(&ctx->hProvider, prov, 0);
  if (st) {
    mserror("NCryptOpenStorageProvider", st);
    return -1;
  }

  st = NCryptOpenKey(ctx->hProvider, &ctx->hKeyCBC, wkey, 0, flags);
  if (st) {
    mserror("NCryptOpenKey", st);
    return -2;
  }

  st = NCryptOpenKey(ctx->hProvider, &ctx->hKeyECB, wkey, 0, flags);
  if (st) {
    mserror("NCryptOpenKey", st);
    return -3;
  }

  st = NCryptSetProperty(ctx->hKeyCBC, NCRYPT_CHAINING_MODE_PROPERTY,
                         (PBYTE) BCRYPT_CHAIN_MODE_CBC,
                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (st) {
    mserror("NCryptSetProperty", st);
    return -4;
  }

  st = NCryptSetProperty(ctx->hKeyECB, NCRYPT_CHAINING_MODE_PROPERTY,
                         (PBYTE) BCRYPT_CHAIN_MODE_ECB,
                         sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
  if (st) {
    mserror("NCryptSetProperty", st);
    return -5;
  }
  return 0;
#else
  UNUSED(key);
  UNUSED(ctx);
  return -1;
#endif
}

int aes_generate_key(const char *name, uint8_t *key, uint32_t key_len) {
#ifdef _WIN32_BCRYPT
  NCRYPT_PROV_HANDLE prov = 0;
  NCRYPT_KEY_HANDLE hkey = 0;

  size_t n = 0;
  wchar_t wkey[2048] = {0};
  mbstowcs_s(&n, wkey, _countof(wkey), name, _TRUNCATE);

  const wchar_t *provname = 0, *keyname = 0;
  DWORD flags = 0;
  ncrypt_parse_name(wkey, &provname, &keyname, &flags);

  int rc = 0;
  SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, provname, 0);
  if (st) {
    mserror("NCryptOpenStorageProvider", st);
    rc = -1;
    goto err;
  }

  st = NCryptCreatePersistedKey(prov, &hkey, NCRYPT_AES_ALGORITHM, keyname, 0,
                                NCRYPT_OVERWRITE_KEY_FLAG | flags);
  if (st) {
    mserror("NCryptCreatePersistedKey", st);
    rc = -2;
    goto err;
  }

  DWORD length = key_len * 8;
  st = NCryptSetProperty(hkey, NCRYPT_LENGTH_PROPERTY, (PBYTE) &length,
                         sizeof(length), 0);
  if (st) {
    mserror("NCryptSetProperty length", st);
    NCryptFreeObject(hkey);
    rc = -3;
    goto err;
  }

  DWORD policy = NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG;
  st = NCryptSetProperty(hkey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE) &policy,
                         sizeof(policy), 0);
  if (st) {
    mserror("NCryptSetProperty export policy", st);
    NCryptFreeObject(hkey);
    rc = -4;
    goto err;
  }

  st = NCryptFinalizeKey(hkey, 0);
  if (st) {
    mserror("NCryptFinalizeKey", st);
    rc = -5;
    goto err;
  }

  struct EXPORT_CIPHER_KEY_BLOB {
    NCRYPT_KEY_BLOB_HEADER nhdr;
    wchar_t algName[_countof(NCRYPT_AES_ALGORITHM)];
    BCRYPT_KEY_DATA_BLOB_HEADER bhdr;
    uint8_t keyData[32];
  } blob = {0};

  DWORD cb = 0;
  st = NCryptExportKey(hkey, 0, NCRYPT_CIPHER_KEY_BLOB, 0, (PBYTE) &blob,
                       sizeof(blob), &cb, 0);
  if (st) {
    mserror("NCryptExportKey", st);
    rc = -6;
    goto err;
  }

  if (blob.nhdr.dwMagic != NCRYPT_CIPHER_KEY_BLOB_MAGIC) {
    rc = -7;
    goto err;
  }

  if (blob.bhdr.dwMagic != BCRYPT_KEY_DATA_BLOB_MAGIC) {
    rc = -8;
    goto err;
  }

  if (blob.bhdr.cbKeyData > key_len) {
    rc = -9;
    goto err;
  }

  memcpy(key, blob.keyData, blob.bhdr.cbKeyData);
  memset(blob.keyData, 0, blob.bhdr.cbKeyData);
  rc = blob.bhdr.cbKeyData;

err:
  if (hkey) {
    NCryptFreeObject(hkey);
  }
  if (prov) {
    NCryptFreeObject(prov);
  }
  return rc;
#else
  UNUSED(name);
  UNUSED(key);
  UNUSED(key_len);
  return -1;
#endif
}

int aes_encrypt(const uint8_t *in, uint8_t *out, uint32_t len,
                aes_context *ctx) {
#ifdef _WIN32_BCRYPT

  DWORD cb = 0;
  SECURITY_STATUS st =
    NCryptEncrypt(ctx->hKeyECB, (PBYTE) in, len, NULL, out, len, &cb, 0);

  if (st) {
    mserror("NCryptEncrypt", st);
    return -1;
  }

  if (cb != len) {
    return -2;
  }

  return 0;

#else

  return aes_cipher(aes_ecb(ctx->key_len), in, out, len, NULL, 1, ctx);

#endif
}

int aes_decrypt(const uint8_t *in, uint8_t *out, uint32_t len,
                aes_context *ctx) {
#ifdef _WIN32_BCRYPT

  DWORD cb = 0;
  SECURITY_STATUS st =
    NCryptDecrypt(ctx->hKeyECB, (PBYTE) in, len, NULL, out, len, &cb, 0);

  if (st) {
    mserror("NCryptDecrypt", st);
    return -1;
  }

  if (cb != len) {
    return -2;
  }

  return 0;

#else

  return aes_cipher(aes_ecb(ctx->key_len), in, out, len, NULL, 0, ctx);

#endif
}

int aes_cbc_encrypt(const uint8_t *in, uint8_t *out, uint32_t len,
                    const uint8_t *iv, aes_context *ctx) {
#ifdef _WIN32_BCRYPT

  DWORD cb = 0;
  uint8_t ivbuf[AES_BLOCK_SIZE] = {0};
  memcpy(ivbuf, iv, sizeof(ivbuf));
  NCRYPT_CIPHER_PADDING_INFO pad = {sizeof(NCRYPT_CIPHER_PADDING_INFO),
                                    NCRYPT_CIPHER_NO_PADDING_FLAG, ivbuf,
                                    sizeof(ivbuf)};
  SECURITY_STATUS st = NCryptEncrypt(ctx->hKeyCBC, (PBYTE) in, len, &pad, out,
                                     len, &cb, NCRYPT_PAD_CIPHER_FLAG);

  if (st) {
    mserror("NCryptEncrypt", st);
    return -1;
  }

  if (cb != len) {
    return -2;
  }

  return 0;

#else

  return aes_cipher(aes_cbc(ctx->key_len), in, out, len, iv, 1, ctx);

#endif
}

int aes_cbc_decrypt(const uint8_t *in, uint8_t *out, uint32_t len,
                    const uint8_t *iv, aes_context *ctx) {
#ifdef _WIN32_BCRYPT

  DWORD cb = 0;
  uint8_t ivbuf[AES_BLOCK_SIZE] = {0};
  memcpy(ivbuf, iv, sizeof(ivbuf));
  NCRYPT_CIPHER_PADDING_INFO pad = {sizeof(NCRYPT_CIPHER_PADDING_INFO),
                                    NCRYPT_CIPHER_NO_PADDING_FLAG, ivbuf,
                                    sizeof(ivbuf)};
  SECURITY_STATUS st = NCryptDecrypt(ctx->hKeyCBC, (PBYTE) in, len, &pad, out,
                                     len, &cb, NCRYPT_PAD_CIPHER_FLAG);

  if (st) {
    mserror("NCryptDecrypt", st);
    return -1;
  }

  if (cb != len) {
    return -2;
  }

  return 0;

#else

  return aes_cipher(aes_cbc(ctx->key_len), in, out, len, iv, 0, ctx);

#endif
}

int aes_add_padding(uint8_t *in, uint32_t max_len, uint32_t *len) {
  uint32_t new_len = *len;

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

void aes_remove_padding(uint8_t *in, uint32_t *len) {

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
    NCryptFreeObject(ctx->hKeyCBC);
  }
  if (ctx->hKeyECB) {
    NCryptFreeObject(ctx->hKeyECB);
  }
  if (ctx->hProvider) {
    NCryptFreeObject(ctx->hProvider);
  }

#else

  EVP_CIPHER_CTX_free(ctx->ctx);

#endif

  insecure_memzero(ctx, sizeof(aes_context));
}
