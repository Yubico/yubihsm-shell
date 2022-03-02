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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <ncrypt.h>
#else
#include <dlfcn.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>

#include "openssl-compat.h"
#include "../pkcs11/pkcs11.h"
#endif

#include "ecdh.h"

#define UNUSED(x) (void) (x)

#ifdef _WIN32_BCRYPT

static const uint8_t n_P256[] = "\xff\xff\xff\xff\x00\x00\x00\x00"
                                "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xbc\xe6\xfa\xad\xa7\x17\x9e\x84"
                                "\xf3\xb9\xca\xc2\xfc\x63\x25\x51";

static const uint8_t n_P384[] = "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xc7\x63\x4d\x81\xf4\x37\x2d\xdf"
                                "\x58\x1a\x0d\xb2\x48\xb0\xa7\x7a"
                                "\xec\xec\x19\x6a\xcc\xc5\x29\x73";

static const uint8_t n_P521[] = "\x01\xff\xff\xff\xff\xff\xff\xff"
                                "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xff\xff\xff\xff\xff\xff\xff\xff"
                                "\xff\xfa\x51\x86\x87\x83\xbf\x2f"
                                "\x96\x6b\x7f\xcc\x01\x48\xf7\x09"
                                "\xa5\xd0\x3b\xb5\xc9\xb8\x89\x9c"
                                "\x47\xae\xbb\x6f\xb7\x1e\x91\x38"
                                "\x64\x09";

static const uint8_t *order[] = {0, n_P256, n_P384, n_P521};
static const ULONG bits[] = {0, 256, 384, 521};
static const ULONG bytes[] = {0, _countof(n_P256) - 1, _countof(n_P384) - 1,
                              _countof(n_P521) - 1};
static const BCRYPT_ALG_HANDLE curves[] = {NULL, BCRYPT_ECDH_P256_ALG_HANDLE,
                                           BCRYPT_ECDH_P384_ALG_HANDLE,
                                           BCRYPT_ECDH_P521_ALG_HANDLE};
static const ULONG priv_magic[] = {0, BCRYPT_ECDH_PRIVATE_P256_MAGIC,
                                   BCRYPT_ECDH_PRIVATE_P384_MAGIC,
                                   BCRYPT_ECDH_PRIVATE_P521_MAGIC};
static const ULONG pub_magic[] = {0, BCRYPT_ECDH_PUBLIC_P256_MAGIC,
                                  BCRYPT_ECDH_PUBLIC_P384_MAGIC,
                                  BCRYPT_ECDH_PUBLIC_P521_MAGIC};
static const LPCWSTR algo[] = {NCRYPT_AES_ALGORITHM, NCRYPT_ECDH_P256_ALGORITHM,
                               NCRYPT_ECDH_P384_ALGORITHM,
                               NCRYPT_ECDH_P521_ALGORITHM};

int ecdh_curve_p256(void) { return 1; }
int ecdh_curve_p384(void) { return 2; }
int ecdh_curve_p521(void) { return 3; }

static int bn_cmp(const uint8_t *a, const uint8_t *b, size_t cb) {
  for (size_t i = 0; i < cb; i++) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }
  return 0;
}

static int validate_privkey(int curve, const uint8_t *privkey,
                            size_t cb_privkey) {
  return cb_privkey == bytes[curve] &&
         bn_cmp(privkey, order[curve], cb_privkey) < 0;
}

void mserror(const char *str, int err) {
  char errbuf[128] = "FormatMessage failed";
  HMODULE module = LoadLibraryA("NTDLL.DLL");
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE |
                   FORMAT_MESSAGE_IGNORE_INSERTS |
                   FORMAT_MESSAGE_MAX_WIDTH_MASK,
                 module, err, 0, errbuf, sizeof(errbuf), NULL);
  fprintf(stderr, "%s: (0x%08X) %s\n", str, err, errbuf);
  if (module) {
    FreeLibrary(module);
  }
}

int ecdh_load_module(const char *module, FILE *out) {
  UNUSED(module);
  return 0;
}

int ecdh_list_providers(void *ctx,
                        int (*callback)(void *ctx, const char *provider)) {
  NCryptProviderName *names = 0;
  DWORD count = 0;
  SECURITY_STATUS st = NCryptEnumStorageProviders(&count, &names, 0);
  if (st) {
    mserror("NCryptEnumStorageProviders", st);
    return -1;
  }
  for (DWORD i = 0; i < count; i++) {
    char buf[2048];
    sprintf_s(buf, sizeof(buf), "%ws", names[i].pszName);
    callback(ctx, buf);
  }
  st = NCryptFreeBuffer(names);
  if (st) {
    mserror("NCryptFreeBuffer", st);
  }
  return 0;
}

int ecdh_list_keys(int curve, void *ctx,
                   int (*callback)(void *ctx, const char *key)) {
  NCryptProviderName *names = 0;
  DWORD count = 0;
  SECURITY_STATUS st =
    NCryptEnumStorageProviders(&count, &names, NCRYPT_SILENT_FLAG);
  if (st) {
    mserror("NCryptEnumStorageProviders", st);
    return -1;
  }
  for (DWORD i = 0; i < count; i++) {
    NCRYPT_PROV_HANDLE prov = 0;
    st = NCryptOpenStorageProvider(&prov, names[i].pszName, 0);
    if (st) {
      mserror("NCryptOpenStorageProvider", st);
    } else {
      PVOID state = 0;
      NCryptKeyName *name = 0;
      char buf[2048] = {0};
      while ((st = NCryptEnumKeys(prov, 0, &name, &state,
                                  NCRYPT_SILENT_FLAG |
                                    NCRYPT_MACHINE_KEY_FLAG)) == 0) {
        if (wcsstr(algo[curve], name->pszAlgid)) {
          sprintf_s(buf, sizeof(buf), "MACHINE:%ws:%ws", names[i].pszName,
                    name->pszName);
          callback(ctx, buf);
        }
        st = NCryptFreeBuffer(name);
        name = 0;
        if (st) {
          mserror("NCryptFreeBuffer", st);
        }
      }
      if (st && st != NTE_NO_MORE_ITEMS && st != NTE_BAD_FLAGS &&
          st != NTE_PERM) {
        mserror("NCryptEnumKeys", st);
      }
      st = NCryptFreeBuffer(state);
      if (st) {
        mserror("NCryptFreeBuffer", st);
      }
      state = 0;
      name = 0;
      while ((st = NCryptEnumKeys(prov, 0, &name, &state,
                                  NCRYPT_SILENT_FLAG)) == 0) {
        if (wcsstr(algo[curve], name->pszAlgid)) {
          sprintf_s(buf, sizeof(buf), "%ws:%ws", names[i].pszName,
                    name->pszName);
          callback(ctx, buf);
        }
        st = NCryptFreeBuffer(name);
        name = 0;
        if (st) {
          mserror("NCryptFreeBuffer", st);
        }
      }
      if (st && st != NTE_NO_MORE_ITEMS && st != NTE_BAD_FLAGS &&
          st != NTE_PERM) {
        mserror("NCryptEnumKeys", st);
      }
      st = NCryptFreeBuffer(state);
      if (st) {
        mserror("NCryptFreeBuffer", st);
      }
      st = NCryptFreeObject(prov);
      if (st) {
        mserror("NCryptFreeObject", st);
      }
    }
  }
  st = NCryptFreeBuffer(names);
  if (st) {
    mserror("NCryptFreeBuffer", st);
  }
  return 0;
}

void ncrypt_parse_name(wchar_t *name, const wchar_t **prov, const wchar_t **key,
                       DWORD *flags) {
  const wchar_t delim[] = L":";
  wchar_t *context = 0;
  const wchar_t *sys = wcstok_s(name, delim, &context);
  *prov = wcstok_s(0, delim, &context);
  *key = wcstok_s(0, delim, &context);
  if (!*prov) {
    *key = sys;
    *prov = MS_KEY_STORAGE_PROVIDER;
    sys = delim; // Anything but MACHINE will do so reuse delim
  }
  if (!*key) {
    *key = *prov;
    *prov = sys;
    sys = delim; // Anything but MACHINE will do so reuse delim
  }
  *flags = _wcsicmp(sys, L"MACHINE") ? 0 : NCRYPT_MACHINE_KEY_FLAG;
}

SECURITY_STATUS ncrypt_open_key(const char *keyname, NCRYPT_PROV_HANDLE *ph,
                                NCRYPT_KEY_HANDLE *kh) {
  size_t n = 0;
  wchar_t buf[2048] = {0};
  mbstowcs_s(&n, buf, _countof(buf), keyname, _TRUNCATE);
  const wchar_t *prov = 0, *key = 0;
  DWORD flags = 0;
  ncrypt_parse_name(buf, &prov, &key, &flags);
  SECURITY_STATUS st = NCryptOpenStorageProvider(ph, prov, 0);
  if (st) {
    mserror("NCryptOpenStorageProvider", st);
  } else {
    st = NCryptOpenKey(*ph, kh, key, 0, flags);
    if (st) {
      mserror("NCryptOpenKey", st);
      NCryptFreeObject(*ph);
    }
  }
  return st;
}

int ecdh_calculate_public_key(int curve, const uint8_t *privkey,
                              size_t cb_privkey, uint8_t *pubkey,
                              size_t cb_pubkey) {
  int rc = 0;
  if (validate_privkey(curve, privkey, cb_privkey)) {
    uint8_t buf[256];
    BCRYPT_ECCKEY_BLOB *blob = (BCRYPT_ECCKEY_BLOB *) buf;
    blob->dwMagic = priv_magic[curve];
    blob->cbKey = (ULONG) cb_privkey;
    memset(buf + sizeof(BCRYPT_ECCKEY_BLOB), 0, 2 * cb_privkey);
    memcpy(buf + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cb_privkey, privkey,
           cb_privkey);
    BCRYPT_KEY_HANDLE key;
    NTSTATUS status =
      BCryptImportKeyPair(curves[curve], NULL, BCRYPT_ECCPRIVATE_BLOB, &key,
                          buf,
                          (ULONG) (sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cb_privkey),
                          BCRYPT_NO_KEY_VALIDATION);
    if (BCRYPT_SUCCESS(status)) {
      ULONG cb;
      status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, buf,
                               sizeof(buf), &cb, 0);
      if (BCRYPT_SUCCESS(status) && cb_pubkey > 2ull * blob->cbKey) {
        *pubkey = 4;
        memcpy(pubkey + 1, buf + sizeof(BCRYPT_ECCKEY_BLOB),
               2ull * blob->cbKey);
        rc = 1 + 2 * blob->cbKey;
      }
      BCryptDestroyKey(key);
    }
  }
  return rc;
}

int ecdh_generate_keypair(int curve, uint8_t *privkey, size_t cb_privkey,
                          uint8_t *pubkey, size_t cb_pubkey) {
  int rc = 0;
  BCRYPT_KEY_HANDLE key;
  NTSTATUS status = BCryptGenerateKeyPair(curves[curve], &key, bits[curve], 0);
  if (BCRYPT_SUCCESS(status)) {
    status = BCryptFinalizeKeyPair(key, 0);
    if (BCRYPT_SUCCESS(status)) {
      uint8_t buf[256];
      ULONG cb;
      status = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, buf,
                               sizeof(buf), &cb, 0);
      BCRYPT_ECCKEY_BLOB *blob = (BCRYPT_ECCKEY_BLOB *) buf;
      if (BCRYPT_SUCCESS(status) && cb_privkey >= blob->cbKey &&
          cb_pubkey > 2ull * blob->cbKey) {
        *pubkey = 4;
        memcpy(pubkey + 1, buf + sizeof(BCRYPT_ECCKEY_BLOB),
               2ull * blob->cbKey);
        memcpy(privkey, buf + sizeof(BCRYPT_ECCKEY_BLOB) + 2ull * blob->cbKey,
               blob->cbKey);
        rc = blob->cbKey;
      }
    }
    BCryptDestroyKey(key);
  }
  return rc;
}

int ecdh_calculate_secret(int curve, const uint8_t *privkey, size_t cb_privkey,
                          const uint8_t *pubkey, size_t cb_pubkey,
                          uint8_t *secret, size_t cb_secret) {
  int rc = 0;
  uint8_t buf[256];
  BCRYPT_ECCKEY_BLOB *blob = (BCRYPT_ECCKEY_BLOB *) buf;
  blob->dwMagic = priv_magic[curve];
  blob->cbKey = (ULONG) cb_privkey;
  memset(buf + sizeof(BCRYPT_ECCKEY_BLOB), 0, 2 * cb_privkey);
  memcpy(buf + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cb_privkey, privkey,
         cb_privkey);
  BCRYPT_KEY_HANDLE priv;
  NTSTATUS status =
    BCryptImportKeyPair(curves[curve], NULL, BCRYPT_ECCPRIVATE_BLOB, &priv, buf,
                        (ULONG) (sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cb_privkey),
                        BCRYPT_NO_KEY_VALIDATION);
  if (BCRYPT_SUCCESS(status)) {
    blob->dwMagic = pub_magic[curve];
    blob->cbKey = (ULONG) cb_privkey;
    memcpy(buf + sizeof(BCRYPT_ECCKEY_BLOB), pubkey + 1, cb_pubkey - 1);
    BCRYPT_KEY_HANDLE pub;
    status =
      BCryptImportKeyPair(curves[curve], NULL, BCRYPT_ECCPUBLIC_BLOB, &pub, buf,
                          (ULONG) (sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cb_privkey),
                          0);
    if (BCRYPT_SUCCESS(status)) {
      BCRYPT_SECRET_HANDLE sec;
      status = BCryptSecretAgreement(priv, pub, &sec, 0);
      if (BCRYPT_SUCCESS(status)) {
        ULONG cb;
        status = BCryptDeriveKey(sec, BCRYPT_KDF_RAW_SECRET, NULL, secret,
                                 (ULONG) cb_secret, &cb, 0);
        if (BCRYPT_SUCCESS(status)) {
          // BCRYPT_KDF_RAW_SECRET returns little-endian so reverse the array
          for (ULONG c = 0; c < cb / 2; c++) {
            uint8_t t = secret[c];
            secret[c] = secret[cb - c - 1];
            secret[cb - c - 1] = t;
          }
          rc = cb;
        }
        BCryptDestroySecret(sec);
      }
      BCryptDestroyKey(pub);
    }
    BCryptDestroyKey(priv);
  }
  return rc;
}

int ecdh_generate_keypair_ex(int curve, const char *privkey, uint8_t *pubkey,
                             size_t cb_pubkey) {
  NCRYPT_PROV_HANDLE prov = 0;
  NCRYPT_KEY_HANDLE priv = 0;

  size_t n = 0;
  wchar_t wkey[2048] = {0};
  mbstowcs_s(&n, wkey, _countof(wkey), privkey, _TRUNCATE);

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

  st = NCryptCreatePersistedKey(prov, &priv, algo[curve], keyname, 0,
                                NCRYPT_OVERWRITE_KEY_FLAG | flags);
  if (st) {
    mserror("NCryptCreatePersistedKey", st);
    rc = -2;
    goto err;
  }

  st = NCryptFinalizeKey(priv, 0);
  if (st) {
    mserror("NCryptFinalizeKey", st);
    rc = -3;
    goto err;
  }

  DWORD cb = 0;
  uint8_t buf[256] = {0};
  BCRYPT_ECCKEY_BLOB *blob = (BCRYPT_ECCKEY_BLOB *) buf;
  st = NCryptExportKey(priv, 0, BCRYPT_ECCPUBLIC_BLOB, 0, buf, sizeof(buf), &cb,
                       0);

  if (st) {
    mserror("NCryptExportKey", st);
    rc = -4;
    goto err;
  }

  if (blob->dwMagic != pub_magic[curve]) {
    rc = -5;
    goto err;
  }

  if (cb_pubkey < 1 + 2ull * blob->cbKey) {
    rc = -6;
    goto err;
  }

  *pubkey = 4;
  memcpy(pubkey + 1, buf + sizeof(BCRYPT_ECCKEY_BLOB), 2ull * blob->cbKey);

  rc = 1 + 2 * blob->cbKey;
err:
  NCryptFreeObject(priv);
  NCryptFreeObject(prov);
  return rc;
}

int ecdh_calculate_public_key_ex(int curve, const char *privkey,
                                 uint8_t *pubkey, size_t cb_pubkey) {
  NCRYPT_PROV_HANDLE prov = 0;
  NCRYPT_KEY_HANDLE priv = 0;
  int rc = 0;

  SECURITY_STATUS st = ncrypt_open_key(privkey, &prov, &priv);
  if (st) {
    rc = -1;
    goto err;
  }

  DWORD cb = 0;
  uint8_t buf[256] = {0};
  BCRYPT_ECCKEY_BLOB *blob = (BCRYPT_ECCKEY_BLOB *) buf;
  st = NCryptExportKey(priv, 0, BCRYPT_ECCPUBLIC_BLOB, 0, buf, sizeof(buf), &cb,
                       0);

  if (st) {
    mserror("NCryptExportKey", st);
    rc = -2;
    goto err;
  }

  if (blob->dwMagic != pub_magic[curve]) {
    rc = -3;
    goto err;
  }

  if (cb_pubkey < 1 + 2ull * blob->cbKey) {
    rc = -4;
    goto err;
  }

  *pubkey = 4;
  memcpy(pubkey + 1, buf + sizeof(BCRYPT_ECCKEY_BLOB), 2ull * blob->cbKey);

  rc = 1 + 2 * blob->cbKey;
err:
  NCryptFreeObject(priv);
  NCryptFreeObject(prov);
  return rc;
}

int ecdh_calculate_secret_ex(int curve, const char *privkey,
                             const uint8_t *pubkey, size_t cb_pubkey,
                             uint8_t *secret, size_t cb_secret) {
  NCRYPT_PROV_HANDLE prov = 0;
  NCRYPT_KEY_HANDLE priv = 0;
  NCRYPT_KEY_HANDLE pub = 0;
  NCRYPT_SECRET_HANDLE sec = 0;
  int rc = 0;

  SECURITY_STATUS st = ncrypt_open_key(privkey, &prov, &priv);
  if (st) {
    rc = -1;
    goto err;
  }

  uint8_t buf[256] = {0};
  BCRYPT_ECCKEY_BLOB *blob = (BCRYPT_ECCKEY_BLOB *) buf;

  blob->dwMagic = pub_magic[curve];
  blob->cbKey = (ULONG) (cb_pubkey / 2);
  memcpy(buf + sizeof(BCRYPT_ECCKEY_BLOB), pubkey + 1, 2ull * blob->cbKey);

  st = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, 0, &pub, buf,
                       sizeof(BCRYPT_ECCKEY_BLOB) + 2ull * blob->cbKey, 0);
  if (st) {
    mserror("NCryptImportKey", st);
    rc = -2;
    goto err;
  }

  st = NCryptSecretAgreement(priv, pub, &sec, 0);
  if (st) {
    mserror("NCryptSecretAgreement", st);
    rc = -3;
    goto err;
  }

  DWORD cb = 0;
  st = NCryptDeriveKey(sec, BCRYPT_KDF_RAW_SECRET, 0, secret, (DWORD) cb_secret,
                       &cb, 0);
  if (st) {
    mserror("NCryptDeriveKey", st);
    rc = -4;
    goto err;
  }

  // BCRYPT_KDF_RAW_SECRET returns little-endian so reverse the array
  for (DWORD c = 0; c < cb / 2; c++) {
    uint8_t t = secret[c];
    secret[c] = secret[cb - c - 1];
    secret[cb - c - 1] = t;
  }

  rc = cb;

err:
  NCryptFreeObject(sec);
  NCryptFreeObject(pub);
  NCryptFreeObject(priv);
  NCryptFreeObject(prov);
  return rc;
}

int ecdh_destroy_key_ex(const char *privkey) {
  NCRYPT_PROV_HANDLE prov = 0;
  NCRYPT_KEY_HANDLE hkey = 0;
  SECURITY_STATUS st = ncrypt_open_key(privkey, &prov, &hkey);
  if (st) {
    return -1;
  }
  if (prov) {
    NCryptFreeObject(prov);
  }
  if (hkey) {
    st = NCryptDeleteKey(hkey, 0);
    if (st) {
      mserror("NCryptDeleteKey", st);
      return -2;
    }
  }
  return 1;
}

#else

int ecdh_curve_p256(void) { return NID_X9_62_prime256v1; }
int ecdh_curve_p384(void) { return NID_secp384r1; }
int ecdh_curve_p521(void) { return NID_secp521r1; }

int ecdh_calculate_public_key(int curve, const uint8_t *privkey,
                              size_t cb_privkey, uint8_t *pubkey,
                              size_t cb_pubkey) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *order = BN_new();
  BIGNUM *pvt = BN_bin2bn(privkey, cb_privkey, NULL);
  EC_GROUP *group = EC_GROUP_new_by_curve_name(curve);
  EC_POINT *pub = NULL;
  size_t cb = 0;
  if (ctx == NULL || order == NULL || pvt == NULL || group == NULL) {
    goto err;
  }
  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
  if (BN_is_zero(pvt) || !EC_GROUP_get_order(group, order, ctx) ||
      BN_cmp(pvt, order) >= 0) {
    goto err;
  }
  pub = EC_POINT_new(group);
  if (pub == NULL || !EC_POINT_mul(group, pub, pvt, NULL, NULL, ctx)) {
    goto err;
  }
  cb = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pubkey,
                          cb_pubkey, ctx);
err:
  EC_POINT_free(pub);
  EC_GROUP_free(group);
  BN_free(pvt);
  BN_free(order);
  BN_CTX_free(ctx);
  return (int) cb;
}

int ecdh_generate_keypair(int curve, uint8_t *privkey, size_t cb_privkey,
                          uint8_t *pubkey, size_t cb_pubkey) {
  EC_KEY *key = EC_KEY_new_by_curve_name(curve);
  if (key == NULL || !EC_KEY_generate_key(key)) {
    EC_KEY_free(key);
    return 0;
  }
  int len = BN_bn2binpad(EC_KEY_get0_private_key(key), privkey, cb_privkey);
  if (len <= 0) {
    EC_KEY_free(key);
    return len;
  }
  size_t cb =
    EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                       POINT_CONVERSION_UNCOMPRESSED, pubkey, cb_pubkey, NULL);
  if (cb == 0 || cb > cb_pubkey) {
    EC_KEY_free(key);
    return 0;
  }
  EC_KEY_free(key);
  return len;
}

int ecdh_calculate_secret(int curve, const uint8_t *privkey, size_t cb_privkey,
                          const uint8_t *pubkey, size_t cb_pubkey,
                          uint8_t *secret, size_t cb_secret) {
  EC_KEY *priv = EC_KEY_new_by_curve_name(curve);
  EC_KEY *pub = EC_KEY_new_by_curve_name(curve);
  EC_POINT *point = NULL;
  int len = 0;
  if (priv == NULL || pub == NULL ||
      !EC_KEY_set_private_key(priv, BN_bin2bn(privkey, cb_privkey, NULL))) {
    goto err;
  }
  point = EC_POINT_new(EC_KEY_get0_group(pub));
  if (point == NULL || !EC_POINT_oct2point(EC_KEY_get0_group(pub), point,
                                           pubkey, cb_pubkey, NULL)) {
    goto err;
  }
  if (!EC_KEY_set_public_key(pub, point) || !EC_KEY_check_key(pub)) {
    goto err;
  }
  len = ECDH_compute_key(secret, cb_secret, EC_KEY_get0_public_key(pub), priv,
                         NULL);
err:
  EC_POINT_free(point);
  EC_KEY_free(pub);
  EC_KEY_free(priv);
  return len;
}

static CK_FUNCTION_LIST function_list;

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs) {
  UNUSED(pInitArgs);
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved) {
  UNUSED(pReserved);
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo) {

  pInfo->cryptokiVersion = function_list.version;

  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  memcpy(pInfo->manufacturerID, "Yubico", 6);

  pInfo->flags = 0;

  memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
  memcpy(pInfo->libraryDescription, "Internal", 8);

  pInfo->libraryVersion.major = 1;
  pInfo->libraryVersion.minor = 0;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)
(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {

  *ppFunctionList = &function_list;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {

  UNUSED(tokenPresent);
  UNUSED(pSlotList);
  UNUSED(pulCount);

  *pulCount = 2;
  for (CK_ULONG i = 0; i < *pulCount; i++) {
    pSlotList[i] = i;
  }

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)
(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {

  int len =
    sprintf((char *) pInfo->slotDescription, "Fake Provider %lu", slotID);
  memset(pInfo->slotDescription + len, ' ',
         sizeof(pInfo->slotDescription) - len);

  len = sprintf((char *) pInfo->manufacturerID, "Fake  Manufacturer");
  memset(pInfo->manufacturerID + len, ' ', sizeof(pInfo->manufacturerID) - len);

  pInfo->hardwareVersion.major = 1;
  pInfo->hardwareVersion.minor = 0;

  pInfo->firmwareVersion.major = 1;
  pInfo->firmwareVersion.minor = 0;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {

  int len = sprintf((char *) pInfo->label, "Fake Label %lu", slotID);
  memset(pInfo->label + len, ' ', sizeof(pInfo->label) - len);

  len = sprintf((char *) pInfo->manufacturerID, "Fake Manufacturer");
  memset(pInfo->manufacturerID + len, ' ', sizeof(pInfo->manufacturerID) - len);

  len = sprintf((char *) pInfo->model, "Fake Model");
  memset(pInfo->model + len, ' ', sizeof(pInfo->model) - len);

  len = sprintf((char *) pInfo->serialNumber, "12345-%lu", slotID);
  memset(pInfo->serialNumber + len, ' ', sizeof(pInfo->serialNumber) - len);

  pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED |
                 CKF_TOKEN_INITIALIZED;

  pInfo->ulMaxSessionCount =
    CK_EFFECTIVELY_INFINITE; // maximum number of sessions that can be opened
                             // with the token at one time by a single
                             // application
  pInfo->ulSessionCount =
    CK_UNAVAILABLE_INFORMATION; // number of sessions that this application
                                // currently has open with the token
  pInfo->ulMaxRwSessionCount =
    CK_EFFECTIVELY_INFINITE; // maximum number of read/write sessions that can
                             // be opened with the token at one time by a single
                             // application
  pInfo->ulRwSessionCount =
    CK_UNAVAILABLE_INFORMATION; // number of read/write sessions that this
                                // application currently has open with the token
  pInfo->ulMaxPinLen = 6;       // maximum length in bytes of the PIN
  pInfo->ulMinPinLen = 8;       // minimum length in bytes of the PIN

  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  CK_VERSION ver = {1, 0};

  pInfo->hardwareVersion = ver;

  pInfo->firmwareVersion = ver;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
 CK_ULONG_PTR pulCount) {

  UNUSED(slotID);
  UNUSED(pMechanismList);

  *pulCount = 0;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {

  UNUSED(slotID);
  UNUSED(type);
  UNUSED(pInfo);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
 CK_UTF8CHAR_PTR pLabel) {

  UNUSED(slotID);
  UNUSED(pPin);
  UNUSED(ulPinLen);
  UNUSED(pLabel);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {

  UNUSED(hSession);
  UNUSED(pPin);
  UNUSED(ulPinLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
 CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {

  UNUSED(hSession);
  UNUSED(pOldPin);
  UNUSED(ulOldLen);
  UNUSED(pNewPin);
  UNUSED(ulNewLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
 CK_SESSION_HANDLE_PTR phSession) {

  UNUSED(slotID);
  UNUSED(Notify);
  UNUSED(pApplication);

  if ((flags & CKF_SERIAL_SESSION) == 0) {
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  *phSession = 1;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession) {

  UNUSED(hSession);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID) {

  UNUSED(slotID);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {

  UNUSED(hSession);

  pInfo->flags = 0;
  pInfo->slotID = 0;
  pInfo->state = 0;
  pInfo->ulDeviceError = 0;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
 CK_ULONG_PTR pulOperationStateLen) {

  UNUSED(hSession);
  UNUSED(pOperationState);
  UNUSED(pulOperationStateLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
 CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
 CK_OBJECT_HANDLE hAuthenticationKey) {

  UNUSED(hSession);
  UNUSED(pOperationState);
  UNUSED(ulOperationStateLen);
  UNUSED(hEncryptionKey);
  UNUSED(hAuthenticationKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)
(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
 CK_ULONG ulPinLen) {

  UNUSED(hSession);
  UNUSED(userType);
  UNUSED(pPin);
  UNUSED(ulPinLen);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession) {

  UNUSED(hSession);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phObject) {

  UNUSED(hSession);
  UNUSED(pTemplate);
  UNUSED(ulCount);
  UNUSED(phObject);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phNewObject) {

  UNUSED(hSession);
  UNUSED(hObject);
  UNUSED(pTemplate);
  UNUSED(ulCount);
  UNUSED(phNewObject);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {

  UNUSED(hSession);
  UNUSED(hObject);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {

  UNUSED(hSession);
  UNUSED(hObject);
  UNUSED(pulSize);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {

  UNUSED(hSession);
  UNUSED(hObject);
  UNUSED(pTemplate);
  UNUSED(ulCount);

  for (CK_ULONG i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_LABEL) {
      pTemplate[i].ulValueLen = 8;
      memcpy(pTemplate[i].pValue, "Fake Key", pTemplate[i].ulValueLen);
    } else {
      pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
    }
  }

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {

  UNUSED(hSession);
  UNUSED(hObject);
  UNUSED(pTemplate);
  UNUSED(ulCount);

  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {

  UNUSED(hSession);
  UNUSED(pTemplate);
  UNUSED(ulCount);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
 CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {

  UNUSED(hSession);
  UNUSED(phObject);
  UNUSED(ulMaxObjectCount);
  UNUSED(pulObjectCount);

  *pulObjectCount = 2;

  for (CK_ULONG i = 0; i < *pulObjectCount; i++) {
    phObject[i] = i + 1;
  }

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession) {

  UNUSED(hSession);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pEncryptedData);
  UNUSED(pulEncryptedDataLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);
  UNUSED(pEncryptedPart);
  UNUSED(pulEncryptedPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
 CK_ULONG_PTR pulLastEncryptedPartLen) {

  UNUSED(hSession);
  UNUSED(pLastEncryptedPart);
  UNUSED(pulLastEncryptedPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pEncryptedData);
  UNUSED(pulEncryptedDataLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);
  UNUSED(pEncryptedPart);
  UNUSED(pulEncryptedPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
 CK_ULONG_PTR pulLastEncryptedPartLen) {

  UNUSED(hSession);
  UNUSED(pLastEncryptedPart);
  UNUSED(pulLastEncryptedPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {

  UNUSED(hSession);
  UNUSED(pMechanism);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pDigest);
  UNUSED(pulDigestLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {

  UNUSED(hSession);
  UNUSED(pDigest);
  UNUSED(pulDigestLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(pulSignatureLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
 CK_ULONG_PTR pulSignatureLen) {

  UNUSED(hSession);
  UNUSED(pSignature);
  UNUSED(pulSignatureLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(pulSignatureLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(ulSignatureLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {

  UNUSED(hSession);
  UNUSED(pSignature);
  UNUSED(ulSignatureLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
 CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {

  UNUSED(hSession);
  UNUSED(pSignature);
  UNUSED(ulSignatureLen);
  UNUSED(pData);
  UNUSED(pulDataLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);
  UNUSED(pEncryptedPart);
  UNUSED(pulEncryptedPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {

  UNUSED(hSession);
  UNUSED(pEncryptedPart);
  UNUSED(ulEncryptedPartLen);
  UNUSED(pPart);
  UNUSED(pulPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);
  UNUSED(pEncryptedPart);
  UNUSED(pulEncryptedPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {

  UNUSED(hSession);
  UNUSED(pEncryptedPart);
  UNUSED(ulEncryptedPartLen);
  UNUSED(pPart);
  UNUSED(pulPartLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(pTemplate);
  UNUSED(ulCount);
  UNUSED(phKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
 CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(pPublicKeyTemplate);
  UNUSED(ulPublicKeyAttributeCount);
  UNUSED(pPrivateKeyTemplate);
  UNUSED(ulPrivateKeyAttributeCount);
  UNUSED(phPublicKey);
  UNUSED(phPrivateKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
 CK_ULONG_PTR pulWrappedKeyLen) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hWrappingKey);
  UNUSED(hKey);
  UNUSED(pWrappedKey);
  UNUSED(pulWrappedKeyLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
 CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hUnwrappingKey);
  UNUSED(pWrappedKey);
  UNUSED(ulWrappedKeyLen);
  UNUSED(pTemplate);
  UNUSED(ulAttributeCount);
  UNUSED(phKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hBaseKey);
  UNUSED(pTemplate);
  UNUSED(ulAttributeCount);
  UNUSED(phKey);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {

  UNUSED(hSession);
  UNUSED(pSeed);
  UNUSED(ulSeedLen);

  return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {

  UNUSED(hSession);
  UNUSED(pRandomData);
  UNUSED(ulRandomLen);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(CK_SESSION_HANDLE hSession) {

  UNUSED(hSession);

  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession) {

  UNUSED(hSession);

  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {

  UNUSED(flags);
  UNUSED(pSlot);
  UNUSED(pReserved);

  return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST function_list = {
  {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent,
};

static void *module_handle;
static CK_FUNCTION_LIST_PTR p11 = &function_list;

static void trimright(unsigned char *buf, size_t len) {
  unsigned char *p = buf + len;
  while (p > buf && *--p == ' ')
    *p = 0;
}

int ecdh_load_module(const char *module, FILE *out) {

  if (module_handle) {
    p11->C_Finalize(0);
    dlclose(module_handle);
    module_handle = 0;
    p11 = &function_list;
  }

  if (strcmp(module, "-")) {
    module_handle = dlopen(module, RTLD_NOW);
    if (module_handle == 0) {
      fprintf(out, "Can't open shared library '%s': %s\n", module, dlerror());
      return CKR_ARGUMENTS_BAD;
    }

    CK_C_GetFunctionList fn = 0;
    *(void **) (&fn) = dlsym(module_handle, "C_GetFunctionList");
    if (fn == 0) {
      fprintf(out, "Can't find symbol 'C_GetFunctionList' in '%s': %s\n",
              module, dlerror());
      dlclose(module_handle);
      module_handle = 0;
      return CKR_GENERAL_ERROR;
    }

    CK_RV rv = fn(&p11);
    if (rv != CKR_OK) {
      fprintf(out, "Can't get function list from '%s', rv=%lu\n", module, rv);
      dlclose(module_handle);
      module_handle = 0;
      p11 = &function_list;
      return rv;
    }

    rv = p11->C_Initialize(0);
    if (rv != CKR_OK) {
      fprintf(out, "Can't initialize module '%s', rv = %lu\n", module, rv);
      dlclose(module_handle);
      module_handle = 0;
      p11 = &function_list;
      return rv;
    }
  }
  return CKR_OK;
}

int ecdh_list_providers(void *ctx,
                        int (*callback)(void *ctx, const char *key)) {
  CK_SLOT_ID slot[128] = {0};
  CK_ULONG slots = 128;
  CK_RV rv = p11->C_GetSlotList(CK_TRUE, slot, &slots);
  if (rv) {
    return 0;
  }
  for (CK_ULONG i = 0; i < slots; i++) {
    CK_TOKEN_INFO info = {0};
    rv = p11->C_GetTokenInfo(slot[i], &info);
    if (rv)
      continue;
    trimright(info.label, sizeof(info.label));
    callback(ctx, (char *) info.label);
  }
  return 0;
}

struct p11_ctx {
  void *ctx;
  CK_SLOT_ID slot;
  CK_SESSION_HANDLE session;
  CK_OBJECT_HANDLE object;
};

static CK_RV p11_list_keys(int curve, struct p11_ctx *ctx,
                           int (*callback)(void *ctx, const char *key)) {
  CK_SLOT_ID slot[256] = {0};
  CK_ULONG slots = sizeof(slot) / sizeof(slot[0]);
  CK_RV rv = p11->C_GetSlotList(CK_TRUE, slot, &slots);
  if (rv) {
    return rv;
  }
  for (CK_ULONG i = 0; i < slots; i++) {
    ctx->slot = slot[i];
    CK_TOKEN_INFO info = {0};
    rv = p11->C_GetTokenInfo(ctx->slot, &info);
    if (rv) {
      return rv;
    }
    trimright(info.label, sizeof(info.label));
    char buf[256] = {0};
    int len = snprintf(buf, sizeof(buf), "%s:", info.label);
    rv = p11->C_OpenSession(ctx->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL, NULL, &ctx->session);
    if (rv) {
      return rv;
    }
    rv = p11->C_Login(ctx->session, CKU_USER, (CK_UTF8CHAR_PTR) "123456", 6);
    if (rv) {
      p11->C_CloseSession(ctx->session);
      return rv;
    }
    CK_BBOOL token = TRUE;
    CK_OBJECT_CLASS class = curve ? CKO_PRIVATE_KEY : CKO_SECRET_KEY;
    CK_KEY_TYPE type = curve ? CKK_EC : CKK_AES;
    CK_ATTRIBUTE template[] = {{CKA_TOKEN, &token, sizeof(token)},
                               {CKA_CLASS, &class, sizeof(class)},
                               {CKA_KEY_TYPE, &type, sizeof(type)}};
    rv = p11->C_FindObjectsInit(ctx->session, template,
                                sizeof(template) / sizeof(template[0]));
    if (rv) {
      p11->C_CloseSession(ctx->session);
      return rv;
    }
    CK_OBJECT_HANDLE object[256] = {0};
    CK_ULONG objects = 0;
    rv = p11->C_FindObjects(ctx->session, object,
                            sizeof(object) / sizeof(object[0]), &objects);
    if (rv) {
      p11->C_CloseSession(ctx->session);
      return rv;
    }
    for (CK_ULONG j = 0; j < objects; j++) {
      ctx->object = object[j];
      CK_ATTRIBUTE attrib[] = {{CKA_LABEL, buf + len, sizeof(buf) - len - 1}};
      rv = p11->C_GetAttributeValue(ctx->session, ctx->object, attrib,
                                    sizeof(attrib) / sizeof(attrib[0]));
      if (rv) {
        p11->C_CloseSession(ctx->session);
        return rv;
      }
      buf[len + attrib->ulValueLen] = 0;
      int rc = callback(ctx->ctx, buf);
      if (rc) {
        p11->C_CloseSession(ctx->session);
        return CKR_CANCEL;
      }
    }
    rv = p11->C_FindObjectsFinal(ctx->session);
    rv = p11->C_CloseSession(ctx->session);
    if (rv) {
      return rv;
    }
  }
  return CKR_OK;
}

int ecdh_list_keys(int curve, void *ctx,
                   int (*callback)(void *ctx, const char *key)) {
  struct p11_ctx p11_ctx = {ctx, 0, 0, 0};
  p11_list_keys(curve, &p11_ctx, callback);
  return 0;
}

int ecdh_calculate_public_key_ex(int curve, const char *privkey,
                                 uint8_t *pubkey, size_t cb_pubkey) {
  UNUSED(curve);
  UNUSED(privkey);
  UNUSED(pubkey);
  UNUSED(cb_pubkey);
  return 0;
}

int ecdh_generate_keypair_ex(int curve, const char *privkey, uint8_t *pubkey,
                             size_t cb_pubkey) {
  UNUSED(curve);
  UNUSED(privkey);
  UNUSED(pubkey);
  UNUSED(cb_pubkey);
  return 0;
}

int ecdh_calculate_secret_ex(int curve, const char *privkey,
                             const uint8_t *pubkey, size_t cb_pubkey,
                             uint8_t *secret, size_t cb_secret) {
  UNUSED(curve);
  UNUSED(privkey);
  UNUSED(pubkey);
  UNUSED(cb_pubkey);
  UNUSED(secret);
  UNUSED(cb_secret);
  return 0;
}

int ecdh_destroy_key_ex(const char *privkey) {
  UNUSED(privkey);
  return 0;
}

#endif
