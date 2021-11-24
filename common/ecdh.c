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
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>

#include "openssl-compat.h"
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

int ecdh_list_providers(void *ctx,
                        int (*callback)(void *ctx, const char *key)) {
  callback(ctx, "Fake Provider");
  callback(ctx, "Fake Provider 2");
  return 0;
}

int ecdh_list_keys(int curve, void *ctx,
                   int (*callback)(void *ctx, const char *key)) {
  if (curve) {
    callback(ctx, "Fake Provider:Fake ECP256 Key 1");
    callback(ctx, "Fake Provider:Fake ECP256 Key 2");
    callback(ctx, "MACHINE:Fake Provider:Fake ECP256 Key 1");
  } else {
    callback(ctx, "Fake Provider:Fake AES Key 1");
    callback(ctx, "Fake Provider:Fake AES Key 2");
    callback(ctx, "MACHINE:Fake Provider:Fake AES Key 1");
  }
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
