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
#include "../lib/debug_lib.h"

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/err.h>

static int ossl_err_cb(const char *str, size_t len, void *u) {
  (void) len;
  (void) u;
  DBG_ERR("%s %s", (const char *) u, str);
  return 1;
}

static void DBG_OSSL(const char *str, int err) {
  DBG_ERR("%s: %d OSSL error stack begin", str, err);
  ERR_print_errors_cb(ossl_err_cb, (void *) str);
  DBG_ERR("%s: OSSL error stack end", str);
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
  const EVP_MD *md = NULL;
  int err = 0;

  if (!(md = get_hash(hash))) {
    DBG_OSSL("get_hash", err);
    return false;
  }

  /* for some reason openssl always returns 1 for PBKDF2 */
  if (!(err = PKCS5_PBKDF2_HMAC((const char *) password, cb_password, salt,
                                cb_salt, iterations, md, cb_key, key))) {
    DBG_OSSL("PKCS5_PBKDF2_HMAC", err);
    return false;
  }

  res = true;

#endif
  return res;
}
