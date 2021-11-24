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

#include "pkcs5.h"

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <ncrypt.h>
#else
#include <openssl/evp.h>
#endif

bool pkcs5_pbkdf2_hmac(const uint8_t *password, size_t cb_password,
                       const uint8_t *salt, size_t cb_salt, uint64_t iterations,
                       hash_t hash, uint8_t *key, size_t cb_key) {
  bool res = false;

#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
  BCRYPT_ALG_HANDLE hAlg = 0;

  if (!(hAlg = get_hash(hash, true))) {
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

#else
  const EVP_MD *md = NULL;

  if (!(md = get_hash(hash))) {
    return false;
  }

  /* for some reason openssl always returns 1 for PBKDF2 */
  if (1 != PKCS5_PBKDF2_HMAC((const char *) password, cb_password, salt,
                             cb_salt, iterations, md, cb_key, key)) {
    return false;
  }

  res = true;

#endif
  return res;
}
