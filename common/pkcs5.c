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

#include "pkcs5.h"
#include "hash.h"

bool pkcs5_pbkdf2_hmac(const uint8_t *password, size_t cb_password,
                       const uint8_t *salt, size_t cb_salt, uint64_t iterations,
                       hash_t hash, uint8_t *key, size_t cb_key) {
  bool res = false;

#ifdef _WIN32_BCRYPT
  NTSTATUS status = 0;
  LPCWSTR alg = NULL;
  BCRYPT_ALG_HANDLE hAlg = 0;

  /* mingw64 defines the BCryptDeriveKeyPBKDF2 function, but its import library
   *doesn't include the export.
   **
   ** Once this is fixed, we can just call the function directly.  Until then,
   *we need to dynamically load the function.
   */

  typedef NTSTATUS WINAPI (
    *PFN_BCryptDeriveKeyPBKDF2)(BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword,
                                ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt,
                                ULONGLONG cIterations, PUCHAR pbDerivedKey,
                                ULONG cbDerivedKey, ULONG dwFlags);
  HMODULE hBCrypt = NULL;
  PFN_BCryptDeriveKeyPBKDF2 fnBCryptDeriveKeyPBKDF2 = NULL;

  if (!(hBCrypt = LoadLibrary("bcrypt.dll"))) {
    goto cleanup;
  }

  if (!(fnBCryptDeriveKeyPBKDF2 = (PFN_BCryptDeriveKeyPBKDF2)(
          (void (*)(void)) GetProcAddress(hBCrypt, "BCryptDeriveKeyPBKDF2")))) {
    goto cleanup;
  }

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
          fnBCryptDeriveKeyPBKDF2(hAlg, (PUCHAR) password, (ULONG) cb_password,
                                  (PUCHAR) salt, (ULONG) cb_salt, iterations,
                                  key, (ULONG) cb_key, 0))) {
    goto cleanup;
  }

  res = true;

cleanup:

  if (hAlg) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
  }
  if (hBCrypt) {
    FreeLibrary(hBCrypt);
  }

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
