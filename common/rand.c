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

#include "rand.h"

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <ncrypt.h>
#else
#include <openssl/rand.h>
#endif

bool rand_generate(uint8_t *buf, size_t cb_buf) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status =
    BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, buf, (ULONG) cb_buf, 0);
  return BCRYPT_SUCCESS(status);
#else
  return (1 == RAND_bytes(buf, cb_buf));
#endif
}
