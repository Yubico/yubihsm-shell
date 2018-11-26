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

/* pkcs5.h
**
** Implements platform specific PKCS5 operations
*/

#ifndef _YUBICOM_PKCS5_H_
#define _YUBICOM_PKCS5_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

bool YH_INTERNAL pkcs5_pbkdf2_hmac(const uint8_t *password, size_t cb_password,
                                   const uint8_t *salt, size_t cb_salt,
                                   uint64_t iterations, hash_t hash,
                                   uint8_t *key, size_t cb_key);

#ifdef __cplusplus
}
#endif

#endif /* _YUBICOM_PKCS5_H_ */
