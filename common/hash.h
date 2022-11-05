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

/* hash.h
**
** Implements platform specific hashing operations
*/

#ifndef _YUBICOM_HASH_H_
#define _YUBICOM_HASH_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "../common/platform-config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  _NONE,
  _SHA1,
  _SHA256,
  _SHA384,
  _SHA512,
} hash_t;

#ifndef _WIN32_BCRYPT
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

bool YH_INTERNAL hash_bytes(const uint8_t *in, size_t len, hash_t hash,
                            uint8_t *out, size_t *out_len);

typedef struct _hash_ctx _hash_ctx, *hash_ctx;

bool YH_INTERNAL hash_create(hash_ctx *ctx, hash_t hash);
bool YH_INTERNAL hash_init(hash_ctx ctx);
bool YH_INTERNAL hash_update(hash_ctx ctx, const uint8_t *in, size_t cb_in);
bool YH_INTERNAL hash_final(hash_ctx ctx, uint8_t *out, size_t *pcb_out);
bool YH_INTERNAL hash_destroy(hash_ctx ctx);

#ifndef _WIN32_BCRYPT
#include <openssl/evp.h>
const YH_INTERNAL EVP_MD *get_hash(hash_t hash);
#else
#include <windows.h>
#include <bcrypt.h>
BCRYPT_ALG_HANDLE YH_INTERNAL get_hash(hash_t hash, bool hmac);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _YUBICOM_HASH_H_ */
