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

/* aes.h
**
** Defines the AES crypto module for CMAC
*/

#ifndef _AESCMAC_AES_H_
#define _AESCMAC_AES_H_

#include <stdint.h>

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/aes.h>
#endif

#ifndef AES_BLOCK_SIZE // Defined in openssl/aes.h
#define AES_BLOCK_SIZE 16
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
#ifdef _WIN32_BCRYPT
  BCRYPT_ALG_HANDLE hAlgCBC;
  BCRYPT_ALG_HANDLE hAlgECB;
  BCRYPT_KEY_HANDLE hKeyCBC;
  BCRYPT_KEY_HANDLE hKeyECB;
  PBYTE pbKeyCBCObj;
  PBYTE pbKeyECBObj;
  size_t cbKeyObj;
#else
  AES_KEY key;
  uint16_t key_len;
#endif
} aes_context;

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

uint8_t YH_INTERNAL aes_set_encrypt_key(uint8_t *key, uint16_t key_len,
                                        aes_context *ctx);
uint8_t YH_INTERNAL aes_set_decrypt_key(uint8_t *key, uint16_t key_len,
                                        aes_context *ctx);

uint8_t YH_INTERNAL aes_encrypt(uint8_t *in, uint8_t *out,
                                const aes_context *ctx);
uint8_t YH_INTERNAL aes_decrypt(uint8_t *in, uint8_t *out,
                                const aes_context *ctx);

uint8_t YH_INTERNAL aes_cbc_encrypt(uint8_t *in, uint8_t *out, uint16_t len,
                                    uint8_t *iv, aes_context *ctx);
uint8_t YH_INTERNAL aes_cbc_decrypt(uint8_t *in, uint8_t *out, uint16_t len,
                                    uint8_t *iv, aes_context *ctx);

void YH_INTERNAL aes_add_padding(uint8_t *in, uint16_t *len);
void YH_INTERNAL aes_remove_padding(uint8_t *in, uint16_t *len);

void YH_INTERNAL aes_destroy(aes_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _AESCMAC_AES_H_ */
