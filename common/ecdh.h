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

/* ecdh.h
**
** Implements platform specific ECDH operations
*/

#ifndef _YUBICOM_ECDH_H_
#define _YUBICOM_ECDH_H_

#include <stdint.h>
#include <stddef.h>

#include "../common/platform-config.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

int YH_INTERNAL ecdh_curve_p256(void);
int YH_INTERNAL ecdh_calculate_public_key(int curve, const uint8_t *privkey,
                                          size_t cb_privkey, uint8_t *pubkey,
                                          size_t cb_pubkey);
int YH_INTERNAL ecdh_generate_keypair(int curve, uint8_t *privkey,
                                      size_t cb_privkey, uint8_t *pubkey,
                                      size_t cb_pubkey);
int YH_INTERNAL ecdh_calculate_secret(int curve, const uint8_t *privkey,
                                      size_t cb_privkey, const uint8_t *pubkey,
                                      size_t cb_pubkey, uint8_t *secret,
                                      size_t cb_secret);

#ifdef __cplusplus
}
#endif

#endif /* _YUBICOM_ECDH_H_ */
