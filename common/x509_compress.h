/*
* Copyright 2024 Yubico AB
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
** Implements platform specific operations to compress and uncompress X509Cert
*/

#ifndef YUBIHSM_SHELL_X509_COMPRESS_H
#define YUBIHSM_SHELL_X509_COMPRESS_H

#ifndef _WIN32_BCRYPT
// Only inlcude this if OpenSSL can be used

#include "../common/platform-config.h"
#include <stdlib.h>
#include <stdint.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YH_INTERNAL __attribute__((visibility("hidden")))

int YH_INTERNAL compress_cert(X509 *cert, uint8_t *compressed_data);
X509* uncompress_cert(uint8_t *data, size_t data_len);

#endif

#endif // YUBIHSM_SHELL_X509_COMPRESS_H
