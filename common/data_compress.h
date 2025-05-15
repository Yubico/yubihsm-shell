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

/*
** Implements platform specific operations to compress and uncompress X509Cert
*/

#ifndef YUBIHSM_SHELL_DATA_COMPRESS_H
#define YUBIHSM_SHELL_DATA_COMPRESS_H

#include "../common/platform-config.h"
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

int YH_INTERNAL compress_data(const uint8_t *data, size_t data_len,
                              uint8_t *compressed_data,
                              size_t *compressed_data_len);
int YH_INTERNAL uncompress_data(uint8_t *compressed_data,
                                size_t compressed_data_len, uint8_t *data,
                                size_t *data_len);

#endif // YUBIHSM_SHELL_DATA_COMPRESS_H
