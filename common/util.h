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

#ifndef YUBICOM_UTIL_H
#define YUBICOM_UTIL_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>

#include <yubihsm.h>

typedef enum {
  _base64,
  _binary,
  _hex,
} format_t;

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

bool YH_INTERNAL set_component(uint8_t *in_ptr, const BIGNUM *bn,
                               int32_t element_len);
bool YH_INTERNAL read_private_key(uint8_t *buf, size_t len, yh_algorithm *algo,
                                  uint8_t *bytes, size_t *bytes_len,
                                  bool internal_repr);
void YH_INTERNAL format_digest(uint8_t *digest, char *str, uint16_t len);
int YH_INTERNAL algo2nid(yh_algorithm algo);
bool YH_INTERNAL algo2type(yh_algorithm algorithm, yh_object_type *type);
void YH_INTERNAL parse_NID(uint8_t *data, uint16_t data_len,
                           const EVP_MD **md_type, int *digestinfo_len);
bool YH_INTERNAL read_file(FILE *fp, uint8_t *buf, size_t *buf_len);
bool YH_INTERNAL write_file(const uint8_t *buf, size_t buf_len, FILE *fp,
                            format_t format);
bool YH_INTERNAL read_ed25519_key(uint8_t *in, size_t in_len, uint8_t *out,
                                  size_t *out_len);
bool YH_INTERNAL write_ed25519_key(uint8_t *buf, size_t buf_len, FILE *fp,
                                   bool b64_encode);

bool YH_INTERNAL base64_decode(const char *in, uint8_t *out, size_t *len);
bool YH_INTERNAL hex_decode(const char *in, uint8_t *out, size_t *len);

bool YH_INTERNAL split_hmac_key(yh_algorithm algorithm, uint8_t *in,
                                size_t in_len, uint8_t *out, size_t *out_len);

#endif
