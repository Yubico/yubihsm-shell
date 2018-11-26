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

#include <stdint.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <string.h>

#include "../../common/pkcs5.h"

static void test_pbkdf2_vectors(void) {
  struct vector {
    const uint8_t *password;
    size_t password_len;
    const uint8_t *salt;
    size_t salt_len;
    uint64_t iterations;
    hash_t hash;
    const uint8_t *output;
    size_t size;
  } vectors[] = {
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 1, _SHA1,
     (const uint8_t *) "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf"
                       "\x60\x12\x06\x2f\xe0\x37\xa6",
     20},
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 2, _SHA1,
     (const uint8_t *) "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce"
                       "\x1d\x41\xf0\xd8\xde\x89\x57",
     20},
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 4096, _SHA1,
     (const uint8_t *) "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26"
                       "\xf7\x21\xd0\x65\xa4\x29\xc1",
     20},
    //{(const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 16777216,
    //_SHA1, (const
    // uint8_t*)"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84",
    // 20},
    {(const uint8_t *) "passwordPASSWORDpassword", 24,
     (const uint8_t *) "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, _SHA1,
     (const uint8_t *) "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62"
                       "\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38",
     25},
    {(const uint8_t *) "pass\0word", 9, (const uint8_t *) "sa\0lt", 5, 4096,
     _SHA1,
     (const uint8_t
        *) "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3",
     16},
  };

  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    uint8_t key[256];
    bool res = pkcs5_pbkdf2_hmac(vectors[i].password, vectors[i].password_len,
                                 vectors[i].salt, vectors[i].salt_len,
                                 vectors[i].iterations, vectors[i].hash, key,
                                 vectors[i].size);
    assert(res == true);
    assert(memcmp(key, vectors[i].output, vectors[i].size) == 0);
  }
}

int main(void) { test_pbkdf2_vectors(); }
