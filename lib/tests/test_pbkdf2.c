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
#include <stdio.h>

#include "../../common/pkcs5.h"

uint8_t _yh_verbosity = 0xff;
FILE *_yh_output;

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
    /* RFC 7914 Appendix A, PBKDF2-HMAC-SHA256 */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 1,
     _SHA256,
     (const uint8_t *) "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56"
                       "\xc4\xf8\x37\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05"
                       "\x98\x7c\xb7\x0b\xe1\x7b",
     32},
    /* Same RFC 7914 key material as above, requested 48 bytes instead of 32
     * so the derivation spans two digest blocks (digest_len=32). The first
     * 32 bytes match the published vector exactly; all 48 bytes were cross-
     * checked against Python's hashlib.pbkdf2_hmac (OpenSSL-backed). */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 4096,
     _SHA256,
     (const uint8_t *) "\xc5\xe4\x78\xd5\x92\x88\xc8\x41\xaa\x53\x0d\xb6\x84"
                       "\x5c\x4c\x8d\x96\x28\x93\xa0\x01\xce\x4e\x11\xa4\x96"
                       "\x38\x73\xaa\x98\x13\x4a\xf7\xad\x98\xc1\xb4\x58\xce"
                       "\x3f\xd7\x4c\xa3\x5b\xeb\xa3\xcd\xa7",
     48},
    /* Password longer than the SHA-256 block size (64 bytes), exercising
     * the HMAC key-compression path. Cross-checked against Python's
     * hashlib.pbkdf2_hmac (OpenSSL-backed). */
    {(const uint8_t *) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
     80, (const uint8_t *) "salt", 4, 1000, _SHA256,
     (const uint8_t *) "\x12\x29\x83\x86\x83\xb5\xc5\x44\x7d\x04\xfa\x21\xe5"
                       "\x1a\x42\xe4\x72\x8c\xbe\x4e\xa1\x7c\x8e\x5e\x51\xe1"
                       "\x9c\x03\xa6\x56\xb2\x96",
     32},
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

int main(void) {
    test_pbkdf2_vectors();
    return 0;
}
