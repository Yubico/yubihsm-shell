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
    /* PBKDF2-HMAC-SHA256 known-answer vector */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 1,
     _SHA256,
     (const uint8_t *) "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56"
                       "\xc4\xf8\x37\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05"
                       "\x98\x7c\xb7\x0b\xe1\x7b",
     32},
    /* Same password and salt as above, using 4096 iterations and requesting
     * 48 bytes so the derivation spans two digest blocks (digest_len=32).
     * All 48 bytes were cross-checked against Python's hashlib.pbkdf2_hmac
     * (OpenSSL-backed). */
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
    /* PBKDF2-HMAC-SHA384. No single widely-cited RFC covers this hash, so
     * all three vectors below were cross-checked against Python's
     * hashlib.pbkdf2_hmac (OpenSSL-backed). */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 1,
     _SHA384,
     (const uint8_t *) "\xc0\xe1\x4f\x06\xe4\x9e\x32\xd7\x3f\x9f\x52\xdd\xf1"
                       "\xd0\xc5\xc7\x19\x16\x09\x23\x36\x31\xda\xdd\x76\xa5"
                       "\x67\xdb\x42\xb7\x86\x76\xb3\x8f\xc8\x00\xcc\x53\xdd"
                       "\xb6\x42\xf5\xc7\x44\x42\xe6\x2b\xe4",
     48},
    /* same key material, 64-byte output spans two digest blocks (digest_len=48) */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 4096,
     _SHA384,
     (const uint8_t *) "\x55\x97\x26\xbe\x38\xdb\x12\x5b\xc8\x5e\xd7\x89\x5f"
                       "\x6e\x3c\xf5\x74\xc7\xa0\x1c\x08\x0c\x34\x47\xdb\x1e"
                       "\x8a\x76\x76\x4d\xeb\x3c\x30\x7b\x94\x85\x3f\xbe\x42"
                       "\x4f\x64\x88\xc5\xf4\xf1\x28\x96\x26\x1d\x1e\xb4\x30"
                       "\x35\x3c\x76\x9e\xe2\xa7\x7a\x26\xfd\x0a\x23\x47",
     64},
    /* password longer than the SHA-384 block size (128 bytes) */
    {(const uint8_t *) "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                       "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                       "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
     150, (const uint8_t *) "salt", 4, 1000, _SHA384,
     (const uint8_t *) "\x73\x04\xcc\x17\xf5\x6b\xc8\x25\xd8\x00\x54\xdd\x81"
                       "\x27\x17\x5f\x43\x28\x6b\x94\x9c\xc3\x2c\x35\x23\x5b"
                       "\x08\x96\x33\xd4\x7b\x94\x67\xdf\xca\xa4\x17\x7d\x0e"
                       "\x13\xf4\x36\x2a\x99\x0e\xe2\x4b\xb8",
     48},
    /* PBKDF2-HMAC-SHA512. Cross-checked against Python's hashlib.pbkdf2_hmac
     * (OpenSSL-backed); the c=1/dkLen=64 vector also matches commonly
     * published PBKDF2-HMAC-SHA512 test vectors for "password"/"salt". */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 1,
     _SHA512,
     (const uint8_t *) "\x86\x7f\x70\xcf\x1a\xde\x02\xcf\xf3\x75\x25\x99\xa3"
                       "\xa5\x3d\xc4\xaf\x34\xc7\xa6\x69\x81\x5a\xe5\xd5\x13"
                       "\x55\x4e\x1c\x8c\xf2\x52\xc0\x2d\x47\x0a\x28\x5a\x05"
                       "\x01\xba\xd9\x99\xbf\xe9\x43\xc0\x8f\x05\x02\x35\xd7"
                       "\xd6\x8b\x1d\xa5\x5e\x63\xf7\x3b\x60\xa5\x7f\xce",
     64},
    /* same key material, 100-byte output spans two digest blocks (digest_len=64) */
    {(const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, 4096,
     _SHA512,
     (const uint8_t *) "\xd1\x97\xb1\xb3\x3d\xb0\x14\x3e\x01\x8b\x12\xf3\xd1"
                       "\xd1\x47\x9e\x6c\xde\xbd\xcc\x97\xc5\xc0\xf8\x7f\x69"
                       "\x02\xe0\x72\xf4\x57\xb5\x14\x3f\x30\x60\x26\x41\xb3"
                       "\xd5\x5c\xd3\x35\x98\x8c\xb3\x6b\x84\x37\x60\x60\xec"
                       "\xd5\x32\xe0\x39\xb7\x42\xa2\x39\x43\x4a\xf2\xd5\xd6"
                       "\x88\x3f\x0b\xe4\xc2\x4d\x36\x3b\x63\x8f\x4c\x2f\x8d"
                       "\x91\x75\x33\xcd\x41\x58\x93\x7d\x0b\x49\x06\x97\xa6"
                       "\x4a\xda\xdb\x07\xf1\x80\xc3\x23\x08",
     100},
    /* password longer than the SHA-512 block size (128 bytes) */
    {(const uint8_t *) "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
                       "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
                       "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
     150, (const uint8_t *) "salt", 4, 1000, _SHA512,
     (const uint8_t *) "\xad\x22\x82\x8c\xa8\x13\x9a\xc4\xa1\x91\x7a\x3d\x47"
                       "\x99\x13\xdf\x71\x4f\x99\x47\x2e\x50\x0b\xcc\x12\x9a"
                       "\x5b\x3d\x2b\xee\xa1\x75\x35\x08\x1a\x9f\xf3\x0d\xd8"
                       "\x8a\xf8\xce\xcd\x3b\x21\x5a\x3d\x75\x75\x55\x31\xae"
                       "\x5c\xd8\x99\x0c\xea\x55\xcd\x1a\x97\x26\xe5\xb0",
     64},
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
