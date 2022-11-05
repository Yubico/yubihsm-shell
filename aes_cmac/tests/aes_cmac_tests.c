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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aes_cmac.h"

#define asrt(c, e, m) _asrt(__LINE__, c, e, m);

static void _asrt(int line, int check, int expected, unsigned char *msg) {

  if (check == expected)
    return;

  fprintf(stderr,
          "<%s>:%d check failed with value %d (0x%x), expected %d (0x%x)\n",
          msg, line, check, check, expected, expected);

  exit(EXIT_FAILURE);
}

int main() {
  aes_context aes = {0};
  aes_cmac_context_t ctx = {0};

  uint8_t mac[AES_BLOCK_SIZE];

  uint8_t m[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
                 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
                 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
                 0xe6, 0x6c, 0x37, 0x10};

  uint8_t k_128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  uint8_t k_192[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                     0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                     0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};

  uint8_t k_256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                     0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                     0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

  uint8_t mac1[] = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                    0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
  uint8_t mac2[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
  uint8_t mac3[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                    0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
  uint8_t mac4[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                    0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};
  uint8_t mac5[] = {0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
                    0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67};
  uint8_t mac6[] = {0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
                    0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84};
  uint8_t mac7[] = {0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
                    0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e};
  uint8_t mac8[] = {0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
                    0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11};
  uint8_t mac9[] = {0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
                    0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83};
  uint8_t mac10[] = {0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
                     0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c};
  uint8_t mac11[] = {0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
                     0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6};
  uint8_t mac12[] = {0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
                     0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10};

  aes_set_key(k_128, sizeof(k_128), &aes);
  aes_cmac_init(&aes, &ctx);
  aes_cmac_encrypt(&ctx, m, 0, mac);
  asrt(memcmp(mac, mac1, 16), 0, (unsigned char *) "MAC1");
  aes_cmac_encrypt(&ctx, m, 16, mac);
  asrt(memcmp(mac, mac2, 16), 0, (unsigned char *) "MAC2");
  aes_cmac_encrypt(&ctx, m, 40, mac);
  asrt(memcmp(mac, mac3, 16), 0, (unsigned char *) "MAC3");
  aes_cmac_encrypt(&ctx, m, 64, mac);
  asrt(memcmp(mac, mac4, 16), 0, (unsigned char *) "MAC4");
  aes_cmac_destroy(&ctx);
  aes_destroy(&aes);

  aes_set_key(k_192, sizeof(k_192), &aes);
  aes_cmac_init(&aes, &ctx);
  aes_cmac_encrypt(&ctx, m, 0, mac);
  asrt(memcmp(mac, mac5, 16), 0, (unsigned char *) "MAC5");
  aes_cmac_encrypt(&ctx, m, 16, mac);
  asrt(memcmp(mac, mac6, 16), 0, (unsigned char *) "MAC6");
  aes_cmac_encrypt(&ctx, m, 40, mac);
  asrt(memcmp(mac, mac7, 16), 0, (unsigned char *) "MAC7");
  aes_cmac_encrypt(&ctx, m, 64, mac);
  asrt(memcmp(mac, mac8, 16), 0, (unsigned char *) "MAC8");
  aes_cmac_destroy(&ctx);
  aes_destroy(&aes);

  aes_set_key(k_256, sizeof(k_256), &aes);
  aes_cmac_init(&aes, &ctx);
  aes_cmac_encrypt(&ctx, m, 0, mac);
  asrt(memcmp(mac, mac9, 16), 0, (unsigned char *) "MAC9");
  aes_cmac_encrypt(&ctx, m, 16, mac);
  asrt(memcmp(mac, mac10, 16), 0, (unsigned char *) "MAC10");
  aes_cmac_encrypt(&ctx, m, 40, mac);
  asrt(memcmp(mac, mac11, 16), 0, (unsigned char *) "MAC11");
  aes_cmac_encrypt(&ctx, m, 64, mac);
  asrt(memcmp(mac, mac12, 16), 0, (unsigned char *) "MAC12");
  aes_cmac_destroy(&ctx);
  aes_destroy(&aes);

  // Padding tests

  uint8_t a[48];
  uint32_t l;

  l = 3;
  memset(a, 0xab, 48);
  aes_add_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x00",
              16),
       0, (unsigned char *) "PADDING 1a");
  asrt(l, 16, (unsigned char *) "PADDING 1b");
  aes_remove_padding(a, &l);
  asrt(memcmp(a, "\xab\xab\xab", 3), 0, (unsigned char *) "PADDING 1c");
  asrt(l, 3, (unsigned char *) "PADDING 1d");
  fprintf(stderr, "\n");

  l = 15;
  memset(a, 0xab, 48);
  aes_add_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\x80",
              16),
       0, (unsigned char *) "PADDING 2a");
  asrt(l, 16, (unsigned char *) "PADDING 2b");
  aes_remove_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab",
              15),
       0, (unsigned char *) "PADDING 2c");
  asrt(l, 15, (unsigned char *) "PADDING 2d");
  fprintf(stderr, "\n");

  l = 16;
  memset(a, 0xab, 48);
  aes_add_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x00\x00",
              32),
       0, (unsigned char *) "PADDING 3a");
  asrt(l, 32, (unsigned char *) "PADDING 3b");
  aes_remove_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab",
              16),
       0, (unsigned char *) "PADDING 3c");
  asrt(l, 16, (unsigned char *) "PADDING 3d");
  fprintf(stderr, "\n");

  l = 19;
  memset(a, 0xab, 48);
  aes_add_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\xab\xab\xab\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x00\x00",
              32),
       0, (unsigned char *) "PADDING 4a");
  asrt(l, 32, (unsigned char *) "PADDING 4b");
  aes_remove_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\xab\xab\xab",
              19),
       0, (unsigned char *) "PADDING 4c");
  asrt(l, 19, (unsigned char *) "PADDING 4d");
  fprintf(stderr, "\n");

  l = 32;
  memset(a, 0xab, 48);
  aes_add_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\xab\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x00\x00\x00",
              48),
       0, (unsigned char *) "PADDING 5a");
  asrt(l, 48, (unsigned char *) "PADDING 5b");
  aes_remove_padding(a, &l);
  asrt(memcmp(a,
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
              "\xab\xab",
              32),
       0, (unsigned char *) "PADDING 5c");
  asrt(l, 32, (unsigned char *) "PADDING 5d");
  fprintf(stderr, "\n");

  l = 0;
  memset(a, 0xab, 48);
  aes_add_padding(a, &l);
  asrt(memcmp(a,
              "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x00",
              16),
       0, (unsigned char *) "PADDING 6a");
  asrt(l, 16, (unsigned char *) "PADDING 6b");
  aes_remove_padding(a, &l);
  asrt(memcmp(a, "", 0), 0, (unsigned char *) "PADDING 6c");
  asrt(l, 0, (unsigned char *) "PADDING 6d");
  fprintf(stderr, "\n");

  return EXIT_SUCCESS;
}
