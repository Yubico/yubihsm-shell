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

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

const char *key_label = "label";
const uint8_t password[] = "password";
const uint8_t otp_key[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                           0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

static const struct {
  uint8_t key[16];
  uint8_t id[6];
  uint16_t use_counter;
  uint16_t timestamp_low;
  uint8_t timestamp_high;
  uint8_t session_counter;
  uint16_t random;
  uint16_t crc;
  uint8_t otp[32];
} test_vectors[] =
  {{"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    "\x01\x02\x03\x04\x05\x06", 0x0001, 0x0001, 0x01, 0x01, 0x0000, 0xfe36,
    "\x2f\x5d\x71\xa4\x91\x5d\xec\x30\x4a\xa1\x3c\xcf\x97\xbb\x0d\xbb"},
   {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    "\x01\x02\x03\x04\x05\x06", 0x0001, 0x0001, 0x01, 0x02, 0x0000, 0x1152,
    "\xcb\x71\x0b\x46\x2b\x7b\x1c\x23\x10\x0c\xb2\x46\x85\xb6\x4d\x33"},
   {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    "\x01\x02\x03\x04\x05\x06", 0x0fff, 0x0001, 0x01, 0x01, 0x0000, 0x9454,
    "\x77\x99\x78\x12\x9b\xcc\x26\x42\xc8\xad\xf5\xc1\x99\x81\xa0\x16"},
   {"\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
    "\x88\x88\x88\x88\x88\x88", 0x8888, 0x8888, 0x88, 0x88, 0x8888, 0xd3b6,
    "\x20\x76\x5f\xc6\x83\xe0\xfc\x7b\x62\x42\x21\x86\x48\x4d\x82\x37"},
   {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\x00\x00\x00\x00\x00\x00", 0x0000, 0x0000, 0x00, 0x00, 0x0000, 0xa96a,
    "\x99\x9b\x08\xbf\x0b\x3b\x98\xf8\x5b\x08\x76\xa8\x77\x15\x16\x16"},
   {"\xc4\x42\x28\x90\x65\x30\x76\xcd\xe7\x3d\x44\x9b\x19\x1b\x41\x6a",
    "\x33\xc6\x9e\x7f\x24\x9e", 0x0001, 0x13a7, 0x24, 0x00, 0xc63c, 0x1c86,
    "\x7e\x0f\xc9\x87\x35\x16\x72\xc0\x70\xfa\x5c\x05\x95\xec\x68\xb8"}};

uint16_t yubikey_crc16(const uint8_t *buf, size_t buf_size) {
  uint16_t m_crc = 0xffff;

  while (buf_size--) {
    int i, j;
    m_crc ^= (uint8_t) *buf++ & 0xFF;
    for (i = 0; i < 8; i++) {
      j = m_crc & 1;
      m_crc >>= 1;
      if (j) {
        m_crc ^= 0x8408;
      }
    }
  }

  return m_crc;
}

int main(void) {
  yh_connector *connector = NULL;
  yh_session *session = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;

  uint16_t authkey = 1;

  const char *connector_url;

  connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }

  yrc = yh_init();
  assert(yrc == YHR_SUCCESS);

  yrc = yh_init_connector(connector_url, &connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_connect(connector, 0);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_create_session_derived(connector, authkey, password,
                                  sizeof(password), false, &session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_authenticate_session(session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);

  yh_capabilities capabilities = {{0}};
  yrc =
    yh_string_to_capabilities("create-otp-aead:decrypt-otp:randomize-otp-aead",
                              &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 16; // Domain five is 0b0000000000010000
  uint16_t key_id = 0;       // ID 0 lets the device generate an ID
  uint32_t nonce_id = 0x12345678;
  yrc = yh_util_generate_otp_aead_key(session, &key_id, key_label, domain_five,
                                      &capabilities, YH_ALGO_AES128_YUBICO_OTP,
                                      nonce_id);
  assert(yrc == YHR_SUCCESS);

  printf("Generated OTP key with ID %04x\n", key_id);

  yrc = yh_util_delete_object(session, key_id, YH_OTP_AEAD_KEY);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_import_otp_aead_key(session, &key_id, key_label, domain_five,
                                    &capabilities, nonce_id, otp_key,
                                    sizeof(otp_key));
  assert(yrc == YHR_SUCCESS);

  for (size_t i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); i++) {
    uint8_t aead[512];
    size_t aead_len = sizeof(aead);
    yrc = yh_util_create_otp_aead(session, key_id, test_vectors[i].key,
                                  test_vectors[i].id, aead, &aead_len);
    assert(yrc == YHR_SUCCESS);

    uint16_t use_counter;
    uint16_t timestamp_low;
    uint8_t timestamp_high;
    uint8_t session_counter;

    printf("Checking test vector %zu ... ", i);
    yrc =
      yh_util_decrypt_otp(session, key_id, aead, aead_len, test_vectors[i].otp,
                          &use_counter, &session_counter, &timestamp_high,
                          &timestamp_low);
    assert(yrc == YHR_SUCCESS);

    assert(test_vectors[i].use_counter == use_counter);
    assert(test_vectors[i].session_counter == session_counter);
    assert(test_vectors[i].timestamp_high == timestamp_high);
    assert(test_vectors[i].timestamp_low == timestamp_low);

    printf("OK\n");
  }

  printf("Put OTP key with ID %04x\n", key_id);

  uint8_t otp_data[64];
  size_t otp_data_len = sizeof(otp_data);
  size_t tag_len = 8;
  size_t nonce_len = 13;
  uint8_t nonce[13] = {0};
  uint8_t out_buf[32];
  int out_len;
  yrc = yh_util_randomize_otp_aead(session, key_id, otp_data, &otp_data_len);
  assert(yrc == YHR_SUCCESS);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  // Select cipher
  assert(EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1);

  // Set nonce length
  assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce_len, NULL) ==
         1);

  // Set expected tag value
  assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len,
                             otp_data + otp_data_len - tag_len) == 1);

  // Specify key and IV
  memcpy(nonce, &nonce_id, 4);
  memcpy(nonce + 4, otp_data, 6);
  assert(EVP_DecryptInit_ex(ctx, NULL, NULL, otp_key, nonce) == 1);

  // Decrypt plaintext, verify tag: can only be called once
  assert(EVP_DecryptUpdate(ctx, out_buf, &out_len, otp_data + 6,
                           otp_data_len - 6 - tag_len) == 1);

  EVP_CIPHER_CTX_free(ctx);

  struct {
    union {
      struct {
        uint8_t id[6];
        uint16_t use_counter;
        uint16_t timestamp_low;
        uint8_t timestamp_high;
        uint8_t session_counter;
        uint16_t rnd;
        uint16_t crc;
      };
      uint8_t raw[16];
    };
  } token = {.raw = {0}};

  uint8_t otp[16] = {0};

  memcpy(token.id, out_buf + 16, 6);
  token.use_counter = 0xabcd;
  token.timestamp_low = 0xdcba;
  token.timestamp_high = 0xff;
  token.session_counter = 0x00;
  token.crc = ~yubikey_crc16(token.raw, 14);

  AES_KEY k;
  AES_set_encrypt_key(out_buf, 128, &k);
  AES_ecb_encrypt(token.raw, otp, &k, AES_ENCRYPT);

  uint16_t use_counter;
  uint16_t timestamp_low;
  uint8_t timestamp_high;
  uint8_t session_counter;

  yrc = yh_util_decrypt_otp(session, key_id, otp_data, otp_data_len, otp,
                            &use_counter, &session_counter, &timestamp_high,
                            &timestamp_low);
  assert(yrc == YHR_SUCCESS);

  assert(use_counter == token.use_counter);
  assert(timestamp_low == token.timestamp_low);
  assert(timestamp_high == token.timestamp_high);
  assert(session_counter == token.session_counter);

  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yh_disconnect(connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return 0;
}
