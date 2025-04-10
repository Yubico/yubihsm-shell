/*
 * Copyright 2021 Yubico AB
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

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <yubihsm.h>

const char *key_label = "label";
const uint8_t password[] = "password";
const uint8_t plaintext[16] = "singleblock msg";

int main(void) {
  yh_connector *connector = NULL;
  yh_session *session = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;
  int r = EXIT_FAILURE;

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

  yrc = yh_create_session_derived(connector, 1, password, sizeof(password) - 1,
                                  false, &session);
  assert(yrc == YHR_SUCCESS);

  uint8_t session_id;
  yrc = yh_get_session_id(session, &session_id);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully established session %02d\n", session_id);

  yh_algorithm algorithms[YH_MAX_ALGORITHM_COUNT];
  size_t algorithm_count = YH_MAX_ALGORITHM_COUNT;
  yrc = yh_util_get_device_info(connector, NULL, NULL, NULL, NULL, NULL, NULL,
                                algorithms, &algorithm_count);
  assert(yrc == YHR_SUCCESS);

  int state = 0; /* unsupported */
  for (size_t i = 0; i < algorithm_count; i++) {
    if (algorithms[i] == YH_ALGO_AES_ECB) {
      state |= 0x01;
    } else if (algorithms[i] == YH_ALGO_AES_CBC) {
      state |= 0x02;
    }
  }
  if (state != 0x03) {
    fprintf(stderr, "ECB/CBC unsupported or disabled (%#04x)\n", state);
    r = 64; /* arbitrarily chosen */
    goto done;
  }

  yh_capabilities capabilities = {{0}};
  yrc =
    yh_string_to_capabilities("encrypt-ecb,decrypt-ecb,encrypt-cbc,decrypt-cbc",
                              &capabilities);
  assert(yrc == YHR_SUCCESS);

  uint16_t domain_five = 0;
  yrc = yh_string_to_domains("5", &domain_five);
  assert(yrc == YHR_SUCCESS);

  uint16_t aes_key_id = 0;
  yrc = yh_util_generate_aes_key(session, &aes_key_id, key_label, domain_five,
                                 &capabilities, YH_ALGO_AES256);
  assert(yrc == YHR_SUCCESS);

  printf("Generated AES key with ID %04x\n", aes_key_id);

  uint8_t data[16];
  size_t data_len = sizeof(data);
  yrc = yh_util_encrypt_aes_ecb(session, aes_key_id, plaintext,
                                sizeof(plaintext), data, &data_len);
  assert(yrc == YHR_SUCCESS);
  assert(memcmp(data, plaintext, sizeof(plaintext)) != 0);

  printf("AES-ECB encryption successful\n");

  yrc = yh_util_decrypt_aes_ecb(session, aes_key_id, data, data_len, data,
                                &data_len);
  assert(yrc == YHR_SUCCESS);

  assert(data_len == sizeof(plaintext));
  assert(memcmp(data, plaintext, sizeof(plaintext)) == 0);

  printf("AES-ECB decryption successful\n");

  uint8_t iv[16];
  size_t iv_len = sizeof(iv);
  yrc = yh_util_get_pseudo_random(session, 16, iv, &iv_len);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_util_encrypt_aes_cbc(session, aes_key_id, iv, plaintext,
                                sizeof(plaintext), data, &data_len);
  assert(yrc == YHR_SUCCESS);
  assert(memcmp(data, plaintext, sizeof(plaintext)) != 0);

  printf("AES-CBC encryption successful\n");

  yrc = yh_util_decrypt_aes_cbc(session, aes_key_id, iv, data, data_len, data,
                                &data_len);
  assert(yrc == YHR_SUCCESS);

  assert(data_len == sizeof(plaintext));
  assert(memcmp(data, plaintext, sizeof(plaintext)) == 0);

  printf("AES-CBC decryption successful\n");

  r = EXIT_SUCCESS;
done:
  yrc = yh_util_close_session(session);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_destroy_session(&session);
  assert(yrc == YHR_SUCCESS);

  yh_disconnect(connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return r;
}
