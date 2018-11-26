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

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cmdline.h"

#include "parsing.h"
#include "util.h"

#include <yubihsm.h>

#define INPUT_BUFSIZE 4096
#define WRAPKEY_BUFSIZE 32

#define OBJECT_HEADER_SIZE 59

static bool wrap_data(uint8_t *key, size_t key_len, uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len) {

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher_type;

  uint8_t nonce[13];
  int nonce_len = 13;
  int tag_len = 16;

  int len;

  switch (key_len) {
    case 16:
      cipher_type = EVP_aes_128_ccm();
      break;

    case 24:
      cipher_type = EVP_aes_192_ccm();
      break;

    case 32:
      cipher_type = EVP_aes_256_ccm();
      break;

    default:
      return false;
  }

  if (RAND_bytes(nonce, nonce_len) != 1) {
    return false;
  }

  memcpy(out, nonce, nonce_len);

  // Select cipher
  if (EVP_EncryptInit_ex(ctx, cipher_type, NULL, NULL, NULL) != 1) {
    return false;
  }

  // Set nonce length
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce_len, NULL) != 1) {
    return false;
  }

  // Set tag length
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL) != 1) {
    return false;
  }

  // Initialize key and IV
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    return false;
  }

  // Provide the total plaintext length
  if (EVP_EncryptUpdate(ctx, NULL, &len, NULL, in_len) != 1) {
    return false;
  }

  // Provide the message to be encrypted, and obtain the encrypted output
  if (EVP_EncryptUpdate(ctx, out + nonce_len, &len, in, in_len) != 1) {
    return false;
  }
  *out_len = len;

  // Finalize the encryption
  if (EVP_EncryptFinal_ex(ctx, out + nonce_len + *out_len, &len) != 1) {
    return false;
  }
  *out_len += len;

  // Get the tag
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len,
                          out + nonce_len + *out_len) != 1) {
    return false;
  }
  *out_len += tag_len;
  *out_len += nonce_len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return true;
}

static void format_header(yh_algorithm wrapkey_algorithm,
                          yh_capabilities capabilities, uint16_t id,
                          uint16_t data_len, uint16_t domains,
                          yh_object_type type, yh_algorithm algorithm,
                          uint8_t *label, uint8_t *header) {

  *header = (uint8_t) wrapkey_algorithm;
  header++;

  memcpy(header, capabilities.capabilities, YH_CAPABILITIES_LEN);
  header += YH_CAPABILITIES_LEN;

  *((uint16_t *) header) = htons(id);
  header += sizeof(uint16_t);

  *((uint16_t *) header) = htons(data_len);
  header += sizeof(uint16_t);

  *((uint16_t *) header) = htons(domains);
  header += sizeof(uint16_t);

  *header = (uint8_t) type;
  header++;

  *header = (uint8_t) algorithm;
  header++;

  *header = 0x00; // Sequence
  header++;

  *header = 0x02; // Origin
  header++;

  memcpy(header, label, YH_OBJ_LABEL_LEN);
  header += YH_OBJ_LABEL_LEN;
}

static FILE *open_file(const char *name, bool input) {
  if (input) {
    if (strcmp(name, "-") == 0) {
      return stdin;
    } else {
      return fopen(name, "rb");
    }
  } else {
    if (strcmp(name, "-") == 0) {
      return stdout;
    } else {
      return fopen(name, "w");
    }
  }
}

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    if (i && !(i % 32))
      fprintf(stderr, "\n");
    else if (i && !(i % 8))
      fprintf(stderr, " ");
    fprintf(stderr, "%02x", buf[i]);
  }
  fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;

  int rc = EXIT_FAILURE;
  yh_rc yhrc;

  FILE *input_file = NULL;
  FILE *output_file = NULL;
  FILE *wrapkey_file = NULL;

#pragma pack(push, 1)
  union {
    struct {
      uint8_t header[OBJECT_HEADER_SIZE];
      uint8_t body[INPUT_BUFSIZE];
    };
    uint8_t buf[1];
  } wrap_object = {{{0}, {0}}};
#pragma pack(pop)
  size_t wrap_object_len = sizeof(wrap_object.body);

  if (cmdline_parser(argc, argv, &args_info) != 0) {
    goto main_exit;
  }

  yh_algorithm algorithm;
  yhrc = yh_string_to_algo(args_info.algorithm_arg, &algorithm);
  if (yhrc != YHR_SUCCESS) {
    fprintf(stderr, "Unable to parse algorithm: %s\n", yh_strerror(yhrc));
    goto main_exit;
  }

  yh_capabilities capabilities = {{0}};
  yhrc = yh_string_to_capabilities(args_info.capabilities_arg, &capabilities);
  if (yhrc != YHR_SUCCESS) {
    fprintf(stderr, "Unable to parse capabilities: %s\n", yh_strerror(yhrc));
    goto main_exit;
  }

  uint16_t domains;
  yhrc = yh_string_to_domains(args_info.domains_arg, &domains);
  if (yhrc != YHR_SUCCESS) {
    fprintf(stderr, "Unable to parse domains: %s\n", yh_strerror(yhrc));
    goto main_exit;
  }

  uint16_t id = args_info.id_arg;

  uint8_t label[YH_OBJ_LABEL_LEN] = {0};
  size_t label_len = strlen(args_info.label_arg);
  if (label_len > YH_OBJ_LABEL_LEN) {
    fprintf(stderr,
            "Unable to parse label: label too long, maximum length is %d\n",
            YH_OBJ_LABEL_LEN);
    goto main_exit;
  }
  memcpy(label, args_info.label_arg, label_len);

  yh_object_type type;
  if (algo2type(algorithm, &type) == false) {
    fprintf(stderr, "Invalid algorithm\n");
    goto main_exit;
  }

  yh_capabilities delegated = {{0}};
  bool has_delegated =
    ((type == YH_AUTHENTICATION_KEY || type == YH_WRAP_KEY) ? true : false);
  if (has_delegated == true) {
    if (!args_info.delegated_given) {
      fprintf(stderr, "Missing delegated capabilities argument\n");
      goto main_exit;
    }

    yhrc = yh_string_to_capabilities(args_info.delegated_arg, &delegated);
    if (yhrc != YHR_SUCCESS) {
      fprintf(stderr, "Unable to parse delegated capabilities: %s\n",
              yh_strerror(yhrc));
      goto main_exit;
    }
  }

  input_file = open_file(args_info.in_arg, true);
  if (input_file == NULL) {
    perror("Unable to open input file");
    goto main_exit;
  }

  switch (type) {
    case YH_AUTHENTICATION_KEY: {
      char password[256] = {0};
      size_t password_len = sizeof(password);

      if (input_file == stdin) {
        const char *prompt = "Derivation Password: ";
        if (EVP_read_pw_string(password, password_len, prompt, 1)) {
          fprintf(stderr, "Unable to read password prompt\n");
          goto main_exit;
        }
        password_len = strlen(password);
      } else {
        if (read_file(input_file, (uint8_t *) password, &password_len) ==
            false) {
          fprintf(stderr, "Unable to read input file\n");
          goto main_exit;
        }
        if (password[password_len - 1] == '\n') {
          password_len--;
        }
        if (password[password_len - 1] == '\r') {
          password_len--;
        }
        password[password_len] = '\0';
      }

      uint8_t key[YH_KEY_LEN * 2];
      int ret =
        PKCS5_PBKDF2_HMAC((const char *) password, password_len,
                          (uint8_t *) YH_DEFAULT_SALT, strlen(YH_DEFAULT_SALT),
                          YH_DEFAULT_ITERS, EVP_sha256(), sizeof(key), key);
      if (ret != 1) {
        fprintf(stderr, "Unable to derive keys\n");
        goto main_exit;
      }

      memcpy(wrap_object.body, delegated.capabilities, YH_CAPABILITIES_LEN);
      wrap_object_len -= YH_CAPABILITIES_LEN;

      memcpy(wrap_object.body + YH_CAPABILITIES_LEN, key, YH_KEY_LEN);
      memcpy(wrap_object.body + YH_CAPABILITIES_LEN + YH_KEY_LEN,
             key + YH_KEY_LEN, YH_KEY_LEN);
      wrap_object_len = YH_CAPABILITIES_LEN + YH_KEY_LEN * 2;
    } break;

    case YH_WRAP_KEY: {
      memcpy(wrap_object.body, delegated.capabilities, YH_CAPABILITIES_LEN);
      wrap_object_len -= YH_CAPABILITIES_LEN;

      if (read_file(input_file, wrap_object.body + YH_CAPABILITIES_LEN,
                    &wrap_object_len) == false) {
        fprintf(stderr, "Unable to read input file\n");
        goto main_exit;
      }
      wrap_object_len += YH_CAPABILITIES_LEN;
    } break;

    case YH_ASYMMETRIC_KEY: {
      yh_algorithm parsed_algorithm;
      if (read_file(input_file, wrap_object.body, &wrap_object_len) == false) {
        fprintf(stderr, "Unable to read input file\n");
        goto main_exit;
      }

      if (read_private_key(wrap_object.body, wrap_object_len, &parsed_algorithm,
                           wrap_object.body, &wrap_object_len, true) != true) {
        fprintf(stderr, "Unable to read asymmetric private key\n");
        goto main_exit;
      }

      if (parsed_algorithm != algorithm) {
        fprintf(stderr, "Mismatched algorithm\n");
        goto main_exit;
      }
    } break;

    case YH_HMAC_KEY: {
      if (read_file(input_file, wrap_object.body, &wrap_object_len) == false) {
        fprintf(stderr, "Unable to read input file\n");
        goto main_exit;
      }

      if (split_hmac_key(algorithm, wrap_object.body, wrap_object_len,
                         wrap_object.body, &wrap_object_len) != true) {
        fprintf(stderr, "Unable to format hmac key\n");
        goto main_exit;
      }
    } break;

    default:
      if (read_file(input_file, wrap_object.body, &wrap_object_len) == false) {
        fprintf(stderr, "Unable to read input file\n");
        goto main_exit;
      }
  }

  wrapkey_file = open_file(args_info.wrapkey_arg, true);
  if (wrapkey_file == NULL) {
    perror("Unable to open wrapkey file");
    goto main_exit;
  }

  uint8_t wrapkey_buf[WRAPKEY_BUFSIZE];
  size_t wrapkey_buf_len = sizeof(wrapkey_buf);
  if (read_file(wrapkey_file, wrapkey_buf, &wrapkey_buf_len) == false) {
    fprintf(stderr, "Unable to read wrapkey file\n");
  }

  yh_algorithm wrapkey_algorithm;
  switch (wrapkey_buf_len) {
    case 16:
      wrapkey_algorithm = YH_ALGO_AES128_CCM_WRAP;
      break;
    case 24:
      wrapkey_algorithm = YH_ALGO_AES192_CCM_WRAP;
      break;
    case 32:
      wrapkey_algorithm = YH_ALGO_AES256_CCM_WRAP;
      break;
    default:
      fprintf(stderr, "Unable to parse wrapkey: invalid length\n");
      goto main_exit;
  }

  output_file = open_file(args_info.out_arg, false);
  if (output_file == NULL) {
    perror("Unable to open output file");
    goto main_exit;
  }

  format_header(wrapkey_algorithm, capabilities, id, wrap_object_len, domains,
                type, algorithm, label, wrap_object.header);

  uint8_t wrapped[2048] = {0};
  size_t wrapped_len = sizeof(wrapped);

  if (wrap_data(wrapkey_buf, wrapkey_buf_len, wrap_object.buf,
                OBJECT_HEADER_SIZE + wrap_object_len, wrapped,
                &wrapped_len) == false) {
    fprintf(stderr, "Unable to wrap data\n");
    goto main_exit;
  }

  if (getenv("DEBUG") != NULL) {
    dump_hex(wrap_object.buf, OBJECT_HEADER_SIZE + wrap_object_len);
  }
  if (write_file(wrapped, wrapped_len, output_file, _base64) == false ||
      write_file((uint8_t *) "\n", 1, output_file, _binary) == false) {
    fprintf(stderr, "Unable to write output file\n");
    goto main_exit;
  }

  rc = EXIT_SUCCESS;

main_exit:

  if (input_file != NULL) {
    fclose(input_file);
    input_file = NULL;
  }

  if (output_file != NULL) {
    fclose(output_file);
    output_file = NULL;
  }

  if (wrapkey_file != NULL) {
    fclose(wrapkey_file);
    wrapkey_file = NULL;
  }

  return rc;
}
