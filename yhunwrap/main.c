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
#include "../common/platform-config.h"

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

static bool unwrap_data(uint8_t *key, size_t key_len, uint8_t *in, size_t in_len,
                      uint8_t *out, size_t *out_len) {

  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher_type;

  uint8_t nonce[13];
  int nonce_len = 13;
  int tag_len = 16;

  int len;

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return false;
  }

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

  memcpy(nonce, in, nonce_len);

  // Select cipher
  if (EVP_DecryptInit_ex(ctx, cipher_type, NULL, NULL, NULL) != 1) {
    return false;
  }

  // Set nonce length
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce_len, NULL) != 1) {
    return false;
  }

  // Set tag
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, in + in_len - tag_len) != 1) {
    return false;
  }

  // Initialize key and IV
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    return false;
  }

  // Provide the total ciphertext length
  if (EVP_DecryptUpdate(ctx, NULL, &len, NULL, in_len - nonce_len - tag_len) != 1) {
    return false;
  }

  // Provide the message to be decrypted, and obtain the decrypted output
  if (EVP_DecryptUpdate(ctx, out, &len, in + nonce_len, in_len - nonce_len - tag_len) != 1) {
    return false;
  }
  *out_len = len;

  // Finalize decryption for completeness. (AES-CCM gets no output from DecryptFinal.)
  if (EVP_DecryptFinal(ctx, out + *out_len, &len) != 1) {
      return false;
  }
  *out_len += len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return true;
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
      return fopen(name, "wb");
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
}

static void print_header(uint8_t *header) {

  uint8_t header_index = 0;
  fprintf(stderr, "Wrapkey algorithm: %02x, ", header[header_index]);
  switch (header[header_index]) {
    case YH_ALGO_AES128_CCM_WRAP:
      fprintf(stderr, "AES128-CCM\n");
      break;
    case YH_ALGO_AES192_CCM_WRAP:
      fprintf(stderr, "AES192-CCM\n");
      break;
    case YH_ALGO_AES256_CCM_WRAP:
      fprintf(stderr, "AES256-CCM\n");
      break;
    default:
      fprintf(stderr, "UNKNOWN\n");
  }
  header_index+=sizeof(uint8_t);

  yh_capabilities capabilities;
  memcpy(capabilities.capabilities, header + header_index, YH_CAPABILITIES_LEN);

  const char *cap[sizeof(yh_capability) / sizeof(yh_capability[0])] = {0};
  size_t n_cap = sizeof(yh_capability) / sizeof(yh_capability[0]);

  fprintf(stderr, "Capabilities: ");
  dump_hex(capabilities.capabilities, YH_CAPABILITIES_LEN);
  fprintf(stderr, ", ");
  if (yh_capabilities_to_strings(&capabilities, cap, &n_cap) !=
      YHR_SUCCESS) {
    for (size_t i = 0; i < YH_CAPABILITIES_LEN; i++) {
      fprintf(stderr, "0x%02x%s", capabilities.capabilities[i],
              i < YH_CAPABILITIES_LEN - 1 ? " " : "");
    }
  } else {
    for (size_t i = 0; i < n_cap; i++) {
      fprintf(stderr, "%s%s", cap[i], i < n_cap - 1 ? ":" : "");
    }
  }
  fprintf(stderr, "\n");
  header_index+=YH_CAPABILITIES_LEN;

  uint16_t id;
  memcpy(&id, header + header_index, sizeof(uint16_t));
  fprintf(stderr, "ID: %04x\n", ntohs(id));
  header_index+=sizeof(uint16_t);

  uint16_t data_len;
  memcpy(&data_len, header + header_index, sizeof(uint16_t));
  fprintf(stderr, "Key size: %04x\n", ntohs(data_len));
  header_index+=sizeof(uint16_t);

  uint16_t object_domains;
  char domains[256] = {0};
  memcpy(&object_domains, header + header_index, sizeof(uint16_t));
  yh_domains_to_string(ntohs(object_domains), domains, 255);
  fprintf(stderr, "Domains: %04x, %s\n", ntohs(object_domains), domains);
  header_index+=sizeof(uint16_t);

  uint8_t object_type;
  const char *type = 0;
  memcpy(&object_type, header + header_index, sizeof(uint8_t));
  yh_type_to_string(object_type, &type);
  fprintf(stderr, "Type: %02x, %s\n", object_type, type);
  header_index+=sizeof(uint8_t);

  uint8_t object_algorithm;
  const char *algorithm = "";
  memcpy(&object_algorithm, header + header_index, sizeof(uint8_t));
  yh_algo_to_string(object_algorithm, &algorithm);
  fprintf(stderr, "Algorithm: %02x, %s\n", object_algorithm, algorithm);
  header_index+=sizeof(uint8_t);

  uint8_t sequence;
  memcpy(&sequence, header + header_index, sizeof(uint8_t));
  fprintf(stderr, "Sequence: %02x\n", sequence);
  header_index+=sizeof(uint8_t);

  uint8_t object_origin;
  memcpy(&object_origin, header + header_index, sizeof(uint8_t));
  fprintf(stderr, "Origin: %02x, ", object_origin);
  if (object_origin & YH_ORIGIN_GENERATED) {
    fprintf(stderr, "generated");
  }
  if (object_origin & YH_ORIGIN_IMPORTED) {
    fprintf(stderr, "imported");
  }
  if (object_origin & YH_ORIGIN_IMPORTED_WRAPPED) {
    fprintf(stderr, ":imported_wrapped");
  }
  fprintf(stderr, "\n");
  header_index+=sizeof(uint8_t);

  uint8_t label[YH_OBJ_LABEL_LEN] = {0};
  memcpy(&label, header + header_index, YH_OBJ_LABEL_LEN);
  fprintf(stderr, "Label: %.*s\n", YH_OBJ_LABEL_LEN, label);
  header_index+=sizeof(YH_OBJ_LABEL_LEN);
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;

  int rc = EXIT_FAILURE;

  FILE *input_file = NULL;
  FILE *output_file = NULL;
  FILE *wrapkey_file = NULL;

  uint8_t wrapped[2048] = {0};
  size_t wrapped_len = sizeof(wrapped);

  if (cmdline_parser(argc, argv, &args_info) != 0) {
    goto main_exit;
  }

  input_file = open_file(args_info.in_arg, true);
  if (input_file == NULL) {
    perror("Unable to open input file");
    goto main_exit;
  }

  if (read_file(input_file, wrapped, &wrapped_len) == false) {
    fprintf(stderr, "Unable to read input file\n");
    goto main_exit;
  }

  // Optionally, base64-decode the input key.
  base64_decode((char *)wrapped, wrapped, &wrapped_len);

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

  output_file = open_file(args_info.out_arg, false);
  if (output_file == NULL) {
    perror("Unable to open output file");
    goto main_exit;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint8_t header[OBJECT_HEADER_SIZE];
      uint8_t body[INPUT_BUFSIZE];
    };
    uint8_t buf[1];
  } wrap_object = {{{0}, {0}}};
#pragma pack(pop)
  size_t wrap_object_len = sizeof(wrap_object.buf);

  if (unwrap_data(wrapkey_buf, wrapkey_buf_len, wrapped,
                  wrapped_len, wrap_object.buf,
                &wrap_object_len) == false) {
    fprintf(stderr, "Unable to unwrap data\n");
    goto main_exit;
  }

  if (getenv("DEBUG") != NULL) {
    print_header(wrap_object.header);
    fprintf(stderr, "\n");
  }
  if (write_file(wrap_object.body, wrap_object_len - OBJECT_HEADER_SIZE, output_file, _base64) == false ||
      write_file((uint8_t *) "\n", 1, output_file, _binary) == false) {
    fprintf(stderr, "Unable to write output file\n");
    goto main_exit;
  }

  rc = EXIT_SUCCESS;

main_exit:

  cmdline_parser_free(&args_info);

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
