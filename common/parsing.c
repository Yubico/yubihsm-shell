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
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <openssl/evp.h>

#include "parsing.h"

#define READ_STR_PROMPT_BASE "Enter %s: "

bool read_string(const char *name, char *str_buf, size_t str_buf_len,
                 enum input_visibility visibility) {

  char prompt[sizeof(READ_STR_PROMPT_BASE) + 64] = {0};
  int ret;

  if (str_buf_len < 1) {
    fprintf(stderr, "Unable to read %s: buffer too small\n", name);
    return false;
  }

  ret = snprintf(prompt, sizeof(prompt), READ_STR_PROMPT_BASE, name);
  if (ret < 0 || ((unsigned int) ret) > (sizeof(prompt) - 1)) {
    fprintf(stderr, "Unable to read %s: snprintf failed\n", name);
    return false;
  }

  bool checked = false;
  switch (visibility) {
    case VISIBLE:
      fprintf(stdout, "%s", prompt);
      str_buf = fgets(str_buf, str_buf_len, stdin);
      if (str_buf == NULL) {
        return false;
      }
      str_buf[strlen(str_buf) - 1] = '\0';

      break;

    case HIDDEN_CHECKED:
      checked = true;
    case HIDDEN_UNCHECKED:
      ret = EVP_read_pw_string(str_buf, str_buf_len - 1, prompt, checked);
      if (ret != 0) {
        fprintf(stderr, "Retrieving %s failed (%d)\n", name, ret);
        return false;
      }

      break;
  }

  return true;
}

bool hex_decode(const char *in, uint8_t *out, size_t *len) {
  int pos = 0;
  if (in == NULL || out == NULL || len == NULL) {
    return false;
  }
  size_t in_len = strlen(in);
  if (in_len > 0 && in[in_len - 1] == '\n') {
    in_len--;
  }
  if (in_len > 0 && in[in_len - 1] == '\r') {
    in_len--;
  }
  if (in_len % 2 != 0) {
    return false;
  } else if (in_len / 2 > *len) {
    return false;
  }

  for (size_t i = 0; i < in_len / 2; i++) {
    char *endptr = NULL;
    char buf[3] = {0};
    long num;
    errno = 0;

    buf[0] = in[pos];
    buf[1] = in[pos + 1];
    num = strtol(buf, &endptr, 16);
    if (errno != 0 || num < 0 || num > UCHAR_MAX || *endptr != '\0') {
      return false;
    }
    out[i] = (uint8_t) num;
    pos += 2;
  }
  *len = in_len / 2;
  return true;
}
