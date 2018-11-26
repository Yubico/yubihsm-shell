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

#include <openssl/evp.h>

#include "parsing.h"

#define READ_STR_PROMPT_BASE "Enter %s: "

bool read_string(const char *name, char *str_buf, size_t str_buf_len,
                 bool hidden) {

  char prompt[sizeof(READ_STR_PROMPT_BASE) + 32] = {0};
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

  if (hidden == true) {
    ret = EVP_read_pw_string(str_buf, str_buf_len, prompt, true);
    if (ret != 0) {
      fprintf(stderr, "Retrieving %s failed (%d)\n", name, ret);
      return false;
    }
  } else {
    fprintf(stdout, "%s", prompt);
    str_buf = fgets(str_buf, str_buf_len, stdin);
    if (str_buf == NULL) {
      return false;
    }
    str_buf[strlen(str_buf) - 1] = '\0';
  }

  return true;
}

bool parse_pw(const char *prompt, char *pw, char *parsed, size_t *parsed_len) {
  if (strlen(pw) > *parsed_len) {
    fprintf(stderr, "Unable to read name, buffer too small\n");
    return false;
  }

  if (strlen(pw) == 0) {
    if (read_string(prompt, parsed, *parsed_len, true) == false) {
      return false;
    }
  } else {
    strncpy(parsed, pw, *parsed_len);
  }

  *parsed_len = strlen(parsed);

  return true;
}
