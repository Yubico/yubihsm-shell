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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ykhsmauth.h>

#include "pkcs5.h"
#include "parsing.h"

#include "cmdline.h"

static bool parse_label(const char *prompt, char *label, char *parsed,
                        size_t *parsed_len) {
  if (strlen(label) > *parsed_len) {
    fprintf(stdout, "Unable to read label, buffer too small\n");
    return false;
  }

  if (strlen(label) == 0) {
    if (read_string(prompt, parsed, *parsed_len, false) == false) {
      return false;
    }
  } else {
    strcpy(parsed, label);
  }

  *parsed_len = strlen(label);

  return true;
}

static bool parse_pw(const char *prompt, char *pw, uint8_t *parsed,
                     size_t *parsed_len) {
  if (strlen(pw) > *parsed_len) {
    fprintf(stderr, "Unable to read password, buffer too small\n");
    return false;
  }

  if (strlen(pw) == 0) {
    if (read_string(prompt, (char *) parsed, *parsed_len, HIDDEN_CHECKED) ==
        false) {
      return false;
    }
  } else {
    strncpy((char *) parsed, pw, *parsed_len);
  }

  *parsed_len = strlen((char *) parsed);

  return true;
}

static bool parse_key(const char *prompt, char *key, uint8_t *parsed,
                      size_t *parsed_len) {
  char buf[128] = {0};
  size_t buf_size = sizeof(buf);

  if (strlen(key) > buf_size) {
    fprintf(stdout, "Unable to read key, buffer too small\n");
    return false;
  }

  if (strlen(key) == 0) {
    if (read_string(prompt, buf, buf_size, true) == false) {
      return false;
    }
    buf_size = strlen(buf);
  } else {
    memcpy(buf, key, strlen(key));
    buf_size = strlen(key);
  }

  if (hex_decode(buf, parsed, parsed_len) == false) {
    fprintf(stdout, "Unable to parse key, must be %d characters hexadecimal\n",
            YKHSMAUTH_YUBICO_AES128_KEY_LEN);
    return false;
  }

  if (*parsed_len != YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2) {
    fprintf(stdout, "Unable to read key, wrong length (must be %d)\n",
            YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2);
    return false;
  }

  return true;
}

static bool parse_context(const char *prompt, char *context, uint8_t *parsed,
                          size_t *parsed_len) {
  char buf[128] = {0};
  size_t buf_size = sizeof(buf);

  if (strlen(context) > buf_size) {
    fprintf(stdout, "Unable to read context, buffer too small\n");
    return false;
  }

  if (strlen(context) == 0) {
    if (read_string(prompt, buf, buf_size, false) == false) {
      return false;
    }
    buf_size = strlen(buf);
  } else {
    memcpy(buf, context, strlen(context));
    buf_size = strlen(context);
  }

  if (hex_decode(buf, parsed, parsed_len) == false) {
    fprintf(stdout,
            "Unable to parse context, must be %d characters hexadecimal\n",
            YKHSMAUTH_CONTEXT_LEN * 2);
    return false;
  }

  if (*parsed_len != YKHSMAUTH_CONTEXT_LEN) {
    fprintf(stdout, "Unable to read context, wrong length (must be %d)\n",
            YKHSMAUTH_CONTEXT_LEN);
    return false;
  }

  return true;
}

static bool parse_touch_policy(enum enum_touch touch_policy,
                               uint8_t *touch_policy_parsed) {

  switch (touch_policy) {
    case touch__NULL:
    case touch_arg_off:
      *touch_policy_parsed = 0;
      break;

    case touch_arg_on:
      *touch_policy_parsed = 1;
      break;
  }

  return true;
}

static bool delete_credential(ykhsmauth_state *state, char *mgmkey,
                              char *label) {
  ykhsmauth_rc ykhsmauthrc;
  uint8_t mgmkey_parsed[YKHSMAUTH_PW_LEN] = {0};
  size_t mgmkey_parsed_len = sizeof(mgmkey_parsed);
  char label_parsed[YKHSMAUTH_MAX_LABEL_LEN + 2] = {0};
  size_t label_parsed_len = sizeof(label_parsed);
  uint8_t retries;

  if (parse_key("Management key", mgmkey, mgmkey_parsed, &mgmkey_parsed_len) ==
      false) {
    return false;
  }

  if (parse_label("Label", label, label_parsed, &label_parsed_len) == false) {
    return false;
  }

  ykhsmauthrc = ykhsmauth_delete(state, mgmkey_parsed, mgmkey_parsed_len,
                                 label_parsed, &retries);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to delete credential: %s, %d retries left\n",
            ykhsmauth_strerror(ykhsmauthrc), retries);
    return false;
  }

  fprintf(stdout, "Credential successfully deleted\n");

  return true;
}

static bool list_credentials(ykhsmauth_state *state) {
  ykhsmauth_rc ykhsmauthrc;
  ykhsmauth_list_entry list[32];
  size_t list_items = sizeof(list) / sizeof(list[0]);

  ykhsmauthrc = ykhsmauth_list_keys(state, list, &list_items);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to list credentials: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return false;
  }

  if (list_items == 0) {
    fprintf(stdout, "No items found\n");
    return true;
  }

  fprintf(stdout, "Found %zu item(s)\n", list_items);
  fprintf(stdout, "Algo\tTouch\tCounter\tLabel\n");

  for (size_t i = 0; i < list_items; i++) {
    fprintf(stdout, "%d\t%d\t%d\t%s\n", list[i].algo, list[i].touch,
            list[i].ctr, list[i].label);
  }

  return true;
}

static bool put_credential(ykhsmauth_state *state, char *mgmkey, char *label,
                           char *derivation_password, char *key_enc,
                           char *key_mac, char *credpassword,
                           enum enum_auth_algo auth_algorithm,
                           enum enum_touch touch_policy) {
  ykhsmauth_rc ykhsmauthrc;
  uint8_t mgmkey_parsed[YKHSMAUTH_PW_LEN] = {0};
  size_t mgmkey_parsed_len = sizeof(mgmkey_parsed);
  char label_parsed[YKHSMAUTH_MAX_LABEL_LEN + 2] = {0};
  size_t label_parsed_len = sizeof(label_parsed);
  uint8_t dpw_parsed[256] = {0};
  size_t dpw_parsed_len = sizeof(dpw_parsed);
  uint8_t key_parsed[YKHSMAUTH_YUBICO_AES128_KEY_LEN] = {0};
  size_t key_parsed_len = sizeof(key_parsed);
  uint8_t cpw_parsed[YKHSMAUTH_PW_LEN + 2] = {0};
  size_t cpw_parsed_len = sizeof(cpw_parsed);
  uint8_t touch_policy_parsed = 0;
  uint8_t retries;

  if (parse_key("Management key", mgmkey, mgmkey_parsed, &mgmkey_parsed_len) ==
      false) {
    return false;
  }

  if (parse_label("Label", label, label_parsed, &label_parsed_len) == false) {
    return false;
  }

  if (strlen(key_mac) == 0 && strlen(key_enc) == 0) {
    if (parse_pw("Derivation password", derivation_password, dpw_parsed,
                 &dpw_parsed_len) == false) {
      return false;
    }
  } else {
    dpw_parsed_len = 0;
  }

  if (dpw_parsed_len == 0) {
    size_t key_enc_parsed_len = sizeof(key_parsed) / 2;
    size_t key_mac_parsed_len = sizeof(key_parsed) / 2;

    if (parse_key("Encryption key", key_enc, key_parsed, &key_enc_parsed_len) ==
        false) {
      return false;
    }

    if (parse_key("MAC key", key_mac, key_parsed + key_enc_parsed_len,
                  &key_mac_parsed_len) == false) {
      return false;
    }

    key_parsed_len = key_enc_parsed_len + key_mac_parsed_len;
  } else {
    if (pkcs5_pbkdf2_hmac((uint8_t *) dpw_parsed, dpw_parsed_len,
                          (const uint8_t *) YKHSMAUTH_DEFAULT_SALT,
                          strlen(YKHSMAUTH_DEFAULT_SALT),
                          YKHSMAUTH_DEFAULT_ITERS, _SHA256, key_parsed,
                          sizeof(key_parsed)) == false) {
      return false;
    }

    key_parsed_len = sizeof(key_parsed);
  }

  if (parse_pw("Credential Password (max 16 characters)", credpassword,
               cpw_parsed, &cpw_parsed_len) == false) {
    return false;
  }

  if (cpw_parsed_len > YKHSMAUTH_PW_LEN) {
    fprintf(stderr, "Credential password can not be more than %d characters.\n",
            YKHSMAUTH_PW_LEN);
    return false;
  }

  if (parse_touch_policy(touch_policy, &touch_policy_parsed) == false) {
    return false;
  }

  ykhsmauthrc =
    ykhsmauth_put(state, mgmkey_parsed, mgmkey_parsed_len, label_parsed,
                  auth_algorithm == auth_algo_arg_yubicoMINUS_aes128
                    ? YKHSMAUTH_YUBICO_AES128_ALGO
                    : YKHSMAUTH_YUBICO_ECP256_ALGO,
                  key_parsed, key_parsed_len, cpw_parsed, cpw_parsed_len,
                  touch_policy_parsed, &retries);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to store credential: %s, %d retries left\n",
            ykhsmauth_strerror(ykhsmauthrc), retries);
    return false;
  }

  fprintf(stdout, "Credential successfully stored\n");

  return true;
}

bool reset_device(ykhsmauth_state *state) {
  ykhsmauth_rc ykhsmauthrc;

  ykhsmauthrc = ykhsmauth_reset(state);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to reset device: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return false;
  }

  fprintf(stdout, "Device successfully reset\n");

  return true;
}

bool get_mgmkey_retries(ykhsmauth_state *state) {
  ykhsmauth_rc ykhsmauthrc;
  uint8_t retries;

  ykhsmauthrc = ykhsmauth_get_mgmkey_retries(state, &retries);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to get mgmkey retries: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return false;
  }

  fprintf(stdout, "Retries left for Management Key: %d\n", retries);

  return true;
}

void print_key(char *prompt, uint8_t *key, size_t len) {
  fprintf(stdout, "%s: ", prompt);
  for (size_t i = 0; i < len; i++) {
    fprintf(stdout, "%02x", key[i]);
  }
  fprintf(stdout, "\n");
}

bool get_challenge(ykhsmauth_state *state, char *label) {
  ykhsmauth_rc ykhsmauthrc;
  char label_parsed[YKHSMAUTH_MAX_LABEL_LEN + 2] = {0};
  size_t label_parsed_len = sizeof(label_parsed);
  uint8_t challenge[YKHSMAUTH_PUBKEY_LEN] = {0};
  size_t challenge_len = sizeof(challenge);

  if (parse_label("Label", label, label_parsed, &label_parsed_len) == false) {
    return false;
  }

  ykhsmauthrc =
    ykhsmauth_get_challenge(state, label_parsed, challenge, &challenge_len);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to get challenge: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return false;
  }

  print_key("Challenge", challenge, challenge_len);

  return true;
}

bool get_pubkey(ykhsmauth_state *state, char *label) {
  ykhsmauth_rc ykhsmauthrc;
  char label_parsed[YKHSMAUTH_MAX_LABEL_LEN + 2] = {0};
  size_t label_parsed_len = sizeof(label_parsed);
  uint8_t pubkey[YKHSMAUTH_PUBKEY_LEN] = {0};
  size_t pubkey_len = sizeof(pubkey);

  if (parse_label("Label", label, label_parsed, &label_parsed_len) == false) {
    return false;
  }

  ykhsmauthrc = ykhsmauth_get_pubkey(state, label_parsed, pubkey, &pubkey_len);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to get pubkey: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return false;
  }

  print_key("Long-term public key", pubkey, pubkey_len);

  return true;
}

bool get_version(ykhsmauth_state *state) {
  ykhsmauth_rc ykhsmauthrc;
  char version[64] = {0};
  size_t version_len = sizeof(version);

  ykhsmauthrc = ykhsmauth_get_version(state, version, version_len);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to get version: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return false;
  }

  fprintf(stdout, "Version %s\n", version);

  return true;
}

static bool calculate_session_keys(ykhsmauth_state *state, char *label,
                                   char *credpassword, char *context) {
  ykhsmauth_rc ykhsmauthrc;
  char label_parsed[YKHSMAUTH_MAX_LABEL_LEN + 2] = {0};
  size_t label_parsed_len = sizeof(label_parsed);
  uint8_t context_parsed[YKHSMAUTH_CONTEXT_LEN] = {0};
  size_t context_parsed_len = sizeof(context_parsed);
  uint8_t cpw_parsed[YKHSMAUTH_PW_LEN + 2] = {0};
  size_t cpw_parsed_len = sizeof(cpw_parsed);
  uint8_t key_s_enc[YKHSMAUTH_SESSION_KEY_LEN] = {0};
  uint8_t key_s_mac[YKHSMAUTH_SESSION_KEY_LEN] = {0};
  uint8_t key_s_rmac[YKHSMAUTH_SESSION_KEY_LEN] = {0};
  size_t key_s_enc_len = sizeof(key_s_enc);
  size_t key_s_mac_len = sizeof(key_s_mac);
  size_t key_s_rmac_len = sizeof(key_s_rmac);
  uint8_t retries;

  if (parse_label("Label", label, label_parsed, &label_parsed_len) == false) {
    return false;
  }

  if (parse_context("Context", context, context_parsed, &context_parsed_len) ==
      false) {
    return false;
  }

  if (parse_pw("Credential password", credpassword, cpw_parsed,
               &cpw_parsed_len) == false) {
    return false;
  }

  ykhsmauthrc =
    ykhsmauth_calculate(state, label_parsed, context_parsed, context_parsed_len,
                        cpw_parsed, cpw_parsed_len, key_s_enc, key_s_enc_len,
                        key_s_mac, key_s_mac_len, key_s_rmac, key_s_rmac_len,
                        &retries);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to calculate session keys: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    if (ykhsmauthrc == YKHSMAUTHR_WRONG_PW) {
      fprintf(stderr, "%d attempts left\n", retries);
    }
    return false;
  }

  print_key("Session encryption key", key_s_enc, key_s_enc_len);
  print_key("Session MAC key", key_s_mac, key_s_mac_len);
  print_key("Session R-MAC key", key_s_rmac, key_s_rmac_len);

  return true;
}

static bool put_mgmkey(ykhsmauth_state *state, char *mgmkey, char *new_mgmkey) {
  ykhsmauth_rc ykhsmauthrc;
  uint8_t mgmkey_parsed[YKHSMAUTH_PW_LEN] = {0};
  size_t mgmkey_parsed_len = sizeof(mgmkey_parsed);
  uint8_t new_mgmkey_parsed[YKHSMAUTH_PW_LEN] = {0};
  size_t new_mgmkey_parsed_len = sizeof(mgmkey_parsed);
  uint8_t retries;

  if (parse_key("Management key", mgmkey, mgmkey_parsed, &mgmkey_parsed_len) ==
      false) {
    return false;
  }

  if (parse_key("New Management key", new_mgmkey, new_mgmkey_parsed,
                &new_mgmkey_parsed_len) == false) {
    return false;
  }

  ykhsmauthrc =
    ykhsmauth_put_mgmkey(state, mgmkey_parsed, mgmkey_parsed_len,
                         new_mgmkey_parsed, new_mgmkey_parsed_len, &retries);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to change Management key: %s, %d retries left\n",
            ykhsmauth_strerror(ykhsmauthrc), retries);
    return false;
  }

  fprintf(stdout, "Management key successfully changed\n");

  return true;
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;
  ykhsmauth_state *state = NULL;
  ykhsmauth_rc ykhsmauthrc;

  int rc = EXIT_FAILURE;

  if (cmdline_parser(argc, argv, &args_info) != 0) {
    goto main_exit;
  }

  ykhsmauthrc = ykhsmauth_init(&state, args_info.verbose_arg);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Failed to initialize libykhsmauth\n");
    goto main_exit;
  }

  ykhsmauthrc = ykhsmauth_connect(state, args_info.reader_arg);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Unable to connect: %s\n", ykhsmauth_strerror(ykhsmauthrc));
    goto main_exit;
  }

  bool result = false;
  switch (args_info.action_arg) {
    case action_arg_calculate:
      result =
        calculate_session_keys(state, args_info.label_arg,
                               args_info.credpwd_arg, args_info.context_arg);
      break;

    case action_arg_changeMINUS_mgmkey:
      result =
        put_mgmkey(state, args_info.mgmkey_arg, args_info.new_mgmkey_arg);
      break;

    case action_arg_delete:
      result =
        delete_credential(state, args_info.mgmkey_arg, args_info.label_arg);
      break;

    case action_arg_list:
      result = list_credentials(state);
      break;

    case action_arg_put:
      result =
        put_credential(state, args_info.mgmkey_arg, args_info.label_arg,
                       args_info.derivation_password_arg, args_info.enckey_arg,
                       args_info.mackey_arg, args_info.credpwd_arg,
                       args_info.auth_algo_arg, args_info.touch_arg);
      break;

    case action_arg_reset:
      result = reset_device(state);
      break;

    case action_arg_retries:
      result = get_mgmkey_retries(state);
      break;

    case action_arg_getMINUS_challenge:
      result = get_challenge(state, args_info.label_arg);
      break;

    case action_arg_getMINUS_pubkey:
      result = get_pubkey(state, args_info.label_arg);
      break;

    case action_arg_version:
      result = get_version(state);
      break;

    case action__NULL:
      fprintf(stderr, "No action given, nothing to do\n");
      break;
  }

  if (result == true) {
    rc = EXIT_SUCCESS;
  }

main_exit:

  ykhsmauth_done(state);

  return rc;
}
