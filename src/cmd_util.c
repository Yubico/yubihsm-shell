/*
* Copyright 2025 Yubico AB
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

#include <openssl/x509.h>
#include <string.h>

#include "yubihsm-shell.h"
#include "cmd_util.h"

static char *string_parser(char *str_orig, char delimiter, char *str_found) {
  char escape_char = '\\';
  int f = 0;
  char *p = str_orig;
  while (*p == delimiter) {
    p++;
  }
  for (; *p; p++) {
    if (*p != delimiter) {
      str_found[f++] = *p;
    } else if (*p == delimiter) {
      if ((*(p - 1) == escape_char &&
           *(p - 2) ==
             escape_char)) { // The escape_char before the delimiter is escaped
                             // => the delimiter is still in effect
        str_found[f - 1] = '\0';
        return p + 1;
      } else if (*(p - 1) == escape_char &&
                 *(p - 2) != escape_char) { // the delimiter is escaped
        str_found[f - 1] = delimiter;
      } else {                              // nothing is escaped
        str_found[f] = '\0';
        return p + 1;
      }
    }
  }
  str_found[f] = '\0';
  return NULL;
}

X509_NAME *parse_subject_name(const char *orig_name) {
  char name[1025] = {0};
  char part[1025] = {0};
  X509_NAME *parsed = NULL;
  char *ptr = name;

  if (strlen(orig_name) > 1024) {
    fprintf(stderr, "Name is too long!\n");
    return NULL;
  }
  strncpy(name, orig_name, sizeof(name));
  name[sizeof(name) - 1] = 0;

  if (*name != '/' || name[strlen(name) - 1] != '/') {
    fprintf(stderr, "Name does not start or does not end with '/'!\n");
    return NULL;
  }
  parsed = X509_NAME_new();
  if (!parsed) {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }
  while ((ptr = string_parser(ptr, '/', part))) {
    char *key;
    char *value;
    char *equals = strchr(part, '=');
    if (!equals) {
      fprintf(stderr, "The part '%s' doesn't seem to contain a =.\n", part);
      goto parse_err;
    }
    *equals++ = '\0';
    value = equals;
    key = part;

    if (!key) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if (!value) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if (!X509_NAME_add_entry_by_txt(parsed, key, MBSTRING_UTF8,
                                    (unsigned char *) value, -1, -1, 0)) {
      fprintf(stderr, "Failed adding %s=%s to name.\n", key, value);
      goto parse_err;
    }
  }
  return parsed;
parse_err:
  X509_NAME_free(parsed);
  return NULL;
}

static int ec_key_ex_data_idx = -1;

struct internal_key {
  yh_session *session;
  uint16_t key_id;
};

static int yk_rsa_meth_finish(RSA *rsa) {
  free(RSA_meth_get0_app_data(RSA_get_method(rsa)));
  return 1;
}

static int yk_rsa_meth_sign(int dtype, const unsigned char *m,
                            unsigned int m_len, unsigned char *sig,
                            unsigned int *sig_len, const RSA *rsa) {
  UNUSED(dtype);

  size_t yh_siglen = RSA_size(rsa);
  const RSA_METHOD *meth = RSA_get_method(rsa);
  const struct internal_key *key = RSA_meth_get0_app_data(meth);

  yh_rc yrc = yh_util_sign_pkcs1v1_5(key->session, key->key_id, true, m, m_len,
                                     sig, &yh_siglen);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to sign data with PKCS#1v1.5: %s\n",
            yh_strerror(yrc));
    return 0;
  }

  *sig_len = (unsigned int) yh_siglen;
  return 1;
}

static void yk_ec_meth_finish(EC_KEY *ec) {
  free(EC_KEY_get_ex_data(ec, ec_key_ex_data_idx));
}

static int yk_ec_meth_sign(int type, const unsigned char *m, int m_len,
                           unsigned char *sig, unsigned int *sig_len,
                           const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec) {
  UNUSED(type);
  UNUSED(kinv);
  UNUSED(r);

  size_t yh_siglen = ECDSA_size(ec);
  const struct internal_key *key = EC_KEY_get_ex_data(ec, ec_key_ex_data_idx);

  yh_rc yrc =
    yh_util_sign_ecdsa(key->session, key->key_id, m, m_len, sig, &yh_siglen);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to sign data with ECDSA: %s\n", yh_strerror(yrc));
    return 0;
  }

  *sig_len = (unsigned int) yh_siglen;
  return 1;
}

EVP_PKEY *wrap_public_key(yh_session *session, yh_algorithm algorithm,
                                 EVP_PKEY *public_key, uint16_t key_id) {
  struct internal_key *int_key = malloc(sizeof(struct internal_key));
  int_key->session = session;
  int_key->key_id = key_id;

  EVP_PKEY *pkey = EVP_PKEY_new();
  if (yh_is_rsa(algorithm)) {
    const RSA *pk = EVP_PKEY_get0_RSA(public_key);
    RSA_METHOD *meth = RSA_meth_dup(RSA_get_default_method());
    if (RSA_meth_set0_app_data(meth, int_key) != 1) {
      fprintf(stderr, "Failed to set RSA data\n");
      return NULL;
    }
    if (RSA_meth_set_finish(meth, yk_rsa_meth_finish) != 1) {
      fprintf(stderr, "Failed to set RSA finish method\n");
      return NULL;
    }
    if (RSA_meth_set_sign(meth, yk_rsa_meth_sign) != 1) {
      fprintf(stderr, "Failed to set RSA sign method\n");
      return NULL;
    }
    RSA *sk = RSA_new();
    RSA_set0_key(sk, BN_dup(RSA_get0_n(pk)), BN_dup(RSA_get0_e(pk)), NULL);
    if (RSA_set_method(sk, meth) != 1) {
      fprintf(stderr, "Failed to set RSA key method\n");
      return NULL;
    }
    EVP_PKEY_assign_RSA(pkey, sk);
  } else if (yh_is_ec(algorithm)) {
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(public_key);
    EC_KEY_METHOD *meth = EC_KEY_METHOD_new(EC_KEY_get_method(ec));
    EC_KEY_METHOD_set_init(meth, NULL, yk_ec_meth_finish, NULL, NULL, NULL,
                           NULL);
    EC_KEY_METHOD_set_sign(meth, yk_ec_meth_sign, NULL, NULL);
    EC_KEY *sk = EC_KEY_new();
    EC_KEY_set_group(sk, EC_KEY_get0_group(ec));
    EC_KEY_set_public_key(sk, EC_KEY_get0_public_key(ec));
    if (ec_key_ex_data_idx == -1)
      ec_key_ex_data_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (EC_KEY_set_ex_data(sk, ec_key_ex_data_idx, int_key) != 1) {
      fprintf(stderr, "Failed to set EC data\n");
      return NULL;
    }
    if (EC_KEY_set_method(sk, meth) != 1) {
      fprintf(stderr, "Failed to wrap public EC key\n");
      return NULL;
    }
    EVP_PKEY_assign_EC_KEY(pkey, sk);
  }
  return pkey;
}
