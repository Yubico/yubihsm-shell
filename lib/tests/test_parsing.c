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

#include "yubihsm.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_domains1(void) {
  struct {
    const char *string;
    uint16_t domains;
  } tests[] = {
    {"1", 1},          {"1,2:3,4|5,6;7,8,9,10,11,12,13,14,15,16", 0xffff},
    {"1,16", 0x8001},  {"16", 0x8000},
    {"16,15", 0xc000}, {"1,0xf", 0x4001},
    {"0x1,0x2", 3},    {"0x8888", 0x8888},
    {"0", 0},          {"all", 0xffff},
    {"2", 2},          {"2:4", 10},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    uint16_t d = 0;
    assert(yh_string_to_domains(tests[i].string, &d) == YHR_SUCCESS);
    assert(d == tests[i].domains);
  }
}

static void test_domains2(void) {
  struct {
    uint16_t domains;
    const char *string;
  } tests[] = {
    {1, "1"},
    {0x8001, "1:16"},
    {0, ""},
    {0xffff, "1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16"},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    char s[256];
    assert(yh_domains_to_string(tests[i].domains, s, 255) == YHR_SUCCESS);
    assert(strcmp(s, tests[i].string) == 0);
  }
}

static void test_capabilities1(void) {
  struct {
    const char *string;
    yh_capabilities capabilities;
  } tests[] = {
    {"get-opaque", {"\x00\x00\x00\x00\x00\x00\x00\x01"}},
    {"sign-hmac:verify-hmac|exportable-under-wrap,",
     {"\x00\x00\x00\x00\x00\xc1\x00\x00"}},
    {",,unwrap-data|:wrap-data,,,", {"\x00\x00\x00\x60\x00\x00\x00\x00"}},
    {"0x7fffffffffffffff", {"\x7f\xff\xff\xff\xff\xff\xff\xff"}},
    {"0xffffffffffffffff", {"\xff\xff\xff\xff\xff\xff\xff\xff"}},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    yh_capabilities c = {{0}};
    assert(yh_string_to_capabilities(tests[i].string, &c) == YHR_SUCCESS);
    assert(memcmp(&c, &tests[i].capabilities, sizeof(c)) == 0);
  }
}

static void test_capabilities2(void) {
  yh_rc yrc = YHR_GENERIC_ERROR;

  yh_capabilities capabilities = {{0}};
  const char *capabilities_array[8];
  size_t capabilities_array_len;
  char *capabilities_list[] = {"sign-pkcs",         "decrypt-pkcs",
                               "export-wrapped",    "set-option",
                               "get-pseudo-random", "sign-hmac",
                               "verify-hmac",       "get-log-entries"};
  char capabilities_string[1024];

  size_t len = 0;
  for (size_t i = 0;
       i < sizeof(capabilities_list) / sizeof(capabilities_list[0]); i++) {
    sprintf(capabilities_string + len, "%s:", capabilities_list[i]);
    len += strlen(capabilities_list[i]) + 1;
  }
  capabilities_string[len - 1] = '\0';

  yrc = yh_string_to_capabilities(capabilities_string, &capabilities);
  assert(yrc == YHR_SUCCESS);

  assert(yh_check_capability(&capabilities, "something") == false);
  assert(yh_check_capability(&capabilities, "sign-pss") == false);

  assert(yh_check_capability(&capabilities, "sign-pkcs") == true);
  assert(yh_check_capability(&capabilities, "decrypt-pkcs") == true);
  assert(yh_check_capability(&capabilities, "export-wrapped") == true);
  assert(yh_check_capability(&capabilities, "set-option") == true);
  assert(yh_check_capability(&capabilities, "get-pseudo-random") == true);
  assert(yh_check_capability(&capabilities, "sign-hmac") == true);
  assert(yh_check_capability(&capabilities, "verify-hmac") == true);
  assert(yh_check_capability(&capabilities, "get-log-entries") == true);
  assert(yh_check_capability(&capabilities, "verify-hmac:get-log-entries") ==
         true);

  capabilities_array_len = 1;
  yrc = yh_capabilities_to_strings(&capabilities, capabilities_array,
                                   &capabilities_array_len);
  assert(yrc == YHR_BUFFER_TOO_SMALL);

  capabilities_array_len =
    sizeof(capabilities_array) / sizeof(capabilities_array[0]);
  yrc = yh_capabilities_to_strings(&capabilities, capabilities_array,
                                   &capabilities_array_len);
  assert(yrc == YHR_SUCCESS);
  for (size_t i = 0;
       i < sizeof(capabilities_list) / sizeof(capabilities_list[0]); i++) {
    size_t j;
    for (j = 0; j < capabilities_array_len; j++) {
      if (strcmp(capabilities_list[i], capabilities_array[j]) == 0) {
        break;
      }
    }
    assert(j < capabilities_array_len);
  }
}

static void test_capabilities3(void) {
  const char *cap1 = "sign-pkcs,sign-pss";
  const char *cap2 = "decrypt-pkcs,decrypt-oaep";
  const char *cap3 = "sign-pss,decrypt-oaep";
  yh_capabilities c1 = {{0}};
  yh_capabilities c2 = {{0}};
  yh_capabilities c3 = {{0}};
  yh_capabilities res = {{0}};

  assert(yh_string_to_capabilities(cap1, &c1) == YHR_SUCCESS);
  assert(yh_string_to_capabilities(cap2, &c2) == YHR_SUCCESS);
  assert(yh_string_to_capabilities(cap3, &c3) == YHR_SUCCESS);

  assert(yh_merge_capabilities(&c1, &c2, &res) == YHR_SUCCESS);
  assert(yh_check_capability(&res, "sign-pkcs") == true);
  assert(yh_check_capability(&res, "sign-pss") == true);
  assert(yh_check_capability(&res, "decrypt-pkcs") == true);
  assert(yh_check_capability(&res, "decrypt-oaep") == true);
  assert(yh_check_capability(&res, "sign-hmac") == false);

  assert(yh_filter_capabilities(&res, &c3, &res) == YHR_SUCCESS);
  assert(yh_check_capability(&res, "sign-pkcs") == false);
  assert(yh_check_capability(&res, "sign-pss") == true);
  assert(yh_check_capability(&res, "decrypt-pkcs") == false);
  assert(yh_check_capability(&res, "decrypt-oaep") == true);
  assert(yh_check_capability(&res, "sign-hmac") == false);
}

static void test_algorithms(void) {
  yh_rc yrc;

  assert(yh_is_hmac(YH_ALGO_RSA_2048) == false);
  assert(yh_is_hmac(YH_ALGO_HMAC_SHA1) == true);
  assert(yh_is_hmac(YH_ALGO_HMAC_SHA256) == true);
  assert(yh_is_hmac(YH_ALGO_HMAC_SHA384) == true);
  assert(yh_is_hmac(YH_ALGO_HMAC_SHA512) == true);

  yh_algorithm algorithm;
  yrc = yh_string_to_algo(NULL, &algorithm);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_algo("something", NULL);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_algo("something", &algorithm);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_algo("rsa-pkcs1-sha1", &algorithm);
  assert(yrc == YHR_SUCCESS && algorithm == YH_ALGO_RSA_PKCS1_SHA1);
  yrc = yh_string_to_algo("rsa2048", &algorithm);
  assert(yrc == YHR_SUCCESS && algorithm == YH_ALGO_RSA_2048);
  yrc = yh_string_to_algo("ecp384", &algorithm);
  assert(yrc == YHR_SUCCESS && algorithm == YH_ALGO_EC_P384);
  yrc = yh_string_to_algo("mgf1-sha512", &algorithm);
  assert(yrc == YHR_SUCCESS && algorithm == YH_ALGO_MGF1_SHA512);
}

static void test_options(void) {
  yh_rc yrc;
  yh_option option;
  yrc = yh_string_to_option(NULL, &option);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_option("something", NULL);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_option("something", &option);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_option("force-audit", &option);
  assert(yrc == YHR_SUCCESS && option == YH_OPTION_FORCE_AUDIT);
}

static void test_types(void) {
  yh_rc yrc;
  yh_object_type type;
  yrc = yh_string_to_type(NULL, &type);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_type("something", NULL);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_type("something", &type);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_string_to_type("opaque", &type);
  assert(yrc == YHR_SUCCESS && type == YH_OPAQUE);
  yrc = yh_string_to_type("authentication-key", &type);
  assert(yrc == YHR_SUCCESS && type == YH_AUTHENTICATION_KEY);
  yrc = yh_string_to_type("asymmetric-key", &type);
  assert(yrc == YHR_SUCCESS && type == YH_ASYMMETRIC_KEY);
  yrc = yh_string_to_type("wrap-key", &type);
  assert(yrc == YHR_SUCCESS && type == YH_WRAP_KEY);
  yrc = yh_string_to_type("hmac-key", &type);
  assert(yrc == YHR_SUCCESS && type == YH_HMAC_KEY);
  yrc = yh_string_to_type("template", &type);
  assert(yrc == YHR_SUCCESS && type == YH_TEMPLATE);
  yrc = yh_string_to_type("otp-aead-key", &type);
  assert(yrc == YHR_SUCCESS && type == YH_OTP_AEAD_KEY);

  const char *string;
  yrc = yh_type_to_string(0, NULL);
  assert(yrc == YHR_INVALID_PARAMETERS);
  yrc = yh_type_to_string(99, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "Unknown") == 0);
  yrc = yh_type_to_string(YH_OPAQUE, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "opaque") == 0);
  yrc = yh_type_to_string(YH_AUTHENTICATION_KEY, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "authentication-key") == 0);
  yrc = yh_type_to_string(YH_ASYMMETRIC_KEY, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "asymmetric-key") == 0);
  yrc = yh_type_to_string(YH_WRAP_KEY, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "wrap-key") == 0);
  yrc = yh_type_to_string(YH_HMAC_KEY, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "hmac-key") == 0);
  yrc = yh_type_to_string(YH_TEMPLATE, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "template") == 0);
  yrc = yh_type_to_string(YH_OTP_AEAD_KEY, &string);
  assert(yrc == YHR_SUCCESS && strcmp(string, "otp-aead-key") == 0);
}

int main(void) {
  yh_init();
  test_domains1();
  test_domains2();
  test_capabilities1();
  test_capabilities2();
  test_capabilities3();
  test_algorithms();
  test_options();
  test_types();
}
