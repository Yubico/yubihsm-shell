/*
 * Copyright 2021-2022 Yubico AB
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../pkcs11y.h"
#include "common.h"

#define FAIL(fmt, ...)                                                         \
  do {                                                                         \
    fprintf(stderr, "%s:%d (%s): " fmt "\n", __FILE__, __LINE__, __func__,     \
            __VA_ARGS__);                                                      \
  } while (0)
#define nitems(a) (sizeof(a) / sizeof(a[0]))

// Disabling automatic formatting so that clang-format does not reflow
// the plaintext blocks. Each row corresponds to a whole block.
// clang-format off
#define PLAINTEXT_LENGTH (4 * 16)
static uint8_t plaintext[PLAINTEXT_LENGTH] =
  "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
  "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
  "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
  "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
// clang-format on

#define TEST_ECB(key, ptlen, ct)                                               \
  { CKM_AES_ECB, key, sizeof(key) - 1, ptlen, ct, sizeof(ct) - 1 }
#define TEST_CBC(key, ptlen, ct)                                               \
  { CKM_AES_CBC, key, sizeof(key) - 1, ptlen, ct, sizeof(ct) - 1 }
#define TEST_CBC_PAD(key, ptlen, ct)                                           \
  { CKM_AES_CBC_PAD, key, sizeof(key) - 1, ptlen, ct, sizeof(ct) - 1 }

struct test {
  CK_MECHANISM_TYPE mechanism;
  uint8_t key[32];
  uint8_t keylen;
  size_t plaintext_len;
  uint8_t ciphertext[sizeof(plaintext) + 16];
  size_t ciphertext_len;
};

static uint8_t iv[16] =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

// CKM_AES_{ECB,CBC} test vectors from NIST.
// CKM_AES_CBC_PAD calculated out-of-band.
static struct test tests[] = {
  TEST_ECB("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
           PLAINTEXT_LENGTH,
           "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97"
           "\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf"
           "\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88"
           "\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4"),
  TEST_ECB("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
           "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
           PLAINTEXT_LENGTH,
           "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc"
           "\x97\x41\x04\x84\x6d\x0a\xd3\xad\x77\x34\xec\xb3\xec\xee\x4e\xef"
           "\xef\x7a\xfd\x22\x70\xe2\xe6\x0a\xdc\xe0\xba\x2f\xac\xe6\x44\x4e"
           "\x9a\x4b\x41\xba\x73\x8d\x6c\x72\xfb\x16\x69\x16\x03\xc1\x8e\x0e"),
  TEST_ECB("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
           "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
           PLAINTEXT_LENGTH,
           "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8"
           "\x59\x1c\xcb\x10\xd4\x10\xed\x26\xdc\x5b\xa7\x4a\x31\x36\x28\x70"
           "\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d"
           "\x23\x30\x4b\x7a\x39\xf9\xf3\xff\x06\x7d\x8d\x8f\x9e\x24\xec\xc7"),
  TEST_CBC("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
           PLAINTEXT_LENGTH,
           "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d"
           "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2"
           "\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16"
           "\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7"),
  TEST_CBC("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
           "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
           PLAINTEXT_LENGTH,
           "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8"
           "\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a"
           "\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0"
           "\x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd"),
  TEST_CBC("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
           "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
           PLAINTEXT_LENGTH,
           "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6"
           "\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d"
           "\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61"
           "\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b"),
  TEST_CBC_PAD(
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    PLAINTEXT_LENGTH - 15,
    "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d"
    "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2"
    "\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16"
    "\x29\xe0\x8a\x17\xfd\xdd\xdd\xe8\x6d\xa9\xbc\xaf\x31\xe0\x28\xd8"),
  TEST_CBC_PAD(
    "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    PLAINTEXT_LENGTH - 1,
    "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8"
    "\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a"
    "\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0"
    "\x89\x7e\x29\x85\x3a\x69\x34\xfd\x58\x9f\xc9\x3e\x7a\xf0\x37\x49"),
  TEST_CBC_PAD(
    "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    PLAINTEXT_LENGTH,
    "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6"
    "\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d"
    "\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61"
    "\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b"
    "\x3f\x46\x17\x96\xd6\xb0\xd6\xb2\xe0\xc2\xa7\x2b\x4d\x80\xe6\x44"),
};

static CK_BBOOL g_true = TRUE;
static CK_RV create_aes_key(CK_FUNCTION_LIST_3_0_PTR p11, CK_SESSION_HANDLE session,
                            CK_BYTE_PTR key, CK_ULONG len,
                            CK_OBJECT_HANDLE *handle) {
  CK_OBJECT_CLASS class = CKO_SECRET_KEY;
  CK_KEY_TYPE type = CKK_AES;
  CK_ATTRIBUTE templ[] = {{CKA_CLASS, &class, sizeof(class)},
                          {CKA_KEY_TYPE, &type, sizeof(type)},
                          {CKA_ENCRYPT, &g_true, sizeof(g_true)},
                          {CKA_DECRYPT, &g_true, sizeof(g_true)},
                          {CKA_VALUE, key, len}};
  return p11->C_CreateObject(session, templ, nitems(templ), handle);
}

typedef CK_RV (*InitFunc)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                          CK_OBJECT_HANDLE);
typedef CK_RV (*SingleFunc)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                            CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*FinalFunc)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef SingleFunc UpdateFunc;
typedef size_t (*CalculateOutputSize)(size_t, size_t);

static int do_test_single_part(InitFunc init, SingleFunc single,
                               CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE handle, CK_MECHANISM mechanism,
                               const uint8_t *input, size_t inlen,
                               const uint8_t *output, size_t outlen) {
  uint8_t buffer[PLAINTEXT_LENGTH + 16];
  CK_ULONG len;
  CK_RV rv;

  if (inlen > sizeof(buffer) || outlen > sizeof(buffer)) {
    FAIL("%s", "input or expected output data too large");
    return -1;
  }

  // Initialize the operation.
  if ((rv = init(session, &mechanism, handle)) != CKR_OK) {
    FAIL("init failed (rv=0x%lx)", rv);
    return -1;
  }

  memcpy(buffer, input, inlen);

  // Test querying output size.
  len = 0;
  if ((rv = single(session, buffer, inlen, NULL, &len)) != CKR_OK ||
      len < outlen) {
    FAIL("single size query failed (rv=0x%lx, %lu, %zu)", rv, len, outlen);
    return -1;
  }

  // Test CKR_BUFFER_TOO_SMALL.
  len = outlen - 1;
  if ((rv = single(session, buffer, inlen, buffer, &len)) !=
        CKR_BUFFER_TOO_SMALL ||
      len < outlen) {
    FAIL("single did not return CKR_BUFFER_TOO_SMALL (rv=0x%lx, %lu, %zu)", rv,
         len, outlen);
    return -1;
  }

  // If the function call was supposed to modify the contents of certain
  // memory addresses on the host computer, these memory addresses may
  // have been modified, despite the failure of the function.
  // PKCS#11 version 2.4; section 5
  memcpy(buffer, input, inlen);

  // Test actual operation.
  if ((rv = single(session, buffer, inlen, buffer, &len)) != CKR_OK ||
      len != outlen) {
    FAIL("single failed (rv=0x%lx, %lu, %zu)", rv, len, outlen);
    return -1;
  }

  // Verify expected data.
  if (memcmp(buffer, output, outlen)) {
    FAIL("%s", "memcmp failed");
    return -1;
  }

  return 0;
}

static int test_single_part(CK_FUNCTION_LIST_3_0_PTR p11, CK_SESSION_HANDLE session,
                            CK_OBJECT_HANDLE handle, struct test *test) {
  CK_MECHANISM mechanism = {test->mechanism, NULL, 0};
  if (mechanism.mechanism != CKM_AES_ECB) {
    mechanism.pParameter = iv;
    mechanism.ulParameterLen = sizeof(iv);
  }

  if (do_test_single_part(p11->C_EncryptInit, p11->C_Encrypt, session, handle,
                          mechanism, plaintext, test->plaintext_len,
                          test->ciphertext, test->ciphertext_len) != 0) {
    FAIL("%s", "single part encryption failed");
    return -1;
  }

  if (do_test_single_part(p11->C_DecryptInit, p11->C_Decrypt, session, handle,
                          mechanism, test->ciphertext, test->ciphertext_len,
                          plaintext, test->plaintext_len) != 0) {
    FAIL("%s", "single part decryption failed");
    return -1;
  }

  return CKR_OK;
}

#define BUFFER_OFFSET(b, p) ((size_t)((p) - (b))) /* assumes p >= b*/

static int
do_test_multiple_part(InitFunc init, UpdateFunc update, FinalFunc finalize,
                      CalculateOutputSize calc_output_size,
                      CK_SESSION_HANDLE session, CK_OBJECT_HANDLE handle,
                      CK_MECHANISM mechanism, const uint8_t *input,
                      size_t inlen, const uint8_t *output, size_t outlen) {
  uint8_t buffer[PLAINTEXT_LENGTH + 16];
  CK_ULONG len;
  CK_RV rv;

  if (inlen > sizeof(buffer) || outlen > sizeof(buffer)) {
    FAIL("%s", "input or expected output data too large");
    return -1;
  }

  // Initialize the operation.
  if ((rv = init(session, &mechanism, handle)) != CKR_OK) {
    FAIL("init failed (rv=0x%lx)", rv);
    return -1;
  }

  memcpy(buffer, input, inlen);
  CK_BYTE_PTR cin = buffer, cout = buffer;

  while (inlen != 0) {
    CK_ULONG chunksiz = inlen > 3 ? 3 : inlen;

    // Verify output size.
    size_t pending = calc_output_size(BUFFER_OFFSET(buffer, cin + chunksiz),
                                      BUFFER_OFFSET(buffer, cout));

    // Query the output size.
    len = 0;
    if ((rv = update(session, cin, chunksiz, NULL, &len)) != CKR_OK ||
        len != pending) {
      FAIL("update size query failed (rv=0x%lx, %lu, %zu)", rv, len, pending);
      return -1;
    }

    // Check the CKR_BUFFER_TOO_SMALL case.
    if (len != 0) {
      CK_ULONG too_small = len - 1;
      if ((rv = update(session, cin, chunksiz, cout, &too_small)) !=
            CKR_BUFFER_TOO_SMALL ||
          too_small != len) {
        FAIL("update did not return CKR_BUFFER_TOO_SMALL (rv=0x%lx, %lu, %lu)",
             rv, too_small, len);
        return -1;
      }
    }

    // Perform the actual update.
    len = sizeof(buffer) - BUFFER_OFFSET(buffer, cout);
    if ((rv = update(session, cin, chunksiz, cout, &len)) != CKR_OK) {
      FAIL("update failed (rv=0x%lx)", rv);
      return -1;
    }

    cin += chunksiz;
    cout += len;
    inlen -= chunksiz;
  }

  size_t remain = outlen - BUFFER_OFFSET(buffer, cout);

  // Check that querying size works.
  len = 0;
  if ((rv = finalize(session, NULL, &len)) != CKR_OK || len < remain) {
    FAIL("finalize size query failed (rv=0x%lx, %lu, %zu)", rv, len, remain);
    return -1;
  }

  // Check the CKR_BUFFER_TOO_SMALL case.
  if (remain != 0) {
    CK_ULONG too_small = remain - 1;
    if ((rv = finalize(session, cout, &too_small)) != CKR_BUFFER_TOO_SMALL ||
        too_small != remain) {
      FAIL("finalize did not return CKR_BUFFER_TOO_SMALL (rv=0x%lx, %lu, %zu)",
           rv, too_small, remain);
      return -1;
    }
  }

  // Finalize the operation.
  len = sizeof(buffer) - BUFFER_OFFSET(buffer, cout);
  if ((rv = finalize(session, cout, &len)) != CKR_OK) {
    FAIL("finalize failed (rv=0x%lx)", rv);
    return -1;
  }

  // Check against the expected ciphertext.
  cout += len;
  if (BUFFER_OFFSET(buffer, cout) != outlen) {
    FAIL("finalize output length does not match (%zu != %zu)",
         BUFFER_OFFSET(buffer, cout), outlen);
    return -1;
  }

  if (memcmp(buffer, output, outlen)) {
    FAIL("%s", "memcmp failed");
    return -1;
  }

  return 0;
}

static size_t simple_output_size(size_t in, size_t out) {
  size_t pending = in - out;
  pending /= 16;
  pending *= 16;
  return pending;
}

static size_t pad_output_size(size_t in, size_t out) {
  size_t pending = in - out;
  return pending <= 16 ? 0 : simple_output_size(in, out);
}

static CK_RV test_multiple_part(CK_FUNCTION_LIST_3_0_PTR p11,
                                CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE handle, struct test *test) {
  CK_MECHANISM mechanism = {test->mechanism, NULL, 0};
  if (mechanism.mechanism != CKM_AES_ECB) {
    mechanism.pParameter = iv;
    mechanism.ulParameterLen = sizeof(iv);
  }

  if (do_test_multiple_part(p11->C_EncryptInit, p11->C_EncryptUpdate,
                            p11->C_EncryptFinal, simple_output_size, session,
                            handle, mechanism, plaintext, test->plaintext_len,
                            test->ciphertext, test->ciphertext_len) != 0) {
    FAIL("%s", "multiple part encryption failed");
    return -1;
  }

  if (do_test_multiple_part(p11->C_DecryptInit, p11->C_DecryptUpdate,
                            p11->C_DecryptFinal,
                            mechanism.mechanism == CKM_AES_CBC_PAD
                              ? pad_output_size
                              : simple_output_size,
                            session, handle, mechanism, test->ciphertext,
                            test->ciphertext_len, plaintext,
                            test->plaintext_len) != 0) {
    FAIL("%s", "multiple part decryption failed");
    return -1;
  }
  return CKR_OK;
}

static int run_test(CK_FUNCTION_LIST_3_0_PTR p11, CK_SESSION_HANDLE session,
                    struct test *test) {
  CK_OBJECT_HANDLE handle = 0;
  int rv;

  if (create_aes_key(p11, session, test->key, test->keylen, &handle) !=
      CKR_OK) {
    FAIL("%s", "Could not create AES key");
    return -1;
  }

  if ((rv = test_single_part(p11, session, handle, test)) != 0 ||
      (rv = test_multiple_part(p11, session, handle, test)) != 0)
    goto end;

end:
  destroy_object(p11, session, handle);
  return rv;
}

static CK_RV is_aes_supported(CK_FUNCTION_LIST_3_0_PTR p11,
                              CK_SESSION_HANDLE session) {
  CK_SESSION_INFO info;
  CK_RV r;

  if ((r = p11->C_GetSessionInfo(session, &info)) != CKR_OK) {
    fprintf(stderr, "C_GetSessionInfo (r = %lu)\n", r);
    return CKR_FUNCTION_FAILED;
  }

  CK_MECHANISM_TYPE m[128];
  CK_ULONG n = nitems(m);
  if ((r = p11->C_GetMechanismList(info.slotID, m, &n)) != CKR_OK) {
    fprintf(stderr, "C_GetMechanismList (r = %lu)\n", r);
    return CKR_FUNCTION_FAILED;
  }

  unsigned int x = 0;
  for (CK_ULONG i = 0; i < n; i++) {
    if (m[i] == CKM_AES_ECB)
      x |= 0x1;
    else if (m[i] == CKM_AES_CBC)
      x |= 0x2;
    else if (m[i] == CKM_AES_CBC_PAD)
      x |= 0x4;
  }

  if ((x >> 1) && (x >> 1) != 0x3) {
    fprintf(stderr,
            "CKM_AES_CBC_PAD and CKM_AES_CBC_PAD are toggled together\n");
    return CKR_FUNCTION_FAILED;
  }

  if (x != 0x7) {
    fprintf(stderr, "CKM_AES_{ECB,CBC} disabled or unsupported\n");
    return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

static const char *mechstr(CK_MECHANISM_TYPE mech) {
  switch (mech) {
    case CKM_AES_ECB:
      return "CKM_AES_ECB";
    case CKM_AES_CBC:
      return "CKM_AES_CBC";
    case CKM_AES_CBC_PAD:
      return "CKM_AES_CBC_PAD";
    default:
      return "unknown";
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: /path/to/yubihsm_pkcs11/module\n");
    exit(EXIT_FAILURE);
  }

  void *handle = open_module(argv[1]);
  CK_FUNCTION_LIST_3_0_PTR p11 = get_function_list(handle);
  CK_SESSION_HANDLE session = open_session(p11);
  print_session_state(p11, session);

  int st = EXIT_SUCCESS;

  CK_RV rv = is_aes_supported(p11, session);
  if (rv == CKR_MECHANISM_INVALID) {
    st = 64; /* arbitrarily chosen */
    goto out;
  } else if (rv != CKR_OK) {
    st = EXIT_FAILURE;
    goto out;
  }

  for (size_t i = 0; i < nitems(tests); i++) {
    fprintf(stderr, "Running test %zu (%s, AES%d)... ", i,
            mechstr(tests[i].mechanism), tests[i].keylen * 8);
    if (run_test(p11, session, &tests[i]) != 0) {
      fprintf(stderr, "FAIL\n");
      st = EXIT_FAILURE;
    } else {
      fprintf(stderr, "OK\n");
    }
  }

out:
  close_session(p11, session);
  close_module(handle);

  return st;
}
