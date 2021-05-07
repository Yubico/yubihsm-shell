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
#include "internal.h"

#ifdef __WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#include <dlfcn.h>
#include <strings.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "../common/rand.h"
#include "../common/pkcs5.h"
#include "../common/hash.h"
#include "../common/ecdh.h"

#include "../aes_cmac/aes_cmac.h"

#include "debug_lib.h"

#include "../common/insecure_memzero.h"

#define STATIC_USB_BACKEND "usb"
#define STATIC_HTTP_BACKEND "http"

// If any of the values in scp.h are changed
// they should be mirrored in yubihsm.h
#ifdef _MSVC
_STATIC_ASSERT(SCP_HOST_CHAL_LEN == YH_HOST_CHAL_LEN);
_STATIC_ASSERT(SCP_CONTEXT_LEN == YH_CONTEXT_LEN);
_STATIC_ASSERT(SCP_MSG_BUF_SIZE == YH_MSG_BUF_SIZE);
_STATIC_ASSERT(SCP_KEY_LEN == YH_KEY_LEN);
#define strtok_r strtok_s
#define strcasecmp _stricmp
#else
_Static_assert(SCP_HOST_CHAL_LEN == YH_HOST_CHAL_LEN,
               "Host challenge length mismatch");
_Static_assert(SCP_CONTEXT_LEN == YH_CONTEXT_LEN, "Context length mismatch");
_Static_assert(SCP_MSG_BUF_SIZE == YH_MSG_BUF_SIZE,
               "Message buffer size mismatch");
_Static_assert(SCP_KEY_LEN == YH_KEY_LEN, "Message buffer size mismatch");
#endif

#define LIST_SEPARATORS ":,;|"

uint8_t _yh_verbosity YH_INTERNAL = 0;
FILE *_yh_output YH_INTERNAL = NULL;

static yh_rc compute_full_mac(uint8_t *data, uint16_t data_len, uint8_t *key,
                              uint16_t key_len, uint8_t *mac) {

  aes_cmac_context_t ctx;

  insecure_memzero(&ctx, sizeof(ctx));
  if (aes_cmac_init((uint8_t *) key, key_len, &ctx)) {
    DBG_ERR("aes_cmac_init failed");
    return YHR_GENERIC_ERROR;
  }

  if (aes_cmac_encrypt(&ctx, data, data_len, mac)) {
    DBG_ERR("aes_cmac_encrypt failed");
    aes_cmac_destroy(&ctx);
    return YHR_GENERIC_ERROR;
  }

  DBG_CRYPTO(data, data_len, "Compute MAC (%3d Bytes): ", data_len);
  DBG_CRYPTO(mac, SCP_PRF_LEN, "Full result is: ");

  aes_cmac_destroy(&ctx);
  return YHR_SUCCESS;
}

static yh_rc send_msg(yh_connector *connector, Msg *msg, Msg *response,
                      const char *identifier) {

  yh_rc yrc;
  if (connector == NULL || connector->bf == NULL) {
    DBG_ERR("No backend loaded");
    return YHR_INVALID_PARAMETERS;
  }
  DBG_NET(msg, dump_msg);
  yrc = connector->bf->backend_send_msg(connector->connection, msg, response,
                                        identifier);
  if (yrc == YHR_SUCCESS) {
    DBG_NET(response, dump_response);
  }
  return yrc;
}

static void increment_ctr(uint8_t *ctr, uint16_t len) {

  while (len > 0) {
    if (++ctr[--len]) {
      break;
    }
  }
}

static yh_rc translate_device_error(uint8_t device_error) {

  enum {
    _DEVICE_OK = 0x00,              // No error
    _DEVICE_INVALID_COMMAND = 0x01, // Invalid command
    _DEVICE_INVALID_DATA = 0x02,    // Malformed command / invalid data
    _DEVICE_INVALID_SESSION = 0x03, // Invalid session
    _DEVICE_AUTHENTICATION_FAILED =
      0x04,                        // Message encryption / verification failed
    _DEVICE_SESSIONS_FULL = 0x05,  // All sessions are allocated
    _DEVICE_SESSION_FAILED = 0x06, // Session creation failed
    _DEVICE_STORAGE_FAILED = 0x07, // Storage failure
    _DEVICE_WRONG_LENGTH = 0x08,   // Wrong length
    _DEVICE_INSUFFICIENT_PERMISSIONS = 0x09, // Wrong permissions for operation
    _DEVICE_LOG_FULL = 0x0a, // Log buffer is full and forced audit is set
    _DEVICE_OBJECT_NOT_FOUND = 0x0b,             // Object not found
    _DEVICE_INVALID_ID = 0x0c,                   // Invalid ID
    _DEVICE_SSH_CA_CONSTRAINT_VIOLIATION = 0x0e, // CA constraint violation
    _DEVICE_INVALID_OTP = 0x0f,                  // Invalid OTP
    _DEVICE_DEMO_MODE = 0x10,          // Demo mode, power cycle device
    _DEVICE_OBJECT_EXISTS = 0x11,      // Object with that ID already exists
    _DEVICE_ALGORITHM_DISABLED = 0x12, // Algorithm is disabled
    _DEVICE_COMMAND_UNEXECUTED =
      0xff, // The command execution has not terminated
  };

  switch (device_error) {
    case _DEVICE_OK:
      return YHR_DEVICE_OK;

    case _DEVICE_INVALID_COMMAND:
      return YHR_DEVICE_INVALID_COMMAND;

    case _DEVICE_INVALID_DATA:
      return YHR_DEVICE_INVALID_DATA;

    case _DEVICE_INVALID_SESSION:
      return YHR_DEVICE_INVALID_SESSION;

    case _DEVICE_AUTHENTICATION_FAILED:
      return YHR_DEVICE_AUTHENTICATION_FAILED;

    case _DEVICE_SESSIONS_FULL:
      return YHR_DEVICE_SESSIONS_FULL;

    case _DEVICE_SESSION_FAILED:
      return YHR_DEVICE_SESSION_FAILED;

    case _DEVICE_STORAGE_FAILED:
      return YHR_DEVICE_STORAGE_FAILED;

    case _DEVICE_WRONG_LENGTH:
      return YHR_DEVICE_WRONG_LENGTH;

    case _DEVICE_INSUFFICIENT_PERMISSIONS:
      return YHR_DEVICE_INSUFFICIENT_PERMISSIONS;

    case _DEVICE_LOG_FULL:
      return YHR_DEVICE_LOG_FULL;

    case _DEVICE_OBJECT_NOT_FOUND:
      return YHR_DEVICE_OBJECT_NOT_FOUND;

    case _DEVICE_INVALID_ID:
      return YHR_DEVICE_INVALID_ID;

    case _DEVICE_SSH_CA_CONSTRAINT_VIOLIATION:
      return YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION;

    case _DEVICE_INVALID_OTP:
      return YHR_DEVICE_INVALID_OTP;

    case _DEVICE_DEMO_MODE:
      return YHR_DEVICE_DEMO_MODE;

    case _DEVICE_OBJECT_EXISTS:
      return YHR_DEVICE_OBJECT_EXISTS;

    case _DEVICE_ALGORITHM_DISABLED:
      return YHR_DEVICE_ALGORITHM_DISABLED;

    case _DEVICE_COMMAND_UNEXECUTED:
      return YHR_DEVICE_COMMAND_UNEXECUTED;
  }

  return YHR_GENERIC_ERROR;
}

yh_rc yh_send_plain_msg(yh_connector *connector, yh_cmd cmd,
                        const uint8_t *data, size_t data_len,
                        yh_cmd *response_cmd, uint8_t *response,
                        size_t *response_len) {

  Msg msg;
  Msg response_msg;

  yh_rc yrc;

  if (connector == NULL || (data_len != 0 && data == NULL) ||
      response_cmd == NULL || response == NULL || response_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (data_len > sizeof(msg.st.data)) {
    DBG_ERR("Tried to transfer oversized data (%zu > %zu)", data_len,
            sizeof(msg.st.data));
    return YHR_INVALID_PARAMETERS;
  }

  msg.st.cmd = cmd;
  msg.st.len = htons(data_len);
  if (data_len > 0) {
    memcpy(msg.st.data, data, data_len);
  }

  yrc = send_msg(connector, &msg, &response_msg, NULL);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("%s", yh_strerror(yrc));
    return yrc;
  }

  uint16_t len = ntohs(response_msg.st.len);
  *response_cmd = response_msg.st.cmd;

  if (*response_len < len) {
    DBG_ERR("%s (received %u Bytes, can fit %zu Bytes) ",
            yh_strerror(YHR_BUFFER_TOO_SMALL), len, *response_len);
    *response_len = len;
    return YHR_BUFFER_TOO_SMALL;
  }

  *response_len = len;
  memcpy(response, response_msg.st.data, len);

  return (*response_cmd == YHC_ERROR) ? translate_device_error(response[0])
                                      : YHR_SUCCESS;
}

static yh_rc _send_secure_msg(yh_session *session, yh_cmd cmd,
                              const uint8_t *data, size_t data_len,
                              yh_cmd *response_cmd, uint8_t *response,
                              size_t *response_len) {

  if (session == NULL || (data_len != 0 && data == NULL) ||
      data_len > SCP_MSG_BUF_SIZE || response_cmd == NULL || response == NULL ||
      response_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint16_t len = 3 + data_len;
  aes_add_padding(NULL, &len);

  // Encrypted message { sid | padded len | mac }
  if (1 + len + SCP_MAC_LEN > SCP_MSG_BUF_SIZE) {
    DBG_ERR("%s", yh_strerror(YHR_BUFFER_TOO_SMALL));
    return YHR_BUFFER_TOO_SMALL;
  }

#pragma pack(push, 1)
  struct {
    uint8_t mac_chaining_value[SCP_PRF_LEN];
    Msg msg;
  } msg, enc_msg;
#pragma pack(pop)

  msg.msg.st.cmd = cmd;
  msg.msg.st.len = htons(data_len);
  memcpy(msg.msg.st.data, data, data_len);

  DBG_NET(&msg.msg, dump_msg);

  len = 3 + data_len;
  aes_add_padding(msg.msg.raw, &len);

  aes_context aes_ctx;
  insecure_memzero(&aes_ctx, sizeof(aes_ctx));
  if (aes_set_key(session->s.s_enc, SCP_KEY_LEN, &aes_ctx)) {
    DBG_ERR("aes_set_key %s", yh_strerror(YHR_GENERIC_ERROR));
    return YHR_GENERIC_ERROR;
  }

  yh_rc yrc = YHR_SUCCESS;
  uint8_t encrypted_ctr[AES_BLOCK_SIZE];
  if (aes_encrypt(session->s.ctr, encrypted_ctr, &aes_ctx)) {
    DBG_ERR("aes_encrypt %s", yh_strerror(YHR_GENERIC_ERROR));
    yrc = YHR_GENERIC_ERROR;
    goto cleanup;
  }

  memcpy(enc_msg.mac_chaining_value, session->s.mac_chaining_value,
         SCP_PRF_LEN);
  enc_msg.msg.st.cmd = YHC_SESSION_MESSAGE;
  enc_msg.msg.st.len = htons(len + SCP_MAC_LEN + 1);
  enc_msg.msg.st.data[0] = session->s.sid;

  if (aes_cbc_encrypt(msg.msg.raw, enc_msg.msg.st.data + 1, len, encrypted_ctr,
                      &aes_ctx)) {
    DBG_ERR("aes_cbc_encrypt %s", yh_strerror(YHR_GENERIC_ERROR));
    yrc = YHR_GENERIC_ERROR;
    goto cleanup;
  }

  yrc = compute_full_mac(enc_msg.mac_chaining_value, len + SCP_PRF_LEN + 4,
                         session->s.s_mac, SCP_KEY_LEN,
                         session->s.mac_chaining_value);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("compute_full_mac %s", yh_strerror(yrc));
    goto cleanup;
  }

  memcpy(enc_msg.msg.st.data + len + 1, session->s.mac_chaining_value,
         SCP_MAC_LEN);

  yrc =
    send_msg(session->parent, &enc_msg.msg, &msg.msg, session->s.identifier);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("send_msg %s", yh_strerror(yrc));
    goto cleanup;
  }

  if (msg.msg.st.cmd == YHC_ERROR) {
    yrc = translate_device_error(msg.msg.st.data[0]);
    DBG_ERR("%s", yh_strerror(yrc));

    *response_cmd = YHC_ERROR;
    response[0] = msg.msg.st.data[0];
    *response_len = 1;

    goto cleanup;
  }

  // The minimum message is { sid | 1 aes block | mac }
  if (ntohs(msg.msg.st.len) < 1 + AES_BLOCK_SIZE + SCP_MAC_LEN) {
    DBG_ERR("%s", yh_strerror(YHR_BUFFER_TOO_SMALL));
    yrc = YHR_BUFFER_TOO_SMALL;
    goto cleanup;
  }

  uint8_t mac[SCP_PRF_LEN];
  memcpy(msg.mac_chaining_value, session->s.mac_chaining_value, SCP_PRF_LEN);
  yrc =
    compute_full_mac(msg.mac_chaining_value,
                     ntohs(msg.msg.st.len) + (SCP_PRF_LEN + 3 - SCP_MAC_LEN),
                     session->s.s_rmac, SCP_KEY_LEN, mac);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("compute_full_mac %s", yh_strerror(yrc));
    goto cleanup;
  }

  len = ntohs(msg.msg.st.len) - SCP_MAC_LEN;

  if (memcmp(msg.msg.st.data + len, mac, SCP_MAC_LEN)) {
    DBG_DUMPERR(mac, SCP_MAC_LEN,
                "%s, expected: ", yh_strerror(YHR_MAC_MISMATCH));
    yrc = YHR_MAC_MISMATCH;
    goto cleanup;
  }

  if (session->s.sid != msg.msg.st.data[0]) {
    DBG_ERR("Session ID mismatch, expected %d, got %d", session->s.sid,
            msg.msg.st.data[0]);
    yrc = YHR_DEVICE_INVALID_SESSION;
    goto cleanup;
  }

  len -= 1;

  if (aes_cbc_decrypt(msg.msg.st.data + 1, enc_msg.msg.raw, len, encrypted_ctr,
                      &aes_ctx)) {
    DBG_ERR("aes_cbc_decrypt %s", yh_strerror(YHR_GENERIC_ERROR));
    yrc = YHR_GENERIC_ERROR;
    goto cleanup;
  }

  aes_remove_padding(enc_msg.msg.raw, &len);
  if (len < 3 || len - 3 != ntohs(enc_msg.msg.st.len)) {
    DBG_ERR("aes_remove_padding %s", yh_strerror(YHR_WRONG_LENGTH));
    yrc = YHR_WRONG_LENGTH;
    goto cleanup;
  }

  increment_ctr(session->s.ctr, SCP_PRF_LEN);

  DBG_NET(&enc_msg.msg, dump_response);

  *response_cmd = enc_msg.msg.st.cmd;
  len -= 3;

  if (*response_len < len) {
    DBG_ERR("%s (received %u Bytes, can fit %zu Bytes) ",
            yh_strerror(YHR_BUFFER_TOO_SMALL), len, *response_len);
    *response_len = len;
    yrc = YHR_BUFFER_TOO_SMALL;
    goto cleanup;
  }

  memcpy(response, enc_msg.msg.st.data, len);
  *response_len = len;

  if (*response_cmd == YHC_ERROR) {
    yrc = translate_device_error(response[0]);
  }

cleanup:
  aes_destroy(&aes_ctx);
  insecure_memzero(&msg, sizeof(msg));
  insecure_memzero(&enc_msg, sizeof(enc_msg));
  return yrc;
}

yh_rc yh_send_secure_msg(yh_session *session, yh_cmd cmd, const uint8_t *data,
                         size_t data_len, yh_cmd *response_cmd,
                         uint8_t *response, size_t *response_len) {

  size_t saved_len = *response_len;

  yh_rc yrc = _send_secure_msg(session, cmd, data, data_len, response_cmd,
                               response, response_len);
  if ((yrc == YHR_DEVICE_INVALID_SESSION ||
       yrc == YHR_DEVICE_AUTHENTICATION_FAILED) &&
      session->recreate) {
    DBG_INFO("Recreating session");
    yrc = yh_create_session(session->parent, session->authkey_id,
                            session->key_enc, SCP_KEY_LEN, session->key_mac,
                            SCP_KEY_LEN, true, &session);
    if (yrc != YHR_SUCCESS) {
      return yrc;
    }
    yrc = yh_authenticate_session(session);
    if (yrc != YHR_SUCCESS) {
      return yrc;
    }
    *response_len = saved_len;
    yrc = _send_secure_msg(session, cmd, data, data_len, response_cmd, response,
                           response_len);
  }
  return yrc;
}

static yh_rc compute_cryptogram(const uint8_t *key, uint16_t key_len,
                                uint8_t type, uint8_t context[SCP_CONTEXT_LEN],
                                uint16_t L, uint8_t *key_out) {

  uint8_t n_iterations;
  uint8_t i;
  uint8_t result[SCP_KEY_LEN];
  uint8_t input[16 + SCP_CONTEXT_LEN];
  uint8_t *ptr = input;

  aes_cmac_context_t ctx;

  if (L == 0x40 || L == 0x80)
    n_iterations = 1;
  else if (L == 0xc0 || L == 0x100)
    n_iterations = 2;
  else
    return YHR_INVALID_PARAMETERS;

  // Label
  memset(ptr, 0, 11);
  ptr += 11;
  *ptr++ = type;

  // Delimiter byte
  *ptr++ = 0;

  // L
  *ptr++ = (L & 0xff00) >> 8;
  *ptr++ = (L & 0x00ff);

  // i
  *ptr++ = 0x01;

  // Context
  memcpy(ptr, context, SCP_CONTEXT_LEN);
  ptr += SCP_CONTEXT_LEN;

  insecure_memzero(&ctx, sizeof(ctx));
  if (aes_cmac_init((uint8_t *) key, key_len, &ctx)) {
    return YHR_GENERIC_ERROR;
  }

  for (i = 0; i < n_iterations; i++) {
    if (aes_cmac_encrypt(&ctx, input, ptr - input,
                         result + (i * SCP_PRF_LEN))) {
      aes_cmac_destroy(&ctx);
      return YHR_GENERIC_ERROR;
    }

    // Update i
    input[15]++;
  }

  memcpy(key_out, result, L / 8);

  aes_cmac_destroy(&ctx);

  return YHR_SUCCESS;
}

/*
 * Derive a session encryption key
 * starting from a static encryption key
 */
static yh_rc derive_s_enc(Scp_ctx *ctx, const uint8_t *key_enc,
                          uint16_t key_enc_len, uint8_t *context) {

  return compute_cryptogram(key_enc, key_enc_len, SCP_S_ENC_DERIVATION, context,
                            SCP_KEY_LEN * 8, ctx->s_enc);
}

/*
 * Derive a session message authentication key
 * starting from a static message authentication key
 */
static yh_rc derive_s_mac(Scp_ctx *ctx, const uint8_t *key_mac,
                          uint16_t key_mac_len,
                          uint8_t context[SCP_CONTEXT_LEN]) {

  // ctx->s_mac_len = s_mac_len / 8;

  return compute_cryptogram(key_mac, key_mac_len, SCP_S_MAC_DERIVATION, context,
                            SCP_KEY_LEN * 8, ctx->s_mac);
}

/*
 * Derive a session message authentication key
 * for responses starting from a static message
 * authentication key
 */
static yh_rc derive_s_rmac(Scp_ctx *ctx, const uint8_t *key_mac,
                           uint16_t key_mac_len,
                           uint8_t context[SCP_CONTEXT_LEN]) {

  // ctx->s_rmac_len = s_rmac_len / 8;

  return compute_cryptogram(key_mac, key_mac_len, SCP_S_RMAC_DERIVATION,
                            context, SCP_KEY_LEN * 8, ctx->s_rmac);
}

/*
 * Recompute and verify a card cryptogram
 */
static yh_rc
verify_card_cryptogram(Scp_ctx *ctx, uint8_t context[SCP_CONTEXT_LEN],
                       uint8_t card_cryptogram[SCP_CARD_CRYPTO_LEN]) {

  uint8_t calculated_card_cryptogram[SCP_CARD_CRYPTO_LEN];
  yh_rc yrc;

  yrc =
    compute_cryptogram(ctx->s_mac, SCP_KEY_LEN, SCP_CARD_CRYPTOGRAM, context,
                       SCP_CARD_CRYPTO_LEN * 8, calculated_card_cryptogram);
  if (yrc != YHR_SUCCESS) {
    return yrc;
  }

  return memcmp(card_cryptogram, calculated_card_cryptogram,
                SCP_CARD_CRYPTO_LEN) == 0
           ? YHR_SUCCESS
           : YHR_CRYPTOGRAM_MISMATCH;
}

/*
 * Compute a host cryptogram
 */
static yh_rc compute_host_cryptogram(yh_session *session,
                                     uint8_t *host_cryptogram) {

  return compute_cryptogram(session->s.s_mac, SCP_KEY_LEN, SCP_HOST_CRYPTOGRAM,
                            session->context, SCP_HOST_CRYPTO_LEN * 8,
                            host_cryptogram);
}

static yh_rc derive_key(const uint8_t *password, size_t password_len,
                        uint8_t *key, size_t key_len) {

  if (!pkcs5_pbkdf2_hmac(password, password_len,
                         (const uint8_t *) YH_DEFAULT_SALT,
                         strlen(YH_DEFAULT_SALT), YH_DEFAULT_ITERS, _SHA256,
                         key, key_len)) {
    return YHR_GENERIC_ERROR;
  }

  return YHR_SUCCESS;
}

yh_rc yh_create_session_derived(yh_connector *connector, uint16_t authkey_id,
                                const uint8_t *password, size_t password_len,
                                bool recreate, yh_session **session) {

  if (connector == NULL || password == NULL || session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t key[2 * SCP_KEY_LEN];
  yh_rc yrc = derive_key(password, password_len, key, sizeof(key));

  if (yrc == YHR_SUCCESS) {
    yrc = yh_create_session(connector, authkey_id, key, SCP_KEY_LEN,
                            key + SCP_KEY_LEN, SCP_KEY_LEN, recreate, session);
    insecure_memzero(key, sizeof(key));
  }
  return yrc;
}

yh_rc yh_create_session(yh_connector *connector, uint16_t authkey_id,
                        const uint8_t *key_enc, size_t key_enc_len,
                        const uint8_t *key_mac, size_t key_mac_len,
                        bool recreate, yh_session **session) {

  Msg msg;
  Msg response_msg;
  yh_rc yrc;
  uint8_t *ptr;
  uint8_t card_cryptogram[SCP_CARD_CRYPTO_LEN];
  yh_session *new_session;
  uint8_t host_challenge[YH_HOST_CHAL_LEN];
  uint8_t identifier[8];

  if (connector == NULL || key_enc == NULL || key_enc_len != SCP_KEY_LEN ||
      key_mac == NULL || key_mac_len != SCP_KEY_LEN || session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (!rand_generate(host_challenge, sizeof(host_challenge))) {
    return YHR_GENERIC_ERROR;
  }

  if (!*session) {
    new_session = calloc(1, sizeof(yh_session));
    if (new_session == NULL) {
      DBG_ERR("%s", yh_strerror(YHR_MEMORY_ERROR));
      return YHR_MEMORY_ERROR;
    }
  } else {
    new_session = *session;
  }

  new_session->authkey_id = authkey_id;

  if (recreate) {
    new_session->recreate = true;
    memcpy(new_session->key_enc, key_enc, SCP_KEY_LEN);
    memcpy(new_session->key_mac, key_mac, SCP_KEY_LEN);
  }

  if (!rand_generate(identifier, sizeof(identifier))) {
    DBG_ERR("Failed getting randomness");
    yrc = YHR_GENERIC_ERROR;
    goto cs_failure;
  }
  snprintf(new_session->s.identifier, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
           identifier[0], identifier[1], identifier[2], identifier[3],
           identifier[4], identifier[5], identifier[6], identifier[7]);

  // Send CREATE SESSION command
  msg.st.cmd = YHC_CREATE_SESSION;
  msg.st.len = htons(SCP_AUTHKEY_ID_LEN + SCP_HOST_CHAL_LEN);

  uint16_t authkey_id_n = htons(authkey_id);
  memcpy(msg.st.data, &authkey_id_n, SCP_AUTHKEY_ID_LEN);
  memcpy(msg.st.data + SCP_AUTHKEY_ID_LEN, host_challenge, SCP_HOST_CHAL_LEN);
  memcpy(new_session->context, host_challenge, SCP_HOST_CHAL_LEN);

  DBG_INT(host_challenge, SCP_HOST_CHAL_LEN, "Host challenge: ");

  yrc = send_msg(connector, &msg, &response_msg, new_session->s.identifier);
  if (yrc != YHR_SUCCESS) {
    goto cs_failure;
  }

  response_msg.st.len = ntohs(response_msg.st.len);

  // Parse response
  if (response_msg.st.cmd != YHC_CREATE_SESSION_R) {
    yrc = translate_device_error(response_msg.st.data[0]);
    DBG_ERR("Device error %s (%d)", yh_strerror(yrc), response_msg.st.data[0]);
    goto cs_failure;
  }

  if (response_msg.st.len != 1 + SCP_CARD_CHAL_LEN + SCP_CARD_CRYPTO_LEN) {
    yrc = YHR_WRONG_LENGTH;
    goto cs_failure;
  }

  ptr = response_msg.st.data;

  // Save sid
  new_session->s.sid = (*ptr++);

  // Save card challenge
  memcpy(new_session->context + SCP_HOST_CHAL_LEN, ptr, SCP_CARD_CHAL_LEN);
  ptr += SCP_CARD_CHAL_LEN;

  memcpy(card_cryptogram, ptr, SCP_CARD_CRYPTO_LEN);
  ptr += SCP_CARD_CRYPTO_LEN;

  DBG_INFO("Received Session ID: %d", new_session->s.sid);

  DBG_INT(new_session->context + SCP_HOST_CHAL_LEN, SCP_CARD_CHAL_LEN,
          "Card challenge: ");
  DBG_INT(card_cryptogram, SCP_CARD_CRYPTO_LEN, "Card cryptogram: ");

  // Derive session keys
  yrc =
    derive_s_enc(&new_session->s, key_enc, key_enc_len, new_session->context);
  if (yrc != YHR_SUCCESS)
    goto cs_failure;

  yrc =
    derive_s_mac(&new_session->s, key_mac, key_mac_len, new_session->context);
  if (yrc != YHR_SUCCESS)
    goto cs_failure;

  yrc =
    derive_s_rmac(&new_session->s, key_mac, key_enc_len, new_session->context);
  if (yrc != YHR_SUCCESS)
    goto cs_failure;

  DBG_INT(new_session->s.s_enc, SCP_KEY_LEN, "S-ENC: ");
  DBG_INT(new_session->s.s_mac, SCP_KEY_LEN, "S-MAC: ");
  DBG_INT(new_session->s.s_rmac, SCP_KEY_LEN, "S-RMAC: ");
  // Verify card cryptogram
  yrc = verify_card_cryptogram(&new_session->s, new_session->context,
                               card_cryptogram);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("%s", yh_strerror(yrc));
    goto cs_failure;
  }

  DBG_INFO("Card cryptogram successfully verified");

  // Save link back to connector
  new_session->parent = connector;

  *session = new_session;

  return YHR_SUCCESS;

cs_failure:
  // Only clear and free if we didn't reuse the session
  if (new_session != *session) {
    insecure_memzero(new_session, sizeof(yh_session));
    free(new_session);
    new_session = NULL;
  }

  DBG_ERR("%s", yh_strerror(yrc));

  return yrc;
}

yh_rc yh_begin_create_session_ext(yh_connector *connector, uint16_t authkey_id,
                                  uint8_t **context, uint8_t *host_challenge,
                                  size_t host_challenge_len,
                                  uint8_t *card_cryptogram,
                                  size_t card_cryptogram_len,
                                  yh_session **session) {

  Msg msg;
  Msg response_msg;
  yh_rc yrc;
  uint8_t *ptr;
  yh_session *new_session;
  uint8_t identifier[8];

  if (connector == NULL || context == NULL || card_cryptogram == NULL ||
      host_challenge == NULL || host_challenge_len != SCP_HOST_CHAL_LEN ||
      card_cryptogram_len != SCP_CARD_CRYPTO_LEN || session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  /**********/
  // TODO(adma): replace with func
  if (!*session) {
    new_session = calloc(1, sizeof(yh_session));
    if (new_session == NULL) {
      DBG_ERR("%s", yh_strerror(YHR_MEMORY_ERROR));
      return YHR_MEMORY_ERROR;
    }
  } else {
    new_session = *session;
  }

  // Send CREATE SESSION command
  msg.st.cmd = YHC_CREATE_SESSION;
  msg.st.len = htons(SCP_AUTHKEY_ID_LEN + SCP_HOST_CHAL_LEN);

  uint16_t authkey_id_n = htons(authkey_id);
  memcpy(msg.st.data, &authkey_id_n, SCP_AUTHKEY_ID_LEN);
  memcpy(msg.st.data + SCP_AUTHKEY_ID_LEN, host_challenge, SCP_HOST_CHAL_LEN);
  memcpy(new_session->context, host_challenge, SCP_HOST_CHAL_LEN);

  if (!rand_generate(identifier, sizeof(identifier))) {
    DBG_ERR("Failed getting randomness");
    yrc = YHR_GENERIC_ERROR;
    goto bcse_failure;
  }
  snprintf(new_session->s.identifier, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
           identifier[0], identifier[1], identifier[2], identifier[3],
           identifier[4], identifier[5], identifier[6], identifier[7]);

  DBG_INT(host_challenge, SCP_HOST_CHAL_LEN, "Host challenge: ");

  yrc = send_msg(connector, &msg, &response_msg, new_session->s.identifier);
  if (yrc != YHR_SUCCESS) {
    goto bcse_failure;
  }

  // Parse response
  if (response_msg.st.cmd != YHC_CREATE_SESSION_R) {
    yrc = translate_device_error(response_msg.st.data[0]);
    DBG_ERR("Device error %s (%d)", yh_strerror(yrc), response_msg.st.data[0]);
    goto bcse_failure;
  }

  if (ntohs(response_msg.st.len) !=
      1 + SCP_CARD_CHAL_LEN + SCP_CARD_CRYPTO_LEN) {
    yrc = YHR_WRONG_LENGTH;
    goto bcse_failure;
  }

  ptr = response_msg.st.data;

  // Save sid
  new_session->s.sid = (*ptr++);

  // Save card challenge
  memcpy(new_session->context + SCP_HOST_CHAL_LEN, ptr, SCP_CARD_CHAL_LEN);
  ptr += SCP_CARD_CHAL_LEN;

  memcpy(card_cryptogram, ptr, SCP_CARD_CRYPTO_LEN);
  ptr += SCP_CARD_CRYPTO_LEN;

  DBG_INFO("Received Session ID: %d", new_session->s.sid);

  DBG_INT(new_session->context + SCP_HOST_CHAL_LEN, SCP_CARD_CHAL_LEN,
          "Card challenge: ");
  DBG_INT(card_cryptogram, SCP_CARD_CRYPTO_LEN, "Card cryptogram: ");

  // Save link back to connector
  new_session->parent = connector;

  *session = new_session;
  *context = new_session->context;

  return YHR_SUCCESS;

bcse_failure:
  // Only clear and free if we didn't reuse the session
  if (new_session != *session) {
    insecure_memzero(new_session, sizeof(yh_session));
    free(new_session);
    new_session = NULL;
  }

  DBG_ERR("%s", yh_strerror(yrc));

  return yrc;
}

yh_rc yh_finish_create_session_ext(
  yh_connector *connector, yh_session *session, const uint8_t *key_senc,
  size_t key_senc_len, const uint8_t *key_smac, size_t key_smac_len,
  const uint8_t *key_srmac, size_t key_srmac_len, uint8_t *card_cryptogram,
  size_t card_cryptogram_len) { // TODO(adma): remove all these

  if (connector == NULL || session == NULL || key_senc == NULL ||
      key_senc_len != YH_KEY_LEN || key_smac == NULL ||
      key_smac_len != YH_KEY_LEN || key_srmac == NULL ||
      key_srmac_len != YH_KEY_LEN || card_cryptogram == NULL ||
      card_cryptogram_len != SCP_CARD_CRYPTO_LEN) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

  memcpy(session->s.s_enc, key_senc, key_senc_len);
  memcpy(session->s.s_mac, key_smac, key_smac_len);
  memcpy(session->s.s_rmac, key_srmac, key_srmac_len);

  DBG_INT(session->s.s_enc, SCP_KEY_LEN, "S-ENC: ");
  DBG_INT(session->s.s_mac, SCP_KEY_LEN, "S-MAC: ");
  DBG_INT(session->s.s_rmac, SCP_KEY_LEN, "S-RMAC: ");

  // Verify card cryptogram
  yrc = verify_card_cryptogram(&session->s, session->context, card_cryptogram);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("%s", yh_strerror(yrc));

    free(session);
    session = NULL;

    DBG_ERR("%s", yh_strerror(yrc));

    return yrc;
  }

  DBG_INFO("Card cryptogram successfully verified");

  return YHR_SUCCESS;
}

static const uint8_t sharedInfo[] =
  {0x3c, 0x88, 0x10}; // sharedInfo as per SCP11 spec, Section 6.5.2.3

static bool x9_63_sha256_kdf(const uint8_t *shsee, size_t shsee_len,
                             const uint8_t *shsss, size_t shsss_len,
                             const uint8_t *shared, size_t shared_len,
                             uint8_t *dst, size_t dst_len) {
  uint8_t *end, cnt[4] = {0};
  size_t hash_len;
  hash_ctx hashctx = NULL;
  bool ok = false;
  if (!hash_create(&hashctx, _SHA256)) {
    return false;
  }
  for (end = dst + dst_len; dst < end; dst += hash_len) {
    increment_ctr(cnt, sizeof(cnt));
    if (!hash_init(hashctx)) {
      goto err_out;
    }
    if (!hash_update(hashctx, shsee, shsee_len)) {
      goto err_out;
    }
    if (!hash_update(hashctx, shsss, shsss_len)) {
      goto err_out;
    }
    if (!hash_update(hashctx, cnt, sizeof(cnt))) {
      goto err_out;
    }
    if (shared) {
      if (!hash_update(hashctx, shared, shared_len)) {
        goto err_out;
      }
    }
    if (!hash_final(hashctx, dst, &hash_len)) {
      goto err_out;
    }
  }
  ok = true;
err_out:
  hash_destroy(hashctx);
  return ok;
}

yh_rc yh_util_get_device_pubkey(yh_connector *connector, uint8_t *device_pubkey,
                                size_t *device_pubkey_len,
                                yh_algorithm *algorithm) {
  yh_cmd response_cmd;
  yh_rc yrc =
    yh_send_plain_msg(connector, YHC_GET_DEVICE_PUBKEY, NULL, 0, &response_cmd,
                      device_pubkey, device_pubkey_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET DEVICE PUBKEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  // Return the algorithm of the key if requested
  if (algorithm) {
    *algorithm = device_pubkey[0];
  }

  device_pubkey[0] = 0x04;
  return YHR_SUCCESS;
}

yh_rc yh_util_derive_ec_p256_key(const uint8_t *password, size_t password_len,
                                 uint8_t *privkey, size_t privkey_len,
                                 uint8_t *pubkey, size_t pubkey_len) {

  if (password == NULL || privkey == NULL || pubkey == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  int curve = ecdh_curve_p256();
  if (!curve) {
    DBG_ERR("%s: Platform support for ec-p256 is missing",
            yh_strerror(YHR_GENERIC_ERROR));
    return YHR_GENERIC_ERROR;
  }

  uint8_t *pwd = calloc(1, password_len + 1);
  if (pwd == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_MEMORY_ERROR));
    return YHR_MEMORY_ERROR;
  }
  memcpy(pwd, password, password_len);

  do {
    DBG_INFO("Deriving key with perturbation %u", pwd[password_len]);
    // We rely on the fact that a trailing zero doesn't change the derived key
    yh_rc yrc = derive_key(pwd, password_len + 1, privkey, privkey_len);
    if (yrc != YHR_SUCCESS) {
      insecure_memzero(pwd, password_len + 1);
      free(pwd);
      DBG_ERR("%s", yh_strerror(yrc));
      return yrc;
    }
    pwd[password_len]++;
  } while (!ecdh_calculate_public_key(curve, privkey, privkey_len, pubkey,
                                      pubkey_len));

  insecure_memzero(pwd, password_len + 1);
  free(pwd);

  DBG_INT(pubkey, YH_EC_P256_PUBKEY_LEN, "Derived PubKey: ");

  return YHR_SUCCESS;
}

yh_rc yh_util_generate_ec_p256_key(uint8_t *privkey, size_t privkey_len,
                                   uint8_t *pubkey, size_t pubkey_len) {
  if (privkey == NULL || pubkey == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
  int curve = ecdh_curve_p256();
  if (!curve) {
    DBG_ERR("%s: Platform support for ec-p256 is missing",
            yh_strerror(YHR_GENERIC_ERROR));
    return YHR_GENERIC_ERROR;
  }
  if (!ecdh_generate_keypair(curve, privkey, privkey_len, pubkey, pubkey_len)) {
    DBG_ERR("Failed to generate ecp256 key %s", yh_strerror(YHR_GENERIC_ERROR));
    return YHR_GENERIC_ERROR;
  }
  return YHR_SUCCESS;
}

yh_rc yh_create_session_asym(yh_connector *connector, uint16_t authkey_id,
                             const uint8_t *privkey, size_t privkey_len,
                             const uint8_t *device_pubkey,
                             size_t device_pubkey_len, yh_session **session) {

  if (connector == NULL || privkey == NULL || device_pubkey == NULL ||
      session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  int curve = ecdh_curve_p256();
  if (!curve) {
    DBG_ERR("%s: Platform support for ec-p256 is missing",
            yh_strerror(YHR_GENERIC_ERROR));
    return YHR_GENERIC_ERROR;
  }

  yh_session *new_session;
  yh_rc rc = YHR_SUCCESS;
  if (!*session) {
    new_session = calloc(1, sizeof(yh_session));
    if (new_session == NULL) {
      DBG_ERR("%s", yh_strerror(YHR_MEMORY_ERROR));
      return YHR_MEMORY_ERROR;
    }
  } else {
    new_session = *session;
  }

  uint8_t esk_oce[YH_EC_P256_PRIVKEY_LEN];
  uint8_t epk_oce[YH_EC_P256_PUBKEY_LEN];

  if (!ecdh_generate_keypair(curve, esk_oce, sizeof(esk_oce), epk_oce,
                             sizeof(epk_oce))) {
    DBG_ERR("ecdh_generate_keypair %s", yh_strerror(YHR_INVALID_PARAMETERS));
    rc = YHR_INVALID_PARAMETERS;
    goto err;
  }

  DBG_INT(epk_oce, sizeof(epk_oce), "EPK-OCE: ");

  uint8_t identifier[8];
  if (!rand_generate(identifier, sizeof(identifier))) {
    DBG_ERR("Failed getting randomness");
    rc = YHR_GENERIC_ERROR;
    goto err;
  }
  snprintf(new_session->s.identifier, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
           identifier[0], identifier[1], identifier[2], identifier[3],
           identifier[4], identifier[5], identifier[6], identifier[7]);

  Msg msg;
  Msg response_msg;
  uint16_t authkey_id_n = htons(authkey_id);

  // Send CREATE SESSION command
  msg.st.cmd = YHC_CREATE_SESSION;
  msg.st.len = htons(sizeof(authkey_id_n) + sizeof(epk_oce));

  memcpy(msg.st.data, &authkey_id_n, sizeof(authkey_id_n));
  memcpy(msg.st.data + sizeof(authkey_id_n), epk_oce, sizeof(epk_oce));

  rc = send_msg(connector, &msg, &response_msg, new_session->s.identifier);
  if (rc != YHR_SUCCESS) {
    goto err;
  }

  // Parse response
  if (response_msg.st.cmd != YHC_CREATE_SESSION_R) {
    rc = translate_device_error(response_msg.st.data[0]);
    DBG_ERR("Device error %s (%d)", yh_strerror(rc), response_msg.st.data[0]);
    goto err;
  }

  DBG_INT(response_msg.st.data, 1, "SessionId: ");
  DBG_INT(response_msg.st.data + 1, sizeof(epk_oce), "EPK-SD: ");
  DBG_INT(response_msg.st.data + 1 + sizeof(epk_oce), SCP_PRF_LEN, "Receipt: ");

  uint8_t shsee[YH_EC_P256_PRIVKEY_LEN];
  if (!ecdh_calculate_secret(curve, esk_oce, sizeof(esk_oce),
                             response_msg.st.data + 1, sizeof(epk_oce), shsee,
                             sizeof(shsee))) {
    DBG_ERR("ecdh_calculate_secret(shsee) %s",
            yh_strerror(YHR_INVALID_PARAMETERS));
    rc = YHR_INVALID_PARAMETERS;
    goto err;
  }

  uint8_t shsss[YH_EC_P256_PRIVKEY_LEN];
  if (!ecdh_calculate_secret(curve, privkey, privkey_len, device_pubkey,
                             device_pubkey_len, shsss, sizeof(shsss))) {
    DBG_ERR("ecdh_calculate_secret(shsss) %s",
            yh_strerror(YHR_INVALID_PARAMETERS));
    rc = YHR_INVALID_PARAMETERS;
    goto err;
  }

  uint8_t shs[4 * SCP_KEY_LEN];
  if (!x9_63_sha256_kdf(shsee, sizeof(shsee), shsss, sizeof(shsss), sharedInfo,
                        sizeof(sharedInfo), shs, sizeof(shs))) {
    DBG_ERR("x9_63_sha256_kdf %s", yh_strerror(YHR_GENERIC_ERROR));
    rc = YHR_GENERIC_ERROR;
    goto err;
  }

  uint8_t keys[2 * sizeof(epk_oce)], mac[SCP_PRF_LEN];
  memcpy(keys, response_msg.st.data + 1, sizeof(epk_oce));
  memcpy(keys + sizeof(epk_oce), epk_oce, sizeof(epk_oce));
  rc = compute_full_mac(keys, sizeof(keys), shs, SCP_KEY_LEN, mac);
  if (rc != YHR_SUCCESS) {
    DBG_ERR("compute_full_mac %s", yh_strerror(rc));
    goto err;
  }

  if (memcmp(mac, response_msg.st.data + 1 + sizeof(epk_oce), SCP_PRF_LEN)) {
    DBG_ERR("Verify receipt %s",
            yh_strerror(YHR_SESSION_AUTHENTICATION_FAILED));
    rc = YHR_SESSION_AUTHENTICATION_FAILED;
    goto err;
  }

  memcpy(new_session->s.s_enc, shs + SCP_KEY_LEN, SCP_KEY_LEN);
  memcpy(new_session->s.s_mac, shs + 2 * SCP_KEY_LEN, SCP_KEY_LEN);
  memcpy(new_session->s.s_rmac, shs + 3 * SCP_KEY_LEN, SCP_KEY_LEN);
  memcpy(new_session->s.mac_chaining_value, mac, SCP_PRF_LEN);

  memset(new_session->s.ctr, 0, SCP_PRF_LEN);
  increment_ctr(new_session->s.ctr, SCP_PRF_LEN);

  new_session->parent = connector;
  new_session->authkey_id = authkey_id;
  new_session->recreate = false;
  new_session->s.sid = response_msg.st.data[0];
  *session = new_session;

err:
  insecure_memzero(esk_oce, sizeof(esk_oce));
  insecure_memzero(shsss, sizeof(shsss));
  insecure_memzero(shsee, sizeof(shsee));
  insecure_memzero(shs, sizeof(shs));

  if (new_session != *session) {
    insecure_memzero(new_session, sizeof(yh_session));
    free(new_session);
    new_session = NULL;
  }

  return rc;
}

yh_rc yh_destroy_session(yh_session **session) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  } else if (*session == NULL) {
    return YHR_SUCCESS;
  }

  insecure_memzero(*session, sizeof(yh_session));
  free(*session);
  *session = NULL;

  return YHR_SUCCESS;
}

bool yh_connector_has_device(yh_connector *connector) {

  return connector && connector->has_device;
}

yh_rc yh_get_connector_version(yh_connector *connector, uint8_t *major,
                               uint8_t *minor, uint8_t *patch) {

  if (connector == NULL || major == NULL || minor == NULL || patch == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  *major = connector->version_major;
  *minor = connector->version_minor;
  *patch = connector->version_patch;

  return YHR_SUCCESS;
}

yh_rc yh_get_connector_address(yh_connector *connector, char **const address) {

  if (connector == NULL || address == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  *address = (char *) connector->address;

  return YHR_SUCCESS;
}

yh_rc yh_util_get_device_info(yh_connector *connector, uint8_t *major,
                              uint8_t *minor, uint8_t *patch, uint32_t *serial,
                              uint8_t *log_total, uint8_t *log_used,
                              yh_algorithm *algorithms, size_t *n_algorithms) {

  if (connector == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint8_t major;
      uint8_t minor;
      uint8_t patch;
      uint32_t serial;
      uint8_t log_total;
      uint8_t log_used;
      uint8_t algorithms[YH_MAX_ALGORITHM_COUNT];
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  yrc = yh_send_plain_msg(connector, YHC_GET_DEVICE_INFO, NULL, 0,
                          &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET DEVICE INFO command: %s", yh_strerror(yrc));
    return yrc;
  }

  if (major != NULL) {
    *major = response.major;
  }

  if (minor != NULL) {
    *minor = response.minor;
  }

  if (patch != NULL) {
    *patch = response.patch;
  }

  if (serial != NULL) {
    *serial = ntohl(response.serial);
  }

  if (log_total != NULL) {
    *log_total = response.log_total;
  }

  if (log_used != NULL) {
    *log_used = response.log_used;
  }

  if (algorithms != NULL && n_algorithms) {
    size_t items = response_len - sizeof(response.major) -
                   sizeof(response.minor) - sizeof(response.patch) -
                   sizeof(response.serial) - sizeof(response.log_total) -
                   sizeof(response.log_used);
    if (*n_algorithms < items) {
      DBG_ERR("Algorithms buffer too small");
      return YHR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < items; i++) {
      algorithms[i] = response.algorithms[i];
    }
    *n_algorithms = items;
  }

  return YHR_SUCCESS;
}

#define LIST_ID 1
#define LIST_TYPE 2
#define LIST_DOMAINS 3
#define LIST_CAPABILITIES 4
#define LIST_ALGORITHM 5
#define LIST_LABEL 6

yh_rc yh_util_list_objects(yh_session *session, uint16_t id,
                           yh_object_type type, uint16_t domains,
                           const yh_capabilities *capabilities,
                           yh_algorithm algorithm, const char *label,
                           yh_object_descriptor *objects, size_t *n_objects) {

  if (session == NULL || objects == NULL || n_objects == NULL ||
      (label != NULL && strlen(label) > YH_OBJ_LABEL_LEN)) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t data[YH_MSG_BUF_SIZE];
  uint8_t *dataptr = data;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yh_rc yrc;
  yh_cmd response_cmd;

  if (id) {
    *dataptr++ = LIST_ID;
    *dataptr++ = id >> 8 & 0xff;
    *dataptr++ = id & 0xff;
  }

  if (type) {
    *dataptr++ = LIST_TYPE;
    *dataptr++ = type;
  }

  if (domains) {
    *dataptr++ = LIST_DOMAINS;
    *dataptr++ = domains >> 8 & 0xff;
    *dataptr++ = domains & 0xff;
  }

  if (algorithm) {
    *dataptr++ = LIST_ALGORITHM;
    *dataptr++ = algorithm;
  }

  if (label && strlen(label)) {
    *dataptr++ = LIST_LABEL;
    memcpy(dataptr, label, strlen(label));
    memset(dataptr + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));
    dataptr += YH_OBJ_LABEL_LEN;
  }

  bool send_capabilities = false;
  for (uint16_t i = 0; i < YH_CAPABILITIES_LEN; i++) {
    if (capabilities->capabilities[i]) {
      send_capabilities = true;
      break;
    }
  }

  if (send_capabilities == true) {
    *dataptr++ = LIST_CAPABILITIES;
    for (uint16_t i = 0; i < YH_CAPABILITIES_LEN; i++) {
      *dataptr++ = capabilities->capabilities[i];
    }
  }

  yrc = yh_send_secure_msg(session, YHC_LIST_OBJECTS, data, dataptr - data,
                           &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send LIST OBJECTS command: %s", yh_strerror(yrc));
    return yrc;
  }

  if ((response_len / 4) > *n_objects) {
    DBG_ERR("Objects buffer too small");
    return YHR_BUFFER_TOO_SMALL;
  }

  *n_objects = response_len / 4;
  for (size_t i = 0; i < response_len; i += 4) {
    // NOTE: clear the fields that we didn't set
    memset(&objects[i / 4], 0, sizeof(yh_object_descriptor));
    objects[i / 4].id = ntohs(*((uint16_t *) (response + i)));
    objects[i / 4].type = response[i + 2];
    objects[i / 4].sequence = response[i + 3];
  }

  DBG_INFO("Found %zu objects", *n_objects);

  return YHR_SUCCESS;
}

yh_rc yh_util_get_object_info(yh_session *session, uint16_t id,
                              yh_object_type type,
                              yh_object_descriptor *object) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t data[3];
  uint8_t *dataptr = data;

#pragma pack(push, 1)
  union {
    struct {
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint16_t id;
      uint16_t len;
      uint16_t domains;
      uint8_t type;
      uint8_t algorithm;
      uint8_t sequence;
      uint8_t origin;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint8_t delegated_capabilities[YH_CAPABILITIES_LEN];
    };
    uint8_t buf[1];
  } response;
  size_t response_len = sizeof(response);
#pragma pack(pop)

  yh_rc yrc;
  yh_cmd response_cmd;

  *dataptr++ = id >> 8 & 0xff;
  *dataptr++ = id & 0xff;

  *dataptr++ = (uint16_t) type;

  yrc = yh_send_secure_msg(session, YHC_GET_OBJECT_INFO, data, sizeof(data),
                           &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET OBJECT INFO command: %s", yh_strerror(yrc));
    return yrc;
  }

  if (response_len == sizeof(response)) {
    if (object) {
      memcpy(object->capabilities.capabilities, response.capabilities,
             YH_CAPABILITIES_LEN);

      object->id = htons(response.id);

      object->len = htons(response.len);

      object->domains = htons(response.domains);

      object->type = response.type;

      object->algorithm = response.algorithm;

      object->sequence = response.sequence;

      object->origin = response.origin;

      memcpy(object->label, response.label, YH_OBJ_LABEL_LEN);
      object->label[YH_OBJ_LABEL_LEN] = 0;

      memcpy(object->delegated_capabilities.capabilities,
             response.delegated_capabilities, YH_CAPABILITIES_LEN);
    }
  } else {
    DBG_ERR("Wrong response length, expecting %lu or 0, received %lu",
            (unsigned long) sizeof(yh_object_descriptor),
            (unsigned long) response_len);
    return YHR_WRONG_LENGTH;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_get_public_key(yh_session *session, uint16_t id, uint8_t *data,
                             size_t *data_len, yh_algorithm *algorithm) {

  if (session == NULL || data == NULL || data_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t cmd[2] = {id >> 8, id & 0xff};
  yh_cmd response_cmd;
  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yh_rc yrc = yh_send_secure_msg(session, YHC_GET_PUBLIC_KEY, cmd, sizeof(cmd),
                                 &response_cmd, response, &response_len);

  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET PUBLIC KEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  if (response_len > *data_len) {
    return YHR_BUFFER_TOO_SMALL;
  }

  if (algorithm) {
    *algorithm = *response;
  }
  *data_len = response_len - 1;
  memcpy(data, response + 1, *data_len);

  return YHR_SUCCESS;
}

yh_rc yh_util_close_session(yh_session *session) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

  uint8_t response[5];
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  yrc = yh_send_secure_msg(session, YHC_CLOSE_SESSION, NULL, 0, &response_cmd,
                           response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send CLOSE SESSION command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_pkcs1v1_5(yh_session *session, uint16_t key_id, bool hashed,
                             const uint8_t *in, size_t in_len, uint8_t *out,
                             size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (hashed)
    switch (in_len) {
      case 20:
      case 32:
      case 48:
      case 64:
        break;

      default:
        DBG_ERR("Data length must be 20, 32, 48 or 64");
        return YHR_INVALID_PARAMETERS;
    }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len;

  yh_cmd response_cmd;

  data.key_id = htons(key_id);

  memcpy(data.bytes, in, in_len);
  data_len = in_len;

  yrc = yh_send_secure_msg(session, YHC_SIGN_PKCS1, data.buf, data_len + 2,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN PKCS1 command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_pss(yh_session *session, uint16_t key_id, const uint8_t *in,
                       size_t in_len, uint8_t *out, size_t *out_len,
                       size_t salt_len, yh_algorithm mgf1Algo) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  switch (in_len) {
    case 20:
    case 32:
    case 48:
    case 64:
      break;

    default:
      DBG_ERR("Data length must be 20, 32, 48 or 64");
      return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t mgf1Algo;
      uint16_t salt_len;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len = in_len;

  yh_cmd response_cmd;

  data.key_id = htons(key_id);

  data.mgf1Algo = mgf1Algo;

  // NOTE(adma): 'in' is already a hash of the data, which type is inferred from
  // the length
  data.salt_len = htons(salt_len);

  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_SIGN_PSS, data.buf, data_len + 5,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN PSS command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_ecdsa(yh_session *session, uint16_t key_id,
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  switch (in_len) {
    case 20:
    case 28: // p224..
    case 32:
    case 48:
    case 64:
    case 66: // p521 needs 66 bytes input
      break;

    default:
      DBG_ERR("Data length must be 20, 28, 32, 48, 64 or 66");
      return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len = in_len;

  yh_cmd response_cmd;

  data.key_id = htons(key_id);

  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_SIGN_ECDSA, data.buf, data_len + 2,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN ECDSA command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_eddsa(yh_session *session, uint16_t key_id,
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len = in_len;

  yh_cmd response_cmd;

  data.key_id = htons(key_id);

  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_SIGN_EDDSA, data.buf, data_len + 2,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN EDDSA command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_hmac(yh_session *session, uint16_t key_id, const uint8_t *in,
                        size_t in_len, uint8_t *out, size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t data[YH_MSG_BUF_SIZE];
  uint16_t data_len = 2;

  yh_cmd response_cmd;

  data[0] = htons(key_id) & 0xff;
  data[1] = htons(key_id) >> 8;

  memcpy(data + 2, in, in_len);
  data_len += in_len;

  yh_rc yrc = yh_send_secure_msg(session, YHC_SIGN_HMAC, data, data_len,
                                 &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN HMAC command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_get_pseudo_random(yh_session *session, size_t len, uint8_t *out,
                                size_t *out_len) {
  yh_rc yrc;
  yh_cmd response_cmd;

  if (session == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  union {
    uint16_t len;
    uint8_t buf[2];
  } data;
  data.len = htons(len);

  yrc = yh_send_secure_msg(session, YHC_GET_PSEUDO_RANDOM, data.buf,
                           sizeof(data), &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET PSEUDO RANDOM command: %s", yh_strerror(yrc));
    return yrc;
  }

  return yrc;
}

static yh_rc import_asymmetric(yh_session *session, uint16_t *key_id,
                               const char *label, uint16_t domains,
                               const yh_capabilities *capabilities,
                               yh_algorithm algorithm, const uint8_t *key,
                               uint16_t key_len) {
#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algo;
      uint8_t bytes[512];
    };
    uint8_t buf[1];
  } k;
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  k.key_id = htons(*key_id);

  memcpy(k.label, label, strlen(label));
  memset(k.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  k.domains = htons(domains);

  k.algo = algorithm;

  memcpy(k.capabilities, capabilities, YH_CAPABILITIES_LEN);

  memcpy(k.bytes, key, key_len);

  uint16_t len = sizeof(k.key_id) + sizeof(k.domains) + sizeof(k.capabilities) +
                 sizeof(k.algo) + sizeof(k.label) + key_len;
  yh_rc yrc = yh_send_secure_msg(session, YHC_PUT_ASYMMETRIC_KEY, k.buf, len,
                                 &response_cmd, response.buf, &response_len);
  insecure_memzero(k.buf, len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT ASYMMETRIC KEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Stored Asymmetric key 0x%04x", *key_id);

  return yrc;
}

yh_rc yh_util_import_rsa_key(yh_session *session, uint16_t *key_id,
                             const char *label, uint16_t domains,
                             const yh_capabilities *capabilities,
                             yh_algorithm algorithm, const uint8_t *p,
                             const uint8_t *q) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || p == NULL || q == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t keybuf[256 * 2];
  uint16_t component_len;

  if (algorithm == YH_ALGO_RSA_2048) {
    component_len = 128;
  } else if (algorithm == YH_ALGO_RSA_3072) {
    component_len = 192;
  } else if (algorithm == YH_ALGO_RSA_4096) {
    component_len = 256;
  } else {
    return YHR_INVALID_PARAMETERS;
  }
  memcpy(keybuf, p, component_len);
  memcpy(keybuf + component_len, q, component_len);

  yh_rc yrc = import_asymmetric(session, key_id, label, domains, capabilities,
                                algorithm, keybuf, component_len * 2);
  insecure_memzero(keybuf, sizeof(keybuf));

  return yrc;
}

yh_rc yh_util_import_ec_key(yh_session *session, uint16_t *key_id,
                            const char *label, uint16_t domains,
                            const yh_capabilities *capabilities,
                            yh_algorithm algorithm, const uint8_t *s) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || s == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint16_t component_len;
  switch (algorithm) {
    case YH_ALGO_EC_P224:
      component_len = 28;
      break;
    case YH_ALGO_EC_P256:
    case YH_ALGO_EC_K256:
    case YH_ALGO_EC_BP256:
      component_len = 32;
      break;
    case YH_ALGO_EC_P384:
    case YH_ALGO_EC_BP384:
      component_len = 48;
      break;
    case YH_ALGO_EC_BP512:
      component_len = 64;
      break;
    case YH_ALGO_EC_P521:
      component_len = 66;
      break;
    default:
      return YHR_INVALID_PARAMETERS;
  }
  return import_asymmetric(session, key_id, label, domains, capabilities,
                           algorithm, s, component_len);
}

yh_rc yh_util_import_ed_key(yh_session *session, uint16_t *key_id,
                            const char *label, uint16_t domains,
                            const yh_capabilities *capabilities,
                            yh_algorithm algorithm, const uint8_t *k) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || k == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint16_t component_len;
  switch (algorithm) {
    case YH_ALGO_EC_ED25519:
      component_len = 32;
      break;
    default:
      return YHR_INVALID_PARAMETERS;
  }
  return import_asymmetric(session, key_id, label, domains, capabilities,
                           algorithm, k, component_len);
}

yh_rc yh_util_import_hmac_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm, const uint8_t *key,
                              size_t key_len) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || key == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint8_t key[128];
    };
    uint8_t buf[1];
  } k;
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  yh_rc yrc;
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;
  size_t max_len = 64;
  int len = sizeof(k) - sizeof(k.key);

  k.key_id = htons(*key_id);

  memcpy(k.label, label, strlen(label));
  memset(k.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  k.domains = htons(domains);

  k.algorithm = algorithm;

  memcpy(k.capabilities, capabilities, YH_CAPABILITIES_LEN);

  if (algorithm == YH_ALGO_HMAC_SHA384 || algorithm == YH_ALGO_HMAC_SHA512) {
    max_len = 128;
  }

  if (key_len > max_len) {
    DBG_ERR("Too long key supplied, max %lu bytes allowed",
            (unsigned long) max_len);
    return YHR_WRONG_LENGTH;
  }

  memcpy(k.key, key, key_len);
  len += key_len;

  yrc = yh_send_secure_msg(session, YHC_PUT_HMAC_KEY, k.buf, len, &response_cmd,
                           response.buf, &response_len);
  insecure_memzero(k.buf, len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT HMAC KEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Stored HMAC key 0x%04x", *key_id);

  return yrc;
}

static yh_rc generate_key(yh_session *session, uint16_t *key_id,
                          const char *label, uint16_t domains,
                          const yh_capabilities *capabilities,
                          yh_algorithm algorithm) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algo;
    };
    uint8_t buf[1];
  } data;
  int data_len = sizeof(data);
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.key_id = htons(*key_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  data.algo = algorithm;

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  yrc =
    yh_send_secure_msg(session, YHC_GENERATE_ASYMMETRIC_KEY, data.buf, data_len,
                       &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GENERATE ASYMMETRIC KEY command: %s",
            yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Generated Asymmetric key 0x%04x", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_generate_rsa_key(yh_session *session, uint16_t *key_id,
                               const char *label, uint16_t domains,
                               const yh_capabilities *capabilities,
                               yh_algorithm algorithm) {

  if (!yh_is_rsa(algorithm)) {
    DBG_ERR("Invalid algorithm %d", algorithm);
    return YHR_INVALID_PARAMETERS;
  }

  return generate_key(session, key_id, label, domains, capabilities, algorithm);
}

yh_rc yh_util_generate_ec_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm) {

  if (!yh_is_ec(algorithm)) {
    DBG_ERR("Invalid algorithm %d", algorithm);
    return YHR_INVALID_PARAMETERS;
  }

  return generate_key(session, key_id, label, domains, capabilities, algorithm);
}

yh_rc yh_util_generate_ed_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm) {

  if (!yh_is_ed(algorithm)) {
    DBG_ERR("Invalid algorithm %d", algorithm);
    return YHR_INVALID_PARAMETERS;
  }

  return generate_key(session, key_id, label, domains, capabilities, algorithm);
}

yh_rc yh_util_verify_hmac(yh_session *session, uint16_t key_id,
                          const uint8_t *signature, size_t signature_len,
                          const uint8_t *data, size_t data_len,
                          bool *verified) {

  if (session == NULL || signature == NULL || data == NULL ||
      verified == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (data_len + signature_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

  uint8_t cmd_data[YH_MSG_BUF_SIZE];
  int cmd_data_len;

  uint8_t response[3];
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  key_id = htons(key_id);

  memcpy(cmd_data, (uint8_t *) &key_id, 2);
  cmd_data_len = 2;
  memcpy(cmd_data + cmd_data_len, signature, signature_len);
  cmd_data_len += signature_len;
  memcpy(cmd_data + cmd_data_len, data, data_len);
  cmd_data_len += data_len;

  yrc = yh_send_secure_msg(session, YHC_VERIFY_HMAC, cmd_data, cmd_data_len,
                           &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send HMAC VERIFY command: %s", yh_strerror(yrc));
    return yrc;
  }

  *verified = response[0];

  return YHR_SUCCESS;
}

yh_rc yh_util_generate_hmac_key(yh_session *session, uint16_t *key_id,
                                const char *label, uint16_t domains,
                                const yh_capabilities *capabilities,
                                yh_algorithm algorithm) {

  if (session == NULL || label == NULL || strlen(label) > YH_OBJ_LABEL_LEN ||
      key_id == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
    };
    uint8_t buf[1];
  } data;
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.key_id = htons(*key_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.algorithm = algorithm;

  yrc =
    yh_send_secure_msg(session, YHC_GENERATE_HMAC_KEY, data.buf, sizeof(data),
                       &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GENERATE HMAC command: %s", yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Generated HMAC key 0x%04x", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_decrypt_pkcs1v1_5(yh_session *session, uint16_t key_id,
                                const uint8_t *in, size_t in_len, uint8_t *out,
                                size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;
  yh_rc yrc;

  data.key_id = htons(key_id);

  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_DECRYPT_PKCS1, data.buf, in_len + 2,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send DECRYPT PKCS1 command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_decrypt_oaep(yh_session *session, uint16_t key_id,
                           const uint8_t *in, size_t in_len, uint8_t *out,
                           size_t *out_len, const uint8_t *label,
                           size_t label_len, yh_algorithm mgf1Algo) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL ||
      label == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t mgf1Algo;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;
  yh_rc yrc;
  uint16_t len = 0;

  data.key_id = htons(key_id);
  len += sizeof(data.key_id);

  data.mgf1Algo = mgf1Algo;
  len += sizeof(data.mgf1Algo);

  // in_len has to match the rsa key size
  if (in_len != 256 && in_len != 384 && in_len != 512) {
    DBG_ERR("Wrong input length");
    return YHR_WRONG_LENGTH;
  }

  // label_len is hashed and specified the mgf hash
  if (label_len != 20 && label_len != 32 && label_len != 48 &&
      label_len != 64) {
    DBG_ERR("Wrong label length");
    return YHR_WRONG_LENGTH;
  }

  memcpy(data.bytes, in, in_len);
  len += in_len;
  memcpy(data.bytes + in_len, label, label_len);
  len += label_len;

  yrc = yh_send_secure_msg(session, YHC_DECRYPT_OAEP, data.buf, len,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send DECRYPT OAEP command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_derive_ecdh(yh_session *session, uint16_t key_id,
                          const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;
  yh_rc yrc;

  data.key_id = htons(key_id);

  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_DERIVE_ECDH, data.buf, in_len + 2,
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send DERIVE ECDH command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_delete_object(yh_session *session, uint16_t id,
                            yh_object_type type) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t id;
      uint8_t type;
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_rc yrc;
  yh_cmd response_cmd;
  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  data.type = type;
  data.id = htons(id);

  yrc = yh_send_secure_msg(session, YHC_DELETE_OBJECT, data.buf, sizeof(data),
                           &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send DELETE command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_export_wrapped(yh_session *session, uint16_t wrapping_key_id,
                             yh_object_type target_type, uint16_t target_id,
                             uint8_t *out, size_t *out_len) {

  if (session == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t type;
      uint16_t tgt_id;
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;
  yh_rc yrc;

  data.key_id = htons(wrapping_key_id);
  data.type = (uint8_t) target_type;
  data.tgt_id = htons(target_id);

  yrc = yh_send_secure_msg(session, YHC_EXPORT_WRAPPED, data.buf, sizeof(data),
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send EXPORT WRAPPED command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_import_wrapped(yh_session *session, uint16_t wrapping_key_id,
                             const uint8_t *in, size_t in_len,
                             yh_object_type *target_type, uint16_t *target_id) {

  if (session == NULL || in == NULL || target_type == NULL ||
      target_id == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE - 2];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len = 2 + in_len;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;
  yh_rc yrc;

  data.key_id = htons(wrapping_key_id);
  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_IMPORT_WRAPPED, data.buf, data_len,
                           &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send IMPORT WRAPPED command: %s", yh_strerror(yrc));
    return yrc;
  }

  *target_type = response[0];
  *target_id = ntohs(*((uint16_t *) (response + 1)));

  return YHR_SUCCESS;
}

yh_rc yh_util_import_wrap_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm,
                              const yh_capabilities *delegated_capabilities,
                              const uint8_t *in, size_t in_len) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || capabilities == NULL ||
      delegated_capabilities == NULL || in == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint8_t delegated_capabilities[YH_CAPABILITIES_LEN];
      uint8_t key[32];
    };
    uint8_t buf[1];
  } data;
  uint16_t data_len = sizeof(data);
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  size_t response_len = sizeof(response);
  yh_cmd response_cmd;
  uint16_t key_len;

  yh_rc yrc;

  switch (algorithm) {
    case YH_ALGO_AES128_CCM_WRAP:
      key_len = 16;
      data_len -= 16;
      break;
    case YH_ALGO_AES192_CCM_WRAP:
      key_len = 24;
      data_len -= 8;
      break;
    case YH_ALGO_AES256_CCM_WRAP:
      key_len = 32;
      break;
    default:
      DBG_ERR("Bad algorithm specified: %x", algorithm);
      return YHR_INVALID_PARAMETERS;
  }

  if (in_len != key_len) {
    DBG_ERR("Key length not matching, should be %d", key_len);
    return YHR_INVALID_PARAMETERS;
  }

  data.key_id = htons(*key_id);
  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));
  data.domains = htons(domains);
  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);
  data.algorithm = algorithm;
  memcpy(data.delegated_capabilities, delegated_capabilities,
         YH_CAPABILITIES_LEN);
  memcpy(data.key, in, key_len);

  yrc = yh_send_secure_msg(session, YHC_PUT_WRAP_KEY, data.buf, data_len,
                           &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, data_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT WRAP KEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Imported Wrap key 0x%04x", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_generate_wrap_key(yh_session *session, uint16_t *key_id,
                                const char *label, uint16_t domains,
                                const yh_capabilities *capabilities,
                                yh_algorithm algorithm,
                                const yh_capabilities *delegated_capabilities) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || capabilities == NULL ||
      delegated_capabilities == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint8_t delegated_capabilities[YH_CAPABILITIES_LEN];
    };
    uint8_t buf[1];
  } data;
  uint16_t data_len = sizeof(data);
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.key_id = htons(*key_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.algorithm = algorithm;

  memcpy(data.delegated_capabilities, delegated_capabilities,
         YH_CAPABILITIES_LEN);

  yrc = yh_send_secure_msg(session, YHC_GENERATE_WRAP_KEY, data.buf, data_len,
                           &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GENERATE WRAP KEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Generated Wrap key 0x%04x\n", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_get_log_entries(yh_session *session, uint16_t *unlogged_boot,
                              uint16_t *unlogged_auth, yh_log_entry *out,
                              size_t *n_items) {

  if (session == NULL || out == NULL || n_items == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

  union {
    struct {
      uint16_t log_overflow_boot;
      uint16_t log_overflow_auth;
      uint8_t items;
      uint8_t data[1];
    };
    uint8_t buf[YH_MSG_BUF_SIZE];
  } response;
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  yrc = yh_send_secure_msg(session, YHC_GET_LOG_ENTRIES, NULL, 0, &response_cmd,
                           response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET LOGS command: %s", yh_strerror(yrc));
    return yrc;
  }

  if (unlogged_boot) {
    *unlogged_boot = ntohs(response.log_overflow_boot);
  }

  if (unlogged_auth) {
    *unlogged_auth = ntohs(response.log_overflow_auth);
  }

  if (response.items > YH_MAX_LOG_ENTRIES) {
    DBG_ERR(
      "Response contain more items than the maximum number of log entries");
    return YHR_DEVICE_INVALID_DATA;
  }

  if (response.items > *n_items) {
    DBG_ERR("Log buffer too small, needed at lest %d, got %zu", response.items,
            *n_items);
    return YHR_BUFFER_TOO_SMALL;
  }

  *n_items = response.items;

  yh_log_entry *ptr = (yh_log_entry *) response.data;
  for (size_t i = 0; i < *n_items; i++) {
    out[i].number = ntohs(ptr[i].number);
    out[i].command = ptr[i].command;
    out[i].length = ntohs(ptr[i].length);
    out[i].session_key = ntohs(ptr[i].session_key);
    out[i].target_key = ntohs(ptr[i].target_key);
    out[i].second_key = ntohs(ptr[i].second_key);
    out[i].result = ptr[i].result;
    out[i].systick = ntohl(ptr[i].systick);
    memcpy(out[i].digest, ptr[i].digest, YH_LOG_DIGEST_SIZE);
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_set_log_index(yh_session *session, uint16_t index) {
  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
  uint8_t data[2];
  yh_cmd response_cmd;
  yh_rc yrc;
  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  uint16_t index_h = htons(index);
  memcpy(data, &index_h, sizeof(index_h));
  yrc = yh_send_secure_msg(session, YHC_SET_LOG_INDEX, data, sizeof(data),
                           &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SET LOG INDEX command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_get_opaque(yh_session *session, uint16_t object_id, uint8_t *out,
                         size_t *out_len) {

  if (session == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t data[2];
  yh_cmd response_cmd;
  yh_rc yrc;

  uint16_t object_id_h = htons(object_id);
  memcpy(data, &object_id_h, sizeof(object_id_h));
  yrc = yh_send_secure_msg(session, YHC_GET_OPAQUE, data, sizeof(data),
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET OPAQUE command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_import_opaque(yh_session *session, uint16_t *object_id,
                            const char *label, uint16_t domains,
                            const yh_capabilities *capabilities,
                            yh_algorithm algorithm, const uint8_t *in,
                            size_t in_len) {

  if (session == NULL || object_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || in == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t object_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint8_t bytes[YH_MSG_BUF_SIZE - sizeof(object_id) - sizeof(domains) -
                    YH_CAPABILITIES_LEN - 2];
    };
    uint8_t buf[1];
  } data;
  uint16_t data_len;
  union {
    struct {
      uint16_t object_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.object_id = htons(*object_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.algorithm = algorithm;

  if (in_len > sizeof(data.bytes)) {
    DBG_ERR("Data length must be in [0, %lu]\n",
            (unsigned long) sizeof(data.bytes));
    return YHR_INVALID_PARAMETERS;
  }

  data_len = in_len + sizeof(data) - sizeof(data.bytes);
  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_PUT_OPAQUE, data.buf, data_len,
                           &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, data_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT OPAQUE command: %s", yh_strerror(yrc));
    return yrc;
  }

  *object_id = ntohs(response.object_id);
  DBG_INFO("Stored Opaque Object 0x%04x", *object_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_ssh_certificate(yh_session *session, uint16_t key_id,
                                   uint16_t template_id, yh_algorithm sig_algo,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t *out_len) {
  if (session == NULL || in == NULL || out == NULL || out_len == NULL ||
      in_len == 0) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint16_t template_id;
      uint8_t algo;
      uint8_t bytes[YH_MSG_BUF_SIZE - sizeof(key_id) - sizeof(template_id) - 2];
    };
    uint8_t buf[1];
  } data;
  uint16_t data_len;
#pragma pack(pop)

  yh_cmd response_cmd;

  data.key_id = htons(key_id);

  data.template_id = htons(template_id);

  data.algo = sig_algo;

  if (in_len > sizeof(data.bytes)) {
    DBG_ERR("Data length must be in [0, %lu]\n",
            (unsigned long) sizeof(data.bytes));
    return YHR_INVALID_PARAMETERS;
  }

  data_len = in_len + 5;
  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_SIGN_SSH_CERTIFICATE, data.buf,
                           data_len, &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN SSH CERTIFICATE command: %s",
            yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_get_template(yh_session *session, uint16_t object_id,
                           uint8_t *out, size_t *out_len) {
  if (session == NULL || out == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t data[2];
  yh_cmd response_cmd;
  yh_rc yrc;

  uint16_t object_id_h = htons(object_id);
  memcpy(data, &object_id_h, sizeof(object_id_h));
  yrc = yh_send_secure_msg(session, YHC_GET_TEMPLATE, data, sizeof(data),
                           &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET TEMPLATE command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_import_template(yh_session *session, uint16_t *object_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm, const uint8_t *in,
                              size_t in_len) {

  if (session == NULL || object_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || in == NULL || in_len == 0) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t object_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint8_t bytes[YH_MSG_BUF_SIZE - sizeof(object_id) - sizeof(domains) -
                    YH_OBJ_LABEL_LEN - YH_CAPABILITIES_LEN - 2];
    };
    uint8_t buf[1];
  } data;
  uint16_t data_len;
  union {
    struct {
      uint16_t object_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.object_id = htons(*object_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.algorithm = algorithm;

  if (in_len > sizeof(data.bytes)) {
    DBG_ERR("Data length must be in [0, %lu]\n",
            (unsigned long) sizeof(data.bytes));
    return YHR_INVALID_PARAMETERS;
  }

  data_len = in_len + sizeof(data.object_id) + sizeof(data.domains) +
             YH_CAPABILITIES_LEN + YH_OBJ_LABEL_LEN + sizeof(data.algorithm);
  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_PUT_TEMPLATE, data.buf, data_len,
                           &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT TEMPLATE command: %s", yh_strerror(yrc));
    return yrc;
  }

  *object_id = ntohs(response.object_id);
  DBG_INFO("Stored Opaque Object 0x%04x", *object_id);

  return YHR_SUCCESS;
}

yh_rc yh_get_session_id(yh_session *session, uint8_t *sid) {

  if (session == NULL || sid == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  *sid = session->s.sid;

  return YHR_SUCCESS;
}

yh_rc yh_authenticate_session(yh_session *session) {

  Msg msg;
  Msg response_msg;
  yh_rc yrc;

  uint8_t mac_buf[64];
  uint16_t mac_buf_len;

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  // Send AUTHENTICATE SESSION command
  msg.st.cmd = YHC_AUTHENTICATE_SESSION;
  msg.st.len = htons(1 + SCP_HOST_CRYPTO_LEN + SCP_MAC_LEN);

  msg.st.data[0] = session->s.sid;

  // Compute host cryptogram
  yrc = compute_host_cryptogram(session, msg.st.data + 1);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("%s", yh_strerror(yrc));
    return yrc;
  }

  DBG_INT(msg.st.data + 1, SCP_HOST_CRYPTO_LEN, "Host cryptogram: ");

  mac_buf_len = SCP_PRF_LEN + ntohs(msg.st.len) + 3 - SCP_MAC_LEN;
  memset(mac_buf, 0, SCP_PRF_LEN); // Initial mac chaining value
  memcpy(mac_buf + SCP_PRF_LEN, msg.raw, mac_buf_len);

  yrc = compute_full_mac(mac_buf, mac_buf_len, session->s.s_mac, SCP_KEY_LEN,
                         session->s.mac_chaining_value);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("compute_full_mac %s", yh_strerror(yrc));
    return yrc;
  }
  memcpy(msg.st.data + 1 + SCP_HOST_CRYPTO_LEN, session->s.mac_chaining_value,
         SCP_MAC_LEN);

  // Reset counter to 1
  memset(session->s.ctr, 0, SCP_PRF_LEN);
  increment_ctr(session->s.ctr, SCP_PRF_LEN);

  yrc = send_msg(session->parent, &msg, &response_msg, session->s.identifier);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("%s", yh_strerror(yrc));
    return yrc;
  }

  if (response_msg.st.cmd != YHC_AUTHENTICATE_SESSION_R) {
    yrc = translate_device_error(response_msg.st.data[0]);
    DBG_ERR("Device error %s (%d)", yh_strerror(yrc), response_msg.st.data[0]);
    return yrc;
  }

  return YHR_SUCCESS;
}

static uint8_t get_auth_key_algo(size_t key_len) {
  switch (key_len) {
    case 32:
      return YH_ALGO_AES128_YUBICO_AUTHENTICATION;
    case 64:
      return YH_ALGO_EC_P256_YUBICO_AUTHENTICATION;
    default:
      return 0;
  }
}

yh_rc yh_util_import_authentication_key(
  yh_session *session, uint16_t *key_id, const char *label, uint16_t domains,
  const yh_capabilities *capabilities,
  const yh_capabilities *delegated_capabilities, const uint8_t *key_enc,
  size_t key_enc_len, const uint8_t *key_mac, size_t key_mac_len) {

  uint8_t algorithm = get_auth_key_algo(key_enc_len + key_mac_len);

  DBG_INFO("Auth Key Algorithm %u", algorithm);

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || capabilities == NULL ||
      delegated_capabilities == NULL || (key_enc == NULL && key_enc_len > 0) ||
      (key_mac == NULL && key_mac_len > 0) || algorithm == 0) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint8_t delegated_capabilities[YH_CAPABILITIES_LEN];
      uint8_t key[64];
    };
    uint8_t buf[1];
  } data;
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  memcpy(data.key, key_enc, key_enc_len);
  memcpy(data.key + key_enc_len, key_mac, key_mac_len);

  data.key_id = htons(*key_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.algorithm = algorithm;

  memcpy(data.delegated_capabilities, delegated_capabilities,
         YH_CAPABILITIES_LEN);

  yh_rc yrc = yh_send_secure_msg(session, YHC_PUT_AUTHENTICATION_KEY, data.buf,
                                 sizeof(data) - sizeof(data.key) + key_enc_len +
                                   key_mac_len,
                                 &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, sizeof(data));
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT AUTHENTICATION KEY command: %s\n",
            yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Stored Authentication key 0x%04x", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_import_authentication_key_derived(
  yh_session *session, uint16_t *key_id, const char *label, uint16_t domains,
  const yh_capabilities *capabilities,
  const yh_capabilities *delegated_capabilities, const uint8_t *password,
  size_t password_len) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || capabilities == NULL ||
      delegated_capabilities == NULL || password == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t key[2 * SCP_KEY_LEN];

  yh_rc yrc = derive_key(password, password_len, key, sizeof(key));

  if (yrc == YHR_SUCCESS) {
    yrc =
      yh_util_import_authentication_key(session, key_id, label, domains,
                                        capabilities, delegated_capabilities,
                                        key, SCP_KEY_LEN, key + SCP_KEY_LEN,
                                        SCP_KEY_LEN);
    insecure_memzero(key, sizeof(key));
  }
  return yrc;
}

yh_rc yh_util_change_authentication_key(yh_session *session, uint16_t *key_id,
                                        const uint8_t *key_enc,
                                        size_t key_enc_len,
                                        const uint8_t *key_mac,
                                        size_t key_mac_len) {

  uint8_t algorithm = get_auth_key_algo(key_enc_len + key_mac_len);

  DBG_INFO("Auth Key Algorithm %u", algorithm);

  if (session == NULL || key_id == NULL || algorithm == 0 ||
      (key_enc == NULL && key_enc_len > 0) ||
      (key_mac == NULL && key_mac_len > 0)) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t algorithm;
      uint8_t key[64];
    };
    uint8_t buf[1];
  } data;
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.key_id = htons(*key_id);
  data.algorithm = algorithm;
  memcpy(data.key, key_enc, key_enc_len);
  memcpy(data.key + key_enc_len, key_mac, key_mac_len);

  yh_rc yrc =
    yh_send_secure_msg(session, YHC_CHANGE_AUTHENTICATION_KEY, data.buf,
                       sizeof(data) - sizeof(data.key) + key_enc_len +
                         key_mac_len,
                       &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, sizeof(data));
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send CHANGE AUTHENTICATION KEY command: %s\n",
            yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Changed Authentication key 0x%04x", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_change_authentication_key_derived(yh_session *session,
                                                uint16_t *key_id,
                                                const uint8_t *password,
                                                size_t password_len) {
  if (session == NULL || key_id == NULL || password == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  uint8_t key[2 * SCP_KEY_LEN];

  yh_rc yrc = derive_key(password, password_len, key, sizeof(key));

  if (yrc == YHR_SUCCESS) {
    yrc = yh_util_change_authentication_key(session, key_id, key, SCP_KEY_LEN,
                                            key + SCP_KEY_LEN, SCP_KEY_LEN);
    insecure_memzero(key, sizeof(key));
  }
  return yrc;
}

yh_rc yh_util_create_otp_aead(yh_session *session, uint16_t key_id,
                              const uint8_t *key, const uint8_t *private_id,
                              uint8_t *out, size_t *out_len) {

  if (session == NULL || key == NULL || private_id == NULL || out == NULL ||
      out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t key[16];
      uint8_t private_id[6];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;

  data.key_id = htons(key_id);
  memcpy(data.key, key, sizeof(data.key));
  memcpy(data.private_id, private_id, sizeof(data.private_id));

  yh_rc yrc = yh_send_secure_msg(session, YHC_CREATE_OTP_AEAD, data.buf,
                                 sizeof(data), &response_cmd, out, out_len);
  insecure_memzero(data.buf, sizeof(data));
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send CREATE OTP AEAD command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_randomize_otp_aead(yh_session *session, uint16_t key_id,
                                 uint8_t *out, size_t *out_len) {

  if (session == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;

  data.key_id = htons(key_id);

  yh_rc yrc = yh_send_secure_msg(session, YHC_RANDOMIZE_OTP_AEAD, data.buf,
                                 sizeof(data), &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send RANDOMIZE OTP AEAD command: %s\n",
            yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_decrypt_otp(yh_session *session, uint16_t key_id,
                          const uint8_t *aead, size_t aead_len,
                          const uint8_t *otp, uint16_t *useCtr,
                          uint8_t *sessionCtr, uint8_t *tstph,
                          uint16_t *tstpl) {

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t aead[6 + 16 + 6 + 8]; // FIXME: ya.. magic numbers!
      uint8_t otp[16];
    };
    uint8_t buf[1];
  } data;
  union {
    struct {
      uint16_t useCtr;
      uint8_t sessionCtr;
      uint8_t tstph;
      uint16_t tstpl;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  if (session == NULL || aead == NULL || otp == NULL ||
      aead_len != sizeof(data.aead)) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_cmd response_cmd;
  size_t response_len = sizeof(response);

  data.key_id = htons(key_id);
  memcpy(data.aead, aead, sizeof(data.aead));
  memcpy(data.otp, otp, sizeof(data.otp));

  yh_rc yrc =
    yh_send_secure_msg(session, YHC_DECRYPT_OTP, data.buf, sizeof(data),
                       &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, sizeof(data));
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send DECRYPT OTP command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  if (response_len != sizeof(response)) {
    DBG_ERR("Wrong size returned");
    return YHR_WRONG_LENGTH;
  }

  if (useCtr) {
    *useCtr = response.useCtr;
  }
  if (sessionCtr) {
    *sessionCtr = response.sessionCtr;
  }
  if (tstph) {
    *tstph = response.tstph;
  }
  if (tstpl) {
    *tstpl = response.tstpl;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_rewrap_otp_aead(yh_session *session, uint16_t id_from,
                              uint16_t id_to, const uint8_t *aead_in,
                              size_t in_len, uint8_t *aead_out,
                              size_t *out_len) {

#pragma pack(push, 1)
  union {
    struct {
      uint16_t from_key;
      uint16_t to_key;
      uint8_t aead[6 + 16 + 6 + 8]; // FIXME: magic numbers!
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  if (session == NULL || aead_in == NULL || aead_out == NULL ||
      out_len == NULL || in_len != sizeof(data.aead) ||
      *out_len < sizeof(data.aead)) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  data.from_key = htons(id_from);
  data.to_key = htons(id_to);
  memcpy(data.aead, aead_in, sizeof(data.aead));

  yh_cmd response_cmd;
  yh_rc yrc =
    yh_send_secure_msg(session, YHC_REWRAP_OTP_AEAD, data.buf, sizeof(data),
                       &response_cmd, aead_out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send REWRAP OTP AEAD command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_import_otp_aead_key(yh_session *session, uint16_t *key_id,
                                  const char *label, uint16_t domains,
                                  const yh_capabilities *capabilities,
                                  uint32_t nonce_id, const uint8_t *in,
                                  size_t in_len) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || capabilities == NULL || in == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint32_t nonce_id;
      uint8_t key[32];
    };
    uint8_t buf[1];
  } data;
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  uint16_t data_len = sizeof(data);
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  yh_rc yrc;

  if (in_len == 16) {
    data.algorithm = YH_ALGO_AES128_YUBICO_OTP;
    data_len -= 16;
  } else if (in_len == 24) {
    data.algorithm = YH_ALGO_AES192_YUBICO_OTP;
    data_len -= 8;
  } else if (in_len == 32) {
    data.algorithm = YH_ALGO_AES256_YUBICO_OTP;
  } else {
    DBG_ERR("Key length has to be 16, 24 or 32 bytes.");
    return YHR_INVALID_PARAMETERS;
  }

  data.key_id = htons(*key_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.nonce_id = nonce_id;

  memcpy(data.key, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_PUT_OTP_AEAD_KEY, data.buf, data_len,
                           &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, data_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send PUT OTP AEAD KEY command: %s", yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Imported OTP AEAD key 0x%04x", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_generate_otp_aead_key(yh_session *session, uint16_t *key_id,
                                    const char *label, uint16_t domains,
                                    const yh_capabilities *capabilities,
                                    yh_algorithm algorithm, uint32_t nonce_id) {

  if (session == NULL || key_id == NULL || label == NULL ||
      strlen(label) > YH_OBJ_LABEL_LEN || capabilities == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t label[YH_OBJ_LABEL_LEN];
      uint16_t domains;
      uint8_t capabilities[YH_CAPABILITIES_LEN];
      uint8_t algorithm;
      uint32_t nonce_id;
    };
    uint8_t buf[1];
  } data;
  uint16_t data_len = sizeof(data);
  union {
    struct {
      uint16_t key_id;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)

  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  data.key_id = htons(*key_id);

  memcpy(data.label, label, strlen(label));
  memset(data.label + strlen(label), 0, YH_OBJ_LABEL_LEN - strlen(label));

  data.domains = htons(domains);

  memcpy(data.capabilities, capabilities, YH_CAPABILITIES_LEN);

  data.algorithm = algorithm;

  data.nonce_id = nonce_id;

  yrc =
    yh_send_secure_msg(session, YHC_GENERATE_OTP_AEAD_KEY, data.buf, data_len,
                       &response_cmd, response.buf, &response_len);
  insecure_memzero(data.buf, data_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GENERATE OTP AEAD KEY command: %s",
            yh_strerror(yrc));
    return yrc;
  }

  *key_id = ntohs(response.key_id);
  DBG_INFO("Generated OTP AEAD key 0x%04x\n", *key_id);

  return YHR_SUCCESS;
}

yh_rc yh_util_sign_attestation_certificate(yh_session *session, uint16_t key_id,
                                           uint16_t attest_id, uint8_t *out,
                                           size_t *out_len) {

  if (session == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint16_t attest_id;
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)

  yh_cmd response_cmd;

  data.key_id = htons(key_id);
  data.attest_id = htons(attest_id);

  yh_rc yrc =
    yh_send_secure_msg(session, YHC_SIGN_ATTESTATION_CERTIFICATE, data.buf,
                       sizeof(data), &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SIGN ATTESTATION CERTIFICATE command: %s\n",
            yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_set_option(yh_session *session, yh_option option, size_t len,
                         uint8_t *val) {

  if (session == NULL || val == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (len > YH_MSG_BUF_SIZE - 3) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 3);
    return YHR_INVALID_PARAMETERS;
  }

#pragma pack(push, 1)
  union {
    struct {
      uint8_t option;
      uint16_t len;
      uint8_t bytes[1];
    };
    uint8_t buf[YH_MSG_BUF_SIZE];
  } data;
#pragma pack(pop)
  uint8_t out[YH_MSG_BUF_SIZE];
  size_t outlen = sizeof(out);
  yh_cmd response_cmd;

  data.option = option;
  data.len = htons(len);
  memcpy(data.bytes, val, len);

  yh_rc yrc = yh_send_secure_msg(session, YHC_SET_OPTION, data.buf, len + 3,
                                 &response_cmd, out, &outlen);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send SET OPTION command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_get_option(yh_session *session, yh_option option, uint8_t *out,
                         size_t *out_len) {

  if (session == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
  uint8_t buf[1] = {option};
  yh_cmd response_cmd;

  yh_rc yrc = yh_send_secure_msg(session, YHC_GET_OPTION, buf, sizeof(buf),
                                 &response_cmd, out, out_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET OPTION command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_get_storage_info(yh_session *session, uint16_t *total_records,
                               uint16_t *free_records, uint16_t *total_pages,
                               uint16_t *free_pages, uint16_t *page_size) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_cmd response_cmd;
#pragma pack(push, 1)
  union {
    struct {
      uint16_t total_records;
      uint16_t free_records;
      uint16_t total_pages;
      uint16_t free_pages;
      uint16_t page_size;
    };
    uint8_t buf[1];
  } response;
#pragma pack(pop)
  size_t response_len = sizeof(response);

  yh_rc yrc = yh_send_secure_msg(session, YHC_GET_STORAGE_INFO, NULL, 0,
                                 &response_cmd, response.buf, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send GET STORAGE INFO command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  if (total_records) {
    *total_records = ntohs(response.total_records);
  }
  if (free_records) {
    *free_records = ntohs(response.free_records);
  }
  if (total_pages) {
    *total_pages = ntohs(response.total_pages);
  }
  if (free_pages) {
    *free_pages = ntohs(response.free_pages);
  }
  if (page_size) {
    *page_size = ntohs(response.page_size);
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_wrap_data(yh_session *session, uint16_t key_id, const uint8_t *in,
                        size_t in_len, uint8_t *out, size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len = in_len + 2;

  yh_cmd response_cmd;

  data.key_id = htons(key_id);
  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_WRAP_DATA, data.buf, data_len,
                           &response_cmd, out, out_len);
  insecure_memzero(data.buf, data_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send WRAP DATA command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_unwrap_data(yh_session *session, uint16_t key_id,
                          const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t *out_len) {

  if (session == NULL || in == NULL || out == NULL || out_len == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (in_len > YH_MSG_BUF_SIZE - 2) {
    DBG_ERR("Too much data, must be < %d", YH_MSG_BUF_SIZE - 2);
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

#pragma pack(push, 1)
  union {
    struct {
      uint16_t key_id;
      uint8_t bytes[YH_MSG_BUF_SIZE];
    };
    uint8_t buf[1];
  } data;
#pragma pack(pop)
  uint16_t data_len = in_len + 2;

  yh_cmd response_cmd;

  data.key_id = htons(key_id);
  memcpy(data.bytes, in, in_len);

  yrc = yh_send_secure_msg(session, YHC_UNWRAP_DATA, data.buf, data_len,
                           &response_cmd, out, out_len);
  insecure_memzero(data.buf, data_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send UNWRAP DATA command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_blink_device(yh_session *session, uint8_t seconds) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

  uint8_t response[5];
  size_t response_len = sizeof(response);
  yh_cmd response_cmd;

  yrc = yh_send_secure_msg(session, YHC_BLINK_DEVICE, &seconds, sizeof(seconds),
                           &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send BLINK DEVICE command: %s", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_util_reset_device(yh_session *session) {

  if (session == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc yrc;

  yh_cmd response_cmd;
  uint8_t response[1];
  size_t response_len = sizeof(response);

  yrc = yh_send_secure_msg(session, YHC_RESET_DEVICE, NULL, 0, &response_cmd,
                           response, &response_len);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed to send RESET DEVICE command: %s\n", yh_strerror(yrc));
    return yrc;
  }

  return YHR_SUCCESS;
}

yh_rc yh_set_verbosity(yh_connector *connector, uint8_t verbosity) {

  _yh_verbosity = verbosity;

  if (connector != NULL && connector->bf != NULL) {
    // TODO(adma): should we error out if NULL?
    connector->bf->backend_set_verbosity(_yh_verbosity, _yh_output);
  }

  return YHR_SUCCESS;
}

yh_rc yh_get_verbosity(uint8_t *verbosity) {

  if (verbosity == NULL) {
    return YHR_INVALID_PARAMETERS;
  }

  *verbosity = _yh_verbosity;

  return YHR_SUCCESS;
}

void yh_set_debug_output(yh_connector *connector, FILE *output) {
  _yh_output = output;

  if (connector != NULL && connector->bf != NULL) {
    // TODO(adma): should we error out if NULL?
    connector->bf->backend_set_verbosity(_yh_verbosity, _yh_output);
  }
}

yh_rc yh_init(void) {
  if (_yh_output == NULL) {
    _yh_output = stderr;
  }
  return YHR_SUCCESS;
}

#ifdef STATIC
static yh_rc load_backend(const char *name,
                          void **backend __attribute__((unused)),
                          struct backend_functions **bf) {
  if (name == NULL) {
    DBG_ERR("No name given to load_backend");
    return YHR_GENERIC_ERROR;
  } else if (strncmp(name, STATIC_USB_BACKEND, strlen(STATIC_USB_BACKEND)) ==
             0) {
    *bf = usb_backend_functions();
  } else if (strncmp(name, STATIC_HTTP_BACKEND, strlen(STATIC_HTTP_BACKEND)) ==
             0) {
    *bf = http_backend_functions();
  } else {
    DBG_ERR("Failed finding backend named '%s'", name);
    return YHR_GENERIC_ERROR;
  }

  return (*bf)->backend_init(_yh_verbosity, _yh_output);
}
#else
static yh_rc load_backend(const char *name, void **backend,
                          struct backend_functions **bf) {
  struct backend_functions *(*backend_functions)(void);
#ifdef WIN32
  HMODULE module = GetModuleHandle("libyubihsm");
  if (!module) {
    DBG_ERR("Failed getting module handle for 'libyubihsm'");
    return YHR_GENERIC_ERROR;
  }
  char path[1024];
  if (!GetModuleFileName(module, path, sizeof(path))) {
    DBG_ERR("Failed getting module path for 'libyubihsm'");
    return YHR_GENERIC_ERROR;
  }
  char *p = strrchr(path, '\\');
  if (!p) {
    DBG_ERR("Path separator not found in module path '%s'", path);
    return YHR_GENERIC_ERROR;
  }
  p[1] = 0;
  strcat_s(path, sizeof(path), name);
  DBG_INFO("Loading backend library '%s'", path);

  *backend = LoadLibraryEx(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

  if (*backend == NULL) {
    DBG_ERR("Failed loading backend library '%s'", path);
    return YHR_GENERIC_ERROR;
  }
  backend_functions = (struct backend_functions * (*) (void) )
    GetProcAddress(*backend, "backend_functions");
#else
  *backend = dlopen(name, RTLD_NOW);
  if (*backend == NULL) {
    DBG_ERR("Failed loading '%s' with error: '%s'", name, dlerror());
    return YHR_GENERIC_ERROR;
  }
  *(void **) (&backend_functions) = dlsym(*backend, "backend_functions");
#endif
  if (backend_functions == NULL) {
    DBG_ERR("Symbol 'backend_functions' not found in '%s'", name);
    return YHR_GENERIC_ERROR;
  }
  *bf = backend_functions();
  return (*bf)->backend_init(_yh_verbosity, _yh_output);
}
#endif

yh_rc yh_exit(void) { return YHR_SUCCESS; }

#define STATUS_ENDPOINT "/connector/status"
#define API_ENDPOINT "/connector/api"

static yh_rc create_connector(yh_connector **connector, const char *url,
                              void *backend, struct backend_functions *bf) {

  yh_rc rc;

  if (connector == NULL) {
    return YHR_INVALID_PARAMETERS;
  }

  *connector = calloc(1, sizeof(yh_connector));
  if (*connector == NULL) {
    return YHR_MEMORY_ERROR;
  }

  if (strncmp(url, YH_USB_URL_SCHEME, strlen(YH_USB_URL_SCHEME)) == 0) {
    (*connector)->status_url = strdup(url);
    if ((*connector)->status_url == NULL) {
      rc = YHR_MEMORY_ERROR;
      goto cc_failure;
    }
    (*connector)->api_url = strdup(url);
    if ((*connector)->api_url == NULL) {
      rc = YHR_MEMORY_ERROR;
      goto cc_failure;
    }
  } else {
    (*connector)->status_url =
      calloc(1, strlen(url) + strlen(STATUS_ENDPOINT) + 1);
    if ((*connector)->status_url == NULL) {
      rc = YHR_MEMORY_ERROR;
      goto cc_failure;
    }
    sprintf((*connector)->status_url, "%s%s", url, STATUS_ENDPOINT);

    (*connector)->api_url = calloc(1, strlen(url) + strlen(API_ENDPOINT) + 1);
    if ((*connector)->api_url == NULL) {
      rc = YHR_MEMORY_ERROR;
      goto cc_failure;
    }
    sprintf((*connector)->api_url, "%s%s", url, API_ENDPOINT);
  }

  (*connector)->connection = bf->backend_create();
  if ((*connector)->connection == NULL) {
    rc = YHR_CONNECTION_ERROR;
    goto cc_failure;
  }

  (*connector)->backend = backend;
  (*connector)->bf = bf;

  return YHR_SUCCESS;

cc_failure:
  if ((*connector)->status_url) {
    free((*connector)->status_url);
    (*connector)->status_url = NULL;
  }

  if ((*connector)->api_url) {
    free((*connector)->api_url);
    (*connector)->api_url = NULL;
  }

  if (*connector) {
    free(*connector);
    *connector = NULL;
  }

  return rc;
}

static void destroy_connector(yh_connector *connector) {

  if (connector == NULL) {
    return;
  }

  if (connector->bf != NULL && connector->connection != NULL) {
    connector->bf->backend_disconnect(connector->connection);
    connector->connection = NULL;
  }

  if (connector->status_url != NULL) {
    free(connector->status_url);
    connector->status_url = NULL;
  }

  if (connector->api_url != NULL) {
    free(connector->api_url);
    connector->api_url = NULL;
  }

  if (connector->bf) {
    connector->bf->backend_cleanup();
#ifndef STATIC
#ifdef WIN32
    FreeLibrary(connector->backend);
#else
    dlclose(connector->backend);
#endif
#endif
    connector->backend = NULL;
    connector->bf = NULL;
  }

  free(connector);
}

yh_rc yh_init_connector(const char *url, yh_connector **connector) {
  if (url == NULL || connector == NULL) {
    DBG_ERR("Invalid parameters: undefined pointer");
    return YHR_INVALID_PARAMETERS;
  }

#ifdef STATIC
#define USB_LIB STATIC_USB_BACKEND
#define HTTP_LIB STATIC_HTTP_BACKEND
#elif defined WIN32
#define USB_LIB "libyubihsm_usb.dll"
#define HTTP_LIB "libyubihsm_http.dll"
#elif defined __APPLE__
#define USB_LIB "libyubihsm_usb." SOVERSION ".dylib"
#define HTTP_LIB "libyubihsm_http." SOVERSION ".dylib"
#else
#define USB_LIB "libyubihsm_usb.so." SOVERSION
#define HTTP_LIB "libyubihsm_http.so." SOVERSION
#endif

  void *backend = NULL;
  struct backend_functions *bf = NULL;

  if (strncmp(url, YH_USB_URL_SCHEME, strlen(YH_USB_URL_SCHEME)) == 0) {
    DBG_INFO("Loading usb backend");
    load_backend(USB_LIB, &backend, &bf);
  } else if (strncmp(url, "http://", strlen("http://")) == 0 ||
             strncmp(url, "https://", strlen("https://")) == 0) {
    DBG_INFO("Loading http backend");
    load_backend(HTTP_LIB, &backend, &bf);
  }
  if (bf == NULL) {
    DBG_ERR("Failed loading the backend");
    return YHR_GENERIC_ERROR;
  }

  return create_connector(connector, url, backend, bf);
}

yh_rc yh_set_connector_option(yh_connector *connector, yh_connector_option opt,
                              const void *val) {

  if (connector == NULL || val == NULL) {
    DBG_ERR("Invalid parameters: undefined pointer");
    return YHR_INVALID_PARAMETERS;
  }

  if (connector->bf == NULL) {
    DBG_ERR("No backend loaded");
    return YHR_INVALID_PARAMETERS;
  }

  return connector->bf->backend_option(connector->connection, opt, val);
}

yh_rc yh_connect(yh_connector *connector, int timeout) {

  if (connector == NULL || connector->bf == NULL) {
    DBG_ERR("Invalid parameters: undefined pointer");
    return YHR_INVALID_PARAMETERS;
  }

  yh_rc rc;

  rc = connector->bf->backend_connect(connector, timeout);

  if (rc != YHR_SUCCESS) {
    DBG_ERR("Failed when connecting: %s", yh_strerror(rc));
  }

  return rc;
}

yh_rc yh_disconnect(yh_connector *connector) {

  if (connector == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  destroy_connector(connector);

  return YHR_SUCCESS;
}

#ifndef htonll
#define htonll(x)                                                              \
  ((1 == htonl(1))                                                             \
     ? (x)                                                                     \
     : ((uint64_t) htonl((x) &0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
yh_rc yh_string_to_capabilities(const char *capability,
                                yh_capabilities *result) {

  char *endptr;
  char *saveptr = NULL;
  char *str = NULL;
  char tmp[2048] = {0};
  uint64_t value;

  if (capability == NULL || result == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  errno = 0;
  value = strtoull(capability, &endptr, 0);

  if (capability != endptr && errno != ERANGE) {
    uint64_t actual = htonll(value);
    memcpy(result, &actual, 8);
    return YHR_SUCCESS;
  }

  if (strcasecmp(capability, "all") == 0) {
    memset(result->capabilities, 0xff, YH_CAPABILITIES_LEN);
    return YHR_SUCCESS;
  } else if (strcasecmp(capability, "none") == 0) {
    memset(result->capabilities, 0x00, YH_CAPABILITIES_LEN);
    return YHR_SUCCESS;
  }

  if (strlen(capability) > sizeof(tmp)) {
    return YHR_BUFFER_TOO_SMALL;
  }
  strncpy(tmp, capability, sizeof(tmp) - 1);

  while ((str = strtok_r(str ? NULL : tmp, LIST_SEPARATORS, &saveptr))) {
    for (size_t i = 0; i < sizeof(yh_capability) / sizeof(yh_capability[0]);
         i++) {
      if (strcasecmp(str, yh_capability[i].name) == 0) {
        result
          ->capabilities[YH_CAPABILITIES_LEN - 1 - yh_capability[i].bit / 8] |=
          1ULL << (yh_capability[i].bit % 8);
        break;
      } else if (i + 1 == sizeof(yh_capability) / sizeof(yh_capability[0])) {
        return YHR_INVALID_PARAMETERS;
      }
    }
  }

  return YHR_SUCCESS;
}

yh_rc yh_capabilities_to_strings(const yh_capabilities *num,
                                 const char *result[], size_t *n_result) {

  if (num == 0 || result == NULL || n_result == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  size_t matching = 0;

  for (size_t i = 0; i < sizeof(yh_capability) / sizeof(yh_capability[0]);
       i++) {
    if (((1ULL << (yh_capability[i].bit % 8)) &
         num->capabilities[YH_CAPABILITIES_LEN - 1 -
                           (yh_capability[i].bit / 8)]) != 0) {
      if (++matching > *n_result) {
        memset(result, 0, *n_result);

        return YHR_BUFFER_TOO_SMALL;
      }

      result[matching - 1] = yh_capability[i].name;
    }
  }

  *n_result = matching;

  return YHR_SUCCESS;
}

bool yh_check_capability(const yh_capabilities *capabilities,
                         const char *capability) {

  yh_capabilities check_capabilities = {{0}};

  if (yh_string_to_capabilities(capability, &check_capabilities) !=
      YHR_SUCCESS) {
    return false;
  }

  for (int i = 0; i < YH_CAPABILITIES_LEN; i++) {
    if (check_capabilities.capabilities[i] != 0 &&
        (check_capabilities.capabilities[i] & capabilities->capabilities[i]) !=
          0) {
      return true;
    }
  }

  return false;
}

yh_rc yh_merge_capabilities(const yh_capabilities *a, const yh_capabilities *b,
                            yh_capabilities *result) {
  if (a == NULL || b == NULL || result == NULL) {
    return YHR_INVALID_PARAMETERS;
  }

  for (int i = 0; i < YH_CAPABILITIES_LEN; i++) {
    result->capabilities[i] = a->capabilities[i] | b->capabilities[i];
  }
  return YHR_SUCCESS;
}

yh_rc yh_filter_capabilities(const yh_capabilities *capabilities,
                             const yh_capabilities *filter,
                             yh_capabilities *result) {
  if (capabilities == NULL || filter == NULL || result == NULL) {
    return YHR_INVALID_PARAMETERS;
  }

  for (int i = 0; i < YH_CAPABILITIES_LEN; i++) {
    result->capabilities[i] =
      capabilities->capabilities[i] & filter->capabilities[i];
  }
  return YHR_SUCCESS;
}

bool yh_is_rsa(yh_algorithm algorithm) {

  switch (algorithm) {
    case YH_ALGO_RSA_2048:
    case YH_ALGO_RSA_3072:
    case YH_ALGO_RSA_4096:
      return true;

    default:
      break;
  }

  return false;
}

bool yh_is_ec(yh_algorithm algorithm) {

  switch (algorithm) {
    case YH_ALGO_EC_P224:
    case YH_ALGO_EC_P256:
    case YH_ALGO_EC_P384:
    case YH_ALGO_EC_P521:
    case YH_ALGO_EC_K256:
    case YH_ALGO_EC_BP256:
    case YH_ALGO_EC_BP384:
    case YH_ALGO_EC_BP512:
      return true;

    default:
      break;
  }

  return false;
}

bool yh_is_ed(yh_algorithm algorithm) {

  switch (algorithm) {
    case YH_ALGO_EC_ED25519:
      return true;

    default:
      break;
  }

  return false;
}

bool yh_is_hmac(yh_algorithm algorithm) {

  switch (algorithm) {
    case YH_ALGO_HMAC_SHA1:
    case YH_ALGO_HMAC_SHA256:
    case YH_ALGO_HMAC_SHA384:
    case YH_ALGO_HMAC_SHA512:
      return true;

    default:
      break;
  }

  return false;
}

yh_rc yh_get_key_bitlength(yh_algorithm algorithm, size_t *result) {

  if (result == NULL) {
    return YHR_INVALID_PARAMETERS;
  }

  switch (algorithm) {
    case YH_ALGO_RSA_2048:
      *result = 2048;
      break;

    case YH_ALGO_RSA_3072:
      *result = 3072;
      break;

    case YH_ALGO_RSA_4096:
      *result = 4096;
      break;

    case YH_ALGO_EC_P256:
      *result = 256;
      break;

    case YH_ALGO_EC_P384:
      *result = 384;
      break;

    case YH_ALGO_EC_P521:
      *result = 521;
      break;

    case YH_ALGO_EC_P224:
      *result = 224;
      break;

    case YH_ALGO_EC_K256:
      *result = 256;
      break;

    case YH_ALGO_EC_BP256:
      *result = 256;
      break;

    case YH_ALGO_EC_BP384:
      *result = 394;
      break;

    case YH_ALGO_EC_BP512:
      *result = 512;
      break;

    case YH_ALGO_HMAC_SHA1:
      *result = 160;
      break;

    case YH_ALGO_HMAC_SHA256:
      *result = 256;
      break;

    case YH_ALGO_HMAC_SHA384:
      *result = 384;
      break;

    case YH_ALGO_HMAC_SHA512:
      *result = 512;
      break;

    default:
      *result = 0;
      return YHR_INVALID_PARAMETERS;
  }

  return YHR_SUCCESS;
}

yh_rc yh_algo_to_string(yh_algorithm algo, char const **result) {

  if (result == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  for (size_t i = 0; i < sizeof(yh_algorithms) / sizeof(yh_algorithms[0]);
       i++) {
    if (algo == yh_algorithms[i].algorithm) {
      *result = yh_algorithms[i].name;
      return YHR_SUCCESS;
    }
  }

  *result = "Unknown";
  return YHR_SUCCESS;
}

yh_rc yh_string_to_algo(const char *string, yh_algorithm *algo) {

  if (string == NULL || algo == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
  if (strcasecmp(string, "any") == 0) {
    *algo = 0;
    return YHR_SUCCESS;
  }
  for (size_t i = 0; i < sizeof(yh_algorithms) / sizeof(yh_algorithms[0]);
       i++) {
    if (strcasecmp(string, yh_algorithms[i].name) == 0) {
      *algo = yh_algorithms[i].algorithm;
      return YHR_SUCCESS;
    }
  }

  return YHR_INVALID_PARAMETERS;
}

yh_rc yh_type_to_string(yh_object_type type, char const **result) {

  if (result == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  for (size_t i = 0; i < sizeof(yh_types) / sizeof(yh_types[0]); i++) {
    if (type == yh_types[i].type) {
      *result = yh_types[i].name;
      return YHR_SUCCESS;
    }
  }

  *result = "Unknown";
  return YHR_SUCCESS;
}

yh_rc yh_string_to_type(const char *string, yh_object_type *type) {

  if (string == NULL || type == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  if (strcasecmp(string, "any") == 0) {
    *type = 0;
    return YHR_SUCCESS;
  }
  for (size_t i = 0; i < sizeof(yh_types) / sizeof(yh_types[0]); i++) {
    if (strcasecmp(string, yh_types[i].name) == 0) {
      *type = yh_types[i].type;
      return YHR_SUCCESS;
    }
  }

  return YHR_INVALID_PARAMETERS;
}

yh_rc yh_string_to_option(const char *string, yh_option *option) {

  if (string == NULL || option == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }

  for (size_t i = 0; i < sizeof(yh_options) / sizeof(yh_options[0]); i++) {
    if (strcasecmp(string, yh_options[i].name) == 0) {
      *option = yh_options[i].option;
      return YHR_SUCCESS;
    }
  }

  return YHR_INVALID_PARAMETERS;
}

bool yh_verify_logs(yh_log_entry *logs, size_t n_items,
                    yh_log_entry *last_previous_log) {
  if (logs == NULL || n_items == 0) {
    return false;
  }

  hash_ctx hashctx = NULL;
  uint8_t previous_hash[32];
  size_t previous_hash_len = 32;
  int start;
  bool ret = false;

  if (!hash_create(&hashctx, _SHA256)) {
    return false;
  }

  if (last_previous_log != NULL) {
    memcpy(previous_hash, last_previous_log->digest, YH_LOG_DIGEST_SIZE);
    start = 0;
  } else {
    memcpy(previous_hash, logs[0].digest, YH_LOG_DIGEST_SIZE);
    start = 1;
  }

  for (size_t i = start; i < n_items; i++) {
    yh_log_entry inverted;
    inverted.number = htons(logs[i].number);
    inverted.command = logs[i].command;
    inverted.length = htons(logs[i].length);
    inverted.session_key = htons(logs[i].session_key);
    inverted.target_key = htons(logs[i].target_key);
    inverted.second_key = htons(logs[i].second_key);
    inverted.result = logs[i].result;
    inverted.systick = htonl(logs[i].systick);

    hash_init(hashctx);
    hash_update(hashctx, (const uint8_t *) &inverted,
                sizeof(yh_log_entry) - YH_LOG_DIGEST_SIZE);
    hash_update(hashctx, previous_hash, YH_LOG_DIGEST_SIZE);
    hash_final(hashctx, previous_hash, &previous_hash_len);

    if (memcmp(logs[i].digest, previous_hash, YH_LOG_DIGEST_SIZE) != 0) {
      goto out;
    }
  }

  ret = true;

out:
  hash_destroy(hashctx);
  hashctx = NULL;

  return ret;
}

yh_rc yh_string_to_domains(const char *domains, uint16_t *result) {
  char *endptr;
  char *saveptr = NULL;
  char *str = NULL;
  char tmp[64] = {0};
  unsigned long value;

  if (domains == NULL || result == NULL) {
    DBG_ERR("%s", yh_strerror(YHR_INVALID_PARAMETERS));
    return YHR_INVALID_PARAMETERS;
  }
  *result = 0;

  if (strcasecmp(domains, "all") == 0) {
    *result = 0xffff;
    goto out;
  } else if (strcmp(domains, "0") == 0) {
    goto out;
  }

  errno = 0;
  value = strtoul(domains, &endptr, 0);

  if (strncmp(domains, "0x", 2) == 0 && *endptr == '\0' && errno != ERANGE &&
      value != ULONG_MAX) {
    if (value > USHRT_MAX) {
      DBG_ERR("Tried to parse to long number for domains");
      return YHR_INVALID_PARAMETERS;
    }
    *result = value;
  } else {
    if (strlen(domains) > sizeof(tmp)) {
      return YHR_BUFFER_TOO_SMALL;
    }
    strncpy(tmp, domains, sizeof(tmp) - 1);

    while ((str = strtok_r(str ? NULL : tmp, LIST_SEPARATORS, &saveptr))) {
      endptr = NULL;
      value = strtoul(str, &endptr, 0);
      if (errno == ERANGE || value > YH_MAX_DOMAINS || value == 0) {
        DBG_ERR("Domains are numbered from 1 to %d", YH_MAX_DOMAINS);
        return YHR_INVALID_PARAMETERS;
      }
      *result |= 1 << (value - 1);
    }
  }

out:
  DBG_INFO("Domains parsed as %x", *result);
  return YHR_SUCCESS;
}

yh_rc yh_domains_to_string(uint16_t domains, char *string, size_t max_len) {
  char *ptr = string;
  *ptr = '\0';
  for (uint16_t i = 0; i < YH_MAX_DOMAINS; i++) {
    if (domains & (1 << i)) {
      size_t wrote = snprintf(ptr, max_len, "%d:", i + 1);
      if (wrote >= max_len) {
        return YHR_BUFFER_TOO_SMALL;
      }
      ptr += wrote;
      max_len -= wrote;
    }
  }
  if (ptr != string) {
    *(ptr - 1) = '\0';
  }
  return YHR_SUCCESS;
}
