/*
 * Copyright 2015-2021 Yubico AB
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

#include "scp.h"
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

using namespace std;

extern "C" {
#include "yubihsm.h"
#include "internal.h"
#include "debug_lib.h"
#include "../common/platform-config.h"
#include "../common/pkcs5.h"
#include "../common/hash.h"
#include "../aes_cmac/aes.h"
#include "../aes_cmac/aes_cmac.h"
}

#include <vector>
#include "../src/fuzz/fuzzer.h"

static void process_msg(Msg *msg, Msg *response);
static bool compute_mac(Scp_ctx *s, uint8_t *key, Msg *msg, size_t raw_msg_len,
                        int host_order_len, uint8_t *mac);

struct state {};

static uint8_t key_enc[SCP_KEY_LEN];
static uint8_t key_mac[SCP_KEY_LEN];

#define FUZZ_MAX_SESSIONS 10
static Scp_ctx sessions[FUZZ_MAX_SESSIONS];
static uint8_t init_sessions[FUZZ_MAX_SESSIONS];
static int current_session_id = -1;

static int get_free_session_slot() {
  for (int i = 0; i < FUZZ_MAX_SESSIONS; i++) {
    if (init_sessions[i] == 0) {
      return i;
    }
  }
  return -1;
}

static int is_session_slot_initialized(int slot) {
  if (slot < 0 || slot >= FUZZ_MAX_SESSIONS) {
    return 0;
  }
  return init_sessions[slot];
}

static bool compute_mac(Scp_ctx *s, uint8_t *key, Msg *msg, size_t raw_msg_len,
                        int host_order_len, uint8_t *mac) {
  aes_context aes_ctx;
  aes_cmac_context_t cmac_ctx;

#pragma pack(push, 1)
  struct {
    uint8_t mac_chaining_value[SCP_PRF_LEN];
    Msg msg;
  } mac_msg;
#pragma pack(pop)

  memset(&mac_msg, 0, sizeof(mac_msg));

  if (raw_msg_len > sizeof(Msg)) {
    return false;
  }
  memcpy(mac_msg.mac_chaining_value, s->mac_chaining_value, SCP_PRF_LEN);
  memcpy(&mac_msg.msg, msg, raw_msg_len);

  if (host_order_len) {
    // macced len field is in network byte order
    mac_msg.msg.st.len = htons(mac_msg.msg.st.len);
  }

  // this is the size of the raw package with everything to be macced
  size_t macced_data_len = SCP_PRF_LEN + raw_msg_len;

  memset(&aes_ctx, 0, sizeof(aes_ctx));
  aes_set_key(key, SCP_KEY_LEN, &aes_ctx);
  aes_cmac_init(&aes_ctx, &cmac_ctx);
  aes_cmac_encrypt(&cmac_ctx, (uint8_t *) &mac_msg, macced_data_len, mac);

  aes_cmac_destroy(&cmac_ctx);
  aes_destroy(&aes_ctx);

  return true;
}

static void process_msg(Msg *msg, Msg *response) {
  aes_context aes_ctx;
  memset(&aes_ctx, 0, sizeof(aes_ctx));

  msg->st.len = ntohs(msg->st.len);

  switch (msg->st.cmd) {

    case YHC_CREATE_SESSION: {
      /* The data (i.e. msg->st.data) associated with a create session request
       * is authentication key ID   -> first SCP_AUTHKEY_ID_LEN bytes host
       * challenge          -> the rest of the msg->st.len bytes See also
       * yh_begin_create_session().
       */
      if (msg->st.len < SCP_AUTHKEY_ID_LEN) {
        response->st.cmd = YHC_ERROR;
        break;
      }

      // Check if a new session can be created or we reached the max number of
      // open sessions.
      int session_id = get_free_session_slot();
      if (session_id < 0) {
        response->st.cmd = YHC_ERROR;
        break;
      }

      uint16_t host_challenge_len;
      host_challenge_len = msg->st.len - SCP_AUTHKEY_ID_LEN;

      /* Setting up the session context used later on to calculate the card
       * cryptogram. See also yh_begin_create_session(). The session context
       * contains the host challenge the card challenge (assumed 0s here)
       */
      uint8_t session_context[2 * YH_EC_P256_PUBKEY_LEN] = {0};
      if (host_challenge_len > sizeof(session_context)) {
        response->st.cmd = YHC_ERROR;
        break;
      }
      memcpy(session_context, msg->st.data + SCP_AUTHKEY_ID_LEN,
             host_challenge_len);

      // Derive the SCP context s_env, s_mac and s_rmac keys.
      compute_cryptogram(key_enc, SCP_KEY_LEN, SCP_S_ENC_DERIVATION,
                         session_context, SCP_KEY_LEN * 8,
                         sessions[session_id].s_enc);
      compute_cryptogram(key_mac, SCP_KEY_LEN, SCP_S_MAC_DERIVATION,
                         session_context, SCP_KEY_LEN * 8,
                         sessions[session_id].s_mac);
      compute_cryptogram(key_mac, SCP_KEY_LEN, SCP_S_RMAC_DERIVATION,
                         session_context, SCP_KEY_LEN * 8,
                         sessions[session_id].s_rmac);

      /* Calculation of the card cryptogram.
       *    type    = SCP_CARD_CRYPTOGRAM
       *    L       = SCP_CARD_CRYPTO_LEN * 8
       *    context = the session context
       */
      uint8_t calculated_card_cryptogram[SCP_PRF_LEN];
      compute_cryptogram(sessions[session_id].s_mac, SCP_KEY_LEN,
                         SCP_CARD_CRYPTOGRAM, session_context,
                         SCP_CARD_CRYPTO_LEN * 8, calculated_card_cryptogram);

      /* The expected response is
       *    session id                - 1 byte
       *    the card challenge        - SCP_CARD_CHAL_LEN
       *    the resulting cryptogram  - SCP_CARD_CRYPTO_LEN
       */
      response->st.cmd = YHC_CREATE_SESSION_R;
      response->st.len = 1 + SCP_CARD_CHAL_LEN + SCP_CARD_CRYPTO_LEN;
      response->st.data[0] = session_id;
      memcpy(response->st.data + 1 + SCP_CARD_CHAL_LEN,
             calculated_card_cryptogram, SCP_CARD_CRYPTO_LEN);

      init_sessions[session_id] = 1;

      break;
    }

    case YHC_AUTHENTICATE_SESSION: {
      int session_id = msg->st.data[0];
      uint8_t mac[SCP_PRF_LEN] = {0};

      if (is_session_slot_initialized(session_id) == 0) {
        response->st.cmd = YHC_ERROR;
        break;
      }
      Scp_ctx *s = &sessions[session_id];

      if (!compute_mac(s, s->s_mac, msg, 3 + msg->st.len - SCP_MAC_LEN, 1,
                       mac)) {
        response->st.cmd = YHC_ERROR;
        break;
      }
      // update the session mac chaining value
      memcpy(s->mac_chaining_value, mac, SCP_PRF_LEN);

      if (memcmp(mac, &msg->st.data[msg->st.len - SCP_MAC_LEN], SCP_MAC_LEN)) {
        DBG_ERR("invalid mac during YHC_AUTHENTICATE_SESSION");
      }

      response->st.cmd = YHC_AUTHENTICATE_SESSION_R;
      response->st.len = SCP_MAC_LEN;
      compute_mac(s, s->s_rmac, response, 3, 1, mac);

      // copy the mac into the response struct and update the length
      memcpy(response->st.data, mac, SCP_MAC_LEN);

      increment_ctr(s->ctr, SCP_PRF_LEN);

      break;
    }

    case YHC_CLOSE_SESSION: {
      if (current_session_id != -1 &&
          is_session_slot_initialized(current_session_id) == 0) {
        response->st.cmd = YHC_ERROR;
        break;
      }

      memset(&sessions[current_session_id], 0, sizeof(Scp_ctx));
      init_sessions[current_session_id] = 0;

      response->st.cmd = YHC_CLOSE_SESSION_R;

      break;
    }

    case YHC_SESSION_MESSAGE: {
      uint8_t encrypted_ctr[AES_BLOCK_SIZE] = {0};
      Msg inner_msg, inner_response;
      uint8_t mac[SCP_PRF_LEN] = {0};
      uint16_t inner_response_padded_len = {0};

      memset(&inner_msg, 0, sizeof(inner_msg));
      memset(&inner_response, 0, sizeof(inner_response));

      current_session_id = msg->st.data[0];
      if (is_session_slot_initialized(current_session_id) == 0) {
        response->st.cmd = YHC_ERROR;
        break;
      }
      Scp_ctx *s = &sessions[current_session_id];

      if (compute_mac(s, s->s_mac, msg, 3 + msg->st.len - SCP_MAC_LEN, 1,
                      mac) == false) {
        response->st.cmd = YHC_ERROR;
        break;
      }
      // update the session mac chaining value
      memcpy(s->mac_chaining_value, mac, SCP_PRF_LEN);

      if (memcmp(mac, &msg->st.data[msg->st.len - SCP_MAC_LEN], SCP_MAC_LEN)) {
        DBG_ERR("invalid mac during YHC_AUTHENTICATE_SESSION");
      }

      aes_set_key(s->s_enc, SCP_KEY_LEN, &aes_ctx);
      aes_encrypt(s->ctr, encrypted_ctr, &aes_ctx);
      increment_ctr(s->ctr, SCP_PRF_LEN);

      // decrypt the message
      aes_cbc_decrypt(msg->st.data + 1, inner_msg.raw,
                      msg->st.len - SCP_MAC_LEN - 1, encrypted_ctr, &aes_ctx);

      /* recursive call to process the inner message
       *
       * if the inner_msg has command YHC_CLOSE_SESSION, then the
       * session object will be zeroed and we will lose access to
       * the associated key material, and the call to compute_mac
       * will fail.
       *
       * for that situation, we should cache the session object before
       * processing the YHC_CLOSE_SESSION command.
       */
      Scp_ctx saved_session;
      memcpy(&saved_session, s, sizeof(Scp_ctx));
      process_msg(&inner_msg, &inner_response);

      // set the response type
      response->st.cmd = YHC_SESSION_MESSAGE_R;

      // copy over the session id to the expected value
      response->st.data[0] = msg->st.data[0];

      // encrypt the inner response
      inner_response_padded_len = ntohs(inner_response.st.len) + 3;
      aes_add_padding(inner_response.raw, sizeof(inner_response.raw),
                      &inner_response_padded_len);
      aes_cbc_encrypt(inner_response.raw, response->st.data + 1,
                      inner_response_padded_len, encrypted_ctr, &aes_ctx);
      response->st.len = 1 + inner_response_padded_len;

      aes_destroy(&aes_ctx);

      // authenticate the response
      response->st.len += SCP_MAC_LEN;
      if (response->st.len + 3 > sizeof(Msg)) {
        // there is no place to add the mac at the end of the message
        response->st.cmd = YHC_ERROR;
        break;
      }

      if (compute_mac(&saved_session, saved_session.s_rmac, response,
                      3 + response->st.len - SCP_MAC_LEN, 1, mac) == false) {
        response->st.cmd = YHC_ERROR;
        break;
      }

      // copy the mac into the response struct and update the length
      memcpy(response->st.data + response->st.len - SCP_MAC_LEN, mac,
             SCP_MAC_LEN);

      current_session_id = -1;
      break;
    }

    default:
      /* inner messages such as YHC_GENERATE_ASYMMETRIC_KEY
       * here put some fuzzer data which gets decrypted and processed on the
       * host side
       */
      std::vector<uint8_t> size_byte = fuzz_data->ConsumeBytes<uint8_t>(1);

      if (size_byte.empty()) {
        response->st.len = 0;
      } else if (size_byte[0] > SCP_MSG_BUF_SIZE - 32) {
        response->st.len = 0;
      } else {
        vector<uint8_t> bytes = fuzz_data->ConsumeBytes<uint8_t>(size_byte[0]);
        response->st.len = bytes.size();
        if (!bytes.empty()) {
          memcpy(response->st.data, bytes.data(), response->st.len);
        }
      }
      break;
  }

  response->st.len = htons(response->st.len);
}

static void fuzz_backend_set_verbosity(uint8_t verbosity, FILE *output) {
  _yh_verbosity = verbosity;
  _yh_output = output;
}

static yh_rc fuzz_backend_init(uint8_t verbosity, FILE *output) {
  fuzz_backend_set_verbosity(verbosity, output);

  uint8_t keys[2 * SCP_KEY_LEN];
  pkcs5_pbkdf2_hmac((const uint8_t *) FUZZ_BACKEND_PASSWORD,
                    strlen(FUZZ_BACKEND_PASSWORD),
                    (const uint8_t *) YH_DEFAULT_SALT, strlen(YH_DEFAULT_SALT),
                    YH_DEFAULT_ITERS, _SHA256, keys, sizeof(keys));

  memcpy(key_enc, keys, SCP_KEY_LEN);
  memcpy(key_mac, keys + SCP_KEY_LEN, SCP_KEY_LEN);

  return YHR_SUCCESS;
}

static yh_backend *fuzz_backend_create(void) {
  yh_backend *backend = (yh_backend *) calloc(1, sizeof(yh_backend));
  return backend;
}

static yh_rc fuzz_backend_connect(yh_connector *connector, int timeout) {
  (void) connector;
  (void) timeout;

  connector->has_device = 1;

  return YHR_SUCCESS;
}

static void fuzz_backend_disconnect(yh_backend *connection) {
  free(connection);
}

static yh_rc fuzz_backend_send_msg(yh_backend *connection, Msg *msg,
                                   Msg *response, const char *identifier) {
  (void) connection;
  (void) identifier;

  memset(response->raw, 0, sizeof(response->raw));

  process_msg(msg, response);

  return YHR_SUCCESS;
}

static void fuzz_backend_cleanup(void) {}

static yh_rc fuzz_backend_option(yh_backend *connection,
                                 yh_connector_option opt, const void *val) {
  (void) connection;
  (void) opt;
  (void) val;
  return YHR_CONNECTOR_ERROR;
}

static struct backend_functions f =
  {fuzz_backend_init,       fuzz_backend_create,       fuzz_backend_connect,
   fuzz_backend_disconnect, fuzz_backend_send_msg,     fuzz_backend_cleanup,
   fuzz_backend_option,     fuzz_backend_set_verbosity};

#ifdef STATIC
extern "C" struct backend_functions *fuzz_backend_functions(void) {
#else
extern "C" struct backend_functions *backend_functions(void) {
#endif
  return &f;
}
