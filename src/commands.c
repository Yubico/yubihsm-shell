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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "yubihsm-shell.h"
#include "../common/insecure_memzero.h"
#include "../common/parsing.h"
#include "time_win.h"

#include "hash.h"
#include "util.h"
#include "openssl-compat.h"

#ifdef __WIN32
#include <winsock.h>
#include <openssl/applink.c>
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#endif

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <time.h>

#ifdef _MSVC
#define gettimeofday(a, b) gettimeofday_win(a)
#endif

static format_t fmt_to_fmt(cmd_format fmt) {
  switch (fmt) {
    case fmt_base64:
      return _base64;
    case fmt_binary:
      return _binary;
    case fmt_hex:
      return _hex;
    case fmt_PEM:
      return _PEM;
    default:
      return 0;
  }
}

// NOTE(adma): Extract log entries
// argc = 1
// arg 0: e:session
int yh_com_audit(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                 cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  uint16_t unlogged_boot = 0;
  uint16_t unlogged_auth = 0;
  yh_log_entry logs[YH_MAX_LOG_ENTRIES];
  size_t n_items = sizeof(logs) / sizeof(logs[0]);

  switch (fmt) {
    case fmt_binary:
    case fmt_PEM:
    case fmt_base64:
    case fmt_password:
      fprintf(stderr,
              "The selected output format is not supported for this operation. "
              "Supported format are \"ASCII\", \"hex\" and \"default\"\n");
      return -1;

    default:
      break;
  }

  yrc = yh_util_get_log_entries(argv[0].e, &unlogged_boot, &unlogged_auth, logs,
                                &n_items);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get logs: %s\n", yh_strerror(yrc));
    return -1;
  }

  char digest_buf[(2 * YH_LOG_DIGEST_SIZE) + 1];

  switch (fmt) {
    case fmt_hex:
      fprintf(ctx->out, "%04x%04x", unlogged_boot, unlogged_auth);
      for (size_t i = 0; i < n_items; i++) {
        format_digest(logs[i].digest, digest_buf, YH_LOG_DIGEST_SIZE);
        fprintf(ctx->out, "%04x%02x%04x%04x%04x%04x%02x%08lx%s", logs[i].number,
                logs[i].command, logs[i].length, logs[i].session_key,
                logs[i].target_key, logs[i].second_key, logs[i].result,
                (unsigned long) logs[i].systick, digest_buf);
      }
      fprintf(ctx->out, "\n");
      break;

    case fmt_ASCII:
    default:
      fprintf(ctx->out, "%d unlogged boots found\n", unlogged_boot);
      fprintf(ctx->out, "%d unlogged authentications found\n", unlogged_auth);

      if (n_items == 0) {
        fprintf(ctx->out, "No logs to extract\n");
        return 0;
      } else if (n_items == 1) {
        fprintf(ctx->out, "Found 1 item\n");
      } else {
        fprintf(ctx->out, "Found %zu items\n", n_items);
      }

      for (size_t i = 0; i < n_items; i++) {
        format_digest(logs[i].digest, digest_buf, YH_LOG_DIGEST_SIZE);
        fprintf(ctx->out,
                "item: %5u -- cmd: 0x%02x -- length: %4u -- session key: "
                "0x%04x -- target key: 0x%04x -- second key: 0x%04x -- "
                "result: 0x%02x -- tick: %lu -- hash: %s\n",
                logs[i].number, logs[i].command, logs[i].length,
                logs[i].session_key, logs[i].target_key, logs[i].second_key,
                logs[i].result, (unsigned long) logs[i].systick, digest_buf);
      }
      break;
  }

  return 0;
}

// NOTE: Set the log index
// argc = 2
// arg 0: e:session
// arg 1: w:index
int yh_com_set_log_index(yubihsm_context *ctx, Argument *argv,
                         cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc = yh_util_set_log_index(argv[0].e, argv[1].w);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to set log index: %s\n", yh_strerror(yrc));
    return -1;
  }

  return 0;
}

// NOTE: Blink the device
// argc = 2
// arg 0: e:session
// arg 1: b:seconds
int yh_com_blink(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                 cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);
  UNUSED(ctx);

  yh_rc yrc = yh_util_blink_device(argv[0].e, argv[1].b);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to blink the device: %s\n", yh_strerror(yrc));
    return -1;
  }

  return 0;
}

// NOTE(adma): Close a session with a connector
// argc = 1
// arg 0: e:session
int yh_com_close_session(yubihsm_context *ctx, Argument *argv,
                         cmd_format in_fmt, cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);
  uint8_t session_id = 0;

  yh_rc yrc = yh_get_session_id(argv[0].e, &session_id);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get session id: %s\n", yh_strerror(yrc));
    return -1;
  }

  yrc = yh_util_close_session(argv[0].e);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to close session: %s\n", yh_strerror(yrc));
    return -1;
  }

  yrc = yh_destroy_session(&argv[0].e);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to destroy session: %s\n", yh_strerror(yrc));
    return -1;
  }

  ctx->sessions[session_id] = NULL;

  return 0;
}

// NOTE(adma): Connect to a connector
// argc = 0
int yh_com_connect(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                   cmd_format fmt) {

  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  ctx->connector = NULL;

  for (int i = 0; ctx->connector_list[i]; i++) {
    if (ctx->connector) {
      yh_disconnect(ctx->connector);
      ctx->connector = NULL;
    }
    yh_rc yrc = yh_init_connector(ctx->connector_list[i], &ctx->connector);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed initializing connector %s: %s\n",
              ctx->connector_list[i], yh_strerror(yrc));
      break;
    }
    if (ctx->cacert) {
      if (yh_set_connector_option(ctx->connector, YH_CONNECTOR_HTTPS_CA,
                                  ctx->cacert) != YHR_SUCCESS) {
        fprintf(stderr, "Failed setting HTTPS CA\n");
        break;
      }
    }
    if (ctx->proxy) {
      if (yh_set_connector_option(ctx->connector, YH_CONNECTOR_PROXY_SERVER,
                                  ctx->proxy) != YHR_SUCCESS) {
        fprintf(stderr, "Failed setting proxy server\n");
        break;
      }
    }
    yrc = yh_connect(ctx->connector, 0);
    if (yrc == YHR_SUCCESS) {
      (void) yh_com_keepalive_on(NULL, NULL, fmt_nofmt, fmt_nofmt);
      return 0;
    }
    fprintf(stderr, "Failed connecting '%s': %s\n", ctx->connector_list[i],
            yh_strerror(yrc));
  }

  if (ctx->connector) {
    yh_disconnect(ctx->connector);
    ctx->connector = NULL;
  }
  return -1;
}

// NOTE(adma): Enable all debug messages
// argc = 0
int yh_com_debug_all(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                     cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_set_verbosity(ctx->connector, YH_VERB_ALL);
  fprintf(stderr, "Debug messages enabled\n");

  return 0;
}

// NOTE(adma): Toggle debug messages
// argc = 0
int yh_com_debug_error(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  uint8_t yh_verbosity;

  yh_get_verbosity(&yh_verbosity);
  yh_verbosity ^= YH_VERB_ERR;

  if (yh_verbosity & YH_VERB_ERR)
    fprintf(stderr, "Error messages on\n");
  else
    fprintf(stderr, "Error messages off\n");

  yh_set_verbosity(ctx->connector, yh_verbosity);

  return 0;
}

// NOTE(adma): Toggle debug messages
// argc = 0
int yh_com_debug_info(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  uint8_t yh_verbosity;

  yh_get_verbosity(&yh_verbosity);
  yh_verbosity ^= YH_VERB_INFO;

  if (yh_verbosity & YH_VERB_INFO)
    fprintf(stderr, "Info messages on\n");
  else
    fprintf(stderr, "Info messages off\n");

  yh_set_verbosity(ctx->connector, yh_verbosity);

  return 0;
}

// NOTE(adma): Toggle debug messages
// argc = 0
int yh_com_debug_intermediate(yubihsm_context *ctx, Argument *argv,
                              cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  uint8_t yh_verbosity;

  yh_get_verbosity(&yh_verbosity);
  yh_verbosity ^= YH_VERB_INTERMEDIATE;

  if (yh_verbosity & YH_VERB_INTERMEDIATE)
    fprintf(stderr, "Intermediate messages on\n");
  else
    fprintf(stderr, "Intermediate messages off\n");

  yh_set_verbosity(ctx->connector, yh_verbosity);

  return 0;
}

// NOTE(adma): Toggle debug messages
// argc = 0
int yh_com_debug_none(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_set_verbosity(ctx->connector, YH_VERB_QUIET);
  fprintf(stderr, "Debug messages disabled\n");

  return 0;
}

// NOTE(adma): Toggle debug messages
// argc = 0
int yh_com_debug_raw(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                     cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  uint8_t yh_verbosity;

  yh_get_verbosity(&yh_verbosity);
  yh_verbosity ^= YH_VERB_RAW;

  if (yh_verbosity & YH_VERB_RAW)
    fprintf(stderr, "Raw messages on\n");
  else
    fprintf(stderr, "Raw messages off\n");

  yh_set_verbosity(ctx->connector, yh_verbosity);

  return 0;
}

// NOTE(adma): Toggle debug messages
// argc = 0
int yh_com_debug_crypto(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                        cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  uint8_t yh_verbosity;

  yh_get_verbosity(&yh_verbosity);
  yh_verbosity ^= YH_VERB_CRYPTO;

  if (yh_verbosity & YH_VERB_CRYPTO)
    fprintf(stderr, "Crypto messages on\n");
  else
    fprintf(stderr, "Crypto messages off\n");

  yh_set_verbosity(ctx->connector, yh_verbosity);

  return 0;
}

// NOTE(adma): Decrypt data
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:data
int yh_com_decrypt_pkcs1v1_5(yubihsm_context *ctx, Argument *argv,
                             cmd_format in_fmt, cmd_format fmt) {

  yh_rc yrc;

  UNUSED(in_fmt);
  UNUSED(ctx);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yrc = yh_util_decrypt_pkcs1v1_5(argv[0].e, argv[1].w, argv[2].x, argv[2].len,
                                  response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to decrypt data: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE: Do a ECDH key exchange
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:pubkey
int yh_com_derive_ecdh(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(ctx);

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    return false;
  }

  (void) BIO_write(bio, argv[2].x, argv[2].len);

  EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if (pubkey == NULL) {
    fprintf(stderr, "Failed to load public key\n");
    return -1;
  }
  if (EVP_PKEY_base_id(pubkey) != EVP_PKEY_EC) {
    EVP_PKEY_free(pubkey);
    fprintf(stderr, "Key is not an EC key.\n");
    return -1;
  }

  EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pubkey);
  EVP_PKEY_free(pubkey);
  if (ec == NULL) {
    fprintf(stderr, "Failed to retrive key.\n");
    return -1;
  }

  uint8_t data[YH_MSG_BUF_SIZE];
  uint8_t *ptr = data;
  size_t data_len = i2o_ECPublicKey(ec, &ptr);

  EC_KEY_free(ec);

  yh_rc yrc;
  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yrc = yh_util_derive_ecdh(argv[0].e, argv[1].w, data, data_len, response,
                            &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to do key exchange: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE: Decrypt data
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:data
int yh_com_decrypt_aesccm(yubihsm_context *ctx, Argument *argv,
                          cmd_format in_fmt, cmd_format fmt) {
  yh_rc yrc;

  UNUSED(in_fmt);
  UNUSED(ctx);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yrc = yh_util_unwrap_data(argv[0].e, argv[1].w, argv[2].x, argv[2].len,
                            response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to decrypt data: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE: Encrypt data
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:data
int yh_com_encrypt_aesccm(yubihsm_context *ctx, Argument *argv,
                          cmd_format in_fmt, cmd_format fmt) {
  yh_rc yrc;

  UNUSED(in_fmt);
  UNUSED(ctx);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yrc = yh_util_wrap_data(argv[0].e, argv[1].w, argv[2].x, argv[2].len,
                          response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to encrypt data: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): Disconnect from a connector
// argc = 0
int yh_com_disconnect(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  for (size_t i = 0; i < sizeof(ctx->sessions) / sizeof(ctx->sessions[0]);
       i++) {
    if (ctx->sessions[i]) {
      yrc = yh_util_close_session(ctx->sessions[i]);
      if (yrc != YHR_SUCCESS) {
        fprintf(stderr, "Failed to close session: %s\n", yh_strerror(yrc));
      }
      yrc = yh_destroy_session(&ctx->sessions[i]);
      if (yrc != YHR_SUCCESS) {
        fprintf(stderr, "Failed to destroy session: %s\n", yh_strerror(yrc));
      }
      ctx->sessions[i] = NULL;
    }
  }

  if (ctx->connector) {
    yrc = yh_disconnect(ctx->connector);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Unable to disconnect: %s\n", yh_strerror(yrc));
      return -1;
    }
    ctx->connector = NULL;
  }

  return 0;
}

// NOTE(adma): Send authenticated echo
// argc = 3
// arg 0: e:session
// arg 1: b:byte
// arg 2: w:count
int yh_com_echo(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  uint8_t data[YH_MSG_BUF_SIZE];
  uint16_t data_len;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len;
  yh_cmd response_cmd;

  uint8_t byte = argv[1].b;

  uint16_t count = argv[2].w;
  if (count > YH_MSG_BUF_SIZE) {
    fprintf(stderr, "Count must be in [0, %d]\n", YH_MSG_BUF_SIZE);
    return -1;
  }

  memset(data, byte, count);

  data_len = count;
  response_len = sizeof(response);

  yrc = yh_send_secure_msg(argv[0].e, YHC_ECHO, data, data_len, &response_cmd,
                           response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to send ECHO command: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(ctx->out, "Response (%zu bytes):\n", response_len);
  for (size_t i = 0; i < response_len; i++) {
    if (i && !(i % 64))
      fprintf(ctx->out, "\n");
    else if (i && !(i % 8))
      fprintf(ctx->out, " ");
    fprintf(ctx->out, "%02x", response[i]);
  }

  fprintf(ctx->out, "\n");

  return 0;
}

// NOTE(adma): Generate an Asymmetric Key
// argc = 6
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: a:algorithm
int yh_com_generate_asymmetric(yubihsm_context *ctx, Argument *argv,
                               cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  if (yh_is_rsa(argv[5].a)) {
    yrc = yh_util_generate_rsa_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                   &argv[4].c, argv[5].a);
  } else if (yh_is_ec(argv[5].a)) {
    yrc = yh_util_generate_ec_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, argv[5].a);
  } else if (yh_is_ed(argv[5].a)) {
    yrc = yh_util_generate_ed_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, argv[5].a);
  } else {
    fprintf(stderr, "Invalid algorithm %d\n", argv[5].a);
    return -1;
  }

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to generate asymmetric key: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Generated Asymmetric key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE: Generate HMAC key
// argc = 6
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: a:algorithm
int yh_com_generate_hmac(yubihsm_context *ctx, Argument *argv,
                         cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  if (!yh_is_hmac(argv[5].a)) {
    fprintf(stderr, "Invalid algorithm: %d\n", argv[5].a);
    return -1;
  }

  yrc = yh_util_generate_hmac_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, argv[5].a);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to generate HMAC key: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Generated HMAC key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE: Generate wrap key
// argc = 6
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: c:delegated_capabilities
// arg 6: a:algorithm
int yh_com_generate_wrap(yubihsm_context *ctx, Argument *argv,
                         cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  yrc = yh_util_generate_wrap_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, argv[6].a, &argv[5].c);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to generate wrapping key: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Generated Wrap key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE(adma): Get an opaque object
// argc = 2
// arg 0: e:session,
// arg 1: w:object_id
// arg 2: F:file
int yh_com_get_opaque(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);
  int ret = -1;

  yh_rc yrc = yh_util_get_opaque(argv[0].e, argv[1].w, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get opaque object: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (fmt == fmt_PEM) {
    const unsigned char *ptr = response;
    X509 *x509 = d2i_X509(NULL, &ptr, response_len);
    if (!x509) {
      fprintf(stderr, "Failed parsing x509 information\n");
    } else {
      if (PEM_write_X509(ctx->out, x509) == 1) {
        ret = 0;
      } else {
        fprintf(stderr, "Failed writing x509 information\n");
      }
    }
    X509_free(x509);
  } else {
    if (write_file(response, response_len, ctx->out, fmt_to_fmt(fmt))) {
      ret = 0;
    }
  }

  return ret;
}

// NOTE(adma): Get a global option value
// argc = 2
// arg 0: o:session
// arg 1: s:option
int yh_com_get_option(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yrc = yh_util_get_option(argv[0].e, argv[1].o, response, &response_len);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get option: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(ctx->out, "Option value is: ");
  for (size_t i = 0; i < response_len; i++) {
    fprintf(ctx->out, "%02x", response[i]);
  }
  fprintf(ctx->out, "\n");

  return 0;
}

// NOTE(adma): Get pseudo-random bytes
// argc = 2
// arg 0: e:session
// arg 1: w:count
int yh_com_get_random(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(in_fmt);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yh_rc yrc =
    yh_util_get_pseudo_random(argv[0].e, argv[1].w, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get pseudo random bytes: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  if (response_len != argv[1].w) {
    fprintf(stderr, "Wrong response length\n");
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): Obtain storage information
// argc = 1
// arg 0: e:session
int yh_com_get_storage(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;
  uint16_t total_records, free_records, free_pages, total_pages, page_size;
  total_records = free_records = free_pages = total_pages = page_size = 0;

  yrc = yh_util_get_storage_info(argv[0].e, &total_records, &free_records,
                                 &total_pages, &free_pages, &page_size);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get storage stats: %s\n", yh_strerror(yrc));
    return -1;
  }
  fprintf(stderr,
          "free records: %d/%d, free pages: %d/%d page size: %d bytes\n",
          free_records, total_records, free_pages, total_pages, page_size);
  return 0;
}

// NOTE: Get public key
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: f:filename
int yh_com_get_pubkey(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(in_fmt);

  yh_rc yrc;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yh_algorithm algo;
  EVP_PKEY *public_key = NULL;

  yrc = yh_util_get_public_key(argv[0].e, argv[1].w, response, &response_len,
                               &algo);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get public key: %s\n", yh_strerror(yrc));
    return -1;
  }

  public_key = EVP_PKEY_new();
  if (public_key == NULL) {
    fprintf(stderr, "Failed to create public key\n");
    return -1;
  }

  if (yh_is_rsa(algo)) {
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
      fprintf(stderr, "Failed to create RSA key\n");
      return -1;
    }
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_bin2bn(response, response_len, NULL);
    BN_hex2bn(&e, "10001");
    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
      fprintf(stderr, "Failed to set RSA key\n");
      RSA_free(rsa);
      return -1;
    }
    if (EVP_PKEY_set1_RSA(public_key, rsa) != 1) {
      fprintf(stderr, "Failed to set RSA key\n");
      RSA_free(rsa);
      return -1;
    }
    RSA_free(rsa);
  } else if (yh_is_ec(algo)) {
    bool error = false;
    EC_KEY *eckey = EC_KEY_new();
    if (eckey == NULL) {
      fprintf(stderr, "Failed to create EC key\n");
      return -1;
    }
    int nid = algo2nid(algo);
    EC_POINT *point = NULL;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
      fprintf(stderr, "Failed to create EC group from curve name\n");
      error = true;
      goto ec_cleanup;
    }

    EC_GROUP_set_asn1_flag(group, nid);
    if (EC_KEY_set_group(eckey, group) != 1) {
      fprintf(stderr, "Failed to set EC group\n");
      error = true;
      goto ec_cleanup;
    }
    point = EC_POINT_new(group);

    memmove(response + 1, response, response_len);
    response[0] = 0x04; // hack to make it a valid ec pubkey..
    response_len++;

    if (EC_POINT_oct2point(group, point, response, response_len, NULL) != 1) {
      fprintf(stderr, "Failed to parse EC point\n");
      error = true;
      goto ec_cleanup;
    }

    if (EC_KEY_set_public_key(eckey, point) != 1) {
      fprintf(stderr, "Failed to set EC public key\n");
      error = true;
      goto ec_cleanup;
    }

    if (EVP_PKEY_set1_EC_KEY(public_key, eckey) != 1) {
      fprintf(stderr, "Failed to set EC public key\n");
      error = true;
    }
  ec_cleanup:
    if (point != NULL) {
      EC_POINT_free(point);
    }
    if (eckey != NULL) {
      EC_KEY_free(eckey);
    }
    if (group != NULL) {
      EC_GROUP_free(group);
    }
    if (error) {
      return -1;
    }
  } else {
    // NOTE(adma): ED25519, there is (was) no support for this in
    // OpenSSL, so we manually export them
    EVP_PKEY_free(public_key);
    if (write_ed25519_key(response, response_len, ctx->out, fmt_to_fmt(fmt)) ==
        false) {
      fprintf(stderr, "Unable to format ed25519 key\n");
      return -1;
    }
    return 0;
  }

  if (fmt == fmt_PEM) {
    if (PEM_write_PUBKEY(ctx->out, public_key) != 1) {
      fprintf(stderr, "Failed to write public key in PEM format\n");
      EVP_PKEY_free(public_key);
      return -1;
    }
  } else if (fmt == fmt_binary) {
    i2d_PUBKEY_fp(ctx->out, public_key);
  } else if (fmt == fmt_base64) {
    BIO *bio;
    BIO *b64;
    bool error = false;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
      fprintf(stderr, "Unable to allocate buffer\n");
      error = true;
      goto getpk_base64_cleanup;
    }

    bio = BIO_new_fp(ctx->out, BIO_NOCLOSE);
    if (bio == NULL) {
      fprintf(stderr, "Unable to allocate BIO\n");
      BIO_free_all(b64);
      error = true;
      goto getpk_base64_cleanup;
    }

    bio = BIO_push(b64, bio);

    (void) i2d_PUBKEY_bio(bio, public_key);

    (void) BIO_flush(bio);
    (void) BIO_free_all(bio);
  getpk_base64_cleanup:
    if (error) {
      EVP_PKEY_free(public_key);
      return -1;
    }
  } // FIXME: other formats or error.
  EVP_PKEY_free(public_key);

  return 0;
}

#ifdef USE_ASYMMETRIC_AUTH
// NOTE: Get device public key
// argc = 0
int yh_com_get_device_pubkey(yubihsm_context *ctx, Argument *argv,
                             cmd_format in_fmt, cmd_format fmt) {
  UNUSED(argv);
  UNUSED(in_fmt);

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yh_algorithm algo;
  yh_rc yrc =
    yh_util_get_device_pubkey(ctx->connector, response, &response_len, &algo);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get device pubkey: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (fmt == fmt_hex) {
    for (size_t i = 0; i < response_len; i++) {
      fprintf(ctx->out, "%02x", response[i]);
    }
    fprintf(ctx->out, "\n");
    return 0;
  }

  int nid = algo2nid(algo);
  EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
  if (group == NULL) {
    fprintf(stderr, "Invalid device public key algorithm\n");
    return -1;
  }
  EC_GROUP_set_asn1_flag(group, nid);

  EC_KEY *eckey = EC_KEY_new();
  EC_KEY_set_group(eckey, group);

  EC_POINT *point = EC_POINT_new(group);
  EC_POINT_oct2point(group, point, response, response_len, NULL);
  EC_KEY_set_public_key(eckey, point);

  EVP_PKEY *public_key = EVP_PKEY_new();
  EVP_PKEY_set1_EC_KEY(public_key, eckey);

  EC_POINT_free(point);
  EC_KEY_free(eckey);
  EC_GROUP_free(group);

  if (fmt == fmt_PEM) {
    PEM_write_PUBKEY(ctx->out, public_key);
  } else if (fmt == fmt_binary) {
    i2d_PUBKEY_fp(ctx->out, public_key);
  } else if (fmt == fmt_base64) {
    BIO *bio;
    BIO *b64;
    bool error = false;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
      fprintf(stderr, "Unable to allocate buffer\n");
      error = true;
      goto getdpk_base64_cleanup;
    }

    bio = BIO_new_fp(ctx->out, BIO_NOCLOSE);
    if (bio == NULL) {
      fprintf(stderr, "Unable to allocate BIO\n");
      BIO_free_all(b64);
      error = true;
      goto getdpk_base64_cleanup;
    }

    bio = BIO_push(b64, bio);

    (void) i2d_PUBKEY_bio(bio, public_key);

    (void) BIO_flush(bio);
    (void) BIO_free_all(bio);
  getdpk_base64_cleanup:
    if (error) {
      EVP_PKEY_free(public_key);
      return -1;
    }
  } // FIXME: other formats or error.
  EVP_PKEY_free(public_key);

  return 0;
}
#endif

// NOTE: Get object information
// argc = 3
// arg 0: e:session
// arg 1: w:id
// arg 2: t:type
int yh_com_get_object_info(yubihsm_context *ctx, Argument *argv,
                           cmd_format in_fmt, cmd_format fmt) {
  yh_rc yrc;
  yh_object_descriptor object;

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yrc = yh_util_get_object_info(argv[0].e, argv[1].w, argv[2].b, &object);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get object info: %s\n", yh_strerror(yrc));
    return -1;
  }

  char domains[256] = {0};
  const char *cap[sizeof(yh_capability) / sizeof(yh_capability[0])];
  size_t n_cap = sizeof(yh_capability) / sizeof(yh_capability[0]);
  const char *type;
  const char *algorithm = "";
  const char *extra_algo = "";
  char *label = object.label;
  size_t label_len = strlen(label);
  yh_type_to_string(object.type, &type);
  if (object.algorithm) {
    yh_algo_to_string(object.algorithm, &algorithm);
    extra_algo = ", algorithm: ";
  }
  yh_domains_to_string(object.domains, domains, 255);

  for (size_t i = 0; i < label_len; i++) {
    if (isprint(label[i]) == 0) {
      label[i] = '.';
    }
  }

  fprintf(ctx->out,
          "id: 0x%04x, type: %s%s%s, label: \"%s\", length: %d, "
          "domains: %s, sequence: %hhu, origin: ",
          object.id, type, extra_algo, algorithm, label, object.len, domains,
          object.sequence);

  if (object.origin & YH_ORIGIN_GENERATED) {
    fprintf(ctx->out, "generated");
  }
  if (object.origin & YH_ORIGIN_IMPORTED) {
    fprintf(ctx->out, "imported");
  }
  if (object.origin & YH_ORIGIN_IMPORTED_WRAPPED) {
    fprintf(ctx->out, ":imported_wrapped");
  }

  fprintf(ctx->out, ", capabilities: ");
  if (yh_capabilities_to_strings(&object.capabilities, cap, &n_cap) !=
      YHR_SUCCESS) {
    for (size_t i = 0; i < YH_CAPABILITIES_LEN; i++) {
      fprintf(ctx->out, "0x%02x%s", object.capabilities.capabilities[i],
              i < YH_CAPABILITIES_LEN - 1 ? " " : "");
    }
  } else {
    for (size_t i = 0; i < n_cap; i++) {
      fprintf(ctx->out, "%s%s", cap[i], i < n_cap - 1 ? ":" : "");
    }
  }
  if (object.type == YH_WRAP_KEY || object.type == YH_AUTHENTICATION_KEY) {
    fprintf(ctx->out, ", delegated_capabilities: ");
    n_cap = sizeof(yh_capability) / sizeof(yh_capability[0]);
    if (yh_capabilities_to_strings(&object.delegated_capabilities, cap,
                                   &n_cap) != YHR_SUCCESS) {
      for (size_t i = 0; i < YH_CAPABILITIES_LEN; i++) {
        fprintf(ctx->out, "0x%02x%s",
                object.delegated_capabilities.capabilities[i],
                i < YH_CAPABILITIES_LEN - 1 ? " " : "");
      }
    } else {
      for (size_t i = 0; i < n_cap; i++) {
        fprintf(ctx->out, "%s%s", cap[i], i < n_cap - 1 ? ":" : "");
      }
    }
  }
  fprintf(ctx->out, "\n");

  return 0;
}

// NOTE: Get an object under wrap
// argc = 5
// arg 0: e:session
// arg 1: w:keyid
// arg 2: t:type
// arg 3: w:id
// arg 4: f:file
int yh_com_get_wrapped(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {
  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);
  yh_rc yrc;

  UNUSED(in_fmt);

  yrc = yh_util_export_wrapped(argv[0].e, argv[1].w, argv[2].b, argv[3].w,
                               response, &response_len);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get wrapped object: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (write_file(response, response_len, ctx->out, fmt_to_fmt(fmt))) {
    return 0;
  }

  return -1;
}

// NOTE(adma): Get a template object
// argc = 2
// arg 0: e:session,
// arg 1: w:object_id
int yh_com_get_template(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                        cmd_format fmt) {

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  UNUSED(in_fmt);

  yh_rc yrc =
    yh_util_get_template(argv[0].e, argv[1].w, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get template object: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): No operation command
// argc = 0
int yh_com_noop(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  return 0;
}

// NOTE(adma): List capabilities
// argc = 0
int yh_com_list_capabilities(yubihsm_context *ctx, Argument *argv,
                             cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  for (size_t i = 0; i < sizeof(yh_capability) / sizeof(yh_capability[0]);
       i++) {
    fprintf(ctx->out, "%-30s (%016llx)\n", yh_capability[i].name,
            1ULL << yh_capability[i].bit);
  }

  return 0;
}

// NOTE: List algorithms
// argc = 0
int yh_com_list_algorithms(yubihsm_context *ctx, Argument *argv,
                           cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  for (size_t i = 0; i < sizeof(yh_algorithms) / sizeof(yh_algorithms[0]);
       i++) {
    fprintf(ctx->out, "%s\n", yh_algorithms[i].name);
  }

  return 0;
}

// NOTE: List types
// argc = 0
int yh_com_list_types(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  for (uint16_t i = 0; i < sizeof(yh_types) / sizeof(yh_types[0]); i++) {
    fprintf(ctx->out, "%s\n", yh_types[i].name);
  }

  return 0;
}

// NOTE(adma): List sessions
// argc = 0
int yh_com_list_sessions(yubihsm_context *ctx, Argument *argv,
                         cmd_format in_fmt, cmd_format fmt) {

  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  for (size_t i = 0; i < sizeof(ctx->sessions) / sizeof(ctx->sessions[0]);
       i++) {
    if (ctx->sessions[i] != NULL) {
      fprintf(stderr, "Session %zu\n", i);
    }
  }

  return 0;
}

static int compare_objects(const void *p1, const void *p2) {
  const yh_object_descriptor *a = p1;
  const yh_object_descriptor *b = p2;

  return a->id - b->id;
}

// NOTE: List object according to a filter
// argc = 7
// arg 0: e:session
// arg 1: w:id
// arg 2: t:type
// arg 3: w:domains
// arg 4: u:capabilities
// arg 5: a:algorithm
// arg 6: s:label
int yh_com_list_objects(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                        cmd_format fmt) {
  yh_rc yrc;
  yh_object_descriptor objects[YH_MAX_ITEMS_COUNT];
  size_t num_objects = YH_MAX_ITEMS_COUNT;
  const char *label_arg;

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  if (argv[6].len == 0) {
    label_arg = NULL;
  } else {
    label_arg = argv[6].s;
  }

  yrc =
    yh_util_list_objects(argv[0].e, argv[1].w, argv[2].b, argv[3].w, &argv[4].c,
                         argv[5].a, label_arg, objects, &num_objects);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to list objects: %s\n", yh_strerror(yrc));
    return -1;
  }

  qsort(objects, num_objects, sizeof(yh_object_descriptor), compare_objects);

  fprintf(ctx->out, "Found %zu object(s)\n", num_objects);
  for (size_t i = 0; i < num_objects; i++) {
    const char *type = "";
    yh_type_to_string(objects[i].type, &type);
    fprintf(ctx->out, "id: 0x%04x, type: %s, sequence: %hhu\n", objects[i].id,
            type, objects[i].sequence);
  }
  return 0;
}

// NOTE(adma): Open a session with a connector using an Authentication Key
// argc = 2
// arg 0: w:authkey
// arg 1: i:password
int yh_com_open_session(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                        cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_session *ses = NULL;
  uint8_t session_id = 0;

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  yh_rc yrc = yh_create_session_derived(ctx->connector, argv[0].w, argv[1].x,
                                        argv[1].len, false, &ses);
  insecure_memzero(argv[1].x, argv[1].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  yrc = yh_authenticate_session(ses);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to authenticate session: %s\n", yh_strerror(yrc));
    return -1;
  }

  yrc = yh_get_session_id(ses, &session_id);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (ctx->sessions[session_id] != NULL) {
    yrc = yh_destroy_session(&ctx->sessions[session_id]);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to destroy old session with same id (%d): %s\n",
              session_id, yh_strerror(yrc));
      return -1;
    }
  }
  ctx->sessions[session_id] = ses;

  fprintf(stderr, "Created session %d\n", session_id);

  return 0;
}

#ifdef USE_ASYMMETRIC_AUTH
// NOTE: Open a session with a connector using an Asymmetric
// Authentication Key argc = 2 arg 0: w:authkey arg 1: i:password
int yh_com_open_session_asym(yubihsm_context *ctx, Argument *argv,
                             cmd_format in_fmt, cmd_format fmt) {

  UNUSED(fmt);

  yh_session *ses = NULL;
  uint8_t session_id = 0;

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  uint16_t authkey = argv[0].w;
  uint8_t privkey[YH_EC_P256_PRIVKEY_LEN];
  yh_rc yrc;

  if (in_fmt == fmt_password) {
    uint8_t pubkey[YH_EC_P256_PUBKEY_LEN];
    yrc = yh_util_derive_ec_p256_key(argv[1].x, argv[1].len, privkey,
                                     sizeof(privkey), pubkey, sizeof(pubkey));
    insecure_memzero(argv[1].x, argv[1].len);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to derive asymmetric authentication key: %s\n",
              yh_strerror(yrc));
      return -1;
    }
  } else if (argv[1].len <= sizeof(privkey)) {
    memset(privkey, 0, sizeof(privkey) - argv[1].len);
    memcpy(privkey + sizeof(privkey) - argv[1].len, argv[1].x, argv[1].len);
    insecure_memzero(argv[1].x, argv[1].len);
  } else {
    insecure_memzero(argv[1].x, argv[1].len);
    fprintf(stderr, "Invalid asymmetric authkey: %s\n",
            yh_strerror(YHR_INVALID_PARAMETERS));
    return -1;
  }

  uint8_t device_pubkey[YH_EC_P256_PUBKEY_LEN];
  size_t device_pubkey_len = sizeof(device_pubkey);
  yrc = yh_util_get_device_pubkey(ctx->connector, device_pubkey,
                                  &device_pubkey_len, NULL);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to retrieve device pubkey: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (device_pubkey_len != YH_EC_P256_PUBKEY_LEN) {
    fprintf(stderr, "Invalid device pubkey\n");
    return -1;
  }

  int matched = 0;
  for (uint8_t **pubkey = ctx->device_pubkey_list; *pubkey; pubkey++) {
    if (!memcmp(*pubkey, device_pubkey, device_pubkey_len)) {
      matched++;
    }
  }

  if (ctx->device_pubkey_list[0] == NULL) {
    fprintf(stderr, "CAUTION: Device public key (PK.SD) not validated\n");
    for (size_t i = 0; i < device_pubkey_len; i++)
      fprintf(stderr, "%02x", device_pubkey[i]);
    fprintf(stderr, "\n");
  } else if (matched == 0) {
    fprintf(stderr, "Failed to validate device pubkey\n");
    return -1;
  }

  yrc =
    yh_create_session_asym(ctx->connector, authkey, privkey, sizeof(privkey),
                           device_pubkey, device_pubkey_len, &ses);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  yrc = yh_get_session_id(ses, &session_id);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (ctx->sessions[session_id] != NULL) {
    yrc = yh_destroy_session(&ctx->sessions[session_id]);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to destroy old session with same id (%d): %s\n",
              session_id, yh_strerror(yrc));
      return -1;
    }
  }
  ctx->sessions[session_id] = ses;

  fprintf(stderr, "Created session %d\n", session_id);

  return 0;
}
#endif

#ifdef YKHSMAUTH_ENABLED
// NOTE: Open a session using a key stored on YubiKey
// argc = 3
// arg 0: w:authkey
// arg 1: s:name
// arg 2: i:password
int yh_com_open_yksession(yubihsm_context *ctx, Argument *argv,
                          cmd_format in_fmt, cmd_format fmt) {
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_session *ses = NULL;
  uint8_t session_id = 0;

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  uint8_t *yh_context;

  uint8_t host_challenge[YH_EC_P256_PUBKEY_LEN];
  uint8_t card_cryptogram[YH_KEY_LEN];
  uint8_t key_s_enc[YH_KEY_LEN];
  uint8_t key_s_mac[YH_KEY_LEN];
  uint8_t key_s_rmac[YH_KEY_LEN];
  size_t host_challenge_len = sizeof(host_challenge);
  size_t card_cryptogram_len = sizeof(card_cryptogram);
  uint8_t retries;

  ykhsmauth_rc ykhsmauthrc = ykhsmauth_connect(ctx->state, NULL);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Failed to connect to the YubiKey: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return -1;
  }

  ykhsmauthrc = ykhsmauth_get_challenge(ctx->state, argv[1].s, host_challenge,
                                        &host_challenge_len);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Failed to get host challenge from the YubiKey: %s\n",
            ykhsmauth_strerror(ykhsmauthrc));
    return -1;
  }

  yh_rc yrc =
    yh_begin_create_session_ext(ctx->connector, argv[0].w, &yh_context,
                                host_challenge, host_challenge_len,
                                card_cryptogram, &card_cryptogram_len, &ses);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  ykhsmauthrc =
    ykhsmauth_calculate(ctx->state, argv[1].s, yh_context,
                        2 * host_challenge_len, card_cryptogram,
                        card_cryptogram_len, argv[2].x, argv[2].len, key_s_enc,
                        sizeof(key_s_enc), key_s_mac, sizeof(key_s_mac),
                        key_s_rmac, sizeof(key_s_rmac), &retries);
  insecure_memzero(argv[2].x, argv[2].len);
  if (ykhsmauthrc != YKHSMAUTHR_SUCCESS) {
    fprintf(stderr, "Failed to get session keys from the YubiKey: %s",
            ykhsmauth_strerror(ykhsmauthrc));
    if (ykhsmauthrc == YKHSMAUTHR_WRONG_PW) {
      fprintf(stderr, ", %d attempts remaining", retries);
    }
    fprintf(stderr, "\n");

    return -1;
  }

  yrc = yh_finish_create_session_ext(ctx->connector, ses, key_s_enc,
                                     sizeof(key_s_enc), key_s_mac,
                                     sizeof(key_s_mac), key_s_rmac,
                                     sizeof(key_s_rmac), card_cryptogram,
                                     card_cryptogram_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (card_cryptogram_len == YKHSMAUTH_CARD_CRYPTO_LEN) {
    yrc = yh_authenticate_session(ses);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to authenticate session: %s\n", yh_strerror(yrc));
      return -1;
    }
  }

  yrc = yh_get_session_id(ses, &session_id);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (ctx->sessions[session_id] != NULL) {
    yrc = yh_destroy_session(&ctx->sessions[session_id]);
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to destroy old session with same id (%d): %s\n",
              session_id, yh_strerror(yrc));
      return -1;
    }
  }
  ctx->sessions[session_id] = ses;

  fprintf(stderr, "Created session %d\n", session_id);

  return 0;
}
#endif

// NOTE(adma): Send unauthenticated echo
// argc = 2
// arg 0: b:byte
// arg 1: w:count
int yh_com_pecho(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                 cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  uint8_t data[YH_MSG_BUF_SIZE];
  uint16_t data_len;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len;
  yh_cmd response_cmd;

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  uint8_t byte = argv[0].b;

  uint16_t count = argv[1].w;
  if (count > YH_MSG_BUF_SIZE) {
    fprintf(stderr, "Count must be in [0, %d]\n", YH_MSG_BUF_SIZE);
    return -1;
  }

  memset(data, byte, count);

  data_len = count;
  response_len = sizeof(response);

  yrc = yh_send_plain_msg(ctx->connector, YHC_ECHO, data, data_len,
                          &response_cmd, response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to send ECHO command: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(ctx->out, "Response (%zu bytes):\n", response_len);
  for (size_t i = 0; i < response_len; i++) {
    if (i && !(i % 64))
      fprintf(ctx->out, "\n");
    else if (i && !(i % 8))
      fprintf(ctx->out, " ");
    fprintf(ctx->out, "%02x", response[i]);
  }

  fprintf(ctx->out, "\n");

  return 0;
}

// NOTE(adma): Store an asymmetric key
// argc = 6
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: i:key
int yh_com_put_asymmetric(yubihsm_context *ctx, Argument *argv,
                          cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  uint8_t key[512];
  size_t key_material_len = sizeof(key);
  yh_algorithm algorithm;

  yh_rc yrc;

  bool ret = read_private_key(argv[5].x, argv[5].len, &algorithm, key,
                              &key_material_len, false);
  if (ret == false) {
    fprintf(stderr, "Unable to read asymmetric key\n");
    return -1;
  }

  switch (algorithm) {
    case YH_ALGO_RSA_2048:
    case YH_ALGO_RSA_3072:
    case YH_ALGO_RSA_4096:
      yrc = yh_util_import_rsa_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                   &argv[4].c, algorithm, key,
                                   key + key_material_len / 2);
      break;
    case YH_ALGO_EC_P224:
    case YH_ALGO_EC_P256:
    case YH_ALGO_EC_P384:
    case YH_ALGO_EC_P521:
    case YH_ALGO_EC_K256:
    case YH_ALGO_EC_BP256:
    case YH_ALGO_EC_BP384:
    case YH_ALGO_EC_BP512:
      yrc = yh_util_import_ec_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, algorithm, key);
      break;

    case YH_ALGO_EC_ED25519:
      yrc = yh_util_import_ed_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, algorithm, key);
      break;
    default:
      fprintf(stderr, "Unsupported algorithm\n");
      return -1;
  }

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store asymmetric key: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored Asymmetric key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE(adma): Store an authentication key
// argc = 7
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: c:delegated_capabilities
// arg 6: x:password
int yh_com_put_authentication(yubihsm_context *ctx, Argument *argv,
                              cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  yrc =
    yh_util_import_authentication_key_derived(argv[0].e, &argv[1].w, argv[2].s,
                                              argv[3].w, &argv[4].c, &argv[5].c,
                                              argv[6].x, argv[6].len);
  insecure_memzero(argv[6].x, argv[6].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store authkey: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored Authentication key 0x%04x\n", argv[1].w);

  return 0;
}

#ifdef USE_ASYMMETRIC_AUTH
// NOTE: Store an asymmetric authentication key
// argc = 7
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: c:delegated_capabilities
// arg 6: x:password
int yh_com_put_authentication_asym(yubihsm_context *ctx, Argument *argv,
                                   cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(fmt);

  yh_rc yrc;

  uint8_t pubkey[YH_EC_P256_PUBKEY_LEN];

  if (in_fmt == fmt_password) {
    uint8_t privkey[YH_EC_P256_PRIVKEY_LEN];
    yrc = yh_util_derive_ec_p256_key(argv[6].x, argv[6].len, privkey,
                                     sizeof(privkey), pubkey, sizeof(pubkey));
    insecure_memzero(argv[6].x, argv[6].len);
    insecure_memzero(privkey, sizeof(privkey));
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to derive asymmetric authentication key: %s\n",
              yh_strerror(yrc));
      return -1;
    }
    fprintf(stderr, "Derived public key (PK.OCE)\n");
    for (size_t i = 0; i < sizeof(pubkey); i++)
      fprintf(stderr, "%02x", pubkey[i]);
    fprintf(stderr, "\n");
  } else if (argv[6].len <= sizeof(pubkey)) {
    memset(pubkey, 0, sizeof(pubkey) - argv[6].len);
    memcpy(pubkey + sizeof(pubkey) - argv[6].len, argv[6].x, argv[6].len);
  } else {
    fprintf(stderr, "Invalid asymmetric authkey: %s\n",
            yh_strerror(YHR_INVALID_PARAMETERS));
    return -1;
  }

  yrc =
    yh_util_import_authentication_key(argv[0].e, &argv[1].w, argv[2].s,
                                      argv[3].w, &argv[4].c, &argv[5].c,
                                      pubkey + 1, sizeof(pubkey) - 1, NULL, 0);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store asymmetric authkey: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored Asymmetric Authentication key 0x%04x\n", argv[1].w);

  return 0;
}
#endif

// NOTE(adma): Store an opaque object
// argc = 6
// arg 0: e:session
// arg 1: w:object_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: a:algorithm
// arg 6: i:datafile
int yh_com_put_opaque(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  yh_rc yrc;

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yrc = yh_util_import_opaque(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                              &argv[4].c, argv[5].a, argv[6].x, argv[6].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store opaque object: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored Opaque object 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE(adma): Set a global option value
// argc = 3
// arg 0: e:session
// arg 1: o:option
// arg 2: x:value
int yh_com_put_option(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  yrc = yh_util_set_option(argv[0].e, argv[1].o, argv[2].len, argv[2].x);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store option: %s\n", yh_strerror(yrc));
    return -1;
  }

  return 0;
}

// NOTE: Put a HMAC key
// argc = 7
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: a:algorithm
// arg 6: x:key
int yh_com_put_hmac(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                    cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  if (argv[6].len > 128) {
    fprintf(stderr, "Too long key supplied, max 128 bytes allowed\n");
    return -1;
  }

  yrc = yh_util_import_hmac_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                &argv[4].c, argv[5].a, argv[6].x, argv[6].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store HMAC key: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored HMAC key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE: Store a wrapping key
// argc = 6
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: c:delegated_capabilities
// arg 6: x:key
int yh_com_put_wrapkey(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {
  yh_rc yrc;

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);
  yh_algorithm algo;

  if (argv[6].len == 16) {
    algo = YH_ALGO_AES128_CCM_WRAP;
  } else if (argv[6].len == 24) {
    algo = YH_ALGO_AES192_CCM_WRAP;
  } else if (argv[6].len == 32) {
    algo = YH_ALGO_AES256_CCM_WRAP;
  } else {
    fprintf(stderr, "Key length not matching, should be 16, 24 or 32\n");
    return -1;
  }

  yrc = yh_util_import_wrap_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                &argv[4].c, algo, &argv[5].c, argv[6].x,
                                argv[6].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store wrapkey: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored Wrap key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE: Store a wrapped object
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:data
int yh_com_put_wrapped(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {
  yh_rc yrc;
  yh_object_type object_type;
  uint16_t object_id;
  const char *type = "";

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yrc = yh_util_import_wrapped(argv[0].e, argv[1].w, argv[2].x, argv[2].len,
                               &object_type, &object_id);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store wrapped object: %s\n", yh_strerror(yrc));
    return -1;
  }

  yh_type_to_string(object_type, &type);

  fprintf(stderr, "Object imported as 0x%04x of type %s\n", object_id, type);

  return 0;
}

// NOTE(adma): Store a template object
// argc = 7
// arg 0: e:session
// arg 1: w:object_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: a:algorithm
// arg 6: i:datafile
int yh_com_put_template(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                        cmd_format fmt) {

  yh_rc yrc;

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yrc = yh_util_import_template(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                &argv[4].c, argv[5].a, argv[6].x, argv[6].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store template object: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored Template object 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE(adma): Sign data using ECDSA
// argc = 4
// arg 0: e:session
// arg 1: w:key_id
// arg 2: a:algorithm
// arg 3: i:datafile
int yh_com_sign_ecdsa(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(in_fmt);

  yh_rc yrc;

  uint8_t data[YH_MSG_BUF_SIZE];
  size_t data_len = sizeof(data);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  int hash;

  switch (argv[2].a) {
    case YH_ALGO_EC_ECDSA_SHA1:
      hash = _SHA1;
      break;

    case YH_ALGO_EC_ECDSA_SHA256:
      hash = _SHA256;
      break;

    case YH_ALGO_EC_ECDSA_SHA384:
      hash = _SHA384;
      break;

    case YH_ALGO_EC_ECDSA_SHA512:
      hash = _SHA512;
      break;

    default:
      fprintf(stderr, "Invalid hash algorithm\n");
      return -1;
  }

  if (hash_bytes(argv[3].x, argv[3].len, hash, data, &data_len) == false) {
    fprintf(stderr, "Unable to hash file\n");
    return -1;
  }

  yrc = yh_util_sign_ecdsa(argv[0].e, argv[1].w, data, data_len, response,
                           &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to sign data with ecdsa: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): Sign data using EDDSA
// argc = 4
// arg 0: e:session
// arg 1: w:key_id
// arg 2: a:algorithm
// arg 3: i:datafile
int yh_com_sign_eddsa(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(in_fmt);

  yh_rc yrc;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  if (argv[2].a != YH_ALGO_EC_ED25519) {
    fprintf(stderr, "Invalid algorithm\n");
    return -1;
  }

  yrc = yh_util_sign_eddsa(argv[0].e, argv[1].w, argv[3].x, argv[3].len,
                           response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to sign data with eddsa: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): Sign data using RSASSA-PKCS#1v1.5
// argc = 4
// arg 0: e:session
// arg 1: w:key_id
// arg 2: a:algorithm
// arg 3: f:datafile
int yh_com_sign_pkcs1v1_5(yubihsm_context *ctx, Argument *argv,
                          cmd_format in_fmt, cmd_format fmt) {

  UNUSED(in_fmt);

  yh_rc yrc;

  uint8_t data[YH_MSG_BUF_SIZE];
  size_t data_len = sizeof(data);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  int hash;

  switch (argv[2].a) {
    case YH_ALGO_RSA_PKCS1_SHA1:
      hash = _SHA1;
      break;

    case YH_ALGO_RSA_PKCS1_SHA256:
      hash = _SHA256;
      break;

    case YH_ALGO_RSA_PKCS1_SHA384:
      hash = _SHA384;
      break;

    case YH_ALGO_RSA_PKCS1_SHA512:
      hash = _SHA512;
      break;

    default:
      fprintf(stderr, "Invalid hash algorithm\n");
      return -1;
  }

  if (hash_bytes(argv[3].x, argv[3].len, hash, data, &data_len) == false) {
    fprintf(stderr, "Unable to hash file\n");
    return -1;
  }

  yrc = yh_util_sign_pkcs1v1_5(argv[0].e, argv[1].w, true, data, data_len,
                               response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to sign data with PKCS#1v1.5: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): Sign data using RSASSA-PSS
// argc = 4
// arg 0: e:session
// arg 1: w:key_id
// arg 2: a:algorithm
// arg 3: f:datafile
int yh_com_sign_pss(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                    cmd_format fmt) {

  UNUSED(in_fmt);

  yh_rc yrc;

  uint8_t data[YH_MSG_BUF_SIZE];
  size_t data_len = sizeof(data);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  int hash;
  yh_algorithm mgf;

  switch (argv[2].a) {
    case YH_ALGO_RSA_PSS_SHA1:
      hash = _SHA1;
      mgf = YH_ALGO_MGF1_SHA1;
      break;

    case YH_ALGO_RSA_PSS_SHA256:
      hash = _SHA256;
      mgf = YH_ALGO_MGF1_SHA256;
      break;

    case YH_ALGO_RSA_PSS_SHA384:
      hash = _SHA384;
      mgf = YH_ALGO_MGF1_SHA384;
      break;

    case YH_ALGO_RSA_PSS_SHA512:
      hash = _SHA512;
      mgf = YH_ALGO_MGF1_SHA512;
      break;

    default:
      fprintf(stderr, "Invalid hash algorithm\n");
      return -1;
  }

  if (hash_bytes(argv[3].x, argv[3].len, hash, data, &data_len) == false) {
    fprintf(stderr, "Unable to hash file\n");
    return -1;
  }

  // NOTE(adma): Salt length always matches the length of the hash
  yrc = yh_util_sign_pss(argv[0].e, argv[1].w, data, data_len, response,
                         &response_len, data_len, mgf);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to sign data with PSS: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE(adma): Extract the version number, serial number and supported
// algorithms
// argc = 0
int yh_com_get_device_info(yubihsm_context *ctx, Argument *argv,
                           cmd_format in_fmt, cmd_format fmt) {

  UNUSED(argv);
  UNUSED(in_fmt);
  UNUSED(fmt);

  if (ctx->connector == NULL) {
    fprintf(stderr, "Not connected\n");
    return -1;
  }

  yh_rc yrc;

  uint8_t major;
  uint8_t minor;
  uint8_t patch;
  uint32_t serial;
  uint8_t log_total;
  uint8_t log_used;
  yh_algorithm algorithms[YH_MAX_ALGORITHM_COUNT];
  size_t n_algorithms = sizeof(algorithms);

  yrc =
    yh_util_get_device_info(ctx->connector, &major, &minor, &patch, &serial,
                            &log_total, &log_used, algorithms, &n_algorithms);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get device info: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(ctx->out, "Version number:\t\t%hhu.%hhu.%hhu\n", major, minor, patch);
  fprintf(ctx->out, "Serial number:\t\t%u\n", serial);
  fprintf(ctx->out, "Log used:\t\t%d/%d\n", log_used, log_total);

  fprintf(ctx->out, "Supported algorithms:\t");
  for (size_t i = 0; i < n_algorithms; i++) {
    const char *algo_str;
    yh_algo_to_string(algorithms[i], &algo_str);
    fprintf(ctx->out, "%s, ", algo_str);
    if ((i + 1) % 3 == 0 && i != 0) {
      fprintf(ctx->out, "\n\t\t\t");
    }
  }
  fprintf(ctx->out, "\n");

  return 0;
}

// NOTE: HMAC data
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: x:data
int yh_com_hmac(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);

  yh_rc yrc;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  yrc = yh_util_sign_hmac(argv[0].e, argv[1].w, argv[2].x, argv[2].len,
                          response, &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to HMAC data: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE: Reset device
// argc = 1
// arg 0: e:session
int yh_com_reset(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                 cmd_format fmt) {
  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  yrc = yh_util_reset_device(argv[0].e);
  if (yrc != YHR_CONNECTION_ERROR && yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to reset device: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(ctx->out, "Device successfully reset\n");

  return 0;
}

// NOTE: Delete an object
// argc = 3
// arg 0: e:session
// arg 1: w:id
// arg 2: t:type
int yh_com_delete(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                  cmd_format fmt) {
  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc = yh_util_delete_object(argv[0].e, argv[1].w, argv[2].t);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to delete object: %s\n", yh_strerror(yrc));
    return -1;
  } // TODO(adma): the order of the arguments should be changed to id and type

  return 0;
}

// NOTE(adma): Sign an SSH public key
// argc = 4
// arg 0: e:session
// arg 1: w:key_id
// arg 2: w:template_id
// arg 3: a:algorithm
// arg 4: i:datafile
int yh_com_sign_ssh_certificate(yubihsm_context *ctx, Argument *argv,
                                cmd_format in_fmt, cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt); // TODO: respect output format

  yh_rc yrc;

  uint8_t data[YH_MSG_BUF_SIZE + 1024];
  size_t response_len = sizeof(data);

  memcpy(data, argv[4].x, argv[4].len);
  response_len -= argv[4].len;

  yrc = yh_util_sign_ssh_certificate(argv[0].e, argv[1].w, argv[2].w, argv[3].a,
                                     data, argv[4].len, data + argv[4].len,
                                     &response_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to get certificate signature: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  BIO *bio;
  BIO *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    fprintf(stderr, "Failed to sign SSH certificate.\n");
    return -1;
  }
  bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    fprintf(stderr, "Failed to sign SSH certificate.\n");
    BIO_free_all(b64);
    return -1;
  }
  bio = BIO_push(b64, bio);

  (void) BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  (void) BIO_write(bio, data + 4 + 256,
                   argv[4].len + response_len - 4 -
                     256); // TODO(adma): FIXME, unmagify
  (void) BIO_flush(bio);
  (void) BIO_get_mem_ptr(bio, &bufferPtr);

  const char *ssh_cert_str =
    "ssh-rsa-cert-v01@openssh.com "; // TODO(adma): ECDSA

  if (fwrite(ssh_cert_str, 1, strlen(ssh_cert_str), ctx->out) !=
        strlen(ssh_cert_str) ||
      ferror(ctx->out)) {
    fprintf(stderr, "Unable to write data to file\n");
    return -1;
  }

  if (fwrite(bufferPtr->data, 1, bufferPtr->length, ctx->out) !=
        bufferPtr->length ||
      ferror(ctx->out)) {
    fprintf(stderr, "Unable to write data to file\n");
    return -1;
  }

  if (fwrite("\n", 1, 1, ctx->out) != 1 || ferror(ctx->out)) {
    fprintf(stderr, "Unable to write data to file\n");
    return -1;
  }

  (void) BIO_free_all(bio); // TODO: fix this leak.

  return 0;
}

static void time_elapsed(struct timeval *after, struct timeval *before,
                         struct timeval *result) {
  result->tv_sec = after->tv_sec - before->tv_sec;
  result->tv_usec = after->tv_usec - before->tv_usec;
  if (result->tv_usec < 0) {
    result->tv_sec--;
    result->tv_usec += 1000000;
  }
}

static void time_add(struct timeval *a, struct timeval *b,
                     struct timeval *result) {
  result->tv_sec = a->tv_sec + b->tv_sec;
  result->tv_usec = a->tv_usec + b->tv_usec;
  if (result->tv_usec >= 1000000) {
    result->tv_sec++;
    result->tv_usec -= 1000000;
  }
}

static void time_average(struct timeval *in, size_t num,
                         struct timeval *result) {
  time_t remains = in->tv_sec % num;
  result->tv_sec = in->tv_sec / num;
  result->tv_usec = in->tv_usec / num;
  if (remains) {
    remains *= 1000000;
    result->tv_usec += remains / num;
  }
}

static double time_tps(struct timeval *in, size_t num) {
  double time = in->tv_sec + (double) in->tv_usec / 1000000;
  return num / time;
}

static bool time_less(struct timeval *a, struct timeval *b) {
  if (a->tv_sec < b->tv_sec) {
    return true;
  } else if (a->tv_sec == b->tv_sec && a->tv_usec < b->tv_usec) {
    return true;
  } else {
    return false;
  }
}

// NOTE: Run a set of benchmarks
// argc = 3
// arg 0: e:session
// arg 1: d:count
// arg 2: w:key_id
// arg 3: a:algorithm
int yh_com_benchmark(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                     cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  struct {
    yh_algorithm algo;
    yh_algorithm algo2;
    uint16_t bytes;
    const char *special;
  } benchmarks[] = {
    {YH_ALGO_RSA_2048, YH_ALGO_RSA_PKCS1_SHA256, 32, ""},
    {YH_ALGO_RSA_3072, YH_ALGO_RSA_PKCS1_SHA384, 48, ""},
    {YH_ALGO_RSA_4096, YH_ALGO_RSA_PKCS1_SHA512, 64, ""},
    {YH_ALGO_RSA_2048, YH_ALGO_RSA_PSS_SHA256, 32, ""},
    {YH_ALGO_RSA_3072, YH_ALGO_RSA_PSS_SHA384, 48, ""},
    {YH_ALGO_RSA_4096, YH_ALGO_RSA_PSS_SHA512, 64, ""},
    {YH_ALGO_EC_P224, YH_ALGO_EC_ECDSA_SHA1, 20, ""},
    {YH_ALGO_EC_P256, YH_ALGO_EC_ECDSA_SHA256, 32, ""},
    {YH_ALGO_EC_P384, YH_ALGO_EC_ECDSA_SHA384, 48, ""},
    {YH_ALGO_EC_P521, YH_ALGO_EC_ECDSA_SHA512, 66, ""},
    {YH_ALGO_EC_K256, YH_ALGO_EC_ECDSA_SHA256, 32, ""},
    {YH_ALGO_EC_BP256, YH_ALGO_EC_ECDSA_SHA256, 32, ""},
    {YH_ALGO_EC_BP384, YH_ALGO_EC_ECDSA_SHA384, 48, ""},
    {YH_ALGO_EC_BP512, YH_ALGO_EC_ECDSA_SHA512, 64, ""},
    {YH_ALGO_EC_P224, YH_ALGO_EC_ECDH, 56, ""},
    {YH_ALGO_EC_P256, YH_ALGO_EC_ECDH, 64, ""},
    {YH_ALGO_EC_P384, YH_ALGO_EC_ECDH, 96, ""},
    {YH_ALGO_EC_P521, YH_ALGO_EC_ECDH, 132, ""},
    {YH_ALGO_EC_K256, YH_ALGO_EC_ECDH, 64, ""},
    {YH_ALGO_EC_BP256, YH_ALGO_EC_ECDH, 64, ""},
    {YH_ALGO_EC_BP384, YH_ALGO_EC_ECDH, 96, ""},
    {YH_ALGO_EC_BP512, YH_ALGO_EC_ECDH, 128, ""},
    {YH_ALGO_EC_ED25519, 0, 32, "32 bytes data"},
    {YH_ALGO_EC_ED25519, 0, 64, "64 bytes data"},
    {YH_ALGO_EC_ED25519, 0, 128, "128 bytes data"},
    {YH_ALGO_EC_ED25519, 0, 256, "256 bytes data"},
    {YH_ALGO_EC_ED25519, 0, 512, "512 bytes data"},
    {YH_ALGO_EC_ED25519, 0, 1024, "1024 bytes data"},
    {YH_ALGO_HMAC_SHA1, 0, 64, ""},
    {YH_ALGO_HMAC_SHA256, 0, 64, ""},
    {YH_ALGO_HMAC_SHA384, 0, 128, ""},
    {YH_ALGO_HMAC_SHA512, 0, 128, ""},
    {YH_ALGO_AES128_CCM_WRAP, 0, 0, ""},
    {YH_ALGO_AES192_CCM_WRAP, 0, 0, ""},
    {YH_ALGO_AES256_CCM_WRAP, 0, 0, ""},
    {YH_ALGO_AES128_CCM_WRAP, 0, 128, "1024 bytes data"},
    {YH_ALGO_AES192_CCM_WRAP, 0, 128, "1024 bytes data"},
    {YH_ALGO_AES256_CCM_WRAP, 0, 128, "1024 bytes data"},
    {YH_ALGO_AES128_YUBICO_OTP, 0, 0, ""},
    {YH_ALGO_AES192_YUBICO_OTP, 0, 0, ""},
    {YH_ALGO_AES256_YUBICO_OTP, 0, 0, ""},
    {0, 0, 8, "Random 8 bytes"},
    {0, 0, 16, "Random 16 bytes"},
    {0, 0, 32, "Random 32 bytes"},
    {0, 0, 64, "Random 64 bytes"},
    {0, 0, 128, "Random 128 bytes"},
    {0, 0, 256, "Random 256 bytes"},
    {0, 0, 512, "Random 512 bytes"},
    {0, 0, 1024, "Random 1024 bytes"},
    {YH_ALGO_AES128_YUBICO_AUTHENTICATION, 0, 0, ""},
#ifdef USE_ASYMMETRIC_AUTH
    {YH_ALGO_EC_P256_YUBICO_AUTHENTICATION, 0, 0, ""},
#endif
  };

  // this is some data for the OTP benchmark
  const uint8_t otp_key[] =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
  const uint8_t otp_id[] = "\x01\x02\x03\x04\x05\x06";
  const uint8_t otp[] =
    "\x2f\x5d\x71\xa4\x91\x5d\xec\x30\x4a\xa1\x3c\xcf\x97\xbb\x0d\xbb";
  const uint8_t password[] = "benchmark";

  if (argv[1].d == 0) {
    fprintf(stderr, "Benchmark with 0 rounds seems pointless\n");
    return -1;
  }

  for (size_t i = 0; i < sizeof(benchmarks) / sizeof(benchmarks[0]); i++) {
    struct timeval total = {0, 0};
    struct timeval avg = {0, 0};
    struct timeval max = {0, 0};
    struct timeval min;
    yh_capabilities capabilities = {{0}};
    yh_rc yrc = YHR_SUCCESS;
    uint8_t algo_data[1024];
    size_t algo_len = sizeof(algo_data);
    const char *str1 = NULL, *str2 = "", *str3 = "";
    uint16_t id = argv[2].w;
    char label[YH_OBJ_LABEL_LEN + 1] = {0};
#ifdef USE_ASYMMETRIC_AUTH
    uint8_t sk_oce[YH_EC_P256_PRIVKEY_LEN], pk_oce[YH_EC_P256_PUBKEY_LEN],
      pk_sd[YH_EC_P256_PUBKEY_LEN];
    size_t pk_sd_len;
#endif
    yh_object_type type = 0;
#ifndef _WIN32
    size_t chars = 0;
#endif

    if (argv[3].a != 0) {
      if (argv[3].a != benchmarks[i].algo && argv[3].a != benchmarks[i].algo2) {
        continue;
      }
    }
    if (benchmarks[i].algo) {
      yh_algo_to_string(benchmarks[i].algo, &str1);
    }
    if (benchmarks[i].algo2) {
      str2 = " ";
      yh_algo_to_string(benchmarks[i].algo2, &str3);
    }
    if (str1) {
      snprintf(label, YH_OBJ_LABEL_LEN, "Benchmark: %s%s%s", str1, str2, str3);
    }

    if (str1) {
#ifndef _WIN32
      chars =
#endif
        fprintf(stderr, "Doing benchmark setup for %s%s%s...", str1, str2,
                str3);
    }

    if (yh_is_rsa(benchmarks[i].algo)) {
      if (benchmarks[i].algo2 == YH_ALGO_RSA_PKCS1_SHA256 ||
          benchmarks[i].algo2 == YH_ALGO_RSA_PKCS1_SHA384 ||
          benchmarks[i].algo2 == YH_ALGO_RSA_PKCS1_SHA512) {
        yh_string_to_capabilities("sign-pkcs", &capabilities);
      } else if (benchmarks[i].algo2 == YH_ALGO_RSA_PSS_SHA256 ||
                 benchmarks[i].algo2 == YH_ALGO_RSA_PSS_SHA384 ||
                 benchmarks[i].algo2 == YH_ALGO_RSA_PSS_SHA512) {
        yh_string_to_capabilities("sign-pss", &capabilities);
      } else {
        fprintf(stderr, "Unknown benchmark algorithms\n");
        return -1;
      }
      type = YH_ASYMMETRIC_KEY;
      yrc = yh_util_generate_rsa_key(argv[0].e, &id, label, 0xffff,
                                     &capabilities, benchmarks[i].algo);
    } else if (yh_is_ec(benchmarks[i].algo)) {
      if (benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA1 ||
          benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA256 ||
          benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA384 ||
          benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA512) {
        yh_string_to_capabilities("sign-ecdsa", &capabilities);
      } else if (benchmarks[i].algo2 == YH_ALGO_EC_ECDH) {
        yh_string_to_capabilities("derive-ecdh", &capabilities);
        yrc = yh_util_generate_ec_key(argv[0].e, &id, label, 0xffff,
                                      &capabilities, benchmarks[i].algo);

        if (yrc != YHR_SUCCESS) {
          fprintf(stderr, "Failed ECDH setup\n");
          return -1;
        }
        algo_len--;
        yrc =
          yh_util_get_public_key(argv[0].e, id, algo_data + 1, &algo_len, NULL);
        if (yrc != YHR_SUCCESS || algo_len != benchmarks[i].bytes) {
          fprintf(stderr, "Failed to get ECDH pubkey (%zu)\n", algo_len);
          return -1;
        }
        algo_data[0] = 0x04; // this is a hack to make it look correct..
        algo_len++;
        yrc = yh_util_delete_object(argv[0].e, id, YH_ASYMMETRIC_KEY);
        if (yrc != YHR_SUCCESS) {
          fprintf(stderr, "Failed deleting temporary ec key\n");
          return -1;
        }
      } else {
        fprintf(stderr, "Unknown benchmark algorithms\n");
        return -1;
      }
      type = YH_ASYMMETRIC_KEY;
      yrc = yh_util_generate_ec_key(argv[0].e, &id, label, 0xffff,
                                    &capabilities, benchmarks[i].algo);
    } else if (benchmarks[i].algo == YH_ALGO_EC_ED25519) {
      yh_string_to_capabilities("sign-eddsa", &capabilities);
      type = YH_ASYMMETRIC_KEY;
      yrc = yh_util_generate_ed_key(argv[0].e, &id, label, 0xffff,
                                    &capabilities, benchmarks[i].algo);
      str2 = " ";
      str3 = benchmarks[i].special;
    } else if (yh_is_hmac(benchmarks[i].algo)) {
      type = YH_HMAC_KEY;
      yh_string_to_capabilities("sign-hmac", &capabilities);
      yrc = yh_util_generate_hmac_key(argv[0].e, &id, label, 0xffff,
                                      &capabilities, benchmarks[i].algo);
    } else if (benchmarks[i].algo == YH_ALGO_AES128_CCM_WRAP ||
               benchmarks[i].algo == YH_ALGO_AES192_CCM_WRAP ||
               benchmarks[i].algo == YH_ALGO_AES256_CCM_WRAP) {
      type = YH_WRAP_KEY;
      yh_string_to_capabilities(
        "export-wrapped,exportable-under-wrap,wrap-data", &capabilities);
      yrc =
        yh_util_generate_wrap_key(argv[0].e, &id, label, 0xffff, &capabilities,
                                  benchmarks[i].algo, &capabilities);
      if (benchmarks[i].bytes > 0) {
        str2 = " ";
        str3 = benchmarks[i].special;
      }
    } else if (benchmarks[i].algo == YH_ALGO_AES128_YUBICO_OTP ||
               benchmarks[i].algo == YH_ALGO_AES192_YUBICO_OTP ||
               benchmarks[i].algo == YH_ALGO_AES256_YUBICO_OTP) {
      type = YH_OTP_AEAD_KEY;
      yh_string_to_capabilities("decrypt-otp,create-otp-aead", &capabilities);
      yrc = yh_util_generate_otp_aead_key(argv[0].e, &id, label, 0xffff,
                                          &capabilities, benchmarks[i].algo,
                                          0x12345678);
      if (yrc == YHR_SUCCESS) {
        yrc = yh_util_create_otp_aead(argv[0].e, id, otp_key, otp_id, algo_data,
                                      &algo_len);
      }
    } else if (strncmp(benchmarks[i].special, "Random ", 7) == 0) {
      str1 = benchmarks[i].special;
    } else if (benchmarks[i].algo == YH_ALGO_AES128_YUBICO_AUTHENTICATION) {
      type = YH_AUTHENTICATION_KEY;
      yh_string_to_capabilities("", &capabilities);
      yrc = yh_util_import_authentication_key_derived(argv[0].e, &id, label,
                                                      0xffff, &capabilities,
                                                      &capabilities, password,
                                                      sizeof(password) - 1);
#ifdef USE_ASYMMETRIC_AUTH
    } else if (benchmarks[i].algo == YH_ALGO_EC_P256_YUBICO_AUTHENTICATION) {
      type = YH_AUTHENTICATION_KEY;
      yh_string_to_capabilities("", &capabilities);
      yrc = yh_util_generate_ec_p256_key(sk_oce, sizeof(sk_oce), pk_oce,
                                         sizeof(pk_oce));
      if (yrc == YHR_SUCCESS) {
        yrc = yh_util_import_authentication_key(argv[0].e, &id, label, 0xffff,
                                                &capabilities, &capabilities,
                                                pk_oce + 1, sizeof(pk_oce) - 1,
                                                NULL, 0);
        if (yrc == YHR_SUCCESS) {
          pk_sd_len = sizeof(pk_sd);
          yrc =
            yh_util_get_device_pubkey(ctx->connector, pk_sd, &pk_sd_len, NULL);
        }
      }
#endif
    } else {
      fprintf(stderr, "Unknown benchmark algorithms\n");
      return -1;
    }

    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed benchmark setup for %s%s%s\n", str1, str2, str3);
      return -1;
    }

    memset(&min, 0x7f, sizeof(min));
    for (uint32_t j = 0; j < argv[1].d; j++) {
      uint8_t data[1024];
      uint8_t out[1024];
      size_t out_len = sizeof(out);
      struct timeval before, after, result;

      memset(data, j, sizeof(data));
      gettimeofday(&before, NULL);
      if (yh_is_rsa(benchmarks[i].algo) &&
          (benchmarks[i].algo2 == YH_ALGO_RSA_PKCS1_SHA256 ||
           benchmarks[i].algo2 == YH_ALGO_RSA_PKCS1_SHA384 ||
           benchmarks[i].algo2 == YH_ALGO_RSA_PKCS1_SHA512)) {
        yrc = yh_util_sign_pkcs1v1_5(argv[0].e, id, true, data,
                                     benchmarks[i].bytes, out, &out_len);
      } else if (yh_is_rsa(benchmarks[i].algo) &&
                 (benchmarks[i].algo2 == YH_ALGO_RSA_PSS_SHA256 ||
                  benchmarks[i].algo2 == YH_ALGO_RSA_PSS_SHA384 ||
                  benchmarks[i].algo2 == YH_ALGO_RSA_PSS_SHA512)) {
        yrc =
          yh_util_sign_pss(argv[0].e, id, data, benchmarks[i].bytes, out,
                           &out_len, benchmarks[i].bytes, YH_ALGO_MGF1_SHA1);
      } else if (yh_is_ec(benchmarks[i].algo) &&
                 (benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA1 ||
                  benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA256 ||
                  benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA384 ||
                  benchmarks[i].algo2 == YH_ALGO_EC_ECDSA_SHA512)) {
        yrc = yh_util_sign_ecdsa(argv[0].e, id, data, benchmarks[i].bytes, out,
                                 &out_len);
      } else if (yh_is_ec(benchmarks[i].algo) &&
                 benchmarks[i].algo2 == YH_ALGO_EC_ECDH) {
        yrc = yh_util_derive_ecdh(argv[0].e, id, algo_data, algo_len, out,
                                  &out_len);
      } else if (benchmarks[i].algo == YH_ALGO_EC_ED25519) {
        yrc = yh_util_sign_eddsa(argv[0].e, id, data, benchmarks[i].bytes, out,
                                 &out_len);
      } else if (yh_is_hmac(benchmarks[i].algo)) {
        yrc = yh_util_sign_hmac(argv[0].e, id, data, benchmarks[i].bytes, out,
                                &out_len);
      } else if (benchmarks[i].bytes > 0 &&
                 (benchmarks[i].algo == YH_ALGO_AES128_CCM_WRAP ||
                  benchmarks[i].algo == YH_ALGO_AES192_CCM_WRAP ||
                  benchmarks[i].algo == YH_ALGO_AES256_CCM_WRAP)) {
        yrc = yh_util_wrap_data(argv[0].e, id, data, benchmarks[i].bytes, out,
                                &out_len);
      } else if (benchmarks[i].algo == YH_ALGO_AES128_CCM_WRAP ||
                 benchmarks[i].algo == YH_ALGO_AES192_CCM_WRAP ||
                 benchmarks[i].algo == YH_ALGO_AES256_CCM_WRAP) {
        yrc =
          yh_util_export_wrapped(argv[0].e, id, YH_WRAP_KEY, id, out, &out_len);
      } else if (benchmarks[i].algo == YH_ALGO_AES128_YUBICO_OTP ||
                 benchmarks[i].algo == YH_ALGO_AES192_YUBICO_OTP ||
                 benchmarks[i].algo == YH_ALGO_AES256_YUBICO_OTP) {
        yrc = yh_util_decrypt_otp(argv[0].e, id, algo_data, algo_len, otp, NULL,
                                  NULL, NULL, NULL);
      } else if (strncmp(benchmarks[i].special, "Random ", 7) == 0) {
        yrc = yh_util_get_pseudo_random(argv[0].e, benchmarks[i].bytes, out,
                                        &out_len);
      } else if (benchmarks[i].algo == YH_ALGO_AES128_YUBICO_AUTHENTICATION) {
        yh_session *ses = NULL;
        yrc = yh_create_session_derived(ctx->connector, id, password,
                                        sizeof(password) - 1, false, &ses);
        if (yrc == YHR_SUCCESS) {
          yrc = yh_authenticate_session(ses);
        }
        if (yrc == YHR_SUCCESS) {
          yrc = yh_util_close_session(ses);
        }
#ifdef USE_ASYMMETRIC_AUTH
      } else if (benchmarks[i].algo == YH_ALGO_EC_P256_YUBICO_AUTHENTICATION) {
        yh_session *ses = NULL;
        yrc = yh_create_session_asym(ctx->connector, id, sk_oce, sizeof(sk_oce),
                                     pk_sd, pk_sd_len, &ses);
        if (yrc == YHR_SUCCESS) {
          yrc = yh_util_close_session(ses);
        }
#endif
      } else {
        fprintf(stderr, "Unknown benchmark algorithm\n");
        return -1;
      }

      gettimeofday(&after, NULL);

      if (yrc != YHR_SUCCESS) {
        fprintf(stderr, "Failed running benchmark %u for %s%s%s\n", j, str1,
                str2, str3);
        return -1;
      }

      time_elapsed(&after, &before, &result);
      if (time_less(&result, &min)) {
        min = result;
      }
      if (time_less(&max, &result)) {
        max = result;
      }
      time_add(&result, &total, &total);
      time_average(&total, j + 1, &avg);
#ifndef _WIN32
      struct winsize w;
      ioctl(fileno(stderr), TIOCGWINSZ, &w);

      if (chars > w.ws_col) {
        // move the cursor up and to column 1
        fprintf(stderr, "\33[%zuF", chars / w.ws_col);
      } else {
        // if we're still on same line, just move to column 1
        fprintf(stderr, "\33[1G");
      }
      // clear display from cursor
      fprintf(stderr, "\33[J");
      chars = fprintf(stderr,
                      "%s%s%s (%u/%d times) total: %ld.%06ld avg: %ld.%06ld "
                      "min: %ld.%06ld max: %ld.%06ld tps: %.06f",
                      str1, str2, str3, j + 1, argv[1].w, total.tv_sec,
                      (long) total.tv_usec, avg.tv_sec, (long) avg.tv_usec,
                      min.tv_sec, (long) min.tv_usec, max.tv_sec,
                      (long) max.tv_usec, time_tps(&total, j + 1));
      fflush(stderr);
#endif
    }
#ifdef _WIN32
    fprintf(stderr,
            "%s%s%s (%d times) total: %ld.%06ld avg: %ld.%06ld "
            "min: %ld.%06ld max: %ld.%06ld tps: %.06f",
            str1, str2, str3, argv[1].w, total.tv_sec, (long) total.tv_usec,
            avg.tv_sec, (long) avg.tv_usec, min.tv_sec, (long) min.tv_usec,
            max.tv_sec, (long) max.tv_usec, time_tps(&total, argv[1].w));

#endif
    fprintf(stderr, "\n");
    if (type != 0) {
      yh_util_delete_object(argv[0].e, id, type);
    }
  }

  return 0;
}

// NOTE: create aead from OTP parameters
// argc = 5
// arg 0: e:session
// arg 1: w:key_id
// arg 2: x:key
// arg 3: x:private_id
// arg 4: f:aead
int yh_com_otp_aead_create(yubihsm_context *ctx, Argument *argv,
                           cmd_format in_fmt, cmd_format fmt) {

  UNUSED(in_fmt);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);
  yh_rc yrc;

  if (argv[2].len != 16) {
    fprintf(stderr, "Wrong length key supplied, has to be 16 bytes\n");
    return -1;
  }

  if (argv[3].len != 6) {
    fprintf(stderr, "Wrong length id supplied, has to be 6 bytes\n");
    return -1;
  }

  yrc = yh_util_create_otp_aead(argv[0].e, argv[1].w, argv[2].x, argv[3].x,
                                response, &response_len);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create OTP AEAD: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (write_file(response, response_len, ctx->out, fmt_to_fmt(fmt))) {
    return 0;
  }

  return -1;
}

// NOTE: create aead from OTP parameters
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: f:aead
int yh_com_otp_aead_random(yubihsm_context *ctx, Argument *argv,
                           cmd_format in_fmt, cmd_format fmt) {

  UNUSED(in_fmt);

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);
  yh_rc yrc;

  yrc =
    yh_util_randomize_otp_aead(argv[0].e, argv[1].w, response, &response_len);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to create OTP AEAD: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (write_file(response, response_len, ctx->out, fmt_to_fmt(fmt))) {
    return 0;
  }

  return -1;
}

// NOTE: decrypt OTP with AEAD
// argc = 4
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:otp
// arg 3: i:aead
int yh_com_otp_decrypt(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                       cmd_format fmt) {
  uint16_t useCtr;
  uint8_t sessionCtr;
  uint8_t tstph;
  uint16_t tstpl;
  yh_rc yrc;
  uint8_t otp[16];
  size_t otp_len = sizeof(otp);

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  if (argv[2].len != 32) {
    fprintf(stderr, "Wrong length OTP supplied, has to be 16 bytes in hex\n");
    return -1;
  }

  if (hex_decode(argv[2].s, otp, &otp_len) == false) {
    fprintf(stderr, "Failed to decode OTP\n");
    return -1;
  }

  yrc = yh_util_decrypt_otp(argv[0].e, argv[1].w, argv[3].x, argv[3].len, otp,
                            &useCtr, &sessionCtr, &tstph, &tstpl);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to decrypt OTP: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "OTP decoded, useCtr:%d, sessionCtr:%d, tstph:%d, tstpl:%d\n",
          useCtr, sessionCtr, tstph, tstpl);

  return 0;
}

// NOTE: rewrap OTP AEAD to a different key
// argc = 5
// arg 0: e:session
// arg 1: w:id_from
// arg 2: w:id_to
// arg 3: i:aead_in
// arg 4: F:aead_out
int yh_com_otp_rewrap(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {
  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);
  yh_rc yrc;

  UNUSED(ctx);
  UNUSED(in_fmt);

  yrc = yh_util_rewrap_otp_aead(argv[0].e, argv[1].w, argv[2].w, argv[3].x,
                                argv[3].len, response, &response_len);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to rewrap OTP AEAD: %s\n", yh_strerror(yrc));
    return -1;
  }

  if (write_file(response, response_len, ctx->out, fmt_to_fmt(fmt))) {
    return 0;
  }

  return -1;
}

// NOTE: decrypt OTP with AEAD
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: 2:attest_id
int yh_com_sign_attestation_certificate(yubihsm_context *ctx, Argument *argv,
                                        cmd_format in_fmt, cmd_format fmt) {
  UNUSED(in_fmt);

  uint8_t data[2048];
  size_t data_len = sizeof(data);
  yh_rc yrc;
  int ret = -1;

  yrc = yh_util_sign_attestation_certificate(argv[0].e, argv[1].w, argv[2].w,
                                             data, &data_len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to attest asymmetric key: %s\n", yh_strerror(yrc));
    return -1;
  }

  const unsigned char *ptr = data;
  X509 *x509 = d2i_X509(NULL, &ptr, data_len);
  if (!x509) {
    fprintf(stderr, "Failed parsing x509 information\n");
  } else {
    if (fmt == fmt_base64 || fmt == fmt_PEM) {
      if (PEM_write_X509(ctx->out, x509) == 1) {
        ret = 0;
      } else {
        fprintf(stderr, "Failed writing x509 information\n");
      }
    } else if (fmt == fmt_binary) {
      if (i2d_X509_fp(ctx->out, x509) == 1) {
        ret = 0;
      } else {
        fprintf(stderr, "Failed writing x509 information\n");
      }
    }
  }

  X509_free(x509);
  return ret;
}

// NOTE: put OTP AEAD key
// argc = 7
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: d:nonce_id
// arg 6: x:key
int yh_com_put_otp_aead_key(yubihsm_context *ctx, Argument *argv,
                            cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  if (argv[6].len != 16 && argv[6].len != 24 && argv[6].len != 32) {
    fprintf(stderr, "Key length (%zu) not matching, should be 16, 24 or 32\n",
            argv[6].len);
    return -1;
  }

  yrc =
    yh_util_import_otp_aead_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                &argv[4].c, argv[5].d, argv[6].x, argv[6].len);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to store OTP AEAD key: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Stored OTP AEAD key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE: generate OTP AEAD key
// argc = 7
// arg 0: e:session
// arg 1: w:key_id
// arg 2: s:label
// arg 3: w:domains
// arg 4: c:capabilities
// arg 5: a:algorithm
// arg 6: d:nonce_id
int yh_com_generate_otp_aead_key(yubihsm_context *ctx, Argument *argv,
                                 cmd_format in_fmt, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(in_fmt);
  UNUSED(fmt);

  yh_rc yrc;

  yrc =
    yh_util_generate_otp_aead_key(argv[0].e, &argv[1].w, argv[2].s, argv[3].w,
                                  &argv[4].c, argv[5].a, argv[6].d);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to generate OTP AEAD key: %s\n", yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Generated OTP AEAD key 0x%04x\n", argv[1].w);

  return 0;
}

// NOTE(adma): Decrypt data using RSAES-OAEP
// argc = 5
// arg 0: e:session
// arg 1: w:key_id
// arg 2: a:algorithm
// arg 3: f:datafile
// arg 4: s:label
int yh_com_decrypt_oaep(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                        cmd_format fmt) {

  UNUSED(in_fmt);
  yh_rc yrc;

  uint8_t response[YH_MSG_BUF_SIZE];
  size_t response_len = sizeof(response);

  uint8_t label[64];
  size_t label_len = sizeof(label);

  int hash;
  yh_algorithm mgf;

  switch (argv[2].a) {
    case YH_ALGO_RSA_OAEP_SHA1:
      hash = _SHA1;
      mgf = YH_ALGO_MGF1_SHA1;
      break;

    case YH_ALGO_RSA_OAEP_SHA256:
      hash = _SHA256;
      mgf = YH_ALGO_MGF1_SHA256;
      break;

    case YH_ALGO_RSA_OAEP_SHA384:
      hash = _SHA384;
      mgf = YH_ALGO_MGF1_SHA384;
      break;

    case YH_ALGO_RSA_OAEP_SHA512:
      hash = _SHA512;
      mgf = YH_ALGO_MGF1_SHA512;
      break;

    default:
      fprintf(stderr, "Invalid hash algorithm\n");
      return -1;
  }

  if (hash_bytes((const uint8_t *) argv[4].s, argv[4].len, hash, label,
                 &label_len) == false) {
    fprintf(stderr, "Unable to hash data\n");
    return -1;
  }

  yrc = yh_util_decrypt_oaep(argv[0].e, argv[1].w, argv[3].x, argv[3].len,
                             response, &response_len, label, label_len, mgf);
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to decrypt data with OAEP: %s\n", yh_strerror(yrc));
    return -1;
  }

  write_file(response, response_len, ctx->out, fmt_to_fmt(fmt));

  return 0;
}

// NOTE: Set ca cert for https validation
// argc = 1
// arg 0: s:filename
int yh_com_set_cacert(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                      cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);

  if (ctx->cacert) {
    free(ctx->cacert);
  }
  ctx->cacert = strdup(argv[0].s);

  return 0;
}

// NOTE: Set proxy server to use for connector
// argc = 1
// arg 0: s:proxy
int yh_com_set_proxy(yubihsm_context *ctx, Argument *argv, cmd_format in_fmt,
                     cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);

  ctx->proxy = strdup(argv[0].s);
  if (ctx->proxy) {
    free(ctx->proxy);
  }

  return 0;
}

// NOTE: Change authentication key
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:password
int yh_com_change_authentication_key(yubihsm_context *ctx, Argument *argv,
                                     cmd_format in_fmt, cmd_format fmt) {

  UNUSED(in_fmt);
  UNUSED(fmt);
  UNUSED(ctx);

  yh_rc yrc = yh_util_change_authentication_key_derived(argv[0].e, &argv[1].w,
                                                        argv[2].x, argv[2].len);
  insecure_memzero(argv[2].x, argv[2].len);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to change authentication key: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Changed Authentication key 0x%04x\n", argv[1].w);

  return 0;
}

#ifdef USE_ASYMMETRIC_AUTH
// NOTE: Change asymmetric authentication key
// argc = 3
// arg 0: e:session
// arg 1: w:key_id
// arg 2: i:password
int yh_com_change_authentication_key_asym(yubihsm_context *ctx, Argument *argv,
                                          cmd_format in_fmt, cmd_format fmt) {

  UNUSED(fmt);
  UNUSED(ctx);

  uint8_t pubkey[YH_EC_P256_PUBKEY_LEN];
  yh_rc yrc;

  if (in_fmt == fmt_password) {
    uint8_t privkey[YH_EC_P256_PRIVKEY_LEN];
    yrc = yh_util_derive_ec_p256_key(argv[2].x, argv[2].len, privkey,
                                     sizeof(privkey), pubkey, sizeof(pubkey));
    insecure_memzero(argv[2].x, argv[2].len);
    insecure_memzero(privkey, sizeof(privkey));
    if (yrc != YHR_SUCCESS) {
      fprintf(stderr, "Failed to derive asymmetric authentication key: %s\n",
              yh_strerror(yrc));
      return -1;
    }
    fprintf(stderr, "Derived public key (PK.OCE)\n");
    for (size_t i = 0; i < sizeof(pubkey); i++)
      fprintf(stderr, "%02x", pubkey[i]);
    fprintf(stderr, "\n");
  } else if (argv[2].len <= sizeof(pubkey)) {
    memset(pubkey, 0, sizeof(pubkey) - argv[2].len);
    memcpy(pubkey + sizeof(pubkey) - argv[2].len, argv[2].x, argv[2].len);
  } else {
    fprintf(stderr, "Invalid asymmetric authkey: %s\n",
            yh_strerror(YHR_INVALID_PARAMETERS));
    return -1;
  }

  yrc = yh_util_change_authentication_key(argv[0].e, &argv[1].w, pubkey + 1,
                                          sizeof(pubkey) - 1, NULL, 0);

  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to change asymmetric authentication key: %s\n",
            yh_strerror(yrc));
    return -1;
  }

  fprintf(stderr, "Changed Asymmetric Authentication key 0x%04x\n", argv[1].w);

  return 0;
}
#endif
