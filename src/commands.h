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

#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdint.h>
#include "yubihsm.h"
#include "yubihsm-shell.h"

typedef struct {
  union {
    uint8_t b;
    uint16_t w;
    uint32_t d;
    const char *s;
    const uint8_t *u;
    yh_session *e;
    yh_capabilities c;
    yh_algorithm a;
    yh_object_type t;
    yh_option o;
  };
  unsigned char *x;
  size_t len;
} Argument;

typedef int CommandFunction(yubihsm_context *ctx, Argument *argv,
                            cmd_format fmt);

int yh_com_audit(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_set_log_index(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_close_session(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_connect(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_debug_all(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_debug_error(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_debug_info(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_debug_intermediate(yubihsm_context *ctx, Argument *argv,
                              cmd_format fmt);
int yh_com_debug_none(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_debug_raw(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_debug_crypto(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_decrypt_pkcs1v1_5(yubihsm_context *ctx, Argument *argv,
                             cmd_format fmt);
int yh_com_decrypt_oaep(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_derive_ecdh(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_decrypt_aesccm(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_encrypt_aesccm(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_disconnect(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_echo(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_generate_asymmetric(yubihsm_context *ctx, Argument *argv,
                               cmd_format fmt);
int yh_com_generate_hmac(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_generate_wrap(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_generate_otp_aead_key(yubihsm_context *ctx, Argument *argv,
                                 cmd_format fmt);
int yh_com_get_opaque(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_get_option(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_get_random(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_get_storage(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_get_pubkey(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_get_object_info(yubihsm_context *ctx, Argument *argv,
                           cmd_format fmt);
int yh_com_get_wrapped(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_get_device_info(yubihsm_context *ctx, Argument *argv,
                           cmd_format fmt);
int yh_com_get_template(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_list_capabilities(yubihsm_context *ctx, Argument *argv,
                             cmd_format fmt);
int yh_com_list_algorithms(yubihsm_context *ctx, Argument *argv,
                           cmd_format fmt);
int yh_com_list_types(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_list_connectors(yubihsm_context *ctx, Argument *argv,
                           cmd_format fmt);
int yh_com_list_sessions(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_list_objects(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_open_session(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_pecho(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_asymmetric(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_authentication(yubihsm_context *ctx, Argument *argv,
                              cmd_format fmt);
int yh_com_put_opaque(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_option(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_hmac(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_wrapkey(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_wrapped(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_template(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_put_otp_aead_key(yubihsm_context *ctx, Argument *argv,
                            cmd_format fmt);
int yh_com_sign_ecdsa(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_sign_eddsa(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_sign_pkcs1v1_5(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_sign_pss(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_hmac(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_reset(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_delete(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_sign_ssh_certificate(yubihsm_context *ctx, Argument *argv,
                                cmd_format fmt);
int yh_com_benchmark(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_otp_aead_create(yubihsm_context *ctx, Argument *argv,
                           cmd_format fmt);
int yh_com_otp_aead_random(yubihsm_context *ctx, Argument *argv,
                           cmd_format fmt);
int yh_com_otp_decrypt(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_sign_attestation_certificate(yubihsm_context *ctx, Argument *argv,
                                        cmd_format fmt);
int yh_com_keepalive_on(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_keepalive_off(yubihsm_context *ctx, Argument *argv, cmd_format fmt);

int yh_com_noop(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_blink(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_set_cacert(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_set_proxy(yubihsm_context *ctx, Argument *argv, cmd_format fmt);

int yh_com_change_authentication_key(yubihsm_context *ctx, Argument *argv,
                                     cmd_format fmt);

#endif
