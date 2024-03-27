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

#ifndef YUBIHSM_SHELL_H
#define YUBIHSM_SHELL_H

#include <assert.h>

#include <yubihsm.h>
#include <cmdline.h>
#include <ykhsmauth.h>

#define UNUSED(x) (void) (x)

typedef enum {
  fmt_nofmt,
  fmt_base64,
  fmt_binary,
  fmt_hex,
  fmt_PEM,
  fmt_password,
  fmt_ASCII
} cmd_format;

static const struct {
  const char *name;
  cmd_format format;
} formats[] = {
  {"default", fmt_nofmt}, {"base64", fmt_base64}, {"binary", fmt_binary},
  {"hex", fmt_hex},       {"PEM", fmt_PEM},       {"password", fmt_password},
  {"ASCII", fmt_ASCII},
};

typedef struct {
  uint8_t **device_pubkey_list;
  char **connector_list;
  yh_connector *connector;
  yh_session *sessions[256];
  ykhsmauth_state *state;
  FILE *out;
  char *cacert;
  char *cert;
  char *key;
  char *proxy;
  char *noproxy;
} yubihsm_context;

int actions_run(struct gengetopt_args_info *args_info);
int do_put_key(uint8_t *enc_key, uint8_t *mac_key, uint16_t key_id,
               uint16_t domains, uint32_t capabilities, yh_session *ses);

#ifdef _MSC_VER
#pragma strict_gs_check(on)
#endif

#endif
