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

#ifndef YUBIHSM_INTERNAL_H
#define YUBIHSM_INTERNAL_H

#include "../common/platform-config.h"
#include "scp.h"

#include <stdlib.h>
#include <stdbool.h>

struct yh_session {
  struct yh_connector *parent;
  uint16_t authkey_id;
  bool recreate;
  uint8_t key_enc[SCP_KEY_LEN];
  uint8_t key_mac[SCP_KEY_LEN];
  Scp_ctx s;
  uint8_t context[2 * YH_EC_P256_PUBKEY_LEN];
};

typedef struct state yh_backend;

struct yh_connector {
  void *backend;
  struct backend_functions *bf;
  yh_backend *connection;
  char *status_url;
  char *api_url;
  bool has_device;
  uint8_t version_major;
  uint8_t version_minor;
  uint8_t version_patch;
  uint8_t address[32];
  uint32_t port;
  uint32_t pid;
};

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

void YH_INTERNAL dump_hex(FILE *file, const uint8_t *ptr, uint16_t len);
void YH_INTERNAL dump_msg(FILE *file, const Msg *msg);
void YH_INTERNAL dump_response(FILE *file, const Msg *msg);

void YH_INTERNAL parse_status_data(char *data, yh_connector *connector);
bool YH_INTERNAL parse_usb_url(const char *url, unsigned long *serial);

struct backend_functions {
  yh_rc (*backend_init)(uint8_t verbosity, FILE *output);
  yh_backend *(*backend_create)(void);
  yh_rc (*backend_connect)(yh_connector *connector, int timeout);
  void (*backend_disconnect)(yh_backend *connection);
  yh_rc (*backend_send_msg)(yh_backend *connection, Msg *msg, Msg *response,
                            const char *identifier);
  void (*backend_cleanup)(void);
  yh_rc (*backend_option)(yh_backend *connection, yh_connector_option opt,
                          const void *val);
  void (*backend_set_verbosity)(uint8_t verbosity, FILE *output);
};

#ifdef STATIC
struct backend_functions YH_INTERNAL *usb_backend_functions(void);
struct backend_functions YH_INTERNAL *http_backend_functions(void);
#endif

#endif
