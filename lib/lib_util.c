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

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#include "yubihsm.h"
#include "internal.h"
#include "debug_lib.h"

#define STATUS_STR "status="
#define VERSION_STR "version="
#define PID_STR "pid="
#define ADDRESS_STR "address="
#define PORT_STR "port="

void dump_hex(FILE *file, const uint8_t *ptr, uint16_t len) {

  uint32_t i;

  for (i = 0; i < len; i++) {
    if (i && !(i % 8)) {
      fprintf(file, " ");
    }
    fprintf(file, "%02x", ptr[i]);
  }
}

void dump_msg(FILE *file, const Msg *msg) {

  fprintf(file, "SEND >> (03 + %04d) %02x %04x ", msg->st.len, msg->st.cmd,
          msg->st.len);

  dump_hex(file, msg->st.data, msg->st.len);

  fprintf(file, "\n");
}

void dump_response(FILE *file, const Msg *msg) {

  fprintf(file, "RECV << (03 + %04d) %02x %04x ", msg->st.len, msg->st.cmd,
          msg->st.len);

  dump_hex(file, msg->st.data, msg->st.len);

  fprintf(file, " \n");
}

void parse_status_data(char *data, yh_connector *connector) {

  char *saveptr = NULL;
  char *str = NULL;

  while ((str = strtok_r(str ? NULL : data, "\n", &saveptr))) {
    if (strncmp(str, STATUS_STR, strlen(STATUS_STR)) == 0) {
      if (strcmp(str + strlen(STATUS_STR), "OK") == 0) {
        connector->has_device = true;
      } else {
        connector->has_device = false;
      }
    } else if (strncmp(str, VERSION_STR, strlen(VERSION_STR)) == 0) {
      unsigned long v_maj = 0;
      unsigned long v_min = 0;
      unsigned long v_pat = 0;

      str = str + strlen(VERSION_STR);
      if (sscanf(str, "%lu.%lu.%lu", &v_maj, &v_min, &v_pat) == 0) {
        DBG_ERR("Unable to parse version string");
        continue;
      }

      connector->version_major = v_maj;
      connector->version_minor = v_min;
      connector->version_patch = v_pat;
    } else if (strncmp(str, PID_STR, strlen(PID_STR)) == 0) {
      char *endptr;
      unsigned long pid;

      str = str + strlen(PID_STR);
      errno = 0;
      pid = strtoul(str, &endptr, 0);
      if ((errno == ERANGE && pid == ULONG_MAX) || (errno != 0 && pid == 0)) {
        continue;
      }

      if (endptr == str || pid == 0) {
        continue;
      }

      connector->pid = pid;
    } else if (strncmp(str, ADDRESS_STR, strlen(ADDRESS_STR)) == 0) {
      strncpy((char *) connector->address, str + strlen(ADDRESS_STR),
              sizeof(connector->address) - 1);
    } else if (strncmp(str, PORT_STR, strlen(PORT_STR)) == 0) {
      char *endptr;
      unsigned long port;

      str = str + strlen(PORT_STR);
      errno = 0;
      port = strtoul(str, &endptr, 0);
      if ((errno == ERANGE && port == ULONG_MAX) || (errno != 0 && port == 0)) {
        continue;
      }

      if (endptr == str || port == 0) {
        continue;
      }

      connector->port = port;
    }
  }

  DBG_INFO("response from connector");
  DBG_INFO("has device: %s", connector->has_device == true ? "yes" : "no");
  DBG_INFO("version: %d.%d.%d", connector->version_major,
           connector->version_minor, connector->version_patch);
  DBG_INFO("pid: %u", connector->pid);
  DBG_INFO("address: %s", connector->address);
  DBG_INFO("port: %u", connector->port);

  return;
}

bool parse_usb_url(const char *url, unsigned long *serial) {
  if (strncmp(url, YH_USB_URL_SCHEME, strlen(YH_USB_URL_SCHEME)) == 0) {
    url += strlen(YH_USB_URL_SCHEME);
    char *copy = strdup(url);
    char *str = NULL;
    char *saveptr = NULL;

    // if we don't find a serial we still want to return serial 0
    *serial = 0;

    while ((str = strtok_r(str ? NULL : copy, "&", &saveptr))) {
      if (strncmp(str, "serial=", strlen("serial=")) == 0) {
        char *endptr;
        str += strlen("serial=");

        errno = 0;
        *serial = strtoul(str, &endptr, 0);
        if ((errno == ERANGE && *serial == ULONG_MAX) || endptr == str ||
            (errno != 0 && *serial == 0)) {
          *serial = 0;
          DBG_INFO("Failed to parse serial argument: '%s'.", str);
        }
      } else {
        DBG_INFO("Unknown USB option '%s'.", str);
      }
    }
    DBG_INFO("USB url parsed with serial %lu.", *serial);
    free(copy);
    return true;
  }
  return false;
}
