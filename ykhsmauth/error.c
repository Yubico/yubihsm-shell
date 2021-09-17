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

#include "ykhsmauth.h"

#include <stddef.h>

#define ERR(name, desc)                                                        \
  { name, #name, desc }

typedef struct {
  ykhsmauth_rc rc;
  const char *name;
  const char *description;
} err_t;

static const err_t errors[] = {
  ERR(YKHSMAUTHR_SUCCESS, "Successful return"),
  ERR(YKHSMAUTHR_MEMORY_ERROR, "Device memory error"),
  ERR(YKHSMAUTHR_PCSC_ERROR, "Error in PCSC call"),
  ERR(YKHSMAUTHR_GENERIC_ERROR, "General device error"),
  ERR(YKHSMAUTHR_WRONG_PW, "Wrong Password/Authentication key"),
  ERR(YKHSMAUTHR_INVALID_PARAMS, "Invalid argument to a device command"),
  ERR(YKHSMAUTHR_ENTRY_NOT_FOUND, "Entry not found"),
  ERR(YKHSMAUTHR_STORAGE_FULL, "Device storage full"),
  ERR(YKHSMAUTHR_TOUCH_ERROR, "Device not touched"),
  ERR(YKHSMAUTHR_ENTRY_INVALID, "Entry invalid"),
  ERR(YKHSMAUTHR_DATA_INVALID, "Invalid authentication data"),
  ERR(YKHSMAUTHR_NOT_SUPPORTED, "Device command not supported"),
};

const char *ykhsmauth_strerror(ykhsmauth_rc err) {
  static const char *unknown = "Unknown ykhsmauth error";
  const char *p;

  if (-err < 0 || -err >= (int) (sizeof(errors) / sizeof(errors[0]))) {
    return unknown;
  }

  p = errors[-err].description;
  if (!p) {
    p = unknown;
  }

  return p;
}

const char *ykhsmauth_strerror_name(ykhsmauth_rc err) {
  if (-err < 0 || -err >= (int) (sizeof(errors) / sizeof(errors[0]))) {
    return NULL;
  }

  return errors[-err].name;
}
