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

#include "ykyh.h"

#include <stddef.h>

#define ERR(name, desc)                                                        \
  { name, #name, desc }

typedef struct {
  ykyh_rc rc;
  const char *name;
  const char *description;
} err_t;

static const err_t errors[] = {
  ERR(YKYHR_SUCCESS, "Successful return"),
  ERR(YKYHR_MEMORY_ERROR, "Error allocating memory"),
  ERR(YKYHR_PCSC_ERROR, "Error in PCSC call"),
  ERR(YKYHR_GENERIC_ERROR, "Something went wrong"),
  ERR(YKYHR_WRONG_PW, "Wrong Password"),
  ERR(YKYHR_INVALID_PARAMS, "Invalid argument to a function"),
  ERR(YKYHR_ENTRY_NOT_FOUND, "Entry not found"),
};

const char *ykyh_strerror(ykyh_rc err) {
  static const char *unknown = "Unknown ykyh error";
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

const char *ykyh_strerror_name(ykyh_rc err) {
  if (-err < 0 || -err >= (int) (sizeof(errors) / sizeof(errors[0]))) {
    return NULL;
  }

  return errors[-err].name;
}
