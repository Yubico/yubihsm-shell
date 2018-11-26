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

#include <stdlib.h>
#include <string.h>

#include "debug_p11.h"
#include "yubihsm.h"

int _YHP11_DBG = 0;
int _YHP11_DINOUT = 0;
FILE *_YHP11_OUTPUT = NULL;

void yh_dbg_init(int dbg, int dinout, int libdbg, const char *debug_file) {
  if (_YHP11_OUTPUT != stderr && _YHP11_OUTPUT != stdout &&
      _YHP11_OUTPUT != NULL) {
    fclose(_YHP11_OUTPUT);
    _YHP11_OUTPUT = stderr;
  }
  if (strcmp(debug_file, "stderr") == 0) {
    _YHP11_OUTPUT = stderr;
  } else if (strcmp(debug_file, "stdout") == 0) {
    _YHP11_OUTPUT = stdout;
  } else {
    FILE *file = fopen(debug_file, "a");
    if (file) {
      _YHP11_OUTPUT = file;
    } else {
      _YHP11_OUTPUT = stderr;
    }
  }
  yh_set_debug_output(NULL, _YHP11_OUTPUT);
  if (dbg || getenv("YUBIHSM_PKCS11_DBG")) {
    _YHP11_DBG = 1;
  }
  if (dinout || getenv("YUBIHSM_PKCS11_DINOUT")) {
    _YHP11_DINOUT = 1;
  }
  if (libdbg || getenv("YUBIHSM_LIB_DBG")) {
    yh_set_verbosity(NULL, YH_VERB_ALL);
  }
}
