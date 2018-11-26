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

#ifndef DEBUG_LIB_H
#define DEBUG_LIB_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "yubihsm.h"

#include "../common/debug.h"

extern uint8_t _yh_verbosity;
extern FILE *_yh_output;

#define DUMPIF(var, len, lev)                                                  \
  do {                                                                         \
    if (_yh_verbosity & lev) {                                                 \
      dump_hex(_yh_output, var, len);                                          \
      fprintf(_yh_output, "\n");                                               \
    }                                                                          \
  } while (0)

#define DBG_INT(var, len, ...)                                                 \
  do {                                                                         \
    D(_yh_verbosity &YH_VERB_INTERMEDIATE, _yh_output, ANSI_YELLOW, "LIB",     \
      "INT", __VA_ARGS__);                                                     \
    DUMPIF(var, len, YH_VERB_INTERMEDIATE);                                    \
  } while (0)

#define DBG_CRYPTO(var, len, ...)                                              \
  do {                                                                         \
    D(_yh_verbosity &YH_VERB_CRYPTO, _yh_output, ANSI_GREEN, "LIB", "CRY",     \
      __VA_ARGS__);                                                            \
    DUMPIF(var, len, YH_VERB_CRYPTO);                                          \
  } while (0)

#define DBG_NET(var, dump)                                                     \
  do {                                                                         \
    D(_yh_verbosity &YH_VERB_RAW, _yh_output, ANSI_MAGENTA, "LIB", "NET",      \
      " ");                                                                    \
    if (_yh_verbosity & YH_VERB_RAW) {                                         \
      dump(_yh_output, (var));                                                 \
    }                                                                          \
  } while (0)

#define DBG_INFO(...)                                                          \
  do {                                                                         \
    DLN(_yh_verbosity &YH_VERB_INFO, _yh_output, ANSI_BLUE, "LIB", "INF",      \
        __VA_ARGS__);                                                          \
  } while (0)

#define DBG_DUMPINFO(var, len, ...)                                            \
  do {                                                                         \
    D(_yh_verbosity &YH_VERB_INFO, _yh_output, ANSI_BLUE, "LIB", "INF",        \
      __VA_ARGS__);                                                            \
    DUMPIF(var, len, YH_VERB_INFO);                                            \
  } while (0)

#define DBG_ERR(...)                                                           \
  do {                                                                         \
    DLN(_yh_verbosity &YH_VERB_ERR, _yh_output, ANSI_RED, "LIB", "ERR",        \
        __VA_ARGS__);                                                          \
  } while (0)
#endif

#define DBG_DUMPERR(var, len, ...)                                             \
  do {                                                                         \
    D(_yh_verbosity &YH_VERB_ERR, _yh_output, ANSI_RED, "LIB", "ERR",          \
      __VA_ARGS__);                                                            \
    DUMPIF(var, len, YH_VERB_ERR);                                             \
  } while (0)
