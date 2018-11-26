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

#ifndef DEBUG_P11_H
#define DEBUG_P11_H

#include <stdio.h>
#include <stdlib.h>

#include "../common/debug.h"

extern int _YHP11_DBG;
extern int _YHP11_DINOUT;
extern FILE *_YHP11_OUTPUT;

void yh_dbg_init(int dbg, int dinout, int libdbg, const char *debug_file);

#define DBG_INFO(...)                                                          \
  do {                                                                         \
    DLN(_YHP11_DBG, _YHP11_OUTPUT, ANSI_BLUE, "P11", "INF", __VA_ARGS__);      \
  } while (0)

#define DBG_WARN(...)                                                          \
  do {                                                                         \
    DLN(_YHP11_DBG, _YHP11_OUTPUT, ANSI_YELLOW, "P11", "WRN", __VA_ARGS__);    \
  } while (0)

#define DBG_ERR(...)                                                           \
  do {                                                                         \
    DLN(_YHP11_DBG, _YHP11_OUTPUT, ANSI_RED, "P11", "ERR", __VA_ARGS__);       \
  } while (0)

#define DIN                                                                    \
  do {                                                                         \
    DLN(_YHP11_DINOUT, _YHP11_OUTPUT, ANSI_BLUE, "P11", "INF", ("In"));        \
  } while (0)

#define DOUT                                                                   \
  do {                                                                         \
    DLN(_YHP11_DINOUT, _YHP11_OUTPUT, ANSI_BLUE, "P11", "INF", ("Out"));       \
  } while (0)

#endif
