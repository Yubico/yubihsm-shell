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

#ifndef DEBUG_H
#define DEBUG_H

#include "../common/platform-config.h"
#include "time_win.h"

#ifdef _MSVC
#include <winsock.h>
#endif

#define ANSI_RED "\x1b[31m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_BLUE "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN "\x1b[36m"
#define ANSI_RESET "\x1b[0m"

#ifdef _MSVC
#define localtime_r(a, b) localtime_s(b, a)
#define __FILENAME__                                                           \
  (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define __FILENAME__                                                           \
  (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define D(var, file, col, who, lev, ...)                                       \
  if (var) {                                                                   \
    struct timeval _tv;                                                        \
    struct tm _tm;                                                             \
    char _tbuf[20];                                                            \
    time_t _tsecs;                                                             \
    gettimeofday(&_tv, NULL);                                                  \
    _tsecs = _tv.tv_sec;                                                       \
    localtime_r(&_tsecs, &_tm);                                                \
    strftime(_tbuf, 20, "%H:%M:%S", &_tm);                                     \
    fprintf(file, "[" col who " - " lev ANSI_RESET " %s.%06ld] ", _tbuf,       \
            (long) _tv.tv_usec);                                               \
    fprintf(file, "%s:%d (%s): ", __FILENAME__, __LINE__, __func__);           \
    fprintf(file, __VA_ARGS__);                                                \
  }

#define DLN(var, file, col, who, lev, ...)                                     \
  if (var) {                                                                   \
    D(var, file != NULL ? file : stderr, col, who, lev, __VA_ARGS__);          \
    fprintf(file != NULL ? file : stderr, "\n");                               \
  }

#endif
