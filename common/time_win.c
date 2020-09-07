/*
 * Copyright 2020 Yubico AB
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

#include "time_win.h"
#include <winsock2.h>

int gettimeofday_win(struct timeval *tv) {
  // There's no equivalent implementation of gettimeofday() on Window
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec;
  return 0;
}
