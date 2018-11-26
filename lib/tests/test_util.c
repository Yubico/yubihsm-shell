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

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "yubihsm.h"
#include "internal.h"

uint8_t _yh_verbosity;
FILE *_yh_output;

static void test_status(void) {
  struct {
    const char *data;
    yh_connector c;
  } tests[] = {
    {"status=OK\nversion=1.2.3\n",
     {NULL, NULL, NULL, NULL, NULL, true, 1, 2, 3, "", 0, 0}},
    {"", {NULL, NULL, NULL, NULL, NULL, false, 0, 0, 0, "", 0, 0}},
    {"foobar", {NULL, NULL, NULL, NULL, NULL, false, 0, 0, 0, "", 0, 0}},
    {"\n\n\n\n\n\n", {NULL, NULL, NULL, NULL, NULL, false, 0, 0, 0, "", 0, 0}},
    {"status=NO_DEVICE\nserial=*\nversion=1.0.2\npid=412\naddress=\nport=12345",
     {NULL, NULL, NULL, NULL, NULL, false, 1, 0, 2, "", 12345, 412}},
    {"version=1.2", {NULL, NULL, NULL, NULL, NULL, false, 1, 2, 0, "", 0, 0}},
    {"version=foobar",
     {NULL, NULL, NULL, NULL, NULL, false, 0, 0, 0, "", 0, 0}},
    {"version=2..\nstatus=OK",
     {NULL, NULL, NULL, NULL, NULL, true, 2, 0, 0, "", 0, 0}},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    yh_connector c = {NULL, NULL, NULL, NULL, NULL, false, 0, 0, 0, "", 0, 0};
    char *data = strdup(tests[i].data);

    parse_status_data(data, &c);
    free(data);
    assert(memcmp(&c, &tests[i].c, sizeof(c)) == 0);
  }
}

int main(void) {
  _yh_output = stderr;
  _yh_verbosity = 0;

  test_status();
}
