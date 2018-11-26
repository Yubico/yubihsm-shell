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
#include <stdio.h>
#include <string.h>

#include "yubihsm.h"
#include "internal.h"

uint8_t _yh_verbosity = YH_VERB_ALL;
FILE *_yh_output;

static void test_urls(void) {
  struct {
    const char *string;
    unsigned long serial;
    bool ret;
  } tests[] = {
    {"yhusb://serial=12345", 12345, true},
    {"", 0, false},
    {"yhusb://", 0, true},
    {"yhusb://foo=bar&serial=1000000", 1000000, true},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    unsigned long serial = 0;
    assert(parse_usb_url(tests[i].string, &serial) == tests[i].ret);
    if (tests[i].ret) {
      assert(serial == tests[i].serial);
    }
  }
}

int main(void) {
  _yh_output = stderr;
  test_urls();
}
