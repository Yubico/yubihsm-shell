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

#ifndef YKYH_INTERNAL_H
#define YKYH_INTERNAL_H

#include <stdbool.h>

//#if BACKEND_PCSC
//#if defined HAVE_PCSC_WINSCARD_H
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
//#else
//# include <winscard.h>
//#endif
//#endif

#define READER_LEN 32
#define MAX_READERS 16

struct ykyh_state {
  SCARDCONTEXT context;
  SCARDHANDLE card;
  int verbose;
};

union u_APDU {
  struct {
    unsigned char cla;
    unsigned char ins;
    unsigned char p1;
    unsigned char p2;
    unsigned char lc;
    unsigned char data[0xff];
  } st;
  unsigned char raw[0xff + 5];
};

typedef union u_APDU APDU;

unsigned const char aid[] = {0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07};

#endif
