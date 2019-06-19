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

#ifndef YUBICOM_PARSING_H
#define YUBICOM_PARSING_H

#include <stdbool.h>
#include <stdlib.h>

// NOTE(adma): those utility functions do not link against libyubihsm

#define READ_STR_PROMPT_BASE "Enter %s: "
#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

enum input_visibility { VISIBLE, HIDDEN_CHECKED, HIDDEN_UNCHECKED };

bool YH_INTERNAL read_string(const char *name, char *str_buf,
                             size_t str_buf_len,
                             enum input_visibility visibility);

#endif
