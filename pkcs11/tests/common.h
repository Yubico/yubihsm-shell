/*
 * Copyright 2021 Yubico AB
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

#ifndef YUBIHSM_PKCS11_TESTS_COMMON_H
#define YUBIHSM_PKCS11_TESTS_COMMON_H

#include <stdbool.h>
#include "../pkcs11y.h"

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

void *open_module(const char *path);
void close_module(void *handle);
CK_FUNCTION_LIST_PTR get_function_list(void *handle);
CK_SESSION_HANDLE open_session(CK_FUNCTION_LIST_PTR p11);
void close_session(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
void print_session_state(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
bool destroy_object(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE key);

#endif
