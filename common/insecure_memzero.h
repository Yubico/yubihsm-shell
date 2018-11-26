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

#ifndef YUBICOM_MEMZERO_H
#define YUBICOM_MEMZERO_H

#ifdef _WIN32
#include <windows.h>
#define insecure_memzero(buf, len) SecureZeroMemory(buf, len)
#elif HAVE_MEMSET_S
#include <string.h>
#define insecure_memzero(buf, len) memset_s(buf, len, 0, len)
#elif HAVE_EXPLICIT_BZERO
#include <string.h>
#define insecure_memzero(buf, len) explicit_bzero(buf, len)
#else
#include <openssl/crypto.h>
#define insecure_memzero(buf, len) OPENSSL_cleanse(buf, len)
#endif

#endif
