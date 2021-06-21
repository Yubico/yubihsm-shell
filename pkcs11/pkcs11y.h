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

#ifndef PKCS11Y_H
#define PKCS11Y_H

#include <stdbool.h>

#ifdef CRYPTOKI_EXPORTS
#ifdef _WIN32
#define CK_SPEC __declspec(dllexport)
#else
#define CK_SPEC __attribute__((visibility("default")))
#endif
#else
#define CK_SPEC
#endif

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#define CRYPTOKI_LEGACY_VERSION_MAJOR 2
#define CRYPTOKI_LEGACY_VERSION_MINOR 40

#define CK_PTR *
#define CK_BOOL bool
#define CK_HANDLE void *
#define CK_DECLARE_FUNCTION(returnType, name) returnType CK_SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#define CK_DEFINE_FUNCTION(returnType, name) returnType CK_SPEC name

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "pkcs11.h"

#ifdef __cplusplus
}
#endif

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

/* This is an offset for the vendor definitions to avoid clashes */
#define YUBICO_BASE_VENDOR 0x59554200

#define CKK_YUBICO_AES128_CCM_WRAP                                             \
  (CKK_VENDOR_DEFINED | YUBICO_BASE_VENDOR | YH_ALGO_AES128_CCM_WRAP)
#define CKK_YUBICO_AES192_CCM_WRAP                                             \
  (CKK_VENDOR_DEFINED | YUBICO_BASE_VENDOR | YH_ALGO_AES192_CCM_WRAP)
#define CKK_YUBICO_AES256_CCM_WRAP                                             \
  (CKK_VENDOR_DEFINED | YUBICO_BASE_VENDOR | YH_ALGO_AES256_CCM_WRAP)

#define CKM_YUBICO_AES_CCM_WRAP                                                \
  (CKM_VENDOR_DEFINED | YUBICO_BASE_VENDOR | YH_WRAP_KEY)

#endif
