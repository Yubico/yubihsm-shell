/*
* Copyright 2024 Yubico AB
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
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "../pkcs11y.h"
#include "common.h"

CK_VOID_PTR funcs;

static CK_C_GetInterface get_interface_function(void *handle) {
  CK_C_GetInterface fn;
  *(void **) (&fn) = dlsym(handle, "C_GetInterface");
  assert(fn != NULL);
  return fn;
}

static void get_default_functions(void *handle) {
 funcs = get_function_list(handle);
}

static void get_named_functions(void *handle) {
 CK_C_GetInterface fn = get_interface_function(handle);
 CK_INTERFACE_PTR interface;
 assert(fn((CK_UTF8CHAR_PTR)"PKCS 11", NULL, &interface, 0) == CKR_OK);
 funcs = interface->pFunctionList;
}

static void get_versioned_functions(void *handle, CK_BYTE major, CK_BYTE minor) {
 CK_C_GetInterface fn = get_interface_function(handle);
 CK_INTERFACE_PTR interface;
 CK_VERSION version;
 version.major=major;
 version.minor=minor;
 assert(fn(NULL,&version,&interface,0) == CKR_OK);
 funcs = interface->pFunctionList;
}

static void test_lib_info(CK_ULONG vmajor, CK_ULONG vminor) {
 const CK_CHAR_PTR MANUFACTURER_ID = (const CK_CHAR_PTR)"Yubico (www.yubico.com)";
 const CK_CHAR_PTR PKCS11_DESCRIPTION = (const CK_CHAR_PTR)"YubiHSM PKCS#11 Library";

 CK_C_INITIALIZE_ARGS initArgs;
 memset(&initArgs, 0, sizeof(initArgs));

 const char *connector_url;
 connector_url = getenv("DEFAULT_CONNECTOR_URL");
 if (connector_url == NULL) {
   connector_url = DEFAULT_CONNECTOR_URL;
 }
 char config[256] = {0};
 assert(strlen(connector_url) + strlen("connector=") < 256);
 snprintf(config, sizeof(config), "connector=%s", connector_url);
 initArgs.pReserved = (void *) config;
 assert(((CK_FUNCTION_LIST_3_0*)funcs)->C_Initialize(&initArgs) == CKR_OK);

 CK_INFO info;
 assert(((CK_FUNCTION_LIST_3_0*)funcs)->C_GetInfo(&info) == CKR_OK);
 assert(strncmp((const char*)info.manufacturerID, (const char*)MANUFACTURER_ID, strlen((const char*)MANUFACTURER_ID)) == 0);

 assert(info.cryptokiVersion.major == vmajor);
 assert(info.cryptokiVersion.minor == vminor);
 assert(info.libraryVersion.major == VERSION_MAJOR);
 assert(info.libraryVersion.minor == ((VERSION_MINOR * 10) + VERSION_PATCH));
 assert(strncmp((const char*)info.libraryDescription, (const char*)PKCS11_DESCRIPTION, strlen((const char*)PKCS11_DESCRIPTION)) == 0);
 assert(((CK_FUNCTION_LIST_3_0*)funcs)->C_Finalize(NULL) == CKR_OK);
}

int main(int argc, char **argv) {

 if (argc != 2) {
   fprintf(stderr, "usage: /path/to/yubihsm_pkcs11/module\n");
   exit(EXIT_FAILURE);
 }

 void *handle = open_module(argv[1]);
 get_default_functions(handle);
 test_lib_info(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);
 assert(((CK_FUNCTION_LIST_3_0*)funcs)->C_SignMessage(0, NULL, 0, NULL, 0, NULL, NULL) == CKR_FUNCTION_NOT_SUPPORTED);

 get_versioned_functions(handle, CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR);
 test_lib_info(CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR);

 get_versioned_functions(handle, CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);
 test_lib_info(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);

 get_named_functions(handle);
 test_lib_info(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);

 return EXIT_SUCCESS;
}
