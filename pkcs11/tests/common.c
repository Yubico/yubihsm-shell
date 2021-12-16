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

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "common.h"

void *open_module(const char *path) {
  void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
  assert(handle != NULL);
  return handle;
}

void close_module(void *handle) {
  assert(handle != NULL);
  int r = dlclose(handle);
  assert(r == 0);
}

CK_FUNCTION_LIST_PTR get_function_list(void *handle) {
  CK_C_GetFunctionList fn;
  *(void **) (&fn) = dlsym(handle, "C_GetFunctionList");
  assert(fn != NULL);

  CK_FUNCTION_LIST_PTR p11 = NULL;
  CK_RV rv = fn(&p11);
  assert(rv == CKR_OK);

  return p11;
}

CK_SESSION_HANDLE open_session(CK_FUNCTION_LIST_PTR p11) {
  CK_SESSION_HANDLE session = 0;
  CK_C_INITIALIZE_ARGS initArgs = {0};

  char config[256] = {0};
  const char *connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url) {
    assert(strlen(connector_url) + strlen("connector=") < 256);
    sprintf(config, "connector=%s", connector_url);
    initArgs.pReserved = (void *) config;
  }

  CK_RV rv = p11->C_Initialize(&initArgs);
  assert(rv == CKR_OK);

  rv = p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
                          &session);
  assert(rv == CKR_OK);

  char password[] = "0001password";
  rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) password,
                    (CK_ULONG) strlen(password));
  assert(rv == CKR_OK);
  printf("Session open and authenticated\n");

  return session;
}

void close_session(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session) {
  CK_RV rv = p11->C_Logout(session);
  assert(rv == CKR_OK);

  rv = p11->C_CloseSession(session);
  assert(rv == CKR_OK);

  rv = p11->C_Finalize(NULL);
  assert(rv == CKR_OK);
}

void print_session_state(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session) {
  CK_SESSION_INFO pInfo;
  CK_RV rv = p11->C_GetSessionInfo(session, &pInfo);
  assert(rv == CKR_OK);
  CK_STATE state = pInfo.state;

  printf("session state: ");
  switch (state) {
    case 0:
      printf("read-only public session\n");
      break;
    case 1:
      printf("read-only user functions\n");
      break;
    case 2:
      printf("read-write public session\n");
      break;
    case 3:
      printf("read-write user functions\n");
      break;
    case 4:
      printf("read-write so functions\n");
      break;
    default:
      printf("unknown state\n");
      break;
  }
}

bool destroy_object(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE key) {
  if ((p11->C_DestroyObject(session, key)) != CKR_OK) {
    printf("WARN. Failed to destroy object 0x%lx on HSM. FAIL\n", key);
    return false;
  }
  return true;
}
