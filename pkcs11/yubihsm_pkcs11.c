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

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <cmdline.h>
#include <yubihsm.h>

#include <openssl/rsa.h>

#include "debug_p11.h"
#include "util_pkcs11.h"
#include "yubihsm_pkcs11.h"
#include "../common/insecure_memzero.h"
#include "../common/parsing.h"
#include "../common/util.h"

#ifdef __WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#ifdef _MSVC
#define strtok_r strtok_s
#endif

#define YUBIHSM_PKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YUBIHSM_PKCS11_LIBDESC "YubiHSM PKCS#11 Library"
#define YUBIHSM_PKCS11_MIN_PIN_LEN 8
#define YUBIHSM_PKCS11_MAX_PIN_LEN 64

#define UNUSED(x) (void) (x) // TODO(adma): also in yubihsm-shell.h

#define GLOBAL_LOCK_OR_RETURN                                                  \
  do {                                                                         \
    if (g_ctx.mutex != NULL) {                                                 \
      CK_RV lock_rv = g_ctx.lock_mutex(g_ctx.mutex);                           \
      if (lock_rv != CKR_OK) {                                                 \
        DBG_ERR("Unable to acquire global lock");                              \
        return lock_rv;                                                        \
      }                                                                        \
    }                                                                          \
  } while (0)

#define GLOBAL_UNLOCK_OR_RETURN                                                \
  do {                                                                         \
    if (g_ctx.mutex != NULL) {                                                 \
      CK_RV lock_rv = g_ctx.unlock_mutex(g_ctx.mutex);                         \
      if (lock_rv != CKR_OK) {                                                 \
        DBG_ERR("Unable to release global lock");                              \
        return lock_rv;                                                        \
      }                                                                        \
    }                                                                          \
  } while (0)

static const CK_FUNCTION_LIST function_list;
static const CK_FUNCTION_LIST_3_0 function_list_3;

static const CK_INTERFACE interfaces_list[] =
  {{(CK_CHAR_PTR) "PKCS 11", (CK_VOID_PTR) &function_list_3, 0},
   {(CK_CHAR_PTR) "PKCS 11", (CK_VOID_PTR) &function_list, 0}};

static bool g_yh_initialized = false;

static yubihsm_pkcs11_context g_ctx;

static void destroy_slot_mutex(void *data) {
  yubihsm_pkcs11_slot *slot = (yubihsm_pkcs11_slot *) data;
  if (slot->mutex != NULL) {
    g_ctx.destroy_mutex(slot->mutex);
  }

  slot->mutex = NULL;
}

static bool compare_ecdh_keys(void *data, void *item) {
  if (data == NULL || item == NULL) {
    return false;
  }

  CK_OBJECT_HANDLE *a = data;

  ListItem *itm = (ListItem *) item;
  ecdh_session_key *key = (ecdh_session_key *) &itm->data;
  CK_OBJECT_HANDLE b = key->id;

  return *a == b;
}

/* General Purpose */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs) {

  DIN;

  if (g_yh_initialized == true) {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  CK_C_INITIALIZE_ARGS_PTR init_args = pInitArgs;

  yh_dbg_init(false, false, 0, "stderr");

  if (pInitArgs != NULL) {
    if ((init_args->flags & CKF_OS_LOCKING_OK) == 0 &&
        init_args->CreateMutex == NULL && init_args->DestroyMutex == NULL &&
        init_args->LockMutex == NULL && init_args->UnlockMutex == NULL) {
      // NOTE(adma): no threading required
      // all is good, do nothing
      g_ctx.create_mutex = NULL;
      g_ctx.destroy_mutex = NULL;
      g_ctx.lock_mutex = NULL;
      g_ctx.unlock_mutex = NULL;
    } else if ((init_args->flags & CKF_OS_LOCKING_OK) != 0 &&
               init_args->CreateMutex == NULL &&
               init_args->DestroyMutex == NULL &&
               init_args->LockMutex == NULL && init_args->UnlockMutex == NULL) {
      // NOTE(adma): threading with native OS locks
      set_native_locking(&g_ctx);
    } else if ((init_args->flags & CKF_OS_LOCKING_OK) == 0 &&
               init_args->CreateMutex != NULL &&
               init_args->DestroyMutex != NULL &&
               init_args->LockMutex != NULL && init_args->UnlockMutex != NULL) {
      // NOTE(adma): threading with supplied functions
      g_ctx.create_mutex = init_args->CreateMutex;
      g_ctx.destroy_mutex = init_args->DestroyMutex;
      g_ctx.lock_mutex = init_args->LockMutex;
      g_ctx.unlock_mutex = init_args->UnlockMutex;
    } else if ((init_args->flags & CKF_OS_LOCKING_OK) != 0 &&
               init_args->CreateMutex != NULL &&
               init_args->DestroyMutex != NULL &&
               init_args->LockMutex != NULL && init_args->UnlockMutex != NULL) {
      // NOTE(adma): threading with native or supplied functions
      g_ctx.create_mutex = init_args->CreateMutex;
      g_ctx.destroy_mutex = init_args->DestroyMutex;
      g_ctx.lock_mutex = init_args->LockMutex;
      g_ctx.unlock_mutex = init_args->UnlockMutex;
    } else {
      DBG_ERR("Invalid locking specified");
      return CKR_ARGUMENTS_BAD;
    }
  }

  CK_RV rv = CKR_OK;

  if (g_ctx.create_mutex != NULL) {
    rv = g_ctx.create_mutex(&g_ctx.mutex);
    if (rv != CKR_OK) {
      DBG_ERR("Unable to create global mutex");
      return rv;
    }
  } else {
    g_ctx.mutex = NULL;
  }

  struct cmdline_parser_params params = {0};

  struct gengetopt_args_info args_info = {0};

  cmdline_parser_params_init(&params);

  params.initialize = 1;
  params.check_required = 1;

  char *tmp = "";

  if (cmdline_parser(0, &tmp, &args_info) != 0) {
    DBG_ERR("Unable to initialize ggo structure");
    return CKR_GENERAL_ERROR;
  }

  params.initialize = 0;
  params.override = 1;

  char *args = NULL;
  char *args_parsed = NULL;

  yh_connector **connector_list = NULL;

  if (init_args != NULL && init_args->pReserved != NULL) {
    args = strdup(init_args->pReserved);
    if (args == NULL) {
      DBG_ERR("Failed copying reserved string");
      return CKR_HOST_MEMORY;
    }

    char *str = args;
    char *save = NULL;
    char *part;
    while ((part = strtok_r(str, " \r\n\t", &save))) {
      str = NULL;
      size_t len = args_parsed ? strlen(args_parsed) : 0;
      char *new_args = realloc(args_parsed, len + strlen(part) + 4);
      if (new_args) {
        args_parsed = new_args;
        snprintf(args_parsed + len, strlen(part) + 4, "--%s ", part);
      } else {
        DBG_ERR("Failed allocating memory for args");
        rv = CKR_HOST_MEMORY;
        goto c_i_failure;
      }
    }

    DBG_INFO("Now parsing supplied init args as '%s'", args_parsed);

    if (cmdline_parser_string_ext(args_parsed, &args_info,
                                  "yubihsm_pkcs11 module", &params) != 0) {
      DBG_ERR("Parsing of the reserved init args '%s' failed", args);
      rv = CKR_GENERAL_ERROR;
      goto c_i_failure;
    }

    free(args);
    args = NULL;
    free(args_parsed);
    args_parsed = NULL;
  }

  // NOTE(thorduri): #TOCTOU
  char *config_file = args_info.config_file_arg;
  struct stat sb = {0};
  if (stat(config_file, &sb) == -1) {
    config_file = getenv("YUBIHSM_PKCS11_CONF");
  }

  params.override = 0;

  if (config_file != NULL &&
      cmdline_parser_config_file(config_file, &args_info, &params) != 0) {
    DBG_ERR("Unable to parse configuration file");
    rv = CKR_GENERAL_ERROR;
    goto c_i_failure;
  }

  yh_dbg_init(args_info.debug_flag, args_info.dinout_flag,
              args_info.libdebug_flag, args_info.debug_file_arg);

  // NOTE(adma): it's better to set the argument optional and check its presence
  // here
  if (args_info.connector_given == 0) {
    DBG_ERR("No connector defined");
    rv = CKR_ARGUMENTS_BAD;
    goto c_i_failure;
  }

  yh_rc yrc = yh_init();
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Unable to initialize libyubihsm: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_i_failure;
  }

  DBG_INFO("Found %u configured connector(s)", args_info.connector_given);

  connector_list = calloc(args_info.connector_given, sizeof(yh_connector *));
  if (connector_list == NULL) {
    DBG_ERR("Failed allocating memory");
    rv = CKR_HOST_MEMORY;
    goto c_i_failure;
  }
  size_t n_connectors = 0;
  for (unsigned int i = 0; i < args_info.connector_given; i++) {
    yrc = yh_init_connector(args_info.connector_arg[i], &connector_list[i]);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to init connector: %s", yh_strerror(yrc));
      rv = yrc_to_rv(yrc);
      goto c_i_failure;
    }
    if (args_info.cacert_given) {
      yrc = yh_set_connector_option(connector_list[i], YH_CONNECTOR_HTTPS_CA,
                                    args_info.cacert_arg);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed to set HTTPS CA option: %s", yh_strerror(yrc));
        rv = yrc_to_rv(yrc);
        goto c_i_failure;
      }
    }
    if (args_info.cert_given) {
      yrc = yh_set_connector_option(connector_list[i], YH_CONNECTOR_HTTPS_CERT,
                                    args_info.cert_arg);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed to set HTTPS cert option: %s", yh_strerror(yrc));
        rv = yrc_to_rv(yrc);
        goto c_i_failure;
      }
    }
    if (args_info.key_given) {
      yrc = yh_set_connector_option(connector_list[i], YH_CONNECTOR_HTTPS_KEY,
                                    args_info.key_arg);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed to set HTTPS key option: %s", yh_strerror(yrc));
        rv = yrc_to_rv(yrc);
        goto c_i_failure;
      }
    }
    if (args_info.proxy_given) {
      yrc =
        yh_set_connector_option(connector_list[i], YH_CONNECTOR_PROXY_SERVER,
                                args_info.proxy_arg);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed to set proxy server option: %s", yh_strerror(yrc));
        rv = yrc_to_rv(yrc);
        goto c_i_failure;
      }
    }
    if (args_info.noproxy_given) {
      yrc = yh_set_connector_option(connector_list[i], YH_CONNECTOR_NOPROXY,
                                    args_info.noproxy_arg);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed to set noproxy option: %s", yh_strerror(yrc));
        rv = yrc_to_rv(yrc);
        goto c_i_failure;
      }
    }

    yrc = yh_connect(connector_list[i], args_info.timeout_arg);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to connect to '%s': %s", args_info.connector_arg[i],
              yh_strerror(yrc));
      continue;
    } else {
      n_connectors++;
    }
  }

  rv = add_connectors(&g_ctx, args_info.connector_given,
                      args_info.connector_arg, connector_list);
  if (rv != CKR_OK) {
    DBG_ERR("Failed building connectors list");
    goto c_i_failure;
  }

  list_create(&g_ctx.device_pubkeys, YH_EC_P256_PUBKEY_LEN, NULL);
  for (unsigned int i = 0; i < args_info.device_pubkey_given; i++) {
    uint8_t pk[80] = {0};
    size_t pk_len = sizeof(pk);
    if (hex_decode(args_info.device_pubkey_arg[i], pk, &pk_len) == false ||
        pk_len != YH_EC_P256_PUBKEY_LEN) {
      DBG_ERR("Invalid device public key configured");
      rv = CKR_ARGUMENTS_BAD;
      goto c_i_failure;
    }
    list_append(&g_ctx.device_pubkeys, pk);
  }

  cmdline_parser_free(&args_info);
  free(connector_list);

  DBG_INFO("Found %zu usable connector(s)", n_connectors);

  DBG_INFO("Found %d configured device public key(s)",
           g_ctx.device_pubkeys.length);

  g_yh_initialized = true;

  DOUT;
  return CKR_OK;

c_i_failure:

  free(args_parsed);
  free(args);

  list_iterate(&g_ctx.slots, destroy_slot_mutex);
  list_destroy(&g_ctx.slots);
  list_destroy(&g_ctx.device_pubkeys);

  if (connector_list) {
    for (unsigned int i = 0; i < args_info.connector_given; i++) {
      yh_disconnect(connector_list[i]);
    }
  }

  cmdline_parser_free(&args_info);
  free(connector_list);

  if (g_ctx.mutex != NULL) {
    g_ctx.destroy_mutex(g_ctx.mutex);
    g_ctx.mutex = NULL;
  }

  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved) {

  DIN;

  if (pReserved != NULL) {
    DBG_ERR("Finalized called with pReserved != NULL");
    return CKR_ARGUMENTS_BAD;
  }

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  list_iterate(&g_ctx.slots, destroy_slot_mutex);
  list_destroy(&g_ctx.slots);
  list_destroy(&g_ctx.device_pubkeys);

  if (g_ctx.mutex != NULL) {
    g_ctx.destroy_mutex(g_ctx.mutex);
    g_ctx.mutex = NULL;
  }

  g_yh_initialized = false;

  yh_exit();

  DOUT;

  if (_YHP11_OUTPUT != stdout && _YHP11_OUTPUT != stderr &&
      _YHP11_OUTPUT != NULL) {
    fclose(_YHP11_OUTPUT);
    _YHP11_OUTPUT = stderr;
  }

  return CKR_OK;
}

static CK_RV C_GetInfo_Ex(CK_INFO_PTR pInfo, CK_VERSION cryptokiVersion) {

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  if (pInfo == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  pInfo->cryptokiVersion = cryptokiVersion;

  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  memcpy((char *) pInfo->manufacturerID, YUBIHSM_PKCS11_MANUFACTURER,
         strlen(YUBIHSM_PKCS11_MANUFACTURER));

  pInfo->flags = 0;

  memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
  memcpy((char *) pInfo->libraryDescription, YUBIHSM_PKCS11_LIBDESC,
         strlen(YUBIHSM_PKCS11_LIBDESC));

  CK_VERSION libraryVersion = {VERSION_MAJOR,
                               (VERSION_MINOR * 10) + VERSION_PATCH};

  pInfo->libraryVersion = libraryVersion;

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo) {

  DIN;

  CK_RV rv = C_GetInfo_Ex(pInfo, function_list.version);

  DOUT;
  return rv;
}

static CK_RV C_GetInfo_3_0(CK_INFO_PTR pInfo) {

  DIN;

  CK_RV rv = C_GetInfo_Ex(pInfo, function_list_3.version);

  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)
(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  yh_dbg_init(false, false, 0, "stderr");

  DIN;

  if (ppFunctionList == NULL) {
    DBG_ERR("GetFunctionList called with ppFunctionList = NULL");
    return CKR_ARGUMENTS_BAD;
  }

  *ppFunctionList = (CK_FUNCTION_LIST_PTR) &function_list;

  DOUT;
  return CKR_OK;
}

/* Slot and token management */

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (!pulCount) {
    DBG_ERR("pulCount argument bad");
    return CKR_ARGUMENTS_BAD;
  }

  GLOBAL_LOCK_OR_RETURN;

  if (pSlotList == NULL) {
    *pulCount = 0;
    // NOTE(adma) just return the number of slots
    if (tokenPresent == CK_TRUE) {
      for (ListItem *item = g_ctx.slots.head; item != NULL; item = item->next) {
        yubihsm_pkcs11_slot *slot = (yubihsm_pkcs11_slot *) item->data;
        if (yh_connector_has_device(slot->connector) == true) {
          *pulCount += 1;
        }
      }

      DBG_INFO("Number of slots with a token is %lu", *pulCount);
    } else {
      *pulCount = g_ctx.slots.length;

      DBG_INFO("Total number of slots is %lu", *pulCount);
    }
    // NOTE(adma): actually return the slot IDs
    DBG_INFO("Can return %lu slot(s)", *pulCount);

    GLOBAL_UNLOCK_OR_RETURN;

    DOUT;
    return CKR_OK;
  }

  uint16_t j = 0;
  bool full = false;
  bool overflow = false;
  for (ListItem *item = g_ctx.slots.head; item != NULL; item = item->next) {
    if (j == *pulCount) {
      full = true;
    }

    yubihsm_pkcs11_slot *slot = (yubihsm_pkcs11_slot *) item->data;
    if (tokenPresent == CK_TRUE) {
      if (yh_connector_has_device(slot->connector) != true) {
        continue;
      }
    }
    if (full == false) {
      pSlotList[j] = slot->id;

      DBG_INFO("Returning slot %lu", pSlotList[j]);
    } else {
      overflow = true;
    }

    j += 1;
  }

  *pulCount = j;

  if (overflow == true) {
    GLOBAL_UNLOCK_OR_RETURN;
    return CKR_BUFFER_TOO_SMALL;
  }

  GLOBAL_UNLOCK_OR_RETURN;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)
(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (!pInfo) {
    DBG_ERR("Invalid pInfo");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_slot *slot = get_slot(&g_ctx, slotID);
  if (slot == NULL) {
    DBG_ERR("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  char *s = "YubiHSM Connector ";
  size_t l = strlen(s);
  memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
  memcpy((char *) pInfo->slotDescription, s, l);

  yh_get_connector_address(slot->connector, &s);
  memcpy((char *) pInfo->slotDescription + l, s, strlen(s));

  s = "Yubico";
  l = strlen(s);
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  memcpy((char *) pInfo->manufacturerID, s, l);

  pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;

  if (yh_connector_has_device(slot->connector) == true) {
    pInfo->flags |= CKF_TOKEN_PRESENT;
  }

  uint8_t major = 0;
  uint8_t minor = 0;
  uint8_t patch = 0;

  yh_get_connector_version(slot->connector, &major, &minor, &patch);

  pInfo->hardwareVersion.major = major;
  pInfo->hardwareVersion.minor = (minor * 10) + patch;

  pInfo->firmwareVersion.major = major;
  pInfo->firmwareVersion.minor = (minor * 10) + patch;

  release_slot(&g_ctx, slot);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (!pInfo) {
    DBG_ERR("Invalid pInfo");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_slot *slot = get_slot(&g_ctx, slotID);
  if (slot == NULL) {
    DBG_ERR("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  CK_RV rv = CKR_OK;

  if (yh_connector_has_device(slot->connector) == false) {
    DBG_ERR("Slot %lu has no token inserted", slotID);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto c_gt_out;
  }

  char *s = "YubiHSM";
  size_t l = strlen(s);
  memset(pInfo->label, ' ', sizeof(pInfo->label));
  memcpy((char *) pInfo->label, s, l);

  s = YUBIHSM_PKCS11_MANUFACTURER;
  l = strlen(s);
  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  memcpy((char *) pInfo->manufacturerID, s, l);

  s = "YubiHSM";
  l = strlen(s);
  memset(pInfo->model, ' ', sizeof(pInfo->model));
  memcpy((char *) pInfo->model, s, l);

  memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
  l = snprintf((char *) pInfo->serialNumber, sizeof(pInfo->serialNumber),
               "%08u", slot->connector->device_info.serial);
  pInfo->serialNumber[l] = ' ';

  pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED |
                 CKF_TOKEN_INITIALIZED;

  pInfo->ulMaxSessionCount =
    CK_EFFECTIVELY_INFINITE;    // maximum number of sessions that can be opened
                                // with the token at one time by a single
                                // application
  pInfo->ulSessionCount =
    CK_UNAVAILABLE_INFORMATION; // number of sessions that this application
                                // currently has open with the token
  pInfo->ulMaxRwSessionCount =
    CK_EFFECTIVELY_INFINITE; // maximum number of read/write sessions that can
                             // be opened with the token at one time by a single
                             // application
  pInfo->ulRwSessionCount =
    CK_UNAVAILABLE_INFORMATION; // number of read/write sessions that this
                                // application currently has open with the token
  pInfo->ulMaxPinLen =
    YUBIHSM_PKCS11_MAX_PIN_LEN; // maximum length in bytes of the PIN
  pInfo->ulMinPinLen =
    YUBIHSM_PKCS11_MIN_PIN_LEN; // minimum length in bytes of the PIN
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  CK_VERSION ver = {slot->connector->device_info.major,
                    (slot->connector->device_info.minor * 10) +
                      slot->connector->device_info.patch};

  pInfo->hardwareVersion = ver;

  pInfo->firmwareVersion = ver;

  memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

  DOUT;

c_gt_out:

  release_slot(&g_ctx, slot);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {

  DIN;

  UNUSED(flags);
  UNUSED(pSlot);
  UNUSED(pReserved);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
 CK_ULONG_PTR pulCount) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulCount == NULL) {
    DBG_ERR("Wrong/missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_slot *slot = get_slot(&g_ctx, slotID);
  if (slot == NULL) {
    DBG_ERR("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  CK_RV rv = get_mechanism_list(slot, pMechanismList, pulCount);
  if (rv != CKR_OK) {
    DBG_ERR("Failed getting device info");
    goto c_gml_out;
  }

  DBG_INFO("Found %lu mechanisms", *pulCount);

  DOUT;

c_gml_out:

  release_slot(&g_ctx, slot);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG_ERR("Wrong/missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_slot *slot = get_slot(&g_ctx, slotID);
  if (slot == NULL) {
    DBG_ERR("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  CK_RV rv = get_mechanism_info(slot, type, pInfo);

  release_slot(&g_ctx, slot);

  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
 CK_UTF8CHAR_PTR pLabel) {

  DIN;

  UNUSED(slotID);
  UNUSED(pPin);
  UNUSED(ulPinLen);
  UNUSED(pLabel);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pPin);
  UNUSED(ulPinLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
 CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pOldPin);
  UNUSED(ulOldLen);
  UNUSED(pNewPin);
  UNUSED(ulNewLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
 CK_SESSION_HANDLE_PTR phSession) {

  DIN; // TODO(adma): check pApplication and Notify

  UNUSED(Notify);
  UNUSED(pApplication);

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL) {
    DBG_ERR("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if ((flags & CKF_SERIAL_SESSION) == 0) {
    // NOTE(adma): required by specs
    DBG_ERR("Open session called without CKF_SERIAL_SESSION set");
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  yubihsm_pkcs11_slot *slot = get_slot(&g_ctx, slotID);
  if (slot == NULL) {
    DBG_ERR("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  CK_RV rv = CKR_OK;

  if (yh_connector_has_device(slot->connector) == false) {
    DBG_ERR("Slot %lu has no token inserted", slotID);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto c_os_out;
  }

  // NOTE(adma): we have already checked that the connector is
  // connectable at this point. This function should only "allocate" a
  // session pointer

  if (create_session(slot, flags, phSession) == false) {
    DBG_ERR("Connector %lu has too many open sessions", slotID);
    rv = CKR_SESSION_COUNT;
    goto c_os_out;
  }

  DBG_INFO("Allocated session %lu", *phSession);

  DOUT;

c_os_out:

  release_slot(&g_ctx, slot);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv == CKR_OK) {
    if (session->slot->pkcs11_sessions.length == 1) {
      // NOTE: if this is the last session and is authenticated we need to
      // de-auth
      yh_rc yrc = yh_util_close_session(session->slot->device_session);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed closing device session: %s, continuing",
                yh_strerror(yrc));
      }

      yrc = yh_destroy_session(&session->slot->device_session);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed destroying session: %s", yh_strerror(yrc));
        // TODO: should we handle the error cases here better?
      }
      session->slot->device_session = NULL;
    }

    release_session(&g_ctx, session);
  } else if (rv == CKR_SESSION_HANDLE_INVALID) {
    // BUG(thorduri): piggybacking off of the validation in get_session()
    // above, which might not hold forever.
    DBG_ERR("Trying to close invalid session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session) {
    list_destroy(&session->ecdh_session_keys);
  }
  if (delete_session(&g_ctx, &hSession) == false) {
    DBG_ERR("Trying to close invalid session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  DBG_INFO("Closing session %lu", hSession);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_slot *slot = get_slot(&g_ctx, slotID);
  if (slot == NULL) {
    DBG_ERR("Invalid slot");
    return CKR_SLOT_ID_INVALID;
  }

  DBG_INFO("Closing all sessions for slot %lu", slotID);

  if (slot->device_session) {
    yh_rc yrc = yh_util_close_session(slot->device_session);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed closing device session: %s, continuing",
              yh_strerror(yrc));
    }
    yrc = yh_destroy_session(&slot->device_session);
    if (yrc != YHR_SUCCESS) {
      // TODO: handle or ignore these errrors?
      DBG_ERR("Failed destroying device session: %s", yh_strerror(yrc));
    }
    slot->device_session = NULL;
  }

  list_destroy(&slot->pkcs11_sessions);
  list_create(&slot->pkcs11_sessions, sizeof(yubihsm_pkcs11_session), NULL);

  release_slot(&g_ctx, slot);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG_ERR("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV ret = get_session(&g_ctx, hSession, &session, 0);
  if (ret != CKR_OK) {
    DBG_ERR("Session handle invalid");
    return ret;
  }

  pInfo->slotID = session->slot->id;
  pInfo->flags = 0;

  CK_RV rv = CKR_OK;

  switch (session->session_state) {
    case SESSION_RESERVED_RO:
      pInfo->state = CKS_RO_PUBLIC_SESSION;
      break;

    case SESSION_RESERVED_RW:
      pInfo->state = CKS_RW_PUBLIC_SESSION;
      pInfo->flags |= CKF_RW_SESSION;
      break;

    case SESSION_AUTHENTICATED_RO:
      pInfo->state = CKS_RO_USER_FUNCTIONS;
      break;

    case SESSION_AUTHENTICATED_RW:
      pInfo->state = CKS_RW_USER_FUNCTIONS;
      pInfo->flags |= CKF_RW_SESSION;
      break;

    default:
      DBG_ERR("Unknown session %lu", hSession);
      rv = CKR_SESSION_HANDLE_INVALID;
  }

  pInfo->flags |= CKF_SERIAL_SESSION;
  pInfo->ulDeviceError = 0;

  if (rv == CKR_OK) {
    DOUT;
  }

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
 CK_ULONG_PTR pulOperationStateLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pOperationState);
  UNUSED(pulOperationStateLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
 CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
 CK_OBJECT_HANDLE hAuthenticationKey) {

  DIN;

  UNUSED(hSession);
  UNUSED(pOperationState);
  UNUSED(ulOperationStateLen);
  UNUSED(hEncryptionKey);
  UNUSED(hAuthenticationKey);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

static void login_sessions(void *data) {
  yubihsm_pkcs11_session *session = (yubihsm_pkcs11_session *) data;
  switch (session->session_state) {
    case SESSION_RESERVED_RO:
      session->session_state = SESSION_AUTHENTICATED_RO;
      break;
    case SESSION_RESERVED_RW:
      session->session_state = SESSION_AUTHENTICATED_RW;
      break;
    case SESSION_AUTHENTICATED_RO:
    case SESSION_AUTHENTICATED_RW:
      break;
  }
}

static void logout_sessions(void *data) {
  yubihsm_pkcs11_session *session = (yubihsm_pkcs11_session *) data;
  switch (session->session_state) {
    case SESSION_AUTHENTICATED_RO:
      session->session_state = SESSION_RESERVED_RO;
      break;
    case SESSION_AUTHENTICATED_RW:
      session->session_state = SESSION_RESERVED_RW;
      break;
    case SESSION_RESERVED_RO:
    case SESSION_RESERVED_RW:
      break;
  }
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)
(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin,
 CK_ULONG ulPinLen) {

  DIN;

  if (pPin == NULL) {
    DBG_ERR("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  CK_ULONG ulUsernameLen = *pPin == '@' ? 5 : 4;

  if (ulUsernameLen > ulPinLen) {
    ulUsernameLen = ulPinLen;
  }

  CK_RV rv = C_LoginUser(hSession, userType, pPin + ulUsernameLen,
                         ulPinLen - ulUsernameLen, pPin, ulUsernameLen);

  DOUT;

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID: %lu", hSession);
    return rv;
  }

  yh_rc yrc = yh_util_close_session(session->slot->device_session);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed closing session: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_l_out;
  }

  yrc = yh_destroy_session(&session->slot->device_session);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Failed destroying session: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_l_out;
  }

  session->slot->device_session = NULL;

  list_iterate(&session->slot->pkcs11_sessions, logout_sessions);

  DOUT;

c_l_out:

  release_session(&g_ctx, session);

  return rv;
}

static yh_rc set_wrapkey_capabilities(yubihsm_pkcs11_object_template *template,
                                      yh_capabilities *capabilities) {
  yh_rc rc;
  if (template->wrap == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("export-wrapped", capabilities);
    if (rc != YHR_SUCCESS) {
      return rc;
    }
  }

  if (template->unwrap == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("import-wrapped", capabilities);
    if (rc != YHR_SUCCESS) {
      return rc;
    }
  }

  if (template->encrypt == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("wrap-data", capabilities);
    if (rc != YHR_SUCCESS) {
      return rc;
    }
  }

  if (template->decrypt == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("unwrap-data", capabilities);
    if (rc != YHR_SUCCESS) {
      return rc;
    }
  }

  return YHR_SUCCESS;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phObject) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL || ulCount == 0 || phObject == NULL) {
    DBG_ERR("Called with invalid parameters: pTemplate=%p ulCount=%lu "
            "phObject=%p",
            (void *) pTemplate, ulCount, (void *) phObject);
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED_RW);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID: %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("A different operation is already active");
    rv = CKR_OPERATION_ACTIVE;
    goto c_co_out;
  }

  struct {
    bool set;
    CK_ULONG d;
  } class = {0}, key_type = {0};
  yubihsm_pkcs11_object_template template = {0};
  pkcs11_meta_object meta_object = {0};
  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {
      case CKA_CLASS:
        if (class.set == false) {
          class.d = *((CK_ULONG_PTR) pTemplate[i].pValue);
          class.set = true;
        } else {
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_co_out;
        }
        break;

      case CKA_KEY_TYPE:
        if (key_type.set == false) {
          key_type.d = *((CK_ULONG_PTR) pTemplate[i].pValue);
          key_type.set = true;
        } else {
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_co_out;
        }
        break;

      case CKA_ID:
        rv =
          parse_meta_id_template(&template, &meta_object, false,
                                 pTemplate[i].pValue, pTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_LABEL:
        rv = parse_meta_label_template(&template, &meta_object, false,
                                       pTemplate[i].pValue,
                                       pTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_EXTRACTABLE:
        if ((rv = set_template_attribute(&template.exportable,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_EXTRACTABLE inconsistent in template");
          goto c_co_out;
        }
    }
  }

  if (class.set == false) {
    rv = CKR_TEMPLATE_INCOMPLETE;
    goto c_co_out;
  }

  yh_capabilities capabilities = {{0}};
  yh_capabilities delegated_capabilities = {{0}};
  uint8_t type = 0;
  yh_rc rc = YHR_SUCCESS;

  if (template.exportable == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("exportable-under-wrap", &capabilities);
    if (rc != YHR_SUCCESS) {
      rv = yrc_to_rv(rc);
      goto c_co_out;
    }
  }

  if (class.d == CKO_PRIVATE_KEY) {
    if (key_type.set == false) {
      rv = CKR_TEMPLATE_INCOMPLETE;
      goto c_co_out;
    }
    type = YH_ASYMMETRIC_KEY;
    if (key_type.d == CKK_RSA) {
      rv = parse_rsa_template(pTemplate, ulCount, &template);
      if (rv != CKR_OK) {
        goto c_co_out;
      }

      DBG_INFO("parsed RSA key, algorithm: %d, objlen: %d", template.algorithm,
               template.objlen);

      uint8_t p[512] = {0}, q[512] = {0};

      set_component(p, template.obj.rsa.p, template.objlen);
      set_component(q, template.obj.rsa.q, template.objlen);

      BN_free(template.obj.rsa.p);
      BN_free(template.obj.rsa.q);

      if (template.unwrap) {
        type = YH_WRAP_KEY;

        rc = set_wrapkey_capabilities(&template, &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }

        rc = yh_string_to_capabilities("all", &delegated_capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }

        uint8_t key[1024] = {0};
        memcpy(key, p, template.objlen);
        memcpy(key + template.objlen, q, template.objlen);

        rc = yh_util_import_wrap_key(session->slot->device_session, &template.id,
                                  template.label, 0xffff, &capabilities,
                                  template.algorithm, &delegated_capabilities,
                                  key, template.objlen * 2);

      } else {

        if (template.sign == ATTRIBUTE_TRUE) {
          rc = yh_string_to_capabilities("sign-pkcs,sign-pss", &capabilities);
          if (rc != YHR_SUCCESS) {
            rv = yrc_to_rv(rc);
            goto c_co_out;
          }
        }

        if (template.decrypt == ATTRIBUTE_TRUE) {
          rc = yh_string_to_capabilities("decrypt-pkcs,decrypt-oaep",
                                         &capabilities);
          if (rc != YHR_SUCCESS) {
            rv = yrc_to_rv(rc);
            goto c_co_out;
          }
        }

        rc = yh_util_import_rsa_key(session->slot->device_session, &template.id,
                                    template.label, 0xffff, &capabilities,
                                    template.algorithm, p, q);
      }
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed importing RSA key to device: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }
    } else if (key_type.d == CKK_EC) {
      rv = parse_ec_template(pTemplate, ulCount, &template);
      if (rv != CKR_OK) {
        goto c_co_out;
      }

      DBG_INFO("parsed EC key, algorithm: %d, objlen: %d", template.algorithm,
               template.objlen);

      if (template.sign == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("sign-ecdsa", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }
      }

      if (template.derive == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("derive-ecdh", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }
      }

      uint8_t d[128] = {0};
      set_component(d, template.obj.ec.d, template.objlen);

      BN_free(template.obj.ec.d);

      rc = yh_util_import_ec_key(session->slot->device_session, &template.id,
                                 template.label, 0xffff, &capabilities,
                                 template.algorithm, d);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed importing EC key to device: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }
    } else if (key_type.d == CKK_EC_EDWARDS) {
      rv = parse_ed_template(pTemplate, ulCount, &template);
      if (rv != CKR_OK) {
        goto c_co_out;
      }

      DBG_INFO("parsed ED key, algorithm: %d, objlen: %d", template.algorithm,
               template.objlen);

      if (template.sign == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("sign-eddsa", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }
      }

      rc = yh_util_import_ed_key(session->slot->device_session, &template.id,
                                 template.label, 0xffff, &capabilities,
                                 template.algorithm, template.obj.buf);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed importing ED key to device");
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }
    } else {
      rv = CKR_ATTRIBUTE_VALUE_INVALID;
      goto c_co_out;
    }

    if (meta_object.cka_id.len > 0 || meta_object.cka_label.len > 0) {
      meta_object.target_id = template.id;
    }
  } else if (class.d == CKO_SECRET_KEY) {
    if (key_type.set == false) {
      rv = CKR_TEMPLATE_INCOMPLETE;
      goto c_co_out;
    }
    if (key_type.d == CKK_SHA_1_HMAC || key_type.d == CKK_SHA256_HMAC ||
        key_type.d == CKK_SHA384_HMAC || key_type.d == CKK_SHA512_HMAC) {
      type = YH_HMAC_KEY;
      rv = parse_hmac_template(pTemplate, ulCount, &template, false);
      if (rv != CKR_OK) {
        goto c_co_out;
      }

      DBG_INFO("parsed HMAC key, algorithm: %d, objlen: %d", template.algorithm,
               template.objlen);

      if (template.sign == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("sign-hmac", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }
      }

      if (template.verify == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("verify-hmac", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }
      }

      rc = yh_util_import_hmac_key(session->slot->device_session, &template.id,
                                   template.label, 0xffff, &capabilities,
                                   template.algorithm, template.obj.buf,
                                   template.objlen);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed writing HMAC key to device: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }
    } else if (key_type.d == CKK_YUBICO_AES128_CCM_WRAP ||
               key_type.d == CKK_YUBICO_AES192_CCM_WRAP ||
               key_type.d == CKK_YUBICO_AES256_CCM_WRAP) {
      yh_algorithm algo = key_type.d & 0xff;
      rv = parse_wrap_template(pTemplate, ulCount, &template, algo, false);
      if (rv != CKR_OK) {
        goto c_co_out;
      }

      DBG_INFO("parsed WRAP key, objlen: %d", template.objlen);

      rc = set_wrapkey_capabilities(&template, &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }

      rc = yh_string_to_capabilities("all", &delegated_capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }

      type = YH_WRAP_KEY;
      rc = yh_util_import_wrap_key(session->slot->device_session, &template.id,
                                template.label, 0xffff, &capabilities, algo,
                                &delegated_capabilities, template.obj.buf,
                                template.objlen);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed writing WRAP key to device: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }
    } else if (key_type.d == CKK_AES) {
      type = YH_SYMMETRIC_KEY;
      rv = parse_aes_template(pTemplate, ulCount, &template, false);
      if (rv != CKR_OK) {
        goto c_co_out;
      }

      if (template.encrypt == ATTRIBUTE_TRUE) {
        rc =
          yh_string_to_capabilities("encrypt-ecb,encrypt-cbc", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = CKR_FUNCTION_FAILED;
          goto c_co_out;
        }
      }

      if (template.decrypt == ATTRIBUTE_TRUE) {
        rc =
          yh_string_to_capabilities("decrypt-ecb,decrypt-cbc", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = CKR_FUNCTION_FAILED;
          goto c_co_out;
        }
      }

      if (yh_util_import_aes_key(session->slot->device_session, &template.id,
                                 template.label, 0xffff, &capabilities,
                                 template.algorithm,
                                 template.obj.buf) != YHR_SUCCESS) {
        DBG_ERR("Failed writing symmetric key to device");
        rv = CKR_FUNCTION_FAILED;
        goto c_co_out;
      }
    } else {
      DBG_ERR("Unknown key_type: %lx", key_type.d);
      rv = CKR_ATTRIBUTE_VALUE_INVALID;
      goto c_co_out;
    }
    if (meta_object.cka_id.len > 0 || meta_object.cka_label.len > 0) {
      meta_object.target_id = template.id;
    }
  } else if (class.d == CKO_CERTIFICATE || class.d == CKO_DATA) {
    yh_algorithm algo = YH_ALGO_OPAQUE_DATA;
    type = YH_OPAQUE;
    if (class.d == CKO_CERTIFICATE) {
      algo = YH_ALGO_OPAQUE_X509_CERTIFICATE;
    } else {
      algo = YH_ALGO_OPAQUE_DATA;
    }
    for (CK_ULONG i = 0; i < ulCount; i++) {
      switch (pTemplate[i].type) {
        case CKA_VALUE:
          if (template.obj.buf == NULL) {
            template.obj.buf = (CK_BYTE_PTR) pTemplate[i].pValue;
            template.objlen = pTemplate[i].ulValueLen;
            DBG_INFO("Object will be stored with length %d", template.objlen);
          } else {
            DBG_ERR("Object buffer already set");
            rv = CKR_TEMPLATE_INCONSISTENT;
            goto c_co_out;
          }
          break;
        case CKA_CERTIFICATE_TYPE:
          if (algo != YH_ALGO_OPAQUE_X509_CERTIFICATE ||
              *(CK_CERTIFICATE_TYPE *) pTemplate[i].pValue != CKC_X_509) {
            DBG_ERR("Certificate type invalid");
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
            goto c_co_out;
          }
          break;
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_COPYABLE:
          if ((rv = check_bool_attribute(pTemplate[i].pValue, false)) !=
              CKR_OK) {
            DBG_ERR("Boolean false check failed for attribute 0x%lx",
                    pTemplate[i].type);
            return rv;
          }
          break;
        case CKA_DESTROYABLE:
          if ((rv = check_bool_attribute(pTemplate[i].pValue, true)) !=
              CKR_OK) {
            DBG_ERR("Boolean truth check failed for attribute 0x%lx",
                    pTemplate[i].type);
            return rv;
          }
          break;
        case CKA_TOKEN: // pkcs11test sets this to false
        case CKA_CLASS:
        case CKA_ID:
        case CKA_LABEL:
        case CKA_APPLICATION:
        case CKA_OBJECT_ID:
        case CKA_SUBJECT:
        case CKA_ISSUER:
        case CKA_SERIAL_NUMBER:
        case CKA_EXTRACTABLE:
          break;
        default:
          DBG_ERR("Invalid attribute type in key template: 0x%lx",
                  pTemplate[i].type);
          rv = CKR_ATTRIBUTE_TYPE_INVALID;
          goto c_co_out;
      }
    }

    rc = yh_util_import_opaque_ex(session->slot->device_session, &template.id,
                                  template.label, 0xffff, &capabilities, algo,
                                  template.obj.buf, template.objlen,
                                  algo == YH_ALGO_OPAQUE_X509_CERTIFICATE
                                    ? COMPRESS_IF_TOO_BIG
                                    : NO_COMPRESS,
                                  NULL);
    if (rc != YHR_SUCCESS) {
      DBG_ERR("Failed writing Opaque object to device: %s", yh_strerror(rc));
      rv = yrc_to_rv(rc);
      goto c_co_out;
    }
    if (algo == YH_ALGO_OPAQUE_X509_CERTIFICATE &&
        (meta_object.cka_id.len > 0 || meta_object.cka_label.len > 0)) {
      meta_object.target_id = template.id;
    }
  } else if (class.d == CKO_PUBLIC_KEY) {

    // Read the value of the public key
    for (CK_ULONG i = 0; i < ulCount; i++) {
      switch (pTemplate[i].type) {
        case CKA_VALUE:
          if (template.obj.buf == NULL) {
            template.obj.buf = (CK_BYTE_PTR) pTemplate[i].pValue;
            template.objlen = pTemplate[i].ulValueLen;
            DBG_INFO("Object will be stored with length %d", template.objlen);
          } else {
            DBG_ERR("Object buffer already set");
            rv = CKR_TEMPLATE_INCONSISTENT;
            goto c_co_out;
          }
          break;
        case CKA_WRAP:
          if ((rv = set_template_attribute(&template.wrap,
                                           pTemplate[i].pValue)) != CKR_OK) {
            DBG_ERR("CKA_WRAP inconsistent in template");
            return rv;
          }
          break;
        case CKA_ENCRYPT:
          if ((rv = set_template_attribute(&template.encrypt,
                                           pTemplate[i].pValue)) != CKR_OK) {
            DBG_ERR("CKA_ENCRYPT inconsistent in template");
            return rv;
          }
          break;
      }
    }

    if (template.wrap && key_type.d == CKK_RSA) {
      switch (template.objlen) {
        case 256:
          template.algorithm = YH_ALGO_RSA_2048;
          break;
        case 384:
          template.algorithm = YH_ALGO_RSA_3072;
          break;
        case 512:
          template.algorithm = YH_ALGO_RSA_4096;
          break;
        default:
          DBG_ERR("Unsupported key length");
          rv = CKR_DATA_INVALID;
          goto c_co_out;
      }

      if (template.algorithm == 0) {
        DBG_ERR("Missing CKA_KEY_TYPE in attribute template");
        rv = CKR_TEMPLATE_INCOMPLETE;
        goto c_co_out;
      }

      rc = set_wrapkey_capabilities(&template, &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }

      rc = yh_string_to_capabilities("all", &delegated_capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }

      rc =
        yh_util_import_public_wrap_key(session->slot->device_session, &template.id,
                                    template.label, 0xffff, &capabilities,
                                    template.algorithm, &delegated_capabilities,
                                    template.obj.buf, template.objlen);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed writing Public Wrap key to device: %s",
                yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }
      type = YH_PUBLIC_WRAP_KEY;

    } else { // Treat it as asymmetric public key. List all asymmetric keys and
             // check whether this public key matches any of them. If not,
             // import operation fails

      bool pubkey_found = false;
      // Get a list of all asym objects in the YubiHSM
      yh_object_descriptor asym_keys[YH_MAX_ITEMS_COUNT] = {0};
      size_t asym_keys_len = sizeof(asym_keys);
      rc = yh_util_list_objects(session->slot->device_session, 0,
                                YH_ASYMMETRIC_KEY, 0, &capabilities, 0, NULL,
                                asym_keys, &asym_keys_len);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed to get object list");
        rv = yrc_to_rv(rc);
        goto c_co_out;
      }

      // Check which asym public key matches the one in the request
      for (size_t i = 0; i < asym_keys_len; i++) {
        uint8_t pubkey[2048] = {0};
        size_t pubkey_len = sizeof(pubkey);
        rc = yh_util_get_public_key_ex(session->slot->device_session, asym_keys[i].type,
                                    asym_keys[i].id, pubkey, &pubkey_len, NULL);
        if (rc != YHR_SUCCESS) {
          DBG_ERR("Failed to get public key of object 0x%x", asym_keys[i].id);
          rv = yrc_to_rv(rc);
          goto c_co_out;
        }

        if (match_byte_array(pubkey, pubkey_len, template.obj.buf,
                             template.objlen)) {
          template.id = asym_keys[i].id;
          pubkey_found = true;

          // If there's need, update or create meta_object
          yubihsm_pkcs11_object_desc *asym_key_desc =
            _get_object_desc(session->slot, asym_keys[i].id, YH_ASYMMETRIC_KEY,
                             asym_keys[i].sequence);
          if (asym_key_desc == NULL) {
            continue;
          }
          if (meta_object.cka_id.len > 0 || meta_object.cka_label.len > 0) {
            yubihsm_pkcs11_object_desc *pMeta_object =
              find_meta_object_by_target(session->slot, asym_keys[i].id,
                                         YH_ASYMMETRIC_KEY,
                                         asym_keys[i].sequence,
                                         asym_key_desc->object.domains);

            if (pMeta_object !=
                NULL) { // meta object already exists. Update it.
              if (meta_object.cka_id.len > 0) {
                pMeta_object->meta_object.cka_id_pubkey.len =
                  meta_object.cka_id.len;
                memcpy(pMeta_object->meta_object.cka_id_pubkey.value,
                       meta_object.cka_id.value, meta_object.cka_id.len);
              }
              if (meta_object.cka_label.len > 0) {
                pMeta_object->meta_object.cka_label_pubkey.len =
                  meta_object.cka_label.len;
                memcpy(pMeta_object->meta_object.cka_label_pubkey.value,
                       meta_object.cka_label.value, meta_object.cka_label.len);
              }
              rv = write_meta_object(session->slot, &pMeta_object->meta_object,
                                     &capabilities,
                                     asym_key_desc->object.domains, true);
              if (rv != CKR_OK) {
                goto c_co_out;
              }
            } else { // meta object does not exist. Create it
              meta_object.target_id = asym_keys[i].id;
              // No need to write this meta object now becase we will do it
              // later
            }
          }
          break;
        }
      }

      if (pubkey_found == false) {
        rv = CKR_ATTRIBUTE_VALUE_INVALID;
        goto c_co_out;
      }
      type = YH_ASYMMETRIC_KEY;
    }
  } else {
    rv = CKR_TEMPLATE_INCONSISTENT;
    goto c_co_out;
  }

  yubihsm_pkcs11_object_desc *object_desc =
    _get_object_desc(session->slot, template.id, type, 0xffff);
  if (object_desc == NULL) {
    DBG_ERR("Failed executing get object info after creating: id 0x%x",
            template.id);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto c_co_out;
  }
  yh_object_descriptor *object = &object_desc->object;

  if (meta_object.target_id != 0) {
    meta_object.target_type = object->type;
    meta_object.target_sequence = object->sequence;
    rv = write_meta_object(session->slot, &meta_object, &capabilities,
                           object->domains, false);
    if (rv != CKR_OK) {
      DBG_ERR("Failed writing meta opaque object to device. Note that the "
              "original object has been successfully imported into the device "
              "but without the expected CKA_ID and/or CKA_LABEL");
      goto c_co_out;
    }
  }

  if (class.d == CKO_PUBLIC_KEY && type != YH_PUBLIC_WRAP_KEY) {
    *phObject =
      object->sequence << 24 | (object->type | 0x80) << 16 | object->id;
  } else {
    *phObject = object->sequence << 24 | object->type << 16 | object->id;
  }

  DBG_INFO("Created object %08lx", *phObject);

  DOUT;

c_co_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phNewObject) {

  DIN;

  UNUSED(hSession);
  UNUSED(hObject);
  UNUSED(pTemplate);
  UNUSED(ulCount);
  UNUSED(phNewObject);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Other operation in progress");
    rv = CKR_OPERATION_ACTIVE;
    goto c_do_out;
  }

  int type = hObject >> 16;

  if (type == ECDH_KEY_TYPE) {
    ListItem *item =
      list_get(&session->ecdh_session_keys, &hObject, compare_ecdh_keys);
    if (item) {
      list_delete(&session->ecdh_session_keys, item);
      DBG_INFO("Deleted ECDH session key %08lx", hObject);
    } else {
      DBG_INFO("No ECDH session key with ID %08lx was found", hObject);
    }
  } else {
    if (((uint8_t) (hObject >> 16)) == YH_PUBLIC_KEY) {
      DBG_INFO("Trying to delete public key, returning success with noop");
      goto c_do_out;
    }

    yubihsm_pkcs11_object_desc *object =
      get_object_desc(session->slot, hObject);
    if (object == NULL) {
      DBG_ERR("Object not found");
      rv = CKR_OBJECT_HANDLE_INVALID;
      goto c_do_out;
    }

    yh_rc yrc;
    yubihsm_pkcs11_object_desc *meta_desc =
      find_meta_object_by_target(session->slot, object->object.id,
                                 object->object.type, object->object.sequence,
                                 object->object.domains);

    yrc = yh_util_delete_object(session->slot->device_session,
                                object->object.id, object->object.type);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to delete object: %s", yh_strerror(yrc));
      rv = yrc_to_rv(yrc);
      goto c_do_out;
    }
    DBG_INFO("Deleted object %08lx", hObject);
    memset(object, 0, sizeof(yubihsm_pkcs11_object_desc));

    if (meta_desc != NULL) {
      yrc = yh_util_delete_object(session->slot->device_session,
                                  meta_desc->object.id, meta_desc->object.type);
      if (yrc != YHR_SUCCESS) {
        DBG_ERR("Failed to delete meta opaque object: %s", yh_strerror(yrc));
        rv = yrc_to_rv(yrc);
        goto c_do_out;
      }
      DBG_INFO("Deleted meta object 0x%x", meta_desc->object.id);
      memset(meta_desc, 0, sizeof(yubihsm_pkcs11_object_desc));
    }
  }

  DOUT;

c_do_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulSize == NULL) {
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  int type = hObject >> 16;

  if (type == ECDH_KEY_TYPE) {
    ListItem *item =
      list_get(&session->ecdh_session_keys, &hObject, compare_ecdh_keys);
    if (item) {
      ecdh_session_key *key = (ecdh_session_key *) item->data;
      *pulSize = key->len;

      DOUT;
    } else {
      rv = CKR_OBJECT_HANDLE_INVALID;
    }
  } else {
    yubihsm_pkcs11_object_desc *object =
      get_object_desc(session->slot, hObject);
    if (object == NULL) {
      rv = CKR_OBJECT_HANDLE_INVALID;
    } else {
      *pulSize = object->object.len;

      DOUT;
    }
  }
  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL || ulCount == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  DBG_INFO("For object %08lx", hObject);

  int type = hObject >> 16;

  if (type == ECDH_KEY_TYPE) {
    bool object_found = false;
    ListItem *item =
      list_get(&session->ecdh_session_keys, &hObject, compare_ecdh_keys);
    if (item) {
      object_found = true;
      DBG_INFO("Object is an ECDH key available only in the current session. "
               "Key id: 0x%lx",
               hObject);
      ecdh_session_key *key = (ecdh_session_key *) item->data;
      rv = populate_template(type, key, pTemplate, ulCount, session);
    }

    if ((rv == CKR_OK) && !object_found) {
      DBG_ERR("Unable to retrieve session ECDH key with ID: %08lx", hObject);
      rv = CKR_OBJECT_HANDLE_INVALID;
      goto c_gav_out;
    } else if (rv != CKR_OK) {
      goto c_gav_out;
    }

  } else {
    yubihsm_pkcs11_object_desc *object =
      get_object_desc(session->slot, hObject);

    if (object == NULL) {
      DBG_ERR("Unable to retrieve object");
      rv = CKR_OBJECT_HANDLE_INVALID;
      goto c_gav_out;
    }

    rv = populate_template(type, object, pTemplate, ulCount, session);
    if (rv != CKR_OK) {
      goto c_gav_out;
    }
  }

  DOUT;

c_gav_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL || ulCount == 0) {
    DBG_ERR("Called with invalid parameters: pTemplate=%p ulCount=%lu",
            (void *) pTemplate, ulCount);
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  int type = hObject >> 16;
  if (type == ECDH_KEY_TYPE) {
    DBG_INFO("Refusing to change attributes of an ECDH session key");
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto c_sav_out;
  }

  yubihsm_pkcs11_object_desc *object = get_object_desc(session->slot, hObject);
  if (object == NULL) {
    DBG_ERR("Unable to retrieve object");
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto c_sav_out;
  }

  yubihsm_pkcs11_object_desc *meta_desc =
    find_meta_object_by_target(session->slot, object->object.id,
                               (object->object.type & 0x7f),
                               object->object.sequence, object->object.domains);

  bool changed = false;
  pkcs11_meta_object new_meta_object = {0};
  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {
      case CKA_ID: {
        if (meta_desc) {
          if (object->object.type == YH_PUBLIC_KEY) {
            if (!match_byte_array(meta_desc->meta_object.cka_id_pubkey.value,
                                  meta_desc->meta_object.cka_id_pubkey.len,
                                  pTemplate[i].pValue,
                                  pTemplate[i].ulValueLen)) {
              changed = true;
              memset(&meta_desc->meta_object.cka_id_pubkey.value, 0,
                     meta_desc->meta_object.cka_id_pubkey.len);
              meta_desc->meta_object.cka_id_pubkey.len =
                pTemplate[i].ulValueLen;
              memcpy(meta_desc->meta_object.cka_id_pubkey.value,
                     pTemplate[i].pValue, pTemplate[i].ulValueLen);
            }
          } else {
            if (!match_byte_array(meta_desc->meta_object.cka_id.value,
                                  meta_desc->meta_object.cka_id.len,
                                  pTemplate[i].pValue,
                                  pTemplate[i].ulValueLen)) {
              changed = true;
              memset(&meta_desc->meta_object.cka_id.value, 0,
                     meta_desc->meta_object.cka_id.len);
              meta_desc->meta_object.cka_id.len = pTemplate[i].ulValueLen;
              memcpy(meta_desc->meta_object.cka_id.value, pTemplate[i].pValue,
                     pTemplate[i].ulValueLen);
            }
          }
        } else {
          uint16_t new_id =
            parse_id_value(pTemplate[i].pValue, pTemplate[i].ulValueLen);
          if (pTemplate[i].ulValueLen != 2 || new_id != object->object.id) {
            if (object->object.type == YH_PUBLIC_KEY) {
              new_meta_object.cka_id_pubkey.len = pTemplate[i].ulValueLen;
              memcpy(new_meta_object.cka_id_pubkey.value, pTemplate[i].pValue,
                     pTemplate[i].ulValueLen);
            } else {
              new_meta_object.cka_id.len = pTemplate[i].ulValueLen;
              memcpy(new_meta_object.cka_id.value, pTemplate[i].pValue,
                     pTemplate[i].ulValueLen);
            }
          }
        }
      } break;

      case CKA_LABEL:
        if (meta_desc) {
          if (object->object.type == YH_PUBLIC_KEY) {
            if (!match_byte_array(meta_desc->meta_object.cka_label_pubkey.value,
                                  meta_desc->meta_object.cka_label_pubkey.len,
                                  pTemplate[i].pValue,
                                  pTemplate[i].ulValueLen)) {
              changed = true;
              memset(&meta_desc->meta_object.cka_label_pubkey.value, 0,
                     meta_desc->meta_object.cka_label_pubkey.len);
              meta_desc->meta_object.cka_label_pubkey.len =
                pTemplate[i].ulValueLen;
              memcpy(meta_desc->meta_object.cka_label_pubkey.value,
                     pTemplate[i].pValue, pTemplate[i].ulValueLen);
            }
          } else {
            if (!match_byte_array(meta_desc->meta_object.cka_label.value,
                                  meta_desc->meta_object.cka_label.len,
                                  pTemplate[i].pValue,
                                  pTemplate[i].ulValueLen)) {
              changed = true;
              memset(&meta_desc->meta_object.cka_label.value, 0,
                     meta_desc->meta_object.cka_label.len);
              meta_desc->meta_object.cka_label.len = pTemplate[i].ulValueLen;
              memcpy(meta_desc->meta_object.cka_label.value,
                     pTemplate[i].pValue, pTemplate[i].ulValueLen);
            }
          }
        } else {
          if (pTemplate[i].ulValueLen != strlen(object->object.label)) {
            if (object->object.type == YH_PUBLIC_KEY) {
              new_meta_object.cka_label_pubkey.len = pTemplate[i].ulValueLen;
              memcpy(new_meta_object.cka_label_pubkey.value,
                     pTemplate[i].pValue, pTemplate[i].ulValueLen);
            } else {
              new_meta_object.cka_label.len = pTemplate[i].ulValueLen;
              memcpy(new_meta_object.cka_label.value, pTemplate[i].pValue,
                     pTemplate[i].ulValueLen);
            }
          }
        }
        break;

      case CKA_SUBJECT:
        DBG_WARN("Setting value of attribute CKA_SUBJECT is ignored");
        break;

      default:
        DBG_INFO("Refusing to change attribute %lx of object",
                 pTemplate[i].type);
        rv = CKR_FUNCTION_NOT_SUPPORTED;
        goto c_sav_out;
    }
  }

  if (changed) {
    rv = write_meta_object(session->slot, &meta_desc->meta_object,
                           &object->object.capabilities, object->object.domains,
                           true);
    if (rv != CKR_OK) {
      goto c_sav_out;
    }
  } else if (new_meta_object.cka_id.len > 0 ||
             new_meta_object.cka_label.len > 0 ||
             new_meta_object.cka_id_pubkey.len > 0 ||
             new_meta_object.cka_label_pubkey.len > 0) {
    new_meta_object.target_id = object->object.id;
    new_meta_object.target_type = object->object.type & 0x7f;
    new_meta_object.target_sequence = object->object.sequence;
    rv = write_meta_object(session->slot, &new_meta_object,
                           &object->object.capabilities, object->object.domains,
                           false);
    if (rv != CKR_OK) {
      goto c_sav_out;
    }
  }

  DOUT;
c_sav_out:
  release_session(&g_ctx, session);

  return rv;
}

static bool should_include_sessionkeys(bool is_secret_key, bool extractable_set,
                                       bool is_extractable, int object_id) {
  if (object_id != 0) {
    // Searching for a specific keys
    return false;
  }
  if (!is_secret_key) {
    return false;
  }
  if (extractable_set && !is_extractable) {
    return false;
  }
  return true;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (ulCount != 0 && pTemplate == NULL) {
    DBG_ERR("Asking for specific objects but no template given");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  char *label = NULL;
  uint8_t *template_value = NULL;

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Another operation is already active %d", session->operation.type);
    rv = CKR_OPERATION_ACTIVE;
    goto c_foi_out;
  }

  session->operation.op.find.only_private = false;
  session->operation.op.find.n_objects = 0;

  if (session->session_state & SESSION_NOT_AUTHENTICATED) {
    rv = CKR_OK;
    // NOTE: we need to take extra care here, we're lying about the operation
    // being succesful, so we need to setup the internal state correctly as
    // well.
    session->operation.type = OPERATION_FIND;
    session->operation.op.find.current_object = 0;
    DOUT;
    goto c_foi_out;
  }

  yh_rc rc = YHR_SUCCESS;

  uint8_t type = 0;
  uint16_t domains = 0;
  yh_capabilities capabilities = {{0}};
  bool pub = false;
  yh_algorithm algorithm = 0;
  bool unknown = false;
  bool secret_key = false;
  bool rsa_key = false;
  bool wrap_key = false;
  bool extractable_set = false;
  size_t template_value_len = 0;
  uint8_t template_id[CKA_ATTRIBUTE_VALUE_SIZE] = {0};
  size_t template_id_len = 0;
  uint8_t template_label[CKA_ATTRIBUTE_VALUE_SIZE] = {0};
  size_t template_label_len = 0;

  DBG_INFO("find with %lu attributes", ulCount);
  if (ulCount != 0) {
    for (CK_ULONG i = 0; i < ulCount; i++) {
      switch (pTemplate[i].type) {
        case CKA_ID:
          template_id_len = pTemplate[i].ulValueLen;
          memcpy(template_id, pTemplate[i].pValue, template_id_len);
          break;

        case CKA_CLASS: {
          uint32_t value = *((CK_ULONG_PTR) (pTemplate[i].pValue));
          uint8_t class_type = 0;
          switch (value) {
            case CKO_CERTIFICATE:
              DBG_INFO("filtering for certificates");
              algorithm =
                YH_ALGO_OPAQUE_X509_CERTIFICATE; // TODO: handle other certs?
              class_type = YH_OPAQUE;
              break;

            case CKO_DATA:
              class_type = YH_OPAQUE;
              break;

            case CKO_PUBLIC_KEY:
              DBG_INFO("filtering for public keys");
              pub = true;
              class_type = YH_ASYMMETRIC_KEY;
              break;

            case CKO_PRIVATE_KEY:
              DBG_INFO("filtering for private keys");
              session->operation.op.find.only_private = true;
              class_type = YH_ASYMMETRIC_KEY;
              break;

            case CKO_SECRET_KEY:
              DBG_INFO("filtering for secret keys");
              secret_key = true;
              break;

            default:
              unknown = true;
              DBG_INFO("Asking for unknown class %x, returning empty set. %x",
                       (uint32_t) pTemplate[i].type, value);
          }
          rv = set_object_type(&type, class_type);
          if (rv != CKR_OK) {
            goto c_foi_out;
          }
        } break;
        case CKA_LABEL:
          template_label_len = pTemplate[i].ulValueLen;
          memcpy(template_label, pTemplate[i].pValue, template_label_len);
          break;

        case CKA_SIGN:
          if (*((CK_BBOOL *) pTemplate[i].pValue) == CK_TRUE) {
            session->operation.op.find.only_private = true;
            rc = yh_string_to_capabilities(
              "sign-pkcs,sign-pss,sign-ecdsa,sign-hmac", &capabilities);
            if (rc != YHR_SUCCESS) {
              rv = yrc_to_rv(rc);
              goto c_foi_out;
            }
          }
          break;

        case CKA_DECRYPT:
          if (*((CK_BBOOL *) pTemplate[i].pValue) == CK_TRUE) {
            session->operation.op.find.only_private = true;
            rc =
              yh_string_to_capabilities("decrypt-pkcs,decrypt-oaep,derive-ecdh,"
                                        "unwrap-data,decrypt-ecb,decrypt-cbc",
                                        &capabilities);
            if (rc != YHR_SUCCESS) {
              rv = yrc_to_rv(rc);
              goto c_foi_out;
            }
          }
          break;

        case CKA_ENCRYPT:
          if (*((CK_BBOOL *) pTemplate[i].pValue) == CK_TRUE) {
            rc = yh_string_to_capabilities("wrap-data,encrypt-ecb,encrypt-cbc",
                                           &capabilities);
            if (rc != YHR_SUCCESS) {
              rv = yrc_to_rv(rc);
              goto c_foi_out;
            }
          }
          break;

        case CKA_WRAP:
          if (*((CK_BBOOL *) pTemplate[i].pValue) == CK_TRUE) {
            wrap_key = true;
            rc = yh_string_to_capabilities("export-wrapped", &capabilities);
            if (rc != YHR_SUCCESS) {
              rv = yrc_to_rv(rc);
              goto c_foi_out;
            }
          }
          break;

        case CKA_UNWRAP:
          if (*((CK_BBOOL *) pTemplate[i].pValue) == CK_TRUE) {
            wrap_key = true;
            rc = yh_string_to_capabilities("import-wrapped", &capabilities);
            if (rc != YHR_SUCCESS) {
              rv = yrc_to_rv(rc);
              goto c_foi_out;
            }
          }
          break;

        case CKA_EXTRACTABLE:
          extractable_set = true;
          if (*((CK_BBOOL *) pTemplate[i].pValue) == CK_TRUE) {
            session->operation.op.find.only_private = true;
            rc =
              yh_string_to_capabilities("exportable-under-wrap", &capabilities);
            if (rc != YHR_SUCCESS) {
              rv = yrc_to_rv(rc);
              goto c_foi_out;
            }
          }
          break;

        case CKA_VALUE:
          template_value_len = pTemplate[i].ulValueLen;
          template_value = malloc(template_value_len * sizeof(uint8_t));
          memcpy(template_value, pTemplate[i].pValue, template_value_len);
          break;

        case CKA_KEY_TYPE: {
          uint32_t value = *((CK_ULONG_PTR) (pTemplate[i].pValue));
          uint8_t key_type = 0;
          switch (value) {
            case CKK_YUBICO_AES128_CCM_WRAP:
            case CKK_YUBICO_AES192_CCM_WRAP:
            case CKK_YUBICO_AES256_CCM_WRAP:
              key_type = YH_WRAP_KEY;
              break;
            case CKK_SHA_1_HMAC:
            case CKK_SHA256_HMAC:
            case CKK_SHA384_HMAC:
            case CKK_SHA512_HMAC:
              key_type = YH_HMAC_KEY;
              break;
            case CKK_AES:
              key_type = YH_SYMMETRIC_KEY;
              break;
            case CKK_RSA:
              rsa_key = true;
            case CKK_EC:
              key_type = YH_ASYMMETRIC_KEY;
              break;
            default:
              unknown = true;
              DBG_INFO("Asking for unknown key type %x, returning empty set. "
                       "%x",
                       (uint32_t) pTemplate[i].type, value);
          }
          rv = set_object_type(&type, key_type);
          if (rv != CKR_OK) {
            goto c_foi_out;
          }
        } break;

        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_DESTROYABLE:
        case CKA_APPLICATION:
        case CKA_CERTIFICATE_TYPE:
          DBG_INFO("Got type %x, ignoring it for results",
                   (uint32_t) pTemplate[i].type);
          break;

        default:
          unknown = true;
          DBG_INFO("Got type %x, returning empty set",
                   (uint32_t) pTemplate[i].type);
          break;
      }
    }
  }

  if(wrap_key && rsa_key) {
    if (pub) {
      type = YH_PUBLIC_WRAP_KEY;
    } else {
      type = YH_WRAP_KEY;
    }
  }

  if (unknown == false) {
    uint16_t found_objects = 0;
    if (secret_key == true) {
      // NOTE(adma): looking for a secret key. Get items of all types and filter
      // manually
      yh_object_descriptor
        tmp_objects[YH_MAX_ITEMS_COUNT + MAX_ECDH_SESSION_KEYS] = {0};
      size_t tmp_n_objects = YH_MAX_ITEMS_COUNT + MAX_ECDH_SESSION_KEYS;
      rc = yh_util_list_objects(session->slot->device_session, 0, type, domains,
                                &capabilities, algorithm, label, tmp_objects,
                                &tmp_n_objects);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed to get object list: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_foi_out;
      }
      for (size_t i = 0; i < tmp_n_objects; i++) {
        if (tmp_objects[i].type == YH_WRAP_KEY ||
            tmp_objects[i].type == YH_HMAC_KEY ||
            tmp_objects[i].type == YH_SYMMETRIC_KEY) {
          yubihsm_pkcs11_object_desc *object_desc =
            _get_object_desc(session->slot, tmp_objects[i].id,
                             tmp_objects[i].type, tmp_objects[i].sequence);

          if (object_desc != NULL &&
              match_meta_attributes(session, &object_desc->object, template_id,
                                    template_id_len, template_label,
                                    template_label_len)) {
            memcpy(session->operation.op.find.objects + found_objects,
                   tmp_objects + i, sizeof(yh_object_descriptor));
            found_objects++;
          }
        }
      }
    } else {
      if (template_value != NULL) {
        // Find by certificate
        if (algorithm != 0 && algorithm != YH_ALGO_OPAQUE_X509_CERTIFICATE) {
          DBG_ERR(
            "Value in template not an X509Certificate. Cannot perform search.");
          rv = CKR_ATTRIBUTE_VALUE_INVALID;
          goto c_foi_out;
        }
        yh_object_descriptor tmp_objects[YH_MAX_ITEMS_COUNT] = {0};
        size_t tmp_n_objects = sizeof(tmp_objects);
        rc = yh_util_list_objects(session->slot->device_session, 0, YH_OPAQUE,
                                  domains, &capabilities,
                                  YH_ALGO_OPAQUE_X509_CERTIFICATE, label,
                                  tmp_objects, &tmp_n_objects);
        if (rc != YHR_SUCCESS) {
          DBG_ERR("Failed to get object list");
          rv = yrc_to_rv(rc);
          goto c_foi_out;
        }

        for (size_t i = 0; i < tmp_n_objects; i++) {
          uint8_t cert[16384] = {0};
          size_t cert_len = sizeof(cert);
          rc = yh_util_get_opaque_ex(session->slot->device_session,
                                     tmp_objects[i].id, cert, &cert_len, NULL,
                                     true);
          if (rc != YHR_SUCCESS) {
            DBG_ERR("Failed to get opaque object 0x%x", tmp_objects[i].id);
            rv = yrc_to_rv(rc);
            goto c_foi_out;
          }

          if (match_byte_array(template_value, template_value_len, cert,
                               cert_len)) {
            session->operation.op.find.objects[0].id = tmp_objects[i].id;
            session->operation.op.find.objects[0].type = tmp_objects[i].type;
            session->operation.op.find.objects[0].sequence =
              tmp_objects[i].sequence;
            found_objects = 1;
            break;
          }
        }
      } else {
        yh_object_descriptor
          tmp_objects[YH_MAX_ITEMS_COUNT + MAX_ECDH_SESSION_KEYS] = {0};
        size_t tmp_n_objects = YH_MAX_ITEMS_COUNT + MAX_ECDH_SESSION_KEYS;
        rc = yh_util_list_objects(session->slot->device_session, 0, type,
                                  domains, &capabilities, algorithm, label,
                                  tmp_objects, &tmp_n_objects);

        if (rc != YHR_SUCCESS) {
          DBG_ERR("Failed to get object list");
          rv = yrc_to_rv(rc);
          goto c_foi_out;
        }
        for (size_t i = 0; i < tmp_n_objects; i++) {
          yubihsm_pkcs11_object_desc *object_desc =
            _get_object_desc(session->slot, tmp_objects[i].id,
                             tmp_objects[i].type, tmp_objects[i].sequence);

          if (object_desc && is_meta_object(&object_desc->object)) {
            continue;
          }

          if (match_meta_attributes(session, &object_desc->object, template_id,
                                    template_id_len, template_label,
                                    template_label_len)) {
            memcpy(session->operation.op.find.objects + found_objects,
                   tmp_objects + i, sizeof(yh_object_descriptor));
            found_objects++;
          }
        }
        if (pub) {
          for (size_t i = 0; i < found_objects; i++) {
            if (session->operation.op.find.objects[i].type ==
                YH_ASYMMETRIC_KEY) {
              session->operation.op.find.objects[i].type |= 0x80;
            }
          }
        }
      }
    }

    uint16_t id = parse_id_value(template_id, template_id_len);
    DBG_INFO("id parsed as %x", id);

    if (ulCount == 0 ||
        should_include_sessionkeys(secret_key, extractable_set,
                                   session->operation.op.find.only_private,
                                   id)) {

      ListItem *item = NULL;
      for (item = session->ecdh_session_keys.head; item != NULL;
           item = item->next) {
        ecdh_session_key *key = (ecdh_session_key *) item->data;

        if (template_label_len == 0 ||
            strcmp((const char *) template_label, key->label) == 0) {

          yh_object_descriptor desc = {0};
          desc.id = key->id & 0xffff;
          desc.len = key->len;
          desc.type = ECDH_KEY_TYPE;
          memcpy(desc.label, key->label, strlen(key->label) + 1);

          // Add this item/key to the list of found objects
          memcpy(session->operation.op.find.objects + found_objects, &desc,
                 sizeof(yh_object_descriptor));

          found_objects++;
        }
      }
    }

    session->operation.op.find.n_objects = found_objects;
  }

  // NOTE: it's important to set the operation type as late as possible so we
  // don't leave it set after erroring out.
  session->operation.type = OPERATION_FIND;
  session->operation.op.find.current_object = 0;

  DOUT;

c_foi_out:
  if (template_value != NULL) {
    free(template_value);
    template_value = NULL;
  }

  if (label != NULL) {
    free(label);
    label = NULL;
  }

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
 CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  if (phObject == NULL || ulMaxObjectCount == 0 || pulObjectCount == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto c_fo_out;
  }

  if (session->operation.type != OPERATION_FIND) {
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_fo_out;
  }

  DBG_INFO("Can return %lu object(s)", ulMaxObjectCount);

  *pulObjectCount = 0;
  for (CK_ULONG i = 0;
       i < ulMaxObjectCount && session->operation.op.find.current_object <
                                 session->operation.op.find.n_objects;
       session->operation.op.find.current_object++) {
    yh_object_descriptor *object =
      &session->operation.op.find
         .objects[session->operation.op.find.current_object];
    uint32_t id;
    switch (object->type) {
      case YH_ASYMMETRIC_KEY:
      case YH_OPAQUE:
      case YH_WRAP_KEY:
      case YH_PUBLIC_WRAP_KEY:
      case YH_HMAC_KEY:
      case YH_PUBLIC_KEY:
      case YH_SYMMETRIC_KEY:
        id = object->sequence << 24;
        id |= object->type << 16;
        id |= object->id;
        break;
      default:
        if (object->type == ECDH_KEY_TYPE) {
          id = ECDH_KEY_TYPE << 16;
          id |= object->id;
        } else {
          DBG_INFO("Found unknown object type %x, skipping over", object->type);
          continue;
        }
    }

    phObject[i++] = id;

    *pulObjectCount += 1;

    if (!session->operation.op.find.only_private &&
        object->type == YH_ASYMMETRIC_KEY) {
      object->type |= 0x80;
      session->operation.op.find.current_object--;
      DBG_INFO("stepping back");
    }

    DBG_INFO("Returning object %zu as %08x",
             session->operation.op.find.current_object, id);
  }

  DBG_INFO("Returning %lu object(s)", *pulObjectCount);

  DOUT;

c_fo_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_FIND) {
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_fof_out;
  }

  session->operation.op.find.current_object = 0;
  session->operation.op.find.n_objects = 0;

  session->operation.type = OPERATION_NOOP;

  DOUT;

c_fof_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL) {
    DBG_ERR("Invalid Mechanism");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Other operation in progress");
    rv = CKR_OPERATION_ACTIVE;
    goto c_ei_out;
  }

  rv = check_decrypt_mechanism(session->slot, pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Encryption mechanism 0x%lx not supported", pMechanism->mechanism);
    goto c_ei_out;
  }

  DBG_INFO("Trying to encrypt data with mechanism 0x%04lx and key %08lx",
           pMechanism->mechanism, hKey);

  rv = apply_encrypt_mechanism_init(session, pMechanism, hKey);
  if (rv != CKR_OK) {
    DBG_ERR("Failed to initialize encryption operation");
    goto c_ei_out;
  }

  session->operation.mechanism.mechanism = pMechanism->mechanism;
  session->operation.op.encrypt.key_id = hKey;
  session->operation.type = OPERATION_ENCRYPT;
  session->operation.buffer_length = 0;
  set_operation_part(&session->operation, PART_INIT);

  DOUT;

c_ei_out:
  release_session(&g_ctx, session);
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;
  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_e_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_e_out;
  }

  if (session->operation.type != OPERATION_ENCRYPT) {
    DBG_ERR("Encryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_e_out;
  }

  rv = set_operation_part(&session->operation, PART_SINGLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another encrypt operation is already active");
    goto c_e_out;
  }

  if (pData == NULL || pulEncryptedDataLen == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_e_out;
  }

  // Calculate exact output size
  CK_ULONG datalen = 0;
  switch (session->operation.mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
      datalen = (session->operation.op.encrypt.key_len + 7) / 8;
      break;
    case CKM_YUBICO_AES_CCM_WRAP:
      if (ULONG_MAX - YH_CCM_WRAP_OVERHEAD < ulDataLen) {
        rv = CKR_DATA_LEN_RANGE;
        goto c_e_out;
      }
      datalen = YH_CCM_WRAP_OVERHEAD + ulDataLen;
      break;
    case CKM_AES_ECB:
    case CKM_AES_CBC:
      datalen = ulDataLen;
      break;
    case CKM_AES_CBC_PAD:
      datalen = ulDataLen / 16 * 16;
      if (ULONG_MAX - 16 < datalen) {
        rv = CKR_DATA_LEN_RANGE;
        goto c_e_out;
      }
      datalen += 16;
      break;
    default:
      DBG_ERR("Mechanism %lu not supported",
              session->operation.mechanism.mechanism);
      rv = CKR_MECHANISM_INVALID;
      goto c_e_out;
  }

  DBG_INFO("Approximated output size is %lu", datalen);

  if (pEncryptedData == NULL) {
    // NOTE: if data is NULL just return size we'll need
    *pulEncryptedDataLen = datalen;
    rv = CKR_OK;
    terminate = false;

    goto c_e_out;
  }

  // Output size is accurately calculated above, we can stop here.
  if (*pulEncryptedDataLen < datalen) {
    DBG_ERR("pulEncryptedDataLen too small, expected = %lu, got %lu", datalen,
            *pulEncryptedDataLen);
    rv = CKR_BUFFER_TOO_SMALL;
    *pulEncryptedDataLen = datalen;
    terminate = false;

    goto c_e_out;
  }

  // Both update and finalize may modify the output. We'll have to calculate
  // the completed size ourselves by summarizing the two operations.
  CK_ULONG ulRemainingSize = *pulEncryptedDataLen;
  CK_BYTE_PTR pPtr = pEncryptedData;
  rv = apply_decrypt_mechanism_update(session->slot->device_session,
                                      &session->operation, pData, ulDataLen,
                                      pPtr, pulEncryptedDataLen);
  if (rv != CKR_OK) {
    // Buffer too small should have been handled above.
    // Translate into a non-recoverable error.
    rv = rv == CKR_BUFFER_TOO_SMALL ? CKR_FUNCTION_FAILED : rv;
    DBG_ERR("Unable to perform encrypt operation step");
    goto c_e_out;
  }

  ulRemainingSize -= *pulEncryptedDataLen;
  pPtr += *pulEncryptedDataLen;
  rv = apply_encrypt_mechanism_finalize(session->slot->device_session,
                                        &session->operation, pPtr,
                                        &ulRemainingSize);
  if (rv != CKR_OK) {
    // Buffer too small should have been handled above.
    // Translate into a non-recoverable error.
    rv = rv == CKR_BUFFER_TOO_SMALL ? CKR_FUNCTION_FAILED : rv;
    DBG_ERR("Unable to perform encrypt operation step");
    goto c_e_out;
  }

  // Calculate final size.
  *pulEncryptedDataLen += ulRemainingSize;
  DBG_INFO("Got %lu butes back", *pulEncryptedDataLen);

  rv = CKR_OK;

  DOUT;

c_e_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
    }
  }
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  DIN;

  CK_RV rv = CKR_OK;
  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_eu_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_eu_out;
  }

  if (session->operation.type != OPERATION_ENCRYPT) {
    DBG_ERR("Decrypt operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_eu_out;
  }

  rv = set_operation_part(&session->operation, PART_MULTIPLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another encrypt operation is already active");
    goto c_eu_out;
  }

  if (pPart == NULL || pulEncryptedPartLen == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_eu_out;
  }

  DBG_INFO("Encrypt update with %lu bytes", ulPartLen);

  rv = apply_decrypt_mechanism_update(session->slot->device_session,
                                      &session->operation, pPart, ulPartLen,
                                      pEncryptedPart, pulEncryptedPartLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform encryption operation step");
    goto c_eu_out;
  }

  DOUT;

c_eu_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
      session->operation.type = OPERATION_NOOP;
      decrypt_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
 CK_ULONG_PTR pulLastEncryptedPartLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;
  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_ef_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_ef_out;
  }

  if (session->operation.type != OPERATION_ENCRYPT) {
    DBG_ERR("Encrypt operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_ef_out;
  }

  rv = set_operation_part(&session->operation, PART_MULTIPLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another encrypt operation is already active");
    goto c_ef_out;
  }

  if (pulLastEncryptedPartLen == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_ef_out;
  }

  if (session->operation.mechanism.mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    CK_ULONG datalen = session->operation.buffer_length + YH_CCM_WRAP_OVERHEAD;

    if (*pulLastEncryptedPartLen < datalen) {
      DBG_ERR("pulLastEncryptedPartLen too small, data will not fit, expected "
              "= "
              "%lu, got %lu",
              datalen, *pulLastEncryptedPartLen);
      rv = CKR_BUFFER_TOO_SMALL;

      *pulLastEncryptedPartLen = datalen;
      terminate = false;
      goto c_ef_out;
    }

    if (pLastEncryptedPart == NULL) {
      // NOTE: should this rather return length and ok?
      DBG_ERR("No buffer provided");
      rv = CKR_ARGUMENTS_BAD;
      goto c_ef_out;
    }
  }

  rv = apply_encrypt_mechanism_finalize(session->slot->device_session,
                                        &session->operation, pLastEncryptedPart,
                                        pulLastEncryptedPartLen);
  if (rv == CKR_BUFFER_TOO_SMALL ||
      (rv == CKR_OK && pLastEncryptedPart == NULL)) {
    terminate = false;
    goto c_ef_out;
  } else if (rv != CKR_OK) {
    DBG_ERR("Unable to perform encrypt operation step");
    goto c_ef_out;
  }

  DBG_INFO("Got %lu bytes back", *pulLastEncryptedPartLen);

  DOUT;

c_ef_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      decrypt_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

typedef struct rsa_pkcs_oaep_params {
  yh_algorithm mgf_algo;
  yh_algorithm oaep_algo;
  uint8_t oaep_label[64];
  u_int oaep_label_len;
} rsa_pkcs_oaep_params_t;

static CK_RV parse_rsa_pkcs_oaep_params(CK_RSA_PKCS_OAEP_PARAMS *p,
                                        rsa_pkcs_oaep_params_t *r) {
  const EVP_MD *md = NULL;
  switch (p->mgf) {
    case CKG_MGF1_SHA1:
      r->mgf_algo = YH_ALGO_MGF1_SHA1;
      break;
    case CKG_MGF1_SHA256:
      r->mgf_algo = YH_ALGO_MGF1_SHA256;
      break;
    case CKG_MGF1_SHA384:
      r->mgf_algo = YH_ALGO_MGF1_SHA384;
      break;
    case CKG_MGF1_SHA512:
      r->mgf_algo = YH_ALGO_MGF1_SHA512;
      break;
    default:
      DBG_ERR("Invalid mgf parameter (%lx)", p->mgf);
      return CKR_MECHANISM_PARAM_INVALID;
  }
  switch (p->hashAlg) {
    case CKM_SHA_1:
      r->oaep_algo = YH_ALGO_RSA_OAEP_SHA1;
      md = EVP_sha1();
      break;
    case CKM_SHA256:
      r->oaep_algo = YH_ALGO_RSA_OAEP_SHA256;
      md = EVP_sha256();
      break;
    case CKM_SHA384:
      r->oaep_algo = YH_ALGO_RSA_OAEP_SHA384;
      md = EVP_sha384();
      break;
    case CKM_SHA512:
      r->oaep_algo = YH_ALGO_RSA_OAEP_SHA512;
      md = EVP_sha512();
      break;
    default:
      DBG_ERR("Invalid hashAlg parameter (%lx)", p->hashAlg);
      return CKR_MECHANISM_PARAM_INVALID;
  }
  switch (p->source) {
    case 0:
      if (p->ulSourceDataLen) {
        DBG_ERR("Invalid ulSourceDataLen (%lu) parameter for source == 0",
                p->ulSourceDataLen);
        return CKR_MECHANISM_PARAM_INVALID;
      }
    case CKZ_DATA_SPECIFIED:
      if (p->ulSourceDataLen && p->pSourceData == NULL) {
        DBG_ERR(
          "Invalid pSourceData parameter (NULL) for ulSourceDataLen != 0");
        return CKR_MECHANISM_PARAM_INVALID;
      }
      break;
    default:
      DBG_ERR("Invalid source parameter (%lx)", p->source);
      return CKR_MECHANISM_PARAM_INVALID;
  }
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  if (mdctx == NULL) {
    DBG_ERR("Failed to digest source");
    return CKR_FUNCTION_FAILED;
  }
  r->oaep_label_len = sizeof(r->oaep_label);
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, p->pSourceData, p->ulSourceDataLen);
  EVP_DigestFinal_ex(mdctx, r->oaep_label, &r->oaep_label_len);
  EVP_MD_CTX_destroy(mdctx);
  return CKR_OK;
}

typedef struct rsa_aes_key_wrap_params {
  yh_algorithm aes_algo;
  rsa_pkcs_oaep_params_t oaep_params;
} rsa_aes_key_wrap_params_t;

static CK_RV parse_rsa_aes_key_wrap_params(CK_RSA_AES_KEY_WRAP_PARAMS *p,
                                           rsa_aes_key_wrap_params_t *r) {

  switch (p->ulAESKeyBits) {
    case 128:
      r->aes_algo = YH_ALGO_AES128;
      break;
    case 192:
      r->aes_algo = YH_ALGO_AES192;
      break;
    case 256:
      r->aes_algo = YH_ALGO_AES256;
      break;
    default:
      DBG_ERR("Invalid ulAESKeyBits parameter");
      return CKR_MECHANISM_PARAM_INVALID;
  }
  return parse_rsa_pkcs_oaep_params(p->pOAEPParams, &r->oaep_params);
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL) {
    DBG_ERR("Invalid Mechanism");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    return rv;
  }

  EVP_MD_CTX *mdctx = NULL;

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Other operation in progress");
    rv = CKR_OPERATION_ACTIVE;
    goto c_di_out;
  }

  DBG_INFO("Trying to decrypt data with mechanism 0x%04lx and key %08lx",
           pMechanism->mechanism, hKey);

  int type = hKey >> 16;
  if (type == ECDH_KEY_TYPE) {
    DBG_ERR("Wrong key type");
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto c_di_out;
  }

  yubihsm_pkcs11_object_desc *object = get_object_desc(session->slot, hKey);

  if (object == NULL) {
    DBG_ERR("Unable to retrieve object");
    rv = CKR_KEY_HANDLE_INVALID;
    goto c_di_out;
  }

  rv = check_decrypt_mechanism(session->slot, pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Decryption mechanism 0x%lx not supported", pMechanism->mechanism);
    goto c_di_out;
  }
  session->operation.mechanism.mechanism = pMechanism->mechanism;

  if (object->object.type == YH_ASYMMETRIC_KEY &&
      yh_is_rsa(object->object.algorithm)) {
    DBG_INFO("RSA decryption requested");

    size_t key_length = 0;
    yh_rc yrc = yh_get_key_bitlength(object->object.algorithm, &key_length);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Unable to get key length: %s", yh_strerror(yrc));
      rv = yrc_to_rv(yrc);
      goto c_di_out;
    }

    session->operation.op.decrypt.key_len = key_length;

    if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP) {
      if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
        DBG_ERR("Length of mechanism parameters does not match expected value: "
                "found %lu, expected %zu",
                pMechanism->ulParameterLen, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto c_di_out;
      }

      CK_RSA_PKCS_OAEP_PARAMS *params = pMechanism->pParameter;

      if (params->source == 0 && params->ulSourceDataLen != 0) {
        DBG_ERR("Source parameter empty but sourceDataLen != 0");
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto c_di_out;
      } else if (params->source != 0 && params->source != CKZ_DATA_SPECIFIED) {
        DBG_ERR("Unknown value in parameter source");
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto c_di_out;
      }

      rsa_pkcs_oaep_params_t oaep_params;
      rv = parse_rsa_pkcs_oaep_params(params, &oaep_params);
      if (rv != CKR_OK) {
        goto c_di_out;
      }

      session->operation.mechanism.oaep.mgf1Algo = oaep_params.mgf_algo;
      session->operation.mechanism.oaep.label_len = oaep_params.oaep_label_len;
      memcpy(session->operation.mechanism.oaep.label, oaep_params.oaep_label,
             oaep_params.oaep_label_len);

    } else if (pMechanism->mechanism != CKM_RSA_PKCS) {
      DBG_ERR("Mechanism %lu not supported", pMechanism->mechanism);
      rv = CKR_MECHANISM_INVALID;
      goto c_di_out;
    }
  } else if (object->object.type == YH_WRAP_KEY &&
             pMechanism->mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    // NOTE: is setup done for the data unwrap?
    rv = CKR_OK;
  } else if (object->object.type == YH_SYMMETRIC_KEY &&
             pMechanism->mechanism == CKM_AES_ECB) {
    rv = CKR_OK;
  } else if (pMechanism->mechanism == CKM_AES_CBC ||
             pMechanism->mechanism == CKM_AES_CBC_PAD) {
    if (object->object.type != YH_SYMMETRIC_KEY ||
        !yh_is_aes(object->object.algorithm)) {
      DBG_ERR("Wrong key type for algorithm");
      return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (pMechanism->pParameter == NULL ||
        pMechanism->ulParameterLen !=
          sizeof(session->operation.mechanism.cbc.iv)) {
      return CKR_MECHANISM_PARAM_INVALID;
    }
    // We need to save two copies to be able to reset the padding
    // mechanisms in case of a CKR_BUFFER_TOO_SMALL return.
    memcpy(session->operation.mechanism.cbc.iv, pMechanism->pParameter,
           sizeof(session->operation.mechanism.cbc.iv));
    memcpy(session->operation.mechanism.cbc.orig, pMechanism->pParameter,
           sizeof(session->operation.mechanism.cbc.orig));
  } else {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto c_di_out;
  }

  session->operation.op.decrypt.key_id = hKey;

  // TODO(adma): check mechanism parameters and key length and key supported
  // parameters

  rv = apply_decrypt_mechanism_init(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to initialize decryption operation");
    goto c_di_out;
  }

  session->operation.type = OPERATION_DECRYPT;
  set_operation_part(&session->operation, PART_INIT);

  DOUT;

c_di_out:

  if (mdctx != NULL) {
    EVP_MD_CTX_destroy(mdctx);
  }

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
 CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_d_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_d_out;
  }

  if (session->operation.type != OPERATION_DECRYPT) {
    DBG_ERR("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_d_out;
  }

  rv = set_operation_part(&session->operation, PART_SINGLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another decrypt operation is already active");
    goto c_d_out;
  }

  if (pEncryptedData == NULL || pulDataLen == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_d_out;
  }

  // Approximate output size
  CK_ULONG datalen = 0;
  switch (session->operation.mechanism.mechanism) {
    case CKM_RSA_PKCS:
      datalen = (session->operation.op.decrypt.key_len + 7) / 8 - 11;
      break;
    case CKM_RSA_PKCS_OAEP:
      datalen = (session->operation.op.decrypt.key_len + 7) / 8 -
                session->operation.mechanism.oaep.label_len * 2 - 2;
      break;
    case CKM_YUBICO_AES_CCM_WRAP:
      if (ulEncryptedDataLen <= YH_CCM_WRAP_OVERHEAD) {
        DBG_ERR("Encrypted data is too short for AES-CCM-WRAP");
        rv = CKR_ENCRYPTED_DATA_INVALID;
        goto c_d_out;
      }
      datalen = ulEncryptedDataLen - YH_CCM_WRAP_OVERHEAD;
      break;
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      datalen = ulEncryptedDataLen;
      break;
    default:
      DBG_ERR("Mechanism %lu not supported",
              session->operation.mechanism.mechanism);
      rv = CKR_MECHANISM_INVALID;
      goto c_d_out;
  }

  DBG_INFO("Approximated output size is %lu", datalen);

  if (pData == NULL) {
    // NOTE(adma): Just return the size of the data
    *pulDataLen = datalen;

    rv = CKR_OK;
    terminate = false;

    DOUT;
    goto c_d_out;
  }

  // NOTE: if pData is set we'll go on with decryption no matter what pulDataLen
  // is, the user might know more than us about the real data length

  DBG_INFO("Sending %lu bytes to decrypt using key %04x", ulEncryptedDataLen,
           session->operation.op.decrypt.key_id);

  CK_ULONG ulRemainingSize = *pulDataLen;
  CK_BYTE_PTR pPtr = pData;
  rv = apply_decrypt_mechanism_update(session->slot->device_session,
                                      &session->operation, pEncryptedData,
                                      ulEncryptedDataLen, pPtr, pulDataLen);
  if (rv != CKR_OK) {
    if (rv == CKR_BUFFER_TOO_SMALL) {
      // PKCS11 specifications wants this to be the _exact_ size; which we
      // cannot know until we call apply_decrypt_mechanism_finalize(). We'll
      // have to use our best guess for what the final length will be.
      DBG_ERR("Update failed, use best guess for actual output size");
      *pulDataLen = datalen;
      terminate = false;
    } else {
      DBG_ERR("Unable to perform decrypt update");
    }
    goto c_d_out;
  }

  ulRemainingSize -= *pulDataLen;
  pPtr += *pulDataLen;

  rv = apply_decrypt_mechanism_finalize(session->slot->device_session,
                                        &session->operation, pPtr,
                                        &ulRemainingSize);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to decrypt data");
    if (rv == CKR_BUFFER_TOO_SMALL) {
      *pulDataLen += ulRemainingSize;
      terminate = false;
    }
    goto c_d_out;
  }

  *pulDataLen += ulRemainingSize;
  DBG_INFO("Got %lu bytes back", *pulDataLen);

  rv = CKR_OK;

  DOUT;

c_d_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      decrypt_mechanism_cleanup(&session->operation);
    }

    // Reset the internal buffer.
    session->operation.buffer_length = 0;
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {

  DIN;

  CK_RV rv = CKR_OK;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_du_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_du_out;
  }

  if (session->operation.type != OPERATION_DECRYPT) {
    DBG_ERR("Decrypt operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_du_out;
  }

  rv = set_operation_part(&session->operation, PART_MULTIPLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another decrypt operation is already active");
    goto c_du_out;
  }

  if (pEncryptedPart == NULL || pulPartLen == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_du_out;
  }

  DBG_INFO("Decrypt update with %lu bytes", ulEncryptedPartLen);

  rv = apply_decrypt_mechanism_update(session->slot->device_session,
                                      &session->operation, pEncryptedPart,
                                      ulEncryptedPartLen, pPart, pulPartLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform decryption operation step");
    goto c_du_out;
  }

  DOUT;

c_du_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL) {
      session->operation.type = OPERATION_NOOP;
      decrypt_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
 CK_ULONG_PTR pulLastPartLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_df_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_df_out;
  }

  if (session->operation.type != OPERATION_DECRYPT) {
    DBG_ERR("Decrypt operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_df_out;
  }

  rv = set_operation_part(&session->operation, PART_MULTIPLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another decrypt operation is already active");
    goto c_df_out;
  }

  if (pulLastPartLen == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_df_out;
  }

  CK_ULONG datalen = 0;
  if (session->operation.mechanism.mechanism == CKM_RSA_PKCS) {
    datalen = (session->operation.op.decrypt.key_len + 7) / 8 - 11;
  } else if (session->operation.mechanism.mechanism == CKM_RSA_PKCS_OAEP) {
    datalen = (session->operation.op.decrypt.key_len + 7) / 8 -
              session->operation.mechanism.oaep.label_len * 2 - 2;
  } else if (session->operation.mechanism.mechanism ==
             CKM_YUBICO_AES_CCM_WRAP) {
    if (session->operation.buffer_length <= YH_CCM_WRAP_OVERHEAD) {
      DBG_ERR("Encrypted data is to short to possibly come from aes-ccm-wrap");
      rv = CKR_ENCRYPTED_DATA_INVALID;
      goto c_df_out;
    }
    datalen = session->operation.buffer_length - YH_CCM_WRAP_OVERHEAD;
  } else if (session->operation.mechanism.mechanism == CKM_AES_ECB ||
             session->operation.mechanism.mechanism == CKM_AES_CBC) {
    datalen = 0;
  } else if (session->operation.mechanism.mechanism == CKM_AES_CBC_PAD) {
    datalen = 16;
  } else {
    DBG_ERR("Mechanism %lu not supported",
            session->operation.mechanism.mechanism);
    rv = CKR_MECHANISM_INVALID;
    goto c_df_out;
  }

  if (pLastPart == NULL) {
    DBG_ERR("No buffer provided, length check only");
    *pulLastPartLen = datalen;
    rv = CKR_OK;
    terminate = false;
    goto c_df_out;
  }

  rv = apply_decrypt_mechanism_finalize(session->slot->device_session,
                                        &session->operation, pLastPart,
                                        pulLastPartLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to decrypt data");
    if (rv == CKR_BUFFER_TOO_SMALL) {
      terminate = false;
    }
    goto c_df_out;
  }

  DBG_INFO("Got %lu bytes back", *pulLastPartLen);

  DOUT;

c_df_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      decrypt_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL) {
    DBG_ERR("Invalid Mechanism");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Other operation in progress");
    rv = CKR_OPERATION_ACTIVE;
    goto c_di_out;
  }

  DBG_INFO("Trying to digest data with mechanism 0x%04lx",
           pMechanism->mechanism);

  rv = check_digest_mechanism(pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Digest mechanism %lu not supported", pMechanism->mechanism);
    goto c_di_out;
  }
  session->operation.mechanism.mechanism = pMechanism->mechanism;

  CK_ULONG digest_length = get_digest_bytelength(pMechanism->mechanism);

  session->operation.op.digest.digest_len = digest_length;

  rv = apply_digest_mechanism_init(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to initialize digest operation");
    goto c_di_out;
  }

  session->operation.type = OPERATION_DIGEST;

  DOUT;

c_di_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_d_out;
  }

  rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_d_out;
  }

  if (session->operation.type != OPERATION_DIGEST) {
    DBG_ERR("Digest operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_d_out;
  }

  rv = set_operation_part(&session->operation, PART_SINGLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another digest operation is already active");
    goto c_d_out;
  }

  if (pulDigestLen == NULL) {
    DBG_ERR("Wrong/missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto c_d_out;
  }

  if (pDigest == NULL) {
    // NOTE(adma): Just return the size of the digest
    DBG_INFO("The size of the digest will be %lu",
             session->operation.op.digest.digest_len);

    *pulDigestLen = session->operation.op.digest.digest_len;

    rv = CKR_OK;
    terminate = false;

    DOUT;
    goto c_d_out;
  }

  if (*pulDigestLen < session->operation.op.digest.digest_len) {
    DBG_ERR("pulDigestLen too small, data will not fit, expected = %lu, got "
            "%lu",
            session->operation.op.digest.digest_len, *pulDigestLen);

    *pulDigestLen = session->operation.op.digest.digest_len;

    rv = CKR_BUFFER_TOO_SMALL;
    terminate = false;
    goto c_d_out;
  }

  DBG_INFO("Sending %lu bytes to digest", ulDataLen);

  rv = apply_digest_mechanism_update(&session->operation, pData, ulDataLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform digest operation step");
    goto c_d_out;
  }

  rv = apply_digest_mechanism_finalize(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to finalize digest operation");
    goto c_d_out;
  }

  rv = perform_digest(&session->operation, pDigest,
                      (uint16_t *) pulDigestLen); // TODO(adma): too zealous?
                                                  // just us a memcpy?
  if (rv != CKR_OK) {
    DBG_ERR("Unable to digest data");
    goto c_d_out;
  }

  DBG_INFO("Got %lu bytes back", *pulDigestLen);

  DOUT;

c_d_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      digest_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {

  DIN;

  CK_RV rv = CKR_OK;

  // TODO(adma): somebody should check that this is a proper mult-part
  // mechanism/operation

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_du_out;
  }

  rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_du_out;
  }

  if (session->operation.type != OPERATION_DIGEST) {
    DBG_ERR("Digest operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_du_out;
  }

  rv = set_operation_part(&session->operation, PART_MULTIPLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another digest operation is already active");
    goto c_du_out;
  }

  if (pPart == NULL) {
    DBG_ERR("No data provided");
    rv = CKR_ARGUMENTS_BAD;
    goto c_du_out;
  }

  DBG_INFO("Digest update with %lu bytes", ulPartLen);

  rv = apply_digest_mechanism_update(&session->operation, pPart, ulPartLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform digest operation step");
    goto c_du_out;
  }

  DOUT;

c_du_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (rv != CKR_OK) {
      session->operation.type = OPERATION_NOOP;
      digest_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {

  DIN;

  UNUSED(hSession);
  UNUSED(hKey);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_df_out;
  }

  rv = get_session(&g_ctx, hSession, &session, 0);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_df_out;
  }

  if (pulDigestLen == NULL) {
    DBG_ERR("Wrong/missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto c_df_out;
  }

  if (session->operation.type != OPERATION_DIGEST) {
    DBG_ERR("Digest operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_df_out;
  }

  rv = set_operation_part(&session->operation, PART_MULTIPLE);
  if (rv != CKR_OK) {
    DBG_ERR("Another digest operation is already active");
    goto c_df_out;
  }

  if (pDigest == NULL) {
    // NOTE(adma): Just return the size of the digest
    DBG_INFO("The size of the digest will be %lu",
             session->operation.op.digest.digest_len);

    *pulDigestLen = session->operation.op.digest.digest_len;

    rv = CKR_OK;
    terminate = false;

    DOUT;
    goto c_df_out;
  }

  if (*pulDigestLen < session->operation.op.digest.digest_len) {
    DBG_ERR("pulDigestLen too small, data will not fit, expected = %lu, got "
            "%lu",
            session->operation.op.digest.digest_len, *pulDigestLen);

    *pulDigestLen = session->operation.op.digest.digest_len;

    terminate = false;
    rv = CKR_BUFFER_TOO_SMALL;
    goto c_df_out;
  }

  rv = apply_digest_mechanism_finalize(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to finalize digest operation");
    goto c_df_out;
  }

  rv = perform_digest(&session->operation, pDigest, (uint16_t *) pulDigestLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to digest data");
    goto c_df_out;
  }

  DBG_INFO("Got %lu bytes back", *pulDigestLen);

  DOUT;

c_df_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      digest_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL) {
    DBG_ERR("Invalid Mechanism");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Other operation in progress");
    rv = CKR_OPERATION_ACTIVE;
    goto c_si_out;
  }

  DBG_INFO("Trying to sign data with mechanism 0x%04lx and key %08lx",
           pMechanism->mechanism, hKey);

  int type = hKey >> 16;
  if (type == ECDH_KEY_TYPE) {
    DBG_ERR("Signing using an ECDH session key is not supported");
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto c_si_out;
  }

  yubihsm_pkcs11_object_desc *object = get_object_desc(session->slot, hKey);

  if (object == NULL) {
    DBG_ERR("Unable to retrieve object");
    rv = CKR_KEY_HANDLE_INVALID;
    goto c_si_out;
  }

  size_t key_length = 0;
  yh_rc yrc = yh_get_key_bitlength(object->object.algorithm, &key_length);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Unable to get key length: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_si_out;
  }

  session->operation.op.sign.key_len = key_length;

  rv = check_sign_mechanism(session->slot, pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Signing mechanism 0x%lx not supported", pMechanism->mechanism);
    goto c_si_out;
  }
  session->operation.mechanism.mechanism =
    pMechanism->mechanism; // TODO(adma): also need to check/copy the
                           // mechanism's parameter, if any

  if (object->object.type == YH_ASYMMETRIC_KEY) {
    if (yh_is_rsa(object->object.algorithm)) {
      if (is_RSA_sign_mechanism(session->operation.mechanism.mechanism)) {
        DBG_INFO("RSA signature requested");
        session->operation.op.sign.sig_len =
          (session->operation.op.sign.key_len + 7) / 8;
        if (is_PSS_sign_mechanism(session->operation.mechanism.mechanism)) {
          if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
            DBG_ERR("Length of mechanism parameters does not match expected "
                    "value, "
                    "%lu != %zu",
                    pMechanism->ulParameterLen, sizeof(CK_RSA_PKCS_PSS_PARAMS));
            rv = CKR_MECHANISM_PARAM_INVALID;
            goto c_si_out;
          }

          CK_RSA_PKCS_PSS_PARAMS *params = pMechanism->pParameter;
          // TODO: validate that params->hashAlg matches mechanism

          if (params->sLen > 0xffff) {
            DBG_ERR("Salt is too big for device");
            rv = CKR_MECHANISM_PARAM_INVALID;
            goto c_si_out;
          }
          session->operation.mechanism.pss.salt_len = params->sLen;

          switch (params->mgf) {
            case CKG_MGF1_SHA1:
              session->operation.mechanism.pss.mgf1Algo = YH_ALGO_MGF1_SHA1;
              break;
            case CKG_MGF1_SHA256:
              session->operation.mechanism.pss.mgf1Algo = YH_ALGO_MGF1_SHA256;
              break;
            case CKG_MGF1_SHA384:
              session->operation.mechanism.pss.mgf1Algo = YH_ALGO_MGF1_SHA384;
              break;
            case CKG_MGF1_SHA512:
              session->operation.mechanism.pss.mgf1Algo = YH_ALGO_MGF1_SHA512;
              break;
            default:
              rv = CKR_MECHANISM_PARAM_INVALID;
              goto c_si_out;
          };
        }
      } else {
        DBG_ERR("Mechanism %lu not supported",
                session->operation.mechanism.mechanism);
        rv = CKR_MECHANISM_INVALID;
        goto c_si_out;
      }
    } else if (yh_is_ed(object->object.algorithm)) {
      if (is_EDDSA_sign_mechanism(session->operation.mechanism.mechanism)) {
        DBG_INFO("EDDSA signature requested");
        session->operation.op.sign.sig_len =
          ((session->operation.op.sign.key_len + 7) / 8) * 2;
      } else {
        DBG_ERR("Mechanism %lu not supported",
                session->operation.mechanism.mechanism);
        rv = CKR_MECHANISM_INVALID;
        goto c_si_out;
      }
    } else {
      if (is_ECDSA_sign_mechanism(session->operation.mechanism.mechanism)) {
        DBG_INFO("ECDSA signature requested");
        session->operation.op.sign.sig_len =
          ((session->operation.op.sign.key_len + 7) / 8) * 2;
      } else {
        DBG_ERR("Mechanism %lu not supported",
                session->operation.mechanism.mechanism);
        rv = CKR_MECHANISM_INVALID;
        goto c_si_out;
      }
    }
  } else if (object->object.type == YH_HMAC_KEY) {
    if (is_HMAC_sign_mechanism(session->operation.mechanism.mechanism) ==
        true) {
      DBG_INFO("HMAC signature requested (len %lu)",
               (unsigned long) (key_length / 8));
      session->operation.op.sign.sig_len =
        (session->operation.op.sign.key_len + 7) / 8;
    } else {
      DBG_ERR("Mechanism %lu not supported",
              session->operation.mechanism.mechanism);
      rv = CKR_MECHANISM_INVALID;
      goto c_si_out;
    }
  } else {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto c_si_out;
  }

  session->operation.op.sign.key_id =
    hKey; // TODO(adma): should we store something else rather than the key ID?

  // TODO(adma): check mechanism parameters and key length and key supported
  // parameters

  rv = apply_sign_mechanism_init(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to initialize signing operation");
    goto c_si_out;
  }

  session->operation.type = OPERATION_SIGN;

  DOUT;

c_si_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = true;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_s_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_s_out;
  }

  if (session->operation.type != OPERATION_SIGN) {
    DBG_ERR("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_s_out;
  }

  DBG_INFO("The size of the signature will be %u",
           session->operation.op.sign.sig_len);

  if (pSignature == NULL) {
    // NOTE(adma): Just return the size of the signature
    *pulSignatureLen = session->operation.op.sign.sig_len;

    rv = CKR_OK;
    terminate = false;
    DOUT;
    goto c_s_out;
  }

  if (*pulSignatureLen < session->operation.op.sign.sig_len) {
    DBG_ERR("pulSignatureLen too small, signature will not fit, expected %u, "
            "got %lu",
            session->operation.op.sign.sig_len, *pulSignatureLen);
    *pulSignatureLen = session->operation.op.sign.sig_len;
    rv = CKR_BUFFER_TOO_SMALL;
    terminate = false;
    goto c_s_out;
  }

  DBG_INFO("Sending %lu bytes to sign", ulDataLen);

  rv = apply_sign_mechanism_update(&session->operation, pData, ulDataLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform signing operation step");
    goto c_s_out;
  }

  rv = apply_sign_mechanism_finalize(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to finalize signing operation");
    goto c_s_out;
  }

  DBG_INFO("Using key %04x", session->operation.op.sign.key_id);
  DBG_INFO("After padding and transformation there are %u bytes",
           session->operation.buffer_length);

  rv = perform_signature(session->slot->device_session, &session->operation,
                         pSignature, (uint16_t *) pulSignatureLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to sign data");
    goto c_s_out;
  }

  DBG_INFO("Got %lu bytes back", *pulSignatureLen);

  DOUT;

c_s_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      sign_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {

  DIN;

  CK_RV rv = CKR_OK;

  // TODO(adma): somebody should check that this is a proper mult-part
  // mechanism/operation

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_su_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_su_out;
  }

  if (session->operation.type != OPERATION_SIGN) {
    DBG_ERR("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_su_out;
  }

  if (pPart == NULL) {
    DBG_ERR("No data provided");
    rv = CKR_ARGUMENTS_BAD;
    goto c_su_out;
  }

  DBG_INFO("Signature update with %lu bytes", ulPartLen);

  rv = apply_sign_mechanism_update(&session->operation, pPart, ulPartLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform signing operation step");
    goto c_su_out;
  }

  DOUT;

c_su_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (rv != CKR_OK) {
      session->operation.type = OPERATION_NOOP;
      sign_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
 CK_ULONG_PTR pulSignatureLen) {

  DIN;

  CK_RV rv = CKR_OK;
  bool terminate = false;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_sf_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_sf_out;
  }

  if (session->operation.type != OPERATION_SIGN) {
    DBG_ERR("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_sf_out;
  }

  if (pSignature == NULL) {
    DBG_ERR("No buffer provided, length check only");
    *pulSignatureLen = session->operation.op.sign.sig_len;
    rv = CKR_OK;
    DOUT;
    goto c_sf_out;
  }

  terminate = true;

  rv = apply_sign_mechanism_finalize(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to finalize signing operation");
    goto c_sf_out;
  }

  rv = perform_signature(session->slot->device_session, &session->operation,
                         pSignature, (uint16_t *) pulSignatureLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to sign data");
    goto c_sf_out;
  }

  DBG_INFO("Got %lu bytes back", *pulSignatureLen);

  DOUT;

c_sf_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (terminate == true) {
      session->operation.type = OPERATION_NOOP;
      sign_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  DIN;

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(pulSignatureLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL) {
    DBG_ERR("Invalid Mechanism");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("Other operation in progress");
    rv = CKR_OPERATION_ACTIVE;
    goto c_vi_out;
  }

  DBG_INFO("Trying to verify data with mechanism 0x%04lx and key %lx",
           pMechanism->mechanism, hKey);

  int type = hKey >> 16;
  if (type == ECDH_KEY_TYPE) {
    DBG_ERR("Wrong key type");
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto c_vi_out;
  }

  yubihsm_pkcs11_object_desc *object = get_object_desc(session->slot, hKey);

  if (object == NULL) {
    DBG_ERR("Unable to retrieve object");
    rv = CKR_KEY_HANDLE_INVALID;
    goto c_vi_out;
  }

  size_t key_length = 0;
  yh_rc yrc = yh_get_key_bitlength(object->object.algorithm, &key_length);
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Unable to get key length: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_vi_out;
  }

  session->operation.op.verify.key_len = key_length;

  rv = check_sign_mechanism(session->slot, pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Verification mechanism 0x%lx not supported", pMechanism->mechanism);
    goto c_vi_out;
  }
  session->operation.mechanism.mechanism =
    pMechanism->mechanism; // TODO(adma): also need to check/copy the
                           // mechanism's parameter, if any

  if (object->object.type == YH_HMAC_KEY) {
    DBG_INFO("HMAC verification requested");
  } else if (object->object.type == YH_PUBLIC_KEY) {
    DBG_INFO("Asymmetric verification requested");
  } else {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto c_vi_out;
  }

  session->operation.op.verify.key_id = hKey;

  rv = apply_verify_mechanism_init(&session->operation);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to initialize verification operation");
    goto c_vi_out;
  }

  if (yh_is_rsa(object->object.algorithm)) {
    if (is_PSS_sign_mechanism(session->operation.mechanism.mechanism)) {
      if (pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
        DBG_ERR("Length of mechanism parameters does not match expected value, "
                "%lu != %zu",
                pMechanism->ulParameterLen, sizeof(CK_RSA_PKCS_PSS_PARAMS));
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto c_vi_out;
      }

      // TODO: validate that params->hashAlg matches mechanism
      CK_RSA_PKCS_PSS_PARAMS *params = pMechanism->pParameter;

      session->operation.op.verify.padding = RSA_PKCS1_PSS_PADDING;
      session->operation.op.verify.saltLen = params->sLen;
      switch (params->mgf) {
        case CKG_MGF1_SHA1:
          session->operation.op.verify.mgf1md = EVP_sha1();
          break;
        case CKG_MGF1_SHA256:
          session->operation.op.verify.mgf1md = EVP_sha256();
          break;
        case CKG_MGF1_SHA384:
          session->operation.op.verify.mgf1md = EVP_sha384();
          break;
        case CKG_MGF1_SHA512:
          session->operation.op.verify.mgf1md = EVP_sha512();
          break;
        default:
          DBG_ERR("Unsupported mgf algorithm: %lu", params->mgf);
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto c_vi_out;
      }
      switch (params->hashAlg) {
        case CKM_SHA_1:
          session->operation.op.verify.md = EVP_sha1();
          break;
        case CKM_SHA256:
          session->operation.op.verify.md = EVP_sha256();
          break;
        case CKM_SHA384:
          session->operation.op.verify.md = EVP_sha384();
          break;
        case CKM_SHA512:
          session->operation.op.verify.md = EVP_sha512();
          break;
        default:
          DBG_ERR("Unsupported pss hash algorithm: %lu", params->hashAlg);
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto c_vi_out;
      }
    } else if (is_PKCS1v1_5_sign_mechanism(
                 session->operation.mechanism.mechanism)) {
      session->operation.op.verify.padding = RSA_PKCS1_PADDING;
    } else if (!is_RSA_sign_mechanism(session->operation.mechanism.mechanism)) {
      DBG_ERR("Unsupported mechanism for RSA key");
      rv = CKR_KEY_TYPE_INCONSISTENT;
      goto c_vi_out;
    }
  } else if (yh_is_ec(object->object.algorithm)) {
    if (!is_ECDSA_sign_mechanism(session->operation.mechanism.mechanism)) {
      DBG_ERR("Unsupported mechanism for EC key");
      rv = CKR_KEY_TYPE_INCONSISTENT;
      goto c_vi_out;
    }
  } else if (yh_is_ed(object->object.algorithm)) {
    if (!is_EDDSA_sign_mechanism(session->operation.mechanism.mechanism)) {
      DBG_ERR("Unsupported mechanism for ED key");
      rv = CKR_KEY_TYPE_INCONSISTENT;
      goto c_vi_out;
    }
  } else if (yh_is_hmac(object->object.algorithm)) {
    if (!is_HMAC_sign_mechanism(session->operation.mechanism.mechanism)) {
      DBG_ERR("Unsupported mechanism for HMAC key");
      rv = CKR_KEY_TYPE_INCONSISTENT;
      goto c_vi_out;
    }
  } else {
    DBG_ERR("Unsupported key type");
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto c_vi_out;
  }

  session->operation.type = OPERATION_VERIFY;

  DOUT;

c_vi_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
 CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {

  DIN;

  CK_RV rv = CKR_OK;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_v_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_v_out;
  }

  if (pData == NULL || pSignature == NULL) {
    DBG_ERR("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto c_v_out;
  }

  if (session->operation.type != OPERATION_VERIFY) {
    DBG_ERR("Verification operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_v_out;
  }

  rv = apply_verify_mechanism_update(&session->operation, pData, ulDataLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform verification operation step");
    goto c_v_out;
  }

  rv = apply_verify_mechanism_finalize(&session->operation, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to finalize verification operation");
    goto c_v_out;
  }

  DBG_INFO("Using key %04x", session->operation.op.verify.key_id);

  rv = perform_verify(session->slot->device_session, &session->operation,
                      pSignature, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to verify signature");
    goto c_v_out;
  }

  DBG_INFO("Signature successfully verified");

  DOUT;

c_v_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    session->operation.type = OPERATION_NOOP;
    verify_mechanism_cleanup(&session->operation);
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {

  DIN;

  CK_RV rv = CKR_OK;

  // TODO(adma): somebody should check that this is a proper mult-part
  // mechanism/operation

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_vu_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_vu_out;
  }

  if (session->operation.type != OPERATION_VERIFY) {
    DBG_ERR("Verification operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_vu_out;
  }

  if (pPart == NULL) {
    DBG_ERR("No data provided");
    rv = CKR_ARGUMENTS_BAD;
    goto c_vu_out;
  }

  DBG_INFO("Verification update with %lu bytes", ulPartLen);

  rv = apply_verify_mechanism_update(&session->operation, pPart, ulPartLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to perform verification operation step");
    goto c_vu_out;
  }

  DOUT;

c_vu_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    if (rv != CKR_OK) {
      session->operation.type = OPERATION_NOOP;
      verify_mechanism_cleanup(&session->operation);
    }
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {

  DIN;

  CK_RV rv = CKR_OK;

  yubihsm_pkcs11_session *session = NULL;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto c_vf_out;
  }

  rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID %lu", hSession);
    goto c_vf_out;
  }

  if (session->operation.type != OPERATION_VERIFY) {
    DBG_ERR("Verification operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto c_vf_out;
  }

  if (pSignature == NULL) {
    DBG_ERR("No buffer provided");
    rv = CKR_ARGUMENTS_BAD;
    goto c_vf_out;
  }

  rv = apply_verify_mechanism_finalize(&session->operation, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to finalize verification operation");
    goto c_vf_out;
  }

  rv = perform_verify(session->slot->device_session, &session->operation,
                      pSignature, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG_ERR("Unable to verify data");
    goto c_vf_out;
  }

  DOUT;

c_vf_out:
  if (session != NULL) {
    release_session(&g_ctx, session);
    session->operation.type = OPERATION_NOOP;
    verify_mechanism_cleanup(&session->operation);
  }

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hKey) {

  DIN;

  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
 CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pSignature);
  UNUSED(ulSignatureLen);
  UNUSED(pData);
  UNUSED(pulDataLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);
  UNUSED(pEncryptedPart);
  UNUSED(pulEncryptedPartLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pEncryptedPart);
  UNUSED(ulEncryptedPartLen);
  UNUSED(pPart);
  UNUSED(pulPartLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
 CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pPart);
  UNUSED(ulPartLen);
  UNUSED(pEncryptedPart);
  UNUSED(pulEncryptedPartLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pEncryptedPart);
  UNUSED(ulEncryptedPartLen);
  UNUSED(pPart);
  UNUSED(pulPartLen);

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL || pTemplate == NULL || phKey == NULL) {
    DBG_ERR("Invalid argument");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED_RW);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID: %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("A different operation is already active");
    rv = CKR_OPERATION_ACTIVE;
    goto c_gk_out;
  }

  if (pMechanism->mechanism != CKM_GENERIC_SECRET_KEY_GEN &&
      pMechanism->mechanism != CKM_AES_KEY_GEN) {
    DBG_ERR("Invalid mechanism %lu", pMechanism->mechanism);
    rv = CKR_MECHANISM_INVALID;
    goto c_gk_out;
  }

  yubihsm_pkcs11_object_template template = {0};
  pkcs11_meta_object meta_object = {0};
  struct {
    bool set;
    CK_ULONG d;
  } class = {0}, key_type = {0};
  for (CK_ULONG i = 0; i < ulCount; i++) {
    switch (pTemplate[i].type) {
      case CKA_CLASS:
        if (class.set == false) {
          class.d = *((CK_ULONG_PTR) pTemplate[i].pValue);
          class.set = true;
        } else {
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_gk_out;
        }
        break;

      case CKA_KEY_TYPE:
        if (key_type.set == false) {
          key_type.d = *((CK_ULONG_PTR) pTemplate[i].pValue);
          key_type.set = true;
        } else {
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_gk_out;
        }
        break;

      case CKA_ID:
        rv =
          parse_meta_id_template(&template, &meta_object, false,
                                 pTemplate[i].pValue, pTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_LABEL:
        rv = parse_meta_label_template(&template, &meta_object, false,
                                       pTemplate[i].pValue,
                                       pTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
          return rv;
        }
        break;

      case CKA_EXTRACTABLE:
        if ((rv = set_template_attribute(&template.exportable,
                                         pTemplate[i].pValue)) != CKR_OK) {
          DBG_ERR("CKA_EXTRACTABLE inconsistent in template");
          return rv;
        }
    }
  }

  if (key_type.set == false || class.set == false) {
    if (pMechanism->mechanism == CKM_AES_KEY_GEN) {
      /* attributes given implicitly */
      if (!key_type.set) {
        key_type.d = CKK_AES;
        key_type.set = true;
      }
      if (!class.set) {
        class.d = CKO_SECRET_KEY;
        class.set = true;
      }
    } else {
      rv = CKR_TEMPLATE_INCOMPLETE;
      goto c_gk_out;
    }
  }

  yh_capabilities capabilities = {{0}};
  yh_capabilities delegated_capabilities = {{0}};
  uint8_t type = 0;
  yh_rc rc = YHR_SUCCESS;

  if (template.exportable == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("exportable-under-wrap", &capabilities);
    if (rc != YHR_SUCCESS) {
      rv = yrc_to_rv(rc);
      goto c_gk_out;
    }
  }

  if (class.d == CKO_SECRET_KEY) {
    if (key_type.d == CKK_SHA_1_HMAC || key_type.d == CKK_SHA256_HMAC ||
        key_type.d == CKK_SHA384_HMAC || key_type.d == CKK_SHA512_HMAC) {
      type = YH_HMAC_KEY;
      rv = parse_hmac_template(pTemplate, ulCount, &template, true);
      if (rv != CKR_OK) {
        goto c_gk_out;
      }

      if (template.sign == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("sign-hmac", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_gk_out;
        }
      }

      if (template.verify == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("verify-hmac", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_gk_out;
        }
      }

      rc = yh_util_generate_hmac_key(session->slot->device_session,
                                     &template.id, template.label, 0xffff,
                                     &capabilities, template.algorithm);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed generating HMAC key: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_gk_out;
      }
    } else if (key_type.d == CKK_YUBICO_AES128_CCM_WRAP ||
               key_type.d == CKK_YUBICO_AES192_CCM_WRAP ||
               key_type.d == CKK_YUBICO_AES256_CCM_WRAP) {
      yh_algorithm algo = key_type.d & 0xff;
      type = YH_WRAP_KEY;
      rv = parse_wrap_template(pTemplate, ulCount, &template, algo, true);
      if (rv != CKR_OK) {
        goto c_gk_out;
      }

      DBG_INFO("parsed WRAP key, objlen: %d", template.objlen);

      rc = set_wrapkey_capabilities(&template, &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gk_out;
      }

      rc = yh_string_to_capabilities("all", &delegated_capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gk_out;
      }

      rc =
        yh_util_generate_wrap_key(session->slot->device_session, &template.id,
                                  template.label, 0xffff, &capabilities, algo,
                                  &delegated_capabilities);
      if (rc != YHR_SUCCESS) {
        DBG_ERR("Failed generating wrap key: %s", yh_strerror(rc));
        rv = yrc_to_rv(rc);
        goto c_gk_out;
      }
    } else if (key_type.d == CKK_AES) {
      type = YH_SYMMETRIC_KEY;
      rv = parse_aes_template(pTemplate, ulCount, &template, true);
      if (rv != CKR_OK) {
        goto c_gk_out;
      }

      if (template.encrypt == ATTRIBUTE_TRUE) {
        rc =
          yh_string_to_capabilities("encrypt-ecb,encrypt-cbc", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = CKR_FUNCTION_FAILED;
          goto c_gk_out;
        }
      }

      if (template.decrypt == ATTRIBUTE_TRUE) {
        rc =
          yh_string_to_capabilities("decrypt-ecb,decrypt-cbc", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = CKR_FUNCTION_FAILED;
          goto c_gk_out;
        }
      }

      if (yh_util_generate_aes_key(session->slot->device_session, &template.id,
                                   template.label, 0xffff, &capabilities,
                                   template.algorithm) != YHR_SUCCESS) {
        DBG_ERR("Failed generating symmetric key");
        rv = CKR_FUNCTION_FAILED;
        goto c_gk_out;
      }
    } else {
      DBG_ERR("Unknown key_type: %lx", class.d);
      rv = CKR_ATTRIBUTE_VALUE_INVALID;
      goto c_gk_out;
    }
  } else {
    rv = CKR_TEMPLATE_INCONSISTENT;
    goto c_gk_out;
  }

  yubihsm_pkcs11_object_desc *object_desc =
    _get_object_desc(session->slot, template.id, type, 0xffff);
  if (object_desc == NULL) {
    DBG_ERR("Failed getting new object %04x: %s", template.id, yh_strerror(rc));
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto c_gk_out;
  }
  yh_object_descriptor *object = &object_desc->object;

  *phKey = object->sequence << 24 | object->type << 16 | object->id;

  if (meta_object.cka_id.len > 0 || meta_object.cka_label.len > 0) {
    meta_object.target_id = object->id;
    meta_object.target_type = object->type;
    meta_object.target_sequence = object->sequence;
    rv = write_meta_object(session->slot, &meta_object, &capabilities,
                           object->domains, false);
    if (rv != CKR_OK) {
      DBG_ERR("Failed writing meta opaque object to device 0x%lx. Note that "
              "the original object has been successfully generated in the "
              "device but without the expected CKA_ID and/or CKA_LABEL.",
              rv);
      goto c_gk_out;
    }
  }

  DBG_INFO("Created object %08lx", *phKey);

  DOUT;

c_gk_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
 CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL || pPublicKeyTemplate == NULL ||
      pPrivateKeyTemplate == NULL || phPublicKey == NULL ||
      phPrivateKey == NULL) {
    DBG_ERR("Invalid argument");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED_RW);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID: %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("A different operation is already active");
    rv = CKR_OPERATION_ACTIVE;
    goto c_gkp_out;
  }

  yubihsm_pkcs11_object_template template = {0};
  pkcs11_meta_object meta_object = {0};

  if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
    rv =
      parse_rsa_generate_template(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                  pPrivateKeyTemplate,
                                  ulPrivateKeyAttributeCount, &template,
                                  &meta_object);
  } else if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
    rv =
      parse_ec_generate_template(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                 pPrivateKeyTemplate,
                                 ulPrivateKeyAttributeCount, &template,
                                 &meta_object);
  } else if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN) {
    rv =
      parse_ed_generate_template(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                 pPrivateKeyTemplate,
                                 ulPrivateKeyAttributeCount, &template,
                                 &meta_object);
  } else {
    DBG_ERR("Invalid mechanism for key generation: %lu", pMechanism->mechanism);
    rv = CKR_MECHANISM_INVALID;
    goto c_gkp_out;
  }

  if (rv != CKR_OK) {
    DBG_ERR("Unable to parse generation template");
    goto c_gkp_out;
  }

  yh_capabilities capabilities = {{0}};
  yh_rc rc = YHR_SUCCESS;

  if (template.exportable == ATTRIBUTE_TRUE) {
    rc = yh_string_to_capabilities("exportable-under-wrap", &capabilities);
    if (rc != YHR_SUCCESS) {
      rv = yrc_to_rv(rc);
      goto c_gkp_out;
    }
  }

  // TODO(adma): check more return values

  if (yh_is_rsa(template.algorithm)) {
    if (template.unwrap) { // This is a wrap key
      rc = set_wrapkey_capabilities(&template, &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gkp_out;
      }

      yh_capabilities delegated_capabilities = {{0}};
      rc = yh_string_to_capabilities("all", &delegated_capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gkp_out;
      }

      rc =
        yh_util_generate_wrap_key(session->slot->device_session, &template.id,
                                  template.label, 0xffff, &capabilities,
                                  template.algorithm, &delegated_capabilities);

    } else {
      if (template.sign == ATTRIBUTE_TRUE) {
        rc = yh_string_to_capabilities("sign-pkcs,sign-pss", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_gkp_out;
        }
      }

      if (template.decrypt == ATTRIBUTE_TRUE) {
        rc =
          yh_string_to_capabilities("decrypt-pkcs,decrypt-oaep", &capabilities);
        if (rc != YHR_SUCCESS) {
          rv = yrc_to_rv(rc);
          goto c_gkp_out;
        }
      }

      rc = yh_util_generate_rsa_key(session->slot->device_session, &template.id,
                                    template.label, 0xffff, &capabilities,
                                    template.algorithm);
    }
    if (rc != YHR_SUCCESS) {
      DBG_ERR("Failed generating RSA key on device: %s", yh_strerror(rc));
      rv = yrc_to_rv(rc);
      goto c_gkp_out;
    }
  } else if (yh_is_ed(template.algorithm)) {

    if (template.sign == ATTRIBUTE_TRUE) {
      rc = yh_string_to_capabilities("sign-eddsa", &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gkp_out;
      }
    }

    rc = yh_util_generate_ed_key(session->slot->device_session, &template.id,
                                 template.label, 0xffff, &capabilities,
                                 template.algorithm);

    if (rc != YHR_SUCCESS) {
      DBG_ERR("Failed generating ED key on device");
      rv = yrc_to_rv(rc);
      goto c_gkp_out;
    }
  } else {

    if (template.sign == ATTRIBUTE_TRUE) {
      rc = yh_string_to_capabilities("sign-ecdsa", &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gkp_out;
      }
    }

    if (template.derive == ATTRIBUTE_TRUE) {
      rc = yh_string_to_capabilities("derive-ecdh", &capabilities);
      if (rc != YHR_SUCCESS) {
        rv = yrc_to_rv(rc);
        goto c_gkp_out;
      }
    }

    rc = yh_util_generate_ec_key(session->slot->device_session, &template.id,
                                 template.label, 0xffff, &capabilities,
                                 template.algorithm);
    if (rc != YHR_SUCCESS) {
      DBG_ERR("Failed generating EC key on device: %s", yh_strerror(rc));
      rv = yrc_to_rv(rc);
      goto c_gkp_out;
    }
  }

  yubihsm_pkcs11_object_desc *object_desc = NULL;
  if (template.unwrap) {
    object_desc =
      _get_object_desc(session->slot, template.id, YH_WRAP_KEY, 0xffff);
  } else {
    object_desc =
      _get_object_desc(session->slot, template.id, YH_ASYMMETRIC_KEY, 0xffff);
  }
  if (object_desc == NULL) {
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto c_gkp_out;
  }
  yh_object_descriptor *object = &object_desc->object;

  if (meta_object.cka_id.len > 0 || meta_object.cka_label.len > 0 ||
      meta_object.cka_id_pubkey.len > 0 ||
      meta_object.cka_label_pubkey.len > 0) {
    meta_object.target_id = object->id;
    meta_object.target_type = object->type;
    meta_object.target_sequence = object->sequence;
    rv = write_meta_object(session->slot, &meta_object, &capabilities,
                           object->domains, false);
    if (rv != CKR_OK) {
      DBG_ERR("Failed writing meta opaque object to device 0x%lx. Note that "
              "the original object has been successfully generated in the "
              "device but without the expected CKA_ID and/or CKA_LABEL.",
              rv);

      goto c_gkp_out;
    }
  }
  *phPublicKey =
    object->sequence << 24 | (object->type | 0x80) << 16 | object->id;
  *phPrivateKey = object->sequence << 24 | object->type << 16 | object->id;

  DOUT;

c_gkp_out:

  insecure_memzero(&template, sizeof(template));

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey,
 CK_ULONG_PTR pulWrappedKeyLen) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL || pulWrappedKeyLen == NULL) {
    DBG_ERR("Invalid argument");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  int wrapped_key_type = hKey >> 16;
  int wrapping_key_type = hWrappingKey >> 16;
  if (wrapped_key_type == ECDH_KEY_TYPE || wrapping_key_type == ECDH_KEY_TYPE) {
    DBG_ERR("Wrapping involving ECDH session keys is not supported");
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto c_wk_out;
  }

  yubihsm_pkcs11_object_desc *object = get_object_desc(session->slot, hKey);
  if (object == NULL) {
    DBG_ERR("Wrapped key not found");
    rv = CKR_KEY_HANDLE_INVALID;
    goto c_wk_out;
  }

  // NOTE: pWrappedKey is NULL so we just return the length we need
  if (pWrappedKey == NULL) {
    *pulWrappedKeyLen = YH_MSG_BUF_SIZE;
    //  CKM_YUBICO_AES_CCM_WRAP len = sizeof(yh_object_descriptor) +
    //  object->object.len + YH_CCM_WRAP_OVERHEAD;
    DBG_INFO("Wrapping will need maximum of %lu bytes", *pulWrappedKeyLen);
    rv = CKR_OK;
    goto c_wk_out;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("A different operation is already active");
    rv = CKR_OPERATION_ACTIVE;
    goto c_wk_out;
  }

  rv = check_wrap_mechanism(session->slot, pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Wrapping mechanism 0x%lx not supported", pMechanism->mechanism);
    goto c_wk_out;
  }

  yubihsm_pkcs11_object_desc *key =
    get_object_desc(session->slot, hWrappingKey);
  if (key == NULL) {
    DBG_ERR("No wrap key found");
    rv = CKR_WRAPPING_KEY_HANDLE_INVALID;
    goto c_wk_out;
  }

  if (yh_check_capability(&key->object.capabilities, "export-wrapped") ==
      false) {
    DBG_ERR("Wrap key does not have \"export-wrapped\" set");
    rv = CKR_WRAPPING_KEY_TYPE_INCONSISTENT; // TODO: say something better?
    goto c_wk_out;
  }

  if (yh_check_capability(&object->object.capabilities,
                          "exportable-under-wrap") == false) {
    DBG_ERR("Key to be wrapped does not have \"exportable-under-wrap\" set");
    rv = CKR_KEY_UNEXTRACTABLE;
    goto c_wk_out;
  }

  size_t len = *pulWrappedKeyLen;

  yh_rc yrc = YHR_SUCCESS;
  if (pMechanism->mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    if (pMechanism->pParameter &&
        pMechanism->ulParameterLen != sizeof(CKM_YUBICO_AES_CCM_WRAP_PARAMS)) {
      DBG_ERR("Wrong mechanism parameter length");
      rv = CKR_MECHANISM_PARAM_INVALID;
      goto c_wk_out;
    }

    CKM_YUBICO_AES_CCM_WRAP_PARAMS *params = pMechanism->pParameter;
    CK_ULONG format = 0; // None = Do not include seed
    if (params != NULL) {
      format = params->format;
    }
    yrc =
      yh_util_export_wrapped_ex(session->slot->device_session, key->object.id,
                                object->object.type, object->object.id, format,
                                pWrappedKey, &len);
  } else { // CKM_RSA_AES_KEY_WRAP or CKM_YUBICO_RSA_WRAP
    if (pMechanism->pParameter == NULL ||
        pMechanism->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS)) {
      DBG_ERR("Wrong mechanism parameter length");
      rv = CKR_MECHANISM_PARAM_INVALID;
      goto c_wk_out;
    }

    rsa_aes_key_wrap_params_t params = {0};
    rv = parse_rsa_aes_key_wrap_params(pMechanism->pParameter, &params);
    if (rv != CKR_OK) {
      goto c_wk_out;
    }

    if (pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) {
      yrc = yh_util_get_rsa_wrapped_key(session->slot->device_session,
                                        key->object.id, object->object.type,
                                        object->object.id, params.aes_algo,
                                        params.oaep_params.oaep_algo,
                                        params.oaep_params.mgf_algo,
                                        params.oaep_params.oaep_label,
                                        params.oaep_params.oaep_label_len,
                                        pWrappedKey, &len);
    } else { // CKM_YUBICO_RSA_WRAP
      yrc = yh_util_export_rsa_wrapped(session->slot->device_session,
                                       key->object.id, object->object.type,
                                       object->object.id, params.aes_algo,
                                       params.oaep_params.oaep_algo,
                                       params.oaep_params.mgf_algo,
                                       params.oaep_params.oaep_label,
                                       params.oaep_params.oaep_label_len,
                                       pWrappedKey, &len);
    }
  }
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Wrapping failed: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_wk_out;
  }

  *pulWrappedKeyLen = len;

  DOUT;

c_wk_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
 CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL || pWrappedKey == NULL || phKey == NULL) {
    DBG_ERR("Invalid argument");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  if (session->operation.type != OPERATION_NOOP) {
    DBG_ERR("A different operation is already active");
    rv = CKR_OPERATION_ACTIVE;
    goto c_uk_out;
  }

  int unwrapping_key_type = hUnwrappingKey >> 16;
  if (unwrapping_key_type == ECDH_KEY_TYPE) {
    DBG_ERR("Unwrapping using ECDH session key is not supported");
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto c_uk_out;
  }

  rv = check_wrap_mechanism(session->slot, pMechanism);
  if (rv != CKR_OK) {
    DBG_ERR("Wrapping mechanism 0x%lx not supported", pMechanism->mechanism);
    goto c_uk_out;
  }

  yubihsm_pkcs11_object_desc *key =
    get_object_desc(session->slot, hUnwrappingKey);
  if (key == NULL) {
    DBG_ERR("No wrap key found");
    rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    goto c_uk_out;
  }

  if (yh_check_capability(&key->object.capabilities, "import-wrapped") ==
      false) {
    DBG_ERR("Wrap key can't unwrap");
    rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT; // TODO: say something better?
    goto c_uk_out;
  }

  uint16_t target_id = 0;
  yh_object_type target_type = 0;
  yh_rc yrc = YHR_SUCCESS;
  if (pMechanism->mechanism == CKM_YUBICO_AES_CCM_WRAP) {
    yrc = yh_util_import_wrapped(session->slot->device_session, key->object.id,
                                 pWrappedKey, ulWrappedKeyLen, &target_type,
                                 &target_id);
  } else { // CKM_RSA_AES_KEY_WRAP or CKM_YUBICO_RSA_WRAP

    if (pMechanism->pParameter == NULL ||
        pMechanism->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS)) {
      DBG_ERR("Wrong mechanism parameter length");
      rv = CKR_MECHANISM_PARAM_INVALID;
      goto c_uk_out;
    }

    rsa_aes_key_wrap_params_t params = {0};
    rv = parse_rsa_aes_key_wrap_params(pMechanism->pParameter, &params);
    if (rv != CKR_OK) {
      goto c_uk_out;
    }

    if (pMechanism->mechanism == CKM_YUBICO_RSA_WRAP) {
      yrc =
        yh_util_import_rsa_wrapped(session->slot->device_session,
                                   key->object.id, params.oaep_params.oaep_algo,
                                   params.oaep_params.mgf_algo,
                                   params.oaep_params.oaep_label,
                                   params.oaep_params.oaep_label_len,
                                   pWrappedKey, ulWrappedKeyLen, &target_type,
                                   &target_id);
    } else { // CKM_RSA_AES_KEY_WRAP

      pkcs11_meta_object pkcs11meta;
      yubihsm_pkcs11_object_template object_template = {0};
      rv = parse_rsa_wrappedkey_template(pTemplate, ulAttributeCount,
                                         &object_template, &pkcs11meta,
                                         (CK_BYTE *) &target_type);
      if (rv != CKR_OK) {
        DBG_ERR("Failed to parse wrapped key template");
        goto c_uk_out;
      }

      yh_capabilities capabilities = {{0}};
      if (object_template.exportable == ATTRIBUTE_TRUE) {
        yrc = yh_string_to_capabilities("exportable-under-wrap", &capabilities);
        if (yrc != YHR_SUCCESS) {
          rv = yrc_to_rv(yrc);
          goto c_uk_out;
        }
      }
      if (object_template.sign == ATTRIBUTE_TRUE) {
        if (yh_is_rsa(object_template.algorithm)) {
          yrc = yh_string_to_capabilities("sign-pkcs,sign-pss", &capabilities);
          if (yrc != YHR_SUCCESS) {
            rv = yrc_to_rv(yrc);
            goto c_uk_out;
          }
        } else if (yh_is_ec(object_template.algorithm)) {
          yrc = yh_string_to_capabilities("sign-ecdsa", &capabilities);
          if (yrc != YHR_SUCCESS) {
            rv = yrc_to_rv(yrc);
            goto c_uk_out;
          }
        } else if (yh_is_ed(object_template.algorithm)) {
          yrc = yh_string_to_capabilities("sign-eddsa", &capabilities);
          if (yrc != YHR_SUCCESS) {
            rv = yrc_to_rv(yrc);
            goto c_uk_out;
          }
        } else {
          DBG_ERR(
            "Key type unsupported for unwrap or for signing capabilities");
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_uk_out;
        }
      }
      if (object_template.decrypt == ATTRIBUTE_TRUE) {
        if (yh_is_rsa(object_template.algorithm)) {
          yrc = yh_string_to_capabilities("decrypt-pkcs,decrypt-oaep",
                                          &capabilities);
          if (yrc != YHR_SUCCESS) {
            rv = yrc_to_rv(yrc);
            goto c_uk_out;
          }
        } else if (yh_is_aes(object_template.algorithm)) {
          if (object_template.decrypt == ATTRIBUTE_TRUE) {
            yrc = yh_string_to_capabilities("decrypt-ecb,decrypt-cbc",
                                            &capabilities);
            if (yrc != YHR_SUCCESS) {
              rv = CKR_FUNCTION_FAILED;
              goto c_uk_out;
            }
          }
        } else {
          DBG_ERR(
            "Key type unsupported for unwrap or for decryptions capabilities");
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_uk_out;
        }
      }
      if (object_template.encrypt == ATTRIBUTE_TRUE) {
        if (!yh_is_aes(object_template.algorithm)) {
          DBG_ERR(
            "Key type unsupported for unwrap or for encryption capabilities");
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_uk_out;
        }
        yrc =
          yh_string_to_capabilities("encrypt-ecb,encrypt-cbc", &capabilities);
        if (yrc != YHR_SUCCESS) {
          rv = CKR_FUNCTION_FAILED;
          goto c_uk_out;
        }
      }
      if (object_template.derive == ATTRIBUTE_TRUE) {
        if (!yh_is_ec(object_template.algorithm)) {
          DBG_ERR("Key type unsupported for unwrap or for ECDH derivation "
                  "capabilities");
          rv = CKR_TEMPLATE_INCONSISTENT;
          goto c_uk_out;
        }
        yrc = yh_string_to_capabilities("derive-ecdh", &capabilities);
        if (yrc != YHR_SUCCESS) {
          rv = yrc_to_rv(yrc);
          goto c_uk_out;
        }
      }

      yrc =
        yh_util_put_rsa_wrapped_key(session->slot->device_session,
                                    key->object.id, target_type, &target_id,
                                    object_template.algorithm,
                                    object_template.label, 0xffff,
                                    &capabilities, params.oaep_params.oaep_algo,
                                    params.oaep_params.mgf_algo,
                                    params.oaep_params.oaep_label,
                                    params.oaep_params.oaep_label_len,
                                    pWrappedKey, ulWrappedKeyLen);
    }
  }
  if (yrc != YHR_SUCCESS) {
    DBG_ERR("Unwrapping failed: %s", yh_strerror(yrc));
    rv = yrc_to_rv(yrc);
    goto c_uk_out;
  }

  yubihsm_pkcs11_object_desc *object_desc =
    _get_object_desc(session->slot, target_id, target_type, 0xffff);
  if (object_desc == NULL) {
    DBG_ERR("Failed executing get object info after creating: id 0x%x",
            target_id);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto c_uk_out;
  }
  yh_object_descriptor *object = &object_desc->object;

  *phKey = object->sequence << 24 | object->type << 16 | object->id;

  DBG_INFO("Unwrapped object %08lx", *phKey);

  DOUT;

c_uk_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
 CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  if (pMechanism == NULL || phKey == NULL) {
    DBG_ERR("Invalid argument");
    rv = CKR_ARGUMENTS_BAD;
    goto c_drv_out;
  }

  if (pMechanism->mechanism != CKM_ECDH1_DERIVE ||
      pMechanism->pParameter == NULL) {
    DBG_ERR("Invalid mechanism for key generation: %lu", pMechanism->mechanism);
    rv = CKR_MECHANISM_INVALID;
    goto c_drv_out;
  }

  CK_ULONG basekey_type = hBaseKey >> 16;
  if (basekey_type == ECDH_KEY_TYPE) {
    DBG_ERR("Cannot derive a session key from another session key");
    rv = CKR_ARGUMENTS_BAD;
    goto c_drv_out;
  }

  char *label = NULL;
  size_t label_len = 0;
  size_t value_len = 0;
  for (CK_ULONG i = 0; i < ulAttributeCount; i++) {
    switch (pTemplate[i].type) {
      case CKA_VALUE_LEN:
        if (pTemplate[i].ulValueLen < sizeof(CK_ULONG)) {
          rv = CKR_ATTRIBUTE_VALUE_INVALID;
          goto c_drv_out;
        }
        value_len = *((CK_ULONG *) pTemplate[i].pValue);
        break;
      case CKA_LABEL:
        if (pTemplate[i].ulValueLen > YH_OBJ_LABEL_LEN) {
          rv = CKR_ATTRIBUTE_VALUE_INVALID;
          goto c_drv_out;
        }
        label = pTemplate[i].pValue;
        label_len = pTemplate[i].ulValueLen;
        break;
      default:
        rv =
          validate_derive_key_attribute(pTemplate[i].type, pTemplate[i].pValue);
        if (rv != CKR_OK) {
          goto c_drv_out;
        }
        break;
    }
  }

  CK_ECDH1_DERIVE_PARAMS *params = pMechanism->pParameter;

  if (params->kdf == CKD_NULL &&
      ((params->pSharedData != NULL) || (params->ulSharedDataLen != 0))) {
    DBG_ERR("Mechanism parameters incompatible with key derivation function");
    rv = CKR_MECHANISM_PARAM_INVALID;
    goto c_drv_out;
  }

  int seq = session->ecdh_session_keys.length + 1;
  if (seq > MAX_ECDH_SESSION_KEYS) {
    DBG_ERR("There are already %d ECDH keys available for this session. "
            "Cannot derive more",
            MAX_ECDH_SESSION_KEYS);
    rv = CKR_FUNCTION_REJECTED;
    goto c_drv_out;
  }

  ecdh_session_key ecdh_key = {0};
  ecdh_key.id = ECDH_KEY_TYPE << 16 | seq;
  ecdh_key.len = sizeof(ecdh_key.ecdh_key);

  DBG_INFO("ecdh_key.id = %lu", ecdh_key.id);

  if (value_len > ecdh_key.len) {
    DBG_ERR("Requested derived key is too long");
    rv = CKR_ATTRIBUTE_VALUE_INVALID;
    goto c_drv_out;
  }

  // Read the base key as the private keyID
  uint16_t privkey_id = hBaseKey & 0xffff;

  yh_rc rc = yh_util_derive_ecdh(session->slot->device_session, privkey_id,
                                 params->pPublicData, params->ulPublicDataLen,
                                 ecdh_key.ecdh_key, &ecdh_key.len);
  if (rc != YHR_SUCCESS) {
    DBG_ERR("Unable to derive raw ECDH key: %s", yh_strerror(rc));
    rv = yrc_to_rv(rc);
    goto c_drv_out;
  }

  DBG_INFO("ECDH ecdh_key.len = %zu", ecdh_key.len);

  rv = ecdh_with_kdf(&ecdh_key, params->pSharedData, params->ulSharedDataLen,
                     params->kdf, value_len);
  if (rv != CKR_OK) {
    DBG_ERR("Failed to derive ECDH key with KDF %lu", params->kdf);
    goto c_drv_out;
  }

  DBG_INFO("KDF ecdh_key.len = %zu", ecdh_key.len);

  if (value_len > 0) {
    if (ecdh_key.len < value_len) {
      DBG_ERR("Failed to derive a key with the requested length");
      rv = CKR_DATA_LEN_RANGE;
      goto c_drv_out;
    }

    if (ecdh_key.len > value_len) {
      // Truncate from the left
      size_t offset = ecdh_key.len - value_len;
      memmove(ecdh_key.ecdh_key, ecdh_key.ecdh_key + offset, value_len);
      memset(ecdh_key.ecdh_key + value_len, 0, offset);
      ecdh_key.len = value_len;
      DBG_INFO("Truncated ecdh_key.len = %zu", ecdh_key.len);
    }
  }

  memcpy(ecdh_key.label, label, label_len);

  // Copy the derived key as a session object
  list_append(&session->ecdh_session_keys, &ecdh_key);

  // Clear the derived key
  insecure_memzero(ecdh_key.ecdh_key, sizeof(ecdh_key.ecdh_key));

  *phKey = ecdh_key.id;

  DBG_INFO("Created object %04lx", *phKey);

  DOUT;

c_drv_out:

  release_session(&g_ctx, session);

  return rv;
}

/* Random number generation functions */

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {

  DIN;

  UNUSED(hSession);
  UNUSED(pSeed);
  UNUSED(ulSeedLen);

  DOUT;
  return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {

  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  size_t len = ulRandomLen;
  if (len != ulRandomLen || pRandomData == NULL) {
    DBG_ERR("Invalid parameter");
    return CKR_ARGUMENTS_BAD;
  }

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Unknown session %lu", hSession);
    return rv;
  }

  // the OpenSC pkcs11 test calls with 0 and expects CKR_OK, do that..
  if (len != 0) {
    yh_rc rc = yh_util_get_pseudo_random(session->slot->device_session,
                                         ulRandomLen, pRandomData, &len);
    if (rc != YHR_SUCCESS) {
      DBG_ERR("Failed to get random data: %s", yh_strerror(rc));
      rv = yrc_to_rv(rc);
      goto c_gr_out;
    }
  }

  if (len != ulRandomLen) {
    DBG_ERR("Incorrect amount of data returned");
    rv = CKR_DATA_LEN_RANGE;
    goto c_gr_out;
  }

  DOUT;

c_gr_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(CK_SESSION_HANDLE hSession)

{

  DIN;

  UNUSED(hSession);

  DOUT;
  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession) {

  DIN;

  UNUSED(hSession);

  DOUT;
  return CKR_FUNCTION_NOT_PARALLEL;
}

/* C_GetInterfaceList returns all the interfaces supported by the module*/
CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)
(CK_INTERFACE_PTR pInterfacesList, /* returned interfaces */
 CK_ULONG_PTR pulCount             /* number of interfaces returned */
) {
  yh_dbg_init(false, false, 0, "stderr");
  DIN;
  CK_RV rv = CKR_OK;
  if (!pulCount) {
    DBG_ERR("C_GetInterfaceList called with pulCount = NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  if (pInterfacesList) {
    if (*pulCount < sizeof(interfaces_list) / sizeof(interfaces_list[0])) {
      DBG_ERR("C_GetInterfaceList called with *pulCount = %lu", *pulCount);
      *pulCount = sizeof(interfaces_list) / sizeof(interfaces_list[0]);
      rv = CKR_BUFFER_TOO_SMALL;
      goto out;
    }
    memcpy(pInterfacesList, interfaces_list, sizeof(interfaces_list));
  }
  *pulCount = sizeof(interfaces_list) / sizeof(interfaces_list[0]);
out:
  DOUT;
  return rv;
}

/* C_GetInterface returns a specific interface from the module. */
CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)
(CK_UTF8CHAR_PTR pInterfaceName,   /* name of the interface */
 CK_VERSION_PTR pVersion,          /* version of the interface */
 CK_INTERFACE_PTR_PTR ppInterface, /* returned interface */
 CK_FLAGS flags                    /* flags controlling the semantics
                                    * of the interface */
) {
  yh_dbg_init(false, false, 0, "stderr");
  DIN;
  CK_RV rv = CKR_FUNCTION_FAILED;
  if (!ppInterface) {
    DBG_ERR("C_GetInterface called with ppInterface = NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  size_t i;
  for (i = 0; i < sizeof(interfaces_list) / sizeof(interfaces_list[0]); i++) {
    CK_FUNCTION_LIST_PTR func_list =
      (CK_FUNCTION_LIST_PTR) interfaces_list[i].pFunctionList;
    if ((flags & interfaces_list[i].flags) != flags) {
      DBG_INFO("C_GetInterface skipped interface %zu (%s %u.%u) because flags "
               "was %lu",
               i, interfaces_list[i].pInterfaceName, func_list->version.major,
               func_list->version.minor, flags);
      continue;
    }
    if (pVersion && (pVersion->major != func_list->version.major ||
                     pVersion->minor != func_list->version.minor)) {
      DBG_INFO("C_GetInterface skipped interface %zu (%s %u.%u) because "
               "pVersion was %u.%u",
               i, interfaces_list[i].pInterfaceName, func_list->version.major,
               func_list->version.minor, pVersion->major, pVersion->minor);
      continue;
    }
    if (pInterfaceName && strcmp((char *) pInterfaceName,
                                 (char *) interfaces_list[i].pInterfaceName)) {
      DBG_INFO("C_GetInterface skipped interface %zu (%s %u.%u) because "
               "pInterfacename was %s",
               i, interfaces_list[i].pInterfaceName, func_list->version.major,
               func_list->version.minor, pInterfaceName);
      continue;
    }
    DBG_INFO("C_GetInterface selected interface %zu (%s %u.%u)", i,
             interfaces_list[i].pInterfaceName, func_list->version.major,
             func_list->version.minor);
    *ppInterface = (CK_INTERFACE_PTR) &interfaces_list[i];
    rv = CKR_OK;
    break;
  }
out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_USER_TYPE userType,      /* the user type */
 CK_UTF8CHAR_PTR pPin,       /* the user's PIN */
 CK_ULONG ulPinLen,          /* the length of the PIN */
 CK_UTF8CHAR_PTR pUsername,  /* the user's name */
 CK_ULONG ulUsernameLen      /*the length of the user's name */
) {
  DIN;

  if (g_yh_initialized == false) {
    DBG_ERR("libyubihsm is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (userType != CKU_USER) {
    DBG_ERR("Inalid user type, only regular user allowed");
    return CKR_USER_TYPE_INVALID;
  }

  if (pPin == NULL) {
    DBG_ERR("Invalid argument pPin");
    return CKR_ARGUMENTS_BAD;
  }

  if (pUsername == NULL) {
    DBG_ERR("Invalid argument pUsername");
    return CKR_ARGUMENTS_BAD;
  }

  if (ulPinLen < YUBIHSM_PKCS11_MIN_PIN_LEN ||
      ulPinLen > YUBIHSM_PKCS11_MAX_PIN_LEN) {
    DBG_ERR("Wrong PIN length, must be [%u, %u] got %lu",
            YUBIHSM_PKCS11_MIN_PIN_LEN, YUBIHSM_PKCS11_MAX_PIN_LEN, ulPinLen);
    return CKR_ARGUMENTS_BAD;
  }

  CK_UTF8CHAR prefix = *pUsername;
  if (prefix == '@') {
    pUsername++;
    ulUsernameLen--;
  }

  if (ulUsernameLen != 4) {
    DBG_ERR("Wrong username length, must be 4 got %lu", ulUsernameLen);
    return CKR_ARGUMENTS_BAD;
  }

  uint16_t key_id = 0;
  size_t key_id_len = sizeof(key_id);
  char tmpUser[5] = {0};
  memcpy(tmpUser, pUsername, 4);

  if (hex_decode((const char *) tmpUser, (uint8_t *) &key_id, &key_id_len) ==
        false ||
      key_id_len != sizeof(key_id)) {
    DBG_ERR(
      "PIN contains invalid characters, first four digits must be [0-9A-Fa-f]");
    return CKR_PIN_INCORRECT;
  }

  key_id = ntohs(key_id);

  yubihsm_pkcs11_session *session = 0;
  CK_RV rv = get_session(&g_ctx, hSession, &session, SESSION_NOT_AUTHENTICATED);
  if (rv != CKR_OK) {
    DBG_ERR("Invalid session ID: %lu", hSession);
    return rv;
  }

  yh_rc yrc = YHR_SUCCESS;

  if (prefix == '@') { // Asymmetric authentication

    uint8_t sk_oce[YH_EC_P256_PRIVKEY_LEN], pk_oce[YH_EC_P256_PUBKEY_LEN],
      pk_sd[YH_EC_P256_PUBKEY_LEN];
    size_t pk_sd_len = sizeof(pk_sd);
    yrc = yh_util_derive_ec_p256_key(pPin, ulPinLen, sk_oce, sizeof(sk_oce),
                                     pk_oce, sizeof(pk_oce));
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to derive asymmetric key: %s", yh_strerror(yrc));
      rv = yrc_to_rv(yrc);
      goto c_l_out;
    }

    yrc = yh_util_get_device_pubkey(session->slot->connector, pk_sd, &pk_sd_len,
                                    NULL);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to get device public key: %s", yh_strerror(yrc));
      rv = yrc_to_rv(yrc);
      goto c_l_out;
    }

    if (pk_sd_len != YH_EC_P256_PUBKEY_LEN) {
      DBG_ERR("Invalid device public key");
      rv = CKR_DATA_LEN_RANGE;
      goto c_l_out;
    }

    int hits = 0;

    for (ListItem *item = g_ctx.device_pubkeys.head; item != NULL;
         item = item->next) {
      if (!memcmp(item->data, pk_sd, YH_EC_P256_PUBKEY_LEN)) {
        hits++;
      }
    }

    if (g_ctx.device_pubkeys.length > 0 && hits == 0) {
      DBG_ERR("Failed to validate device public key");
      rv = CKR_DATA_LEN_RANGE;
      goto c_l_out;
    }

    yrc = yh_create_session_asym(session->slot->connector, key_id, sk_oce,
                                 sizeof(sk_oce), pk_sd, pk_sd_len,
                                 &session->slot->device_session);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to create asymmetric session: %s", yh_strerror(yrc));
      if (yrc == YHR_SESSION_AUTHENTICATION_FAILED) {
        rv = CKR_PIN_INCORRECT;
      } else {
        rv = yrc_to_rv(yrc);
      }
      goto c_l_out;
    }
  } else { // Symmetric authentication
    yrc =
      yh_create_session_derived(session->slot->connector, key_id, pPin,
                                ulPinLen, true, &session->slot->device_session);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to create session: %s", yh_strerror(yrc));
      if (yrc == YHR_CRYPTOGRAM_MISMATCH ||
          yrc == YHR_DEVICE_AUTHENTICATION_FAILED) {
        rv = CKR_PIN_INCORRECT;
      } else {
        rv = yrc_to_rv(yrc);
      }
      goto c_l_out;
    }

    yrc = yh_authenticate_session(session->slot->device_session);
    if (yrc != YHR_SUCCESS) {
      DBG_ERR("Failed to authenticate session: %s", yh_strerror(yrc));
      if (yrc == YHR_CRYPTOGRAM_MISMATCH) {
        rv = CKR_PIN_INCORRECT;
      } else {
        rv = yrc_to_rv(yrc);
      }
      goto c_l_out;
    }
  }

  list_iterate(&session->slot->pkcs11_sessions, login_sessions);
  populate_cache_with_data_opaques(session->slot);

#ifndef FUZZING
  yubihsm_pkcs11_object_desc *authkey_desc =
    _get_object_desc(session->slot, key_id, YH_AUTHENTICATION_KEY, 0xffff);
  if (authkey_desc == NULL) {
    DBG_ERR("Failed to read authentication key info.");
    goto c_l_out;
  }
  session->slot->authkey_domains = authkey_desc->object.domains;
#else
  session->slot->authkey_domains = 0xffff;
#endif

  DOUT;

c_l_out:

  release_session(&g_ctx, session);

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_FLAGS flags              /* flags control which sessions are cancelled */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(flags);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the encryption mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of encryption key */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)
(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_VOID_PTR pParameter,       /* message specific parameter */
 CK_ULONG ulParameterLen,      /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen, /* AEAD Associated data length */
 CK_BYTE_PTR pPlaintext,       /* plain text  */
 CK_ULONG ulPlaintextLen,      /* plain text length */
 CK_BYTE_PTR pCiphertext,      /* gets cipher text */
 CK_ULONG_PTR pulCiphertextLen /* gets cipher text length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pAssociatedData);
  UNUSED(ulAssociatedDataLen);
  UNUSED(pPlaintext);
  UNUSED(ulPlaintextLen);
  UNUSED(pCiphertext);
  UNUSED(pulCiphertextLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData, /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen /* AEAD Associated data length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pAssociatedData);
  UNUSED(ulAssociatedDataLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)
(CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_VOID_PTR pParameter,            /* message specific parameter */
 CK_ULONG ulParameterLen,           /* length of message specific parameter */
 CK_BYTE_PTR pPlaintextPart,        /* plain text */
 CK_ULONG ulPlaintextPartLen,       /* plain text length */
 CK_BYTE_PTR pCiphertextPart,       /* gets cipher text */
 CK_ULONG_PTR pulCiphertextPartLen, /* gets cipher text length */
 CK_FLAGS flags                     /* multi mode flag */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pPlaintextPart);
  UNUSED(ulPlaintextPartLen);
  UNUSED(pCiphertextPart);
  UNUSED(pulCiphertextPartLen);
  UNUSED(flags);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  UNUSED(hSession);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the decryption mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of decryption key */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)
(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_VOID_PTR pParameter,       /* message specific parameter */
 CK_ULONG ulParameterLen,      /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen, /* AEAD Associated data length */
 CK_BYTE_PTR pCiphertext,      /* cipher text */
 CK_ULONG ulCiphertextLen,     /* cipher text length */
 CK_BYTE_PTR pPlaintext,       /* gets plain text */
 CK_ULONG_PTR pulPlaintextLen  /* gets plain text length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pAssociatedData);
  UNUSED(ulAssociatedDataLen);
  UNUSED(pCiphertext);
  UNUSED(ulCiphertextLen);
  UNUSED(pPlaintext);
  UNUSED(pulPlaintextLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData, /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen /* AEAD Associated data length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pAssociatedData);
  UNUSED(ulAssociatedDataLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)
(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_VOID_PTR pParameter,       /* message specific parameter */
 CK_ULONG ulParameterLen,      /* length of message specific parameter */
 CK_BYTE_PTR pCiphertext,      /* cipher text */
 CK_ULONG ulCiphertextLen,     /* cipher text length */
 CK_BYTE_PTR pPlaintext,       /* gets plain text */
 CK_ULONG_PTR pulPlaintextLen, /* gets plain text length */
 CK_FLAGS flags                /* multi mode flag */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pCiphertext);
  UNUSED(ulCiphertextLen);
  UNUSED(pPlaintext);
  UNUSED(pulPlaintextLen);
  UNUSED(flags);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  UNUSED(hSession);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the signing mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of signing key */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pData,           /* data to sign */
 CK_ULONG ulDataLen,          /* data to sign length */
 CK_BYTE_PTR pSignature,      /* gets signature */
 CK_ULONG_PTR pulSignatureLen /* gets signature length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(pulSignatureLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen     /* length of message specific parameter */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pData,           /* data to sign */
 CK_ULONG ulDataLen,          /* data to sign length */
 CK_BYTE_PTR pSignature,      /* gets signature */
 CK_ULONG_PTR pulSignatureLen /* gets signature length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(pulSignatureLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  UNUSED(hSession);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the signing mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of signing key */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pMechanism);
  UNUSED(hKey);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen,    /* length of message specific parameter */
 CK_BYTE_PTR pData,          /* data to sign */
 CK_ULONG ulDataLen,         /* data to sign length */
 CK_BYTE_PTR pSignature,     /* signature */
 CK_ULONG ulSignatureLen     /* signature length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(ulSignatureLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen     /* length of message specific parameter */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen,    /* length of message specific parameter */
 CK_BYTE_PTR pData,          /* data to sign */
 CK_ULONG ulDataLen,         /* data to sign length */
 CK_BYTE_PTR pSignature,     /* signature */
 CK_ULONG ulSignatureLen     /* signature length */
) {
  DIN;
  UNUSED(hSession);
  UNUSED(pParameter);
  UNUSED(ulParameterLen);
  UNUSED(pData);
  UNUSED(ulDataLen);
  UNUSED(pSignature);
  UNUSED(ulSignatureLen);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  UNUSED(hSession);
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

static const CK_FUNCTION_LIST function_list = {
  {CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR},
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent,
};

static const CK_FUNCTION_LIST_3_0 function_list_3 = {
  {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
  C_Initialize,
  C_Finalize,
  C_GetInfo_3_0,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent,
  C_GetInterfaceList,
  C_GetInterface,
  C_LoginUser,
  C_SessionCancel,
  C_MessageEncryptInit,
  C_EncryptMessage,
  C_EncryptMessageBegin,
  C_EncryptMessageNext,
  C_MessageEncryptFinal,
  C_MessageDecryptInit,
  C_DecryptMessage,
  C_DecryptMessageBegin,
  C_DecryptMessageNext,
  C_MessageDecryptFinal,
  C_MessageSignInit,
  C_SignMessage,
  C_SignMessageBegin,
  C_SignMessageNext,
  C_MessageSignFinal,
  C_MessageVerifyInit,
  C_VerifyMessage,
  C_VerifyMessageBegin,
  C_VerifyMessageNext,
  C_MessageVerifyFinal,
};
