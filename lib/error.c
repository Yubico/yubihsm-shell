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

#include <yubihsm.h>

#include <stddef.h>

#define ERR(name, desc)                                                        \
  { name, desc }

typedef struct {
  yh_rc rc;
  const char *description;
} err_t;

static const err_t errors[] = {
  ERR(YHR_SUCCESS, "Success"),
  ERR(YHR_MEMORY_ERROR, "Unable to allocate memory"),
  ERR(YHR_INIT_ERROR, "Unable to initialize libyubihsm"),
  ERR(YHR_CONNECTION_ERROR, "Connection error"),
  ERR(YHR_CONNECTOR_NOT_FOUND, "Unable to find a suitable connector"),
  ERR(YHR_INVALID_PARAMETERS, "Invalid argument to a function"),
  ERR(YHR_WRONG_LENGTH, "Mismatch between expected and received length"),
  ERR(YHR_BUFFER_TOO_SMALL, "Not enough space to store data"),
  ERR(YHR_CRYPTOGRAM_MISMATCH, "Unable to verify cryptogram"),
  ERR(YHR_SESSION_AUTHENTICATION_FAILED, "Unable to authenticate session"),
  ERR(YHR_MAC_MISMATCH, "Unable to verify MAC"),
  ERR(YHR_DEVICE_OK, "No error"),
  ERR(YHR_DEVICE_INVALID_COMMAND, "Invalid command"),
  ERR(YHR_DEVICE_INVALID_DATA, "Malformed command / invalid data"),
  ERR(YHR_DEVICE_INVALID_SESSION, "Invalid session"),
  ERR(YHR_DEVICE_AUTHENTICATION_FAILED,
      "Message encryption / verification failed"),
  ERR(YHR_DEVICE_SESSIONS_FULL, "All sessions are allocated"),
  ERR(YHR_DEVICE_SESSION_FAILED, "Session creation failed"),
  ERR(YHR_DEVICE_STORAGE_FAILED, "Storage failure"),
  ERR(YHR_DEVICE_WRONG_LENGTH, "Wrong length"),
  ERR(YHR_DEVICE_INSUFFICIENT_PERMISSIONS, "Wrong permissions for operation"),
  ERR(YHR_DEVICE_LOG_FULL, "Log buffer is full and forced audit is set"),
  ERR(YHR_DEVICE_OBJECT_NOT_FOUND, "Object not found"),
  ERR(YHR_DEVICE_INVALID_ID, "Invalid ID used"),
  ERR(YHR_DEVICE_INVALID_OTP, "Invalid OTP"),
  ERR(YHR_DEVICE_DEMO_MODE, "Demo mode, power cycle device"),
  ERR(YHR_DEVICE_COMMAND_UNEXECUTED,
      "The command execution has not terminated"),
  ERR(YHR_GENERIC_ERROR, "Generic error"),
  ERR(YHR_DEVICE_OBJECT_EXISTS, "An Object with that ID already exists"),
  ERR(YHR_CONNECTOR_ERROR, "Connector operation failed"),
  ERR(YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION, "SSH CA constraint violation"),
};

const char *yh_strerror(yh_rc err) {
  static const char *unknown = "Unknown yubihsm error";
  const char *p;

  if (-err < 0 || -err >= (int) (sizeof(errors) / sizeof(errors[0]))) {
    return unknown;
  }

  p = errors[-err].description;
  if (!p) {
    p = unknown;
  }

  return p;
}
