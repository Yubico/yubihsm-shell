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

#include <windows.h>
#include <winusb.h>
#include <string.h>
#include <setupapi.h>

#include "yubihsm.h"
#include "internal.h"
#include "yubihsm_usb.h"
#include "debug_lib.h"

struct state {
  HANDLE hDevice;
  WINUSB_INTERFACE_HANDLE hWinUSB;
  unsigned long serial;
};

// Device GUID {D1D3C87E-0574-4E38-8346-A56439234528}
static const GUID devGUID = {0xD1D3C87E,
                             0x0574,
                             0x4E38,
                             {0x83, 0x46, 0xA5, 0x64, 0x39, 0x23, 0x45, 0x28}};

#define PIPE_OUT 0x01 // Must match endpoint descriptor definitions
#define PIPE_IN 0x81

void usb_set_serial(yh_backend *state, unsigned long serial) {
  state->serial = serial;
}

bool usb_open_device(yh_backend *backend) {
  BOOL bResult = TRUE;
  HDEVINFO hDeviceInfo;
  SP_DEVINFO_DATA DeviceInfoData;
  SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
  PSP_DEVICE_INTERFACE_DETAIL_DATA pInterfaceDetailData = NULL;
  ULONG requiredLength = 0;
  DWORD index = 0;
  HANDLE hnd = INVALID_HANDLE_VALUE;
  WINUSB_INTERFACE_HANDLE wusbHnd = INVALID_HANDLE_VALUE;

  // Get information about all the installed devices for the specified
  // device interface class.
  hDeviceInfo = SetupDiGetClassDevs(&devGUID, NULL, NULL,
                                    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

  if (hDeviceInfo == INVALID_HANDLE_VALUE) {
    DBG_ERR("SetupDiGetClassDevs failed, error=%lx\n", GetLastError());
    return false;
  }

  // Enumerate all the device interfaces in the device information set.
  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

  for (index = 0; SetupDiEnumDeviceInfo(hDeviceInfo, index, &DeviceInfoData);
       index++) {

    deviceInterfaceData.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

    // Get information about the device interface.

    bResult = SetupDiEnumDeviceInterfaces(hDeviceInfo, &DeviceInfoData,
                                          &devGUID, 0, &deviceInterfaceData);

    if (!bResult) {
      // Check if last item
      if (GetLastError() == ERROR_NO_MORE_ITEMS) {
        DBG_ERR("No more items found");
        goto out;
      }

      // Check for some other error
      DBG_ERR("SetupDiEnumDeviceInterfaces(1) failed, error=%lx\n",
              GetLastError());
      goto out;
    }

    // Interface data is returned in SP_DEVICE_INTERFACE_DETAIL_DATA
    // which we need to allocate, so we have to call this function twice.
    // First to get the size so that we know how much to allocate
    // Second, the actual call with the allocated buffer

    bResult = SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &deviceInterfaceData,
                                              NULL, 0, &requiredLength, NULL);

    if (!bResult && (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
      DBG_ERR("SetupDiEnumDeviceInterfaces(2) failed, error=%lx\n",
              GetLastError());
      goto out;
    }

    // Get the interface detailed data and allocate storage
    pInterfaceDetailData = malloc(requiredLength);
    pInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    // Now call it with the correct size and allocated buffer
    bResult =
      SetupDiGetDeviceInterfaceDetail(hDeviceInfo, &deviceInterfaceData,
                                      pInterfaceDetailData, requiredLength,
                                      NULL, &DeviceInfoData);

    if (!bResult) {
      DBG_ERR("SetupDiGetDeviceInterfaceDetail failed, error=%lx\n",
              GetLastError());
      goto out;
    }

    hnd =
      CreateFile(pInterfaceDetailData->DevicePath, GENERIC_READ | GENERIC_WRITE,
                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                 FILE_FLAG_OVERLAPPED, NULL);

    free(pInterfaceDetailData);
    pInterfaceDetailData = NULL;

    if (hnd == INVALID_HANDLE_VALUE) {
      DBG_ERR("CreateFile failed, error=%lx", GetLastError());
      continue;
    }

    if (!WinUsb_Initialize(hnd, &wusbHnd)) {
      DBG_ERR("WinUsb_Initialize failed, error=%lx", GetLastError());
      goto next;
    }

    if (backend->serial != 0) {
      USB_DEVICE_DESCRIPTOR desc;
      ULONG written;
      unsigned char ser_num[128] = {0};

      if (!WinUsb_GetDescriptor(wusbHnd, USB_DEVICE_DESCRIPTOR_TYPE, 0, 0,
                                (unsigned char *) &desc, sizeof(desc),
                                &written)) {
        DBG_ERR("WinUsb_GetDescriptor failed, error=%lx", GetLastError());
        goto next;
      }

      if (!WinUsb_GetDescriptor(wusbHnd, USB_STRING_DESCRIPTOR_TYPE,
                                desc.iSerialNumber,
                                0x0409, // English (US)
                                ser_num, sizeof(ser_num), &written)) {
        DBG_ERR("WinUsb_GetDescriptor failed, error=%lx", GetLastError());
        goto next;
      }

      DBG_INFO("Extracted serial %ls (%lu bytes) from device desc %d",
               (wchar_t *) (ser_num + 2), written, desc.iSerialNumber);

      unsigned long devSerial = wcstoul((wchar_t *) (ser_num + 2), NULL, 10);
      if (devSerial != backend->serial) {
        DBG_INFO("Device has serial %lu, not matching searched %lu", devSerial,
                 backend->serial);
        goto next;
      }
    }
    break;
  next:
    if (wusbHnd != INVALID_HANDLE_VALUE) {
      WinUsb_Free(wusbHnd);
      wusbHnd = INVALID_HANDLE_VALUE;
    }
    if (hnd != INVALID_HANDLE_VALUE) {
      CloseHandle(hnd);
      hnd = INVALID_HANDLE_VALUE;
    }
    continue;
  }

  if (wusbHnd != INVALID_HANDLE_VALUE) {

    // Make sure we get a ZLP at the end every time
    bResult = WinUsb_SetPipePolicy(wusbHnd, PIPE_OUT, SHORT_PACKET_TERMINATE, 1,
                                   (PVOID) "\x1");
    if (!bResult) {
      DBG_ERR("SetPipePolicy failed");
      WinUsb_Free(wusbHnd);
      wusbHnd = INVALID_HANDLE_VALUE;
      CloseHandle(hnd);
      hnd = INVALID_HANDLE_VALUE;
      goto out;
    }

    {
      // we set up a dummy read with a 10ms timeout here, if the timeout is too
      // short this times out before it has time to complete. The reason for
      // doing this is that there might be data left in the device buffers from
      // earlier transactions, this should flush it.
      unsigned char buf[YH_MSG_BUF_SIZE];
      unsigned long transferred = 0;
      unsigned long timeout = 10;

      bResult = WinUsb_SetPipePolicy(wusbHnd, PIPE_IN, PIPE_TRANSFER_TIMEOUT,
                                     sizeof(timeout), &timeout);
      if (!bResult) {
        DBG_ERR("SetPipePolicy failed");
        WinUsb_Free(wusbHnd);
        wusbHnd = INVALID_HANDLE_VALUE;
        CloseHandle(hnd);
        hnd = INVALID_HANDLE_VALUE;
        goto out;
      }

      if (WinUsb_ReadPipe(wusbHnd, PIPE_IN, buf, sizeof(buf), &transferred,
                          0)) {
        DBG_INFO("%lu bytes of stale data read", transferred);
      }

      timeout = 0;
      bResult = WinUsb_SetPipePolicy(wusbHnd, PIPE_IN, PIPE_TRANSFER_TIMEOUT,
                                     sizeof(timeout), &timeout);
      if (!bResult) {
        DBG_ERR("SetPipePolicy failed");
        WinUsb_Free(wusbHnd);
        wusbHnd = INVALID_HANDLE_VALUE;
        CloseHandle(hnd);
        hnd = INVALID_HANDLE_VALUE;
        goto out;
      }
    }
  }

out:
  backend->hDevice = hnd;
  backend->hWinUSB = wusbHnd;

  if (hDeviceInfo) {
    SetupDiDestroyDeviceInfoList(hDeviceInfo);
  }

  free(pInterfaceDetailData);

  if (wusbHnd != INVALID_HANDLE_VALUE) {
    return true;
  } else {
    return false;
  }
}

yh_backend *backend_create(void) {
  yh_backend *backend = calloc(1, sizeof(yh_backend));
  return backend;
}

void usb_close(yh_backend *state) {
  if (state && state->hDevice != INVALID_HANDLE_VALUE) {
    CloseHandle(state->hDevice);
    state->hDevice = INVALID_HANDLE_VALUE;
  }
  if (state && state->hWinUSB != INVALID_HANDLE_VALUE) {
    WinUsb_Free(state->hWinUSB);
    state->hWinUSB = INVALID_HANDLE_VALUE;
  }
}

void usb_destroy(yh_backend **state) {
  if (state && *state) {
    free(*state);
    *state = NULL;
  }
}

int usb_write(yh_backend *state, unsigned char *buf, long unsigned len) {
  long unsigned transferred;

  if (state->hWinUSB == INVALID_HANDLE_VALUE) {
    DBG_ERR("No connected device");
    return 0;
  }

  BOOL bResult =
    WinUsb_WritePipe(state->hWinUSB, PIPE_OUT, buf, len, &transferred, 0);
  if (bResult) {
    DBG_INFO("Written %lu bytes", transferred);
  } else {
    DBG_ERR("WinUsb_WritePipe failed, error=%lx", GetLastError());
    return 0;
  }

  if (transferred != len) {
    DBG_ERR("Transferred did not match len of write %lu-%lu", transferred, len);
    return 0;
  }

  return 1;
}

int usb_read(yh_backend *state, unsigned char *buf, long unsigned *len) {
  long unsigned transferred = 0;
  BOOL bResult;

  if (state->hWinUSB == INVALID_HANDLE_VALUE) {
    DBG_ERR("No connected device");
    return 0;
  }

  DBG_INFO("Doing usb read");

  bResult =
    WinUsb_ReadPipe(state->hWinUSB, PIPE_IN, buf, *len, &transferred, 0);
  if (!bResult) {
    DBG_ERR("WinUsb_ReadPipe failed, error=%lx\n", GetLastError());
    return 0;
  }
  DBG_INFO("Read %lu bytes", transferred);
  *len = transferred;
  return 1;
}
