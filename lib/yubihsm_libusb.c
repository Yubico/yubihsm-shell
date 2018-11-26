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

#include <libusb.h>

#include <string.h>

#include "yubihsm.h"
#include "internal.h"
#include "yubihsm_usb.h"
#include "debug_lib.h"

#ifdef NO_LIBUSB_STRERROR
#define libusb_strerror(x) libusb_error_name(x)
#endif

struct state {
  libusb_context *ctx;
  libusb_device_handle *handle;
  unsigned long serial;
};

void usb_set_serial(yh_backend *state, unsigned long serial) {
  state->serial = serial;
}

void usb_close(yh_backend *state) {
  if (state && state->handle) {
    libusb_release_interface(state->handle, 0);
    libusb_close(state->handle);
    state->handle = NULL;
  }
}

void usb_destroy(yh_backend **state) {
  if (state && *state) {
    usb_close(*state);
    if ((*state)->ctx) {
      libusb_exit((*state)->ctx);
      (*state)->ctx = NULL;
    }
    free(*state);
    *state = NULL;
  }
}

yh_backend *backend_create(void) {
  yh_backend *backend = calloc(1, sizeof(yh_backend));
  if (backend) {
    libusb_init(&backend->ctx);
  }
  return backend;
}

bool usb_open_device(yh_backend *backend) {
  libusb_device **list;
  libusb_device_handle *h = NULL;
  ssize_t cnt = libusb_get_device_list(backend->ctx, &list);

  if (backend->handle) {
    usb_close(backend);
  }

  if (cnt < 0) {
    DBG_ERR("Failed to get device list: %s", libusb_strerror(cnt));
    return NULL;
  }

  for (ssize_t i = 0; i < cnt; i++) {
    struct libusb_device_descriptor desc;
    int ret = libusb_get_device_descriptor(list[i], &desc);
    if (ret != 0) {
      DBG_INFO("Failed to get descriptor for device %zd: %s", i,
               libusb_strerror(ret));
      continue;
    }
    if (desc.idVendor == YH_VID && desc.idProduct == YH_PID) {
      ret = libusb_open(list[i], &h);
      if (ret != 0 || h == NULL) {
        DBG_INFO("Failed to open device for index %zd: %s", i,
                 libusb_strerror(ret));
        continue;
      }
      if (backend->serial != 0) {
        unsigned char data[16] = {0};

        ret = libusb_get_string_descriptor_ascii(h, desc.iSerialNumber, data,
                                                 sizeof(data));

        unsigned long devSerial = strtoul((char *) data, NULL, 10);

        if (devSerial != backend->serial) {
          DBG_INFO("Device %zd has serial %lu, not matching searched %lu", i,
                   devSerial, backend->serial);
          goto next;
        }
      }

      ret = libusb_claim_interface(h, 0);
      if (ret != 0) {
        DBG_ERR("Failed to claim interface: %s of device %zd",
                libusb_strerror(ret), i);
        goto next;
      }

      break;
    next:
      libusb_close(h);
      h = NULL;
    }
  }

  libusb_free_device_list(list, 1);
  backend->handle = h;
  if (h) {
    // we set up a dummy read with a 1ms timeout here. The reason for doing this
    // is that there might be data left in th e device buffers from earlier
    // transactions, this should flush it.
    unsigned char buf[YH_MSG_BUF_SIZE];
    int transferred = 0;
    if (libusb_bulk_transfer(h, 0x81, buf, sizeof(buf), &transferred, 1) == 0) {
      DBG_INFO("%d bytes of stale data read from device", transferred);
    }
    return true;
  } else {
    return false;
  }
}

int usb_write(yh_backend *state, unsigned char *buf, long unsigned len) {
  int transferred = 0;
  if (state->handle == NULL) {
    DBG_ERR("Handle is not connected");
    return 0;
  }
  /* TODO: does this need to loop and transmit several times? */
  int ret =
    libusb_bulk_transfer(state->handle, 0x01, buf, len, &transferred, 0);
  DBG_INFO("Write of %lu %d, err %d", len, transferred, ret);
  if (ret != 0 || transferred != (int) len) {
    DBG_ERR("Transferred did not match len of write %d-%lu", transferred, len);
    return 0;
  }
  if (len % 64 == 0) {
    /* this writes the ZLP */
    ret = libusb_bulk_transfer(state->handle, 0x01, buf, 0, &transferred, 0);
    if (ret != 0) {
      return 0;
    }
  }
  return 1;
}

int usb_read(yh_backend *state, unsigned char *buf, unsigned long *len) {
  int transferred = 0;
  int ret;

  if (state->handle == NULL) {
    DBG_ERR("Handle is not connected");
    return 0;
  }

  DBG_INFO("Doing usb read");

  /* TODO: does this need to loop for all data?*/
  ret = libusb_bulk_transfer(state->handle, 0x81, buf, *len, &transferred, 0);
  if (ret != 0) {
    DBG_ERR("Failed usb_read with ret: %d", ret);
    return 0;
  }
  DBG_INFO("Read, transfer %d", transferred);
  *len = transferred;
  return 1;
}
