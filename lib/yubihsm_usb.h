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

#ifndef YUBIHSM_USB_H
#define YUBIHSM_USB_H

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

void YH_INTERNAL usb_close(yh_backend *state);
void YH_INTERNAL usb_destroy(yh_backend **state);
yh_backend YH_INTERNAL *backend_create(void);
bool YH_INTERNAL usb_open_device(yh_backend *backend);
int YH_INTERNAL usb_write(yh_backend *state, unsigned char *buf,
                          long unsigned len);
int YH_INTERNAL usb_read(yh_backend *state, unsigned char *buf,
                         long unsigned *len);
void YH_INTERNAL usb_set_serial(yh_backend *state, unsigned long serial);

#endif
