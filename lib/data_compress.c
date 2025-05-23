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

#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "data_compress.h"
#include "debug_lib.h"

int compress_data(const uint8_t *data, size_t data_len,
                  uint8_t *compressed_data, size_t *compressed_data_len) {

  z_stream zs = {0};
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (uInt) data_len;
  zs.next_in = (Bytef *) data;
  zs.avail_out = (uInt) *compressed_data_len;
  zs.next_out = (Bytef *) compressed_data;

  int res = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | 16,
                         8, Z_DEFAULT_STRATEGY);
  if (res != Z_OK) {
    DBG_ERR("Failed to compress data. ZLIB error code: %d (%s)", res,
            zError(res));
    return -1;
  }

  res = deflate(&zs, Z_FINISH);
  if (res != Z_STREAM_END) {
    DBG_ERR("Failed to compress data. ZLIB error code: %d (%s)", res,
            zError(res));
    return -1;
  }

  res = deflateEnd(&zs);
  if (res != Z_OK) {
    DBG_ERR("Failed to compress data. ZLIB error code: %d (%s)", res,
            zError(res));
    return -1;
  }

  *compressed_data_len = zs.total_out;
  return 0;
}

int decompress_data(uint8_t *compressed_data, size_t compressed_data_len,
                    uint8_t *data, size_t *data_len) {
  uint8_t *dataptr = compressed_data;

  z_stream zs = {0};
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (uInt) compressed_data_len;
  zs.next_in = (Bytef *) dataptr;
  zs.avail_out = (uInt) *data_len;
  zs.next_out = (Bytef *) data;

  int res = inflateInit2(&zs, MAX_WBITS | 16);
  if (res != Z_OK) {
    DBG_ERR("Failed to initialize data decompression. ZLIB error code: %d (%s)",
            res, zError(res));
    return -1;
  }

  res = inflate(&zs, Z_FINISH);
  if (res != Z_STREAM_END) {
    DBG_ERR("Failed to decompress data. ZLIB error code: %d (%s)", res,
            zError(res));
    return -1;
  }

  res = inflateEnd(&zs);
  if (res != Z_OK) {
    DBG_ERR("Failed to finish data decompression. ZLIB error code: %d (%s)",
            res, zError(res));
    return -1;
  }
  *data_len = zs.total_out;
  return 0;
}
