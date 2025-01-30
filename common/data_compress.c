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

#include "data_compress.h"

#include <stdio.h>
#include <zlib.h>
#include <string.h>

const char COMPRESSED_DATA_PREFIX[4] = "YHC1";

int is_compressed_data(uint8_t *data, size_t data_len) {
  if (data_len < sizeof(COMPRESSED_DATA_PREFIX)) {
    return 0;
  }
  return memcmp(data, COMPRESSED_DATA_PREFIX, sizeof(COMPRESSED_DATA_PREFIX)) ==
         0;
}

int compress_data(uint8_t* data, size_t data_len, uint8_t *compressed_data, size_t *compressed_data_len) {

  memcpy(compressed_data, COMPRESSED_DATA_PREFIX, sizeof(COMPRESSED_DATA_PREFIX));
  uint8_t *ptr = compressed_data + sizeof(COMPRESSED_DATA_PREFIX);

  z_stream zs;
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (uInt)data_len;
  zs.next_in = (Bytef *)data;
  zs.avail_out = (uInt) (*compressed_data_len - sizeof(COMPRESSED_DATA_PREFIX));
  zs.next_out = (Bytef *)ptr;

  if(deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    fprintf(stderr, "Failed to compress data\n");
    return -1;
  }
  if(deflate(&zs, Z_FINISH) != Z_STREAM_END) {
    fprintf(stderr, "Failed to compress data\n");
    return -1;
  }
  if(deflateEnd(&zs) != Z_OK) {
    fprintf(stderr, "Failed to compress data\n");
    return -1;
  }

  *compressed_data_len = zs.total_out + sizeof(COMPRESSED_DATA_PREFIX);
  return 0;
}


int uncompress_data(uint8_t *compressed_data, size_t compressed_data_len, uint8_t *data, size_t *data_len) {
  if(!is_compressed_data(compressed_data, compressed_data_len)) {
    memcpy(data, compressed_data, compressed_data_len);
    return 0;
  }


  uint8_t *dataptr = compressed_data + sizeof(COMPRESSED_DATA_PREFIX);

  z_stream zs;
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (uInt) compressed_data_len - sizeof(COMPRESSED_DATA_PREFIX);
  zs.next_in = (Bytef *) dataptr;
  zs.avail_out = (uInt) *data_len;
  zs.next_out = (Bytef *) data;

  if (inflateInit2(&zs, MAX_WBITS | 16) != Z_OK) {
    fprintf(stderr, "Failed to initialize data decompression\n");
    return -1;
  }

  int res = inflate(&zs, Z_FINISH);
  if (res != Z_STREAM_END) {
    if (res == Z_BUF_ERROR) {
      fprintf(stderr, "Failed to decompress data. Allocated buffer is too small\n");
    } else {
      fprintf(stderr, "Failed to decompress data\n");
    }
    return -1;
  }
  if (inflateEnd(&zs) != Z_OK) {
    fprintf(stderr, "Failed to finish data decompression\n");
    return -1;
  }
  *data_len = zs.total_out;
  return 0;
}
