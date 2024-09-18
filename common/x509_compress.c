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

#ifndef _WIN32_BCRYPT

#include "x509_compress.h"

#include <openssl/x509.h>
#include <zlib.h>

int compress_cert(X509 *cert, uint8_t *compressed_data) {

  unsigned char uncompressed_certdata[4096] = {0};
  unsigned char *uncompressed_certptr = uncompressed_certdata;
  int cert_len = i2d_X509(cert, &uncompressed_certptr);

  if( cert_len < 0) {
    fprintf(stderr, "Failed to encode X509 certificate before compression\n");
    return 0;
  }

  z_stream zs;
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (uInt)cert_len;
  zs.next_in = (Bytef *)uncompressed_certdata;
  zs.avail_out = (uInt) sizeof(uncompressed_certdata);
  zs.next_out = (Bytef *)compressed_data;

  if(deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    fprintf(stderr, "Failed to compress certificate: deflateInit2()\n");
    return 0;
  }
  if(deflate(&zs, Z_FINISH) != Z_STREAM_END) {
    fprintf(stderr, "Failed to compress certificate: deflate()\n");
    return 0;
  }
  if(deflateEnd(&zs) != Z_OK) {
    fprintf(stderr, "Failed to compress certificate: deflateEnd()\n");
    return 0;
  }

  return zs.total_out;
}


X509* uncompress_cert(uint8_t *data, size_t data_len) {
  uint8_t *dataptr = data;
  uint8_t certdata[4096] = {0};
  size_t certdata_len = sizeof(certdata);

  z_stream zs;
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (uInt) data_len;
  zs.next_in = (Bytef *) dataptr;
  zs.avail_out = (uInt) certdata_len;
  zs.next_out = (Bytef *) certdata;

  if (inflateInit2(&zs, MAX_WBITS | 16) != Z_OK) {
    fprintf(stderr, "Failed to initialize certificate decompression\n");
    return NULL;
  }

  int res = inflate(&zs, Z_FINISH);
  if (res != Z_STREAM_END) {
    if (res == Z_BUF_ERROR) {
      fprintf(stderr, "Failed to decompress certificate. Allocated buffer is too small\n");
    } else {
      fprintf(stderr, "Failed to decompress certificate\n");
    }
    return NULL;
  }
  if (inflateEnd(&zs) != Z_OK) {
    fprintf(stderr, "Failed to finish certificate decompression\n");
    return NULL;
  }
  certdata_len = zs.total_out;

  const unsigned char *certdata_ptr = certdata;
  return d2i_X509(NULL, &certdata_ptr, certdata_len);
}


#endif
