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

#include <errno.h>
#include <string.h>
#include <limits.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "openssl-compat.h"
#include "util.h"
#include "insecure_memzero.h"

bool set_component(unsigned char *in_ptr, const BIGNUM *bn, int element_len) {
  int real_len = BN_num_bytes(bn);

  if (real_len > element_len) {
    return false;
  }

  memset(in_ptr, 0, (size_t)(element_len - real_len));
  in_ptr += element_len - real_len;
  BN_bn2bin(bn, in_ptr);

  return true;
}

static unsigned const char sha1oid[] = {0x30, 0x21, 0x30, 0x09, 0x06,
                                        0x05, 0x2B, 0x0E, 0x03, 0x02,
                                        0x1A, 0x05, 0x00, 0x04, 0x14};

static unsigned const char sha256oid[] = {0x30, 0x31, 0x30, 0x0D, 0x06,
                                          0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x01,
                                          0x05, 0x00, 0x04, 0x20};

static unsigned const char sha384oid[] = {0x30, 0x41, 0x30, 0x0D, 0x06,
                                          0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x02,
                                          0x05, 0x00, 0x04, 0x30};

static unsigned const char sha512oid[] = {0x30, 0x51, 0x30, 0x0D, 0x06,
                                          0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x03,
                                          0x05, 0x00, 0x04, 0x40};

static unsigned const char PEM_private_header[] =
  "-----BEGIN PRIVATE KEY-----\n";
static unsigned const char PEM_private_trailer[] =
  "-----END PRIVATE KEY-----\n";
static unsigned const char PEM_public_header[] = "-----BEGIN PUBLIC KEY-----\n";
static unsigned const char PEM_public_trailer[] = "-----END PUBLIC KEY-----\n";
static unsigned const char ed25519private_oid[] = {0x30, 0x2e, 0x02, 0x01,
                                                   0x00, 0x30, 0x05, 0x06,
                                                   0x03, 0x2b, 0x65, 0x70,
                                                   0x04, 0x22, 0x04, 0x20};
static unsigned const char ed25519public_oid[] = {0x30, 0x29, 0x30, 0x05,
                                                  0x06, 0x03, 0x2b, 0x65,
                                                  0x70, 0x03, 0x20};

bool read_ed25519_key(uint8_t *in, size_t in_len, uint8_t *out,
                      size_t *out_len) {

  uint8_t decoded[128];
  size_t decoded_len = sizeof(decoded);

  if (memcmp(in, PEM_private_header, 28) != 0 ||
      memcmp(in + in_len - 26, PEM_private_trailer, 25) != 0) {
    return false;
  }

  int ret;
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);

  (void) BIO_write(bio, in + 28, in_len - 28 - 25);
  (void) BIO_flush(bio);
  ret = BIO_read(b64, decoded, decoded_len);

  BIO_free_all(bio);

  if (ret <= 0 || ret != 48) {
    return false;
  }

  if (memcmp(decoded, ed25519private_oid, sizeof(ed25519private_oid)) != 0) {
    return false;
  }

  memcpy(out, decoded + 16, 32);
  *out_len = 32;

  insecure_memzero(decoded, 48);

  return true;
}

bool read_private_key(uint8_t *buf, size_t len, yh_algorithm *algo,
                      uint8_t *bytes, size_t *bytes_len, bool internal_repr) {

  if (read_ed25519_key(buf, len, bytes, bytes_len) == true) {
    *algo = YH_ALGO_EC_ED25519;
    return true;
  }

  EVP_PKEY *private_key;

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    return false;
  }

  (void) BIO_write(bio, buf, len);

  private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, /*password*/ NULL);
  if (private_key == NULL) {
    BIO_free_all(bio);
    return false;
  }

  BIO_free_all(bio);

  bool ret = false;

  RSA *rsa = NULL;

  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  EC_KEY *ec_private = NULL;

  switch (EVP_PKEY_base_id(private_key)) {
    case EVP_PKEY_RSA: {
      rsa = EVP_PKEY_get1_RSA(private_key);
      unsigned char e[4];
      int size = RSA_size(rsa);
      const BIGNUM *bn_n, *bn_e, *bn_p, *bn_q;

      RSA_get0_key(rsa, &bn_n, &bn_e, NULL);
      RSA_get0_factors(rsa, &bn_p, &bn_q);

      if (set_component(e, bn_e, 3) == false ||
          !(e[0] == 0x01 && e[1] == 0x00 && e[2] == 0x01)) {
        goto cleanup;
      }

      if (size == 256) {
        *algo = YH_ALGO_RSA_2048;
      } else if (size == 384) {
        *algo = YH_ALGO_RSA_3072;
      } else if (size == 512) {
        *algo = YH_ALGO_RSA_4096;
      } else {
        goto cleanup;
      }

      if (set_component(bytes, bn_p, size / 2) == false) {
        goto cleanup;
      }

      if (set_component(bytes + size / 2, bn_q, size / 2) == false) {
        goto cleanup;
      }

      if (internal_repr == true) {
        const BIGNUM *dmp1, *dmq1, *iqmp;
        uint8_t *ptr = bytes + size;

        RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
        if (set_component(ptr, dmp1, size / 2) == false) {
          goto cleanup;
        }
        ptr += size / 2;

        if (set_component(ptr, dmq1, size / 2) == false) {
          goto cleanup;
        }
        ptr += size / 2;

        if (set_component(ptr, iqmp, size / 2) == false) {
          goto cleanup;
        }
        ptr += size / 2;

        if (set_component(ptr, bn_n, size) == false) {
          goto cleanup;
        }

        *bytes_len = (size / 2) * 7;
      } else {
        *bytes_len = size;
      }
    } break;

    case EVP_PKEY_EC: {
      ec_private = EVP_PKEY_get1_EC_KEY(private_key);
      if (ec_private == NULL) {
        goto cleanup;
      }

      const BIGNUM *s = EC_KEY_get0_private_key(ec_private);
      const EC_GROUP *group = EC_KEY_get0_group(ec_private);
      int curve = EC_GROUP_get_curve_name(group);
      int size = 0;

      if (curve == NID_X9_62_prime256v1) {
        *algo = YH_ALGO_EC_P256;
        size = 32;
      } else if (curve == NID_secp384r1) {
        *algo = YH_ALGO_EC_P384;
        size = 48;
      } else if (curve == NID_secp521r1) {
        *algo = YH_ALGO_EC_P521;
        size = 66;
      } else if (curve == NID_secp224r1) {
        *algo = YH_ALGO_EC_P224;
        size = 28;
#ifdef NID_brainpoolP256r1
      } else if (curve == NID_brainpoolP256r1) {
        *algo = YH_ALGO_EC_BP256;
        size = 32;
#endif
#ifdef NID_brainpoolP384r1
      } else if (curve == NID_brainpoolP384r1) {
        *algo = YH_ALGO_EC_BP384;
        size = 48;
#endif
#ifdef NID_brainpoolP512r1
      } else if (curve == NID_brainpoolP512r1) {
        *algo = YH_ALGO_EC_BP512;
        size = 64;
#endif
      } else if (curve == NID_secp256k1) {
        *algo = YH_ALGO_EC_K256;
        size = 32;
      } else {
        goto cleanup;
      }

      if (set_component(bytes, s, size) == false) {
        goto cleanup;
      }

      if (internal_repr == true) {
        const EC_POINT *ec_public = EC_KEY_get0_public_key(ec_private);

        x = BN_new();
        if (x == NULL) {
          goto cleanup;
        }

        y = BN_new();
        if (y == NULL) {
          goto cleanup;
        }

        if (EC_POINT_get_affine_coordinates_GFp(group, ec_public, x, y, NULL) ==
            0) {
          goto cleanup;
        }

        uint8_t *ptr = bytes + size;
        if (set_component(ptr, x, size) == false) {
          goto cleanup;
        }
        ptr += size;

        if (set_component(ptr, y, size) == false) {
          goto cleanup;
        }

        *bytes_len = size * 3;
      } else {
        *bytes_len = size;
      }
    } break;

    default:
      goto cleanup;
  }

  ret = true;

cleanup:

  if (rsa != NULL) {
    RSA_free(rsa);
    rsa = NULL;
  }

  if (x != NULL) {
    BN_free(x);
    x = NULL;
  }

  if (y != NULL) {
    BN_free(y);
    y = NULL;
  }

  if (ec_private != NULL) {
    EC_KEY_free(ec_private);
    ec_private = NULL;
  }

  return ret;
}

void format_digest(uint8_t *digest, char *str, uint16_t len) {

  for (uint32_t i = 0; i < len; i++) {
    sprintf(str + (2 * i), "%02x", digest[i]);
  }

  str[2 * len] = '\0';
}

int algo2nid(yh_algorithm algo) {
  switch (algo) {
    case YH_ALGO_EC_P256:
      return NID_X9_62_prime256v1;

    case YH_ALGO_EC_P384:
      return NID_secp384r1;

    case YH_ALGO_EC_P521:
      return NID_secp521r1;

    case YH_ALGO_EC_P224:
      return NID_secp224r1;

    case YH_ALGO_EC_K256:
      return NID_secp256k1;

#ifdef NID_brainpoolP256r1
    case YH_ALGO_EC_BP256:
      return NID_brainpoolP256r1;
#endif

#ifdef NID_brainpoolP384r1
    case YH_ALGO_EC_BP384:
      return NID_brainpoolP384r1;
#endif

#ifdef NID_brainpoolP512r1
    case YH_ALGO_EC_BP512:
      return NID_brainpoolP512r1;
#endif

    default:
      return 0;
  }

  return 0;
}

bool algo2type(yh_algorithm algorithm, yh_object_type *type) {

  switch (algorithm) {
    case YH_ALGO_RSA_PKCS1_SHA1:
    case YH_ALGO_RSA_PKCS1_SHA256:
    case YH_ALGO_RSA_PKCS1_SHA384:
    case YH_ALGO_RSA_PKCS1_SHA512:
    case YH_ALGO_RSA_PSS_SHA1:
    case YH_ALGO_RSA_PSS_SHA256:
    case YH_ALGO_RSA_PSS_SHA384:
    case YH_ALGO_RSA_PSS_SHA512:
    case YH_ALGO_RSA_2048:
    case YH_ALGO_RSA_3072:
    case YH_ALGO_RSA_4096:
    case YH_ALGO_EC_P224:
    case YH_ALGO_EC_P256:
    case YH_ALGO_EC_P384:
    case YH_ALGO_EC_P521:
    case YH_ALGO_EC_K256:
    case YH_ALGO_EC_BP256:
    case YH_ALGO_EC_BP384:
    case YH_ALGO_EC_BP512:
    case YH_ALGO_EC_ECDSA_SHA1:
    case YH_ALGO_EC_ECDH:
    case YH_ALGO_RSA_OAEP_SHA1:
    case YH_ALGO_RSA_OAEP_SHA256:
    case YH_ALGO_RSA_OAEP_SHA384:
    case YH_ALGO_RSA_OAEP_SHA512:
    case YH_ALGO_EC_ECDSA_SHA256:
    case YH_ALGO_EC_ECDSA_SHA384:
    case YH_ALGO_EC_ECDSA_SHA512:
    case YH_ALGO_EC_ED25519:
      *type = YH_ASYMMETRIC_KEY;
      break;

    case YH_ALGO_HMAC_SHA1:
    case YH_ALGO_HMAC_SHA256:
    case YH_ALGO_HMAC_SHA384:
    case YH_ALGO_HMAC_SHA512:
      *type = YH_HMAC_KEY;
      break;

    case YH_ALGO_AES128_CCM_WRAP:
    case YH_ALGO_AES192_CCM_WRAP:
    case YH_ALGO_AES256_CCM_WRAP:
      *type = YH_WRAP_KEY;
      break;

    case YH_ALGO_OPAQUE_DATA:
    case YH_ALGO_OPAQUE_X509_CERTIFICATE:
      *type = YH_OPAQUE;
      break;

    case YH_ALGO_TEMPLATE_SSH:
      *type = YH_TEMPLATE;
      break;

    case YH_ALGO_AES128_YUBICO_OTP:
    case YH_ALGO_AES192_YUBICO_OTP:
    case YH_ALGO_AES256_YUBICO_OTP:
      *type = YH_OTP_AEAD_KEY;
      break;

    case YH_ALGO_AES128_YUBICO_AUTHENTICATION:
      *type = YH_AUTHENTICATION_KEY;
      break;

    case YH_ALGO_MGF1_SHA1:
    case YH_ALGO_MGF1_SHA256:
    case YH_ALGO_MGF1_SHA384:
    case YH_ALGO_MGF1_SHA512:
    default:
      return false;
  }

  return true;
}

void parse_NID(uint8_t *data, uint16_t data_len, const EVP_MD **md_type,
               int *digestinfo_len) {
  if (data_len >= sizeof(sha1oid) &&
      memcmp(sha1oid, data, sizeof(sha1oid)) == 0) {
    *md_type = EVP_sha1();
    *digestinfo_len = sizeof(sha1oid);
  } else if (data_len >= sizeof(sha256oid) &&
             memcmp(sha256oid, data, sizeof(sha256oid)) == 0) {
    *md_type = EVP_sha256();
    *digestinfo_len = sizeof(sha256oid);
  } else if (data_len >= sizeof(sha384oid) &&
             memcmp(sha384oid, data, sizeof(sha384oid)) == 0) {
    *md_type = EVP_sha384();
    *digestinfo_len = sizeof(sha384oid);
  } else if (data_len >= sizeof(sha512oid) &&
             memcmp(sha512oid, data, sizeof(sha512oid)) == 0) {
    *md_type = EVP_sha512();
    *digestinfo_len = sizeof(sha512oid);
  } else {
    *md_type = EVP_md_null();
    *digestinfo_len = 0;
  }
}

bool read_file(FILE *fp, uint8_t *buf, size_t *buf_len) {
  size_t n = 0;
  size_t available = *buf_len;
  uint8_t *p = buf;

  do {
    n = fread(p, 1, available, fp);
    available -= n;
    p += n;
  } while (!feof(fp) && !ferror(fp) && available > 0);

  if (ferror(fp)) {
    return false;
  }

  if (!feof(fp) && available == 0) {
    uint8_t b[1];
    n = fread(b, 1, 1, fp);
    if (!feof(fp)) {
      return false;
    }
  }

  *buf_len = p - buf;
  return true;
}

bool base64_decode(const char *in, uint8_t *out, size_t *len) {
  int ret;
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bio);

  (void) BIO_write(bio, in, strlen(in));
  (void) BIO_flush(bio);
  ret = BIO_read(b64, out, *len);

  BIO_free_all(bio);

  if (ret <= 0) {
    return false;
  } else {
    *len = ret;
    return true;
  }
}

bool hex_decode(const char *in, uint8_t *out, size_t *len) {
  int pos = 0;
  size_t in_len = strlen(in);
  if (in[in_len - 1] == '\n') {
    in_len--;
  }
  if (in[in_len - 1] == '\r') {
    in_len--;
  }
  if (in_len % 2 != 0) {
    return false;
  } else if (in_len / 2 > *len) {
    return false;
  }

  for (size_t i = 0; i < in_len / 2; i++) {
    char *endptr = NULL;
    char buf[3] = {0};
    long num;
    errno = 0;

    buf[0] = in[pos];
    buf[1] = in[pos + 1];
    num = strtol((const char *) buf, &endptr, 16);
    if ((errno == ERANGE && (num < 0 || num > UCHAR_MAX)) ||
        (errno != 0 && num == 0) || *endptr != '\0') {
      return false;
    }
    out[i] = (uint8_t) num;
    pos += 2;
  }
  *len = in_len / 2;
  return true;
}

bool write_file(const uint8_t *buf, size_t buf_len, FILE *fp, format_t format) {

  const uint8_t *p = buf;
  uint8_t *data = NULL;
  size_t length = buf_len;
  size_t written = 0;
  BIO *bio = NULL;

  if (format == _base64) {
    BIO *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    (void) BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    (void) BIO_write(bio, buf, buf_len);
    (void) BIO_flush(bio);
    (void) BIO_get_mem_ptr(bio, &bufferPtr);
    p = (uint8_t *) bufferPtr->data;
    length = bufferPtr->length;
  } else if (format == _hex) {
    data = calloc(buf_len * 2 + 1, 1);
    if (data == NULL) {
      return false;
    }
    for (size_t i = 0; i < buf_len; i++) {
      sprintf((char *) data + i * 2, "%02x", buf[i]);
    }
    p = data;
    length = buf_len * 2;
  }

  do {
    written = fwrite(p, 1, length, fp);
    length -= written;
    p += written;
  } while (!feof(fp) && !ferror(fp) && length > 0);

  if (fp == stdout || fp == stderr) {
    fprintf(fp, "\n");
  }

  if (bio != NULL) {
    (void) BIO_free_all(bio);
    bio = NULL;
  }

  if (data != NULL) {
    free(data);
    data = NULL;
  }

  if (ferror(fp) || feof(fp)) {
    return false;
  }

  fflush(fp);

  return true;
}

bool write_ed25519_key(uint8_t *buf, size_t buf_len, FILE *fp,
                       bool b64_encode) {

  if (b64_encode == true) {
    uint8_t newline = '\n';
    uint8_t asn1[64];
    uint8_t padding = 0;

    if ((buf[0] & 0x80) != 0) {
      padding = 1;
    }

    memcpy(asn1, ed25519public_oid, sizeof(ed25519public_oid));
    asn1[1] += padding;
    memset(asn1 + sizeof(ed25519public_oid), 0, padding);
    asn1[10] += padding;
    memcpy(asn1 + sizeof(ed25519public_oid) + padding, buf, buf_len);

    write_file((uint8_t *) PEM_public_header, sizeof(PEM_public_header) - 1, fp,
               false);
    write_file(asn1, sizeof(ed25519public_oid) + padding + buf_len, fp, true);
    write_file(&newline, 1, fp, false);
    write_file((uint8_t *) PEM_public_trailer, sizeof(PEM_public_trailer) - 1,
               fp, false);
  } else {
    write_file(buf, buf_len, fp, false);
  }

  return true;
}

bool split_hmac_key(yh_algorithm algorithm, uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len) {

  uint8_t key[128 * 2] = {0};
  uint8_t block_size;

  switch (algorithm) {
    case YH_ALGO_HMAC_SHA1:
      block_size = EVP_MD_block_size(EVP_sha1());
      break;

    case YH_ALGO_HMAC_SHA256:
      block_size = EVP_MD_block_size(EVP_sha256());
      break;

    case YH_ALGO_HMAC_SHA384:
      block_size = EVP_MD_block_size(EVP_sha384());
      break;

    case YH_ALGO_HMAC_SHA512:
      block_size = EVP_MD_block_size(EVP_sha512());
      break;

    default:
      return false;
  }

  if (in_len > block_size) {
    return false; // TODO(adma): hash the key
  }

  memcpy(key, in, in_len);

  for (uint8_t i = 0; i < block_size; i++) {
    out[i] = key[i] ^ 0x36;
    out[i + block_size] = key[i] ^ 0x5c;
  }

  *out_len = 2 * block_size;

  return true;
}
