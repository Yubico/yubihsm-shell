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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>

#include "openssl-compat.h"
#endif

#include "ecdh.h"

#ifdef _WIN32_BCRYPT

// TODO

int ecdh_curve_p256(void) { return 0; }
int ecdh_calculate_public_key(int curve, const uint8_t *privkey,
                              size_t cb_privkey, uint8_t *pubkey,
                              size_t cb_pubkey) {
  return 0;
}
int ecdh_generate_keypair(int curve, uint8_t *privkey, size_t cb_privkey,
                          uint8_t *pubkey, size_t cb_pubkey) {
  return 0;
}
int ecdh_calculate_secret(int curve, const uint8_t *privkey, size_t cb_privkey,
                          const uint8_t *pubkey, size_t cb_pubkey,
                          uint8_t *secret, size_t cb_secret) {
  return 0;
}

#else

int ecdh_curve_p256(void) { return NID_X9_62_prime256v1; }

int ecdh_calculate_public_key(int curve, const uint8_t *privkey,
                              size_t cb_privkey, uint8_t *pubkey,
                              size_t cb_pubkey) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *order = BN_new();
  BIGNUM *pvt = BN_bin2bn(privkey, cb_privkey, NULL);
  EC_GROUP *group = EC_GROUP_new_by_curve_name(curve);
  EC_POINT *pub = NULL;
  size_t cb = 0;
  if (ctx == NULL || order == NULL || pvt == NULL || group == NULL) {
    goto err;
  }
  if (BN_is_zero(pvt) || !EC_GROUP_get_order(group, order, ctx) ||
      BN_cmp(pvt, order) >= 0) {
    goto err;
  }
  pub = EC_POINT_new(group);
  if (pub == NULL || !EC_POINT_mul(group, pub, pvt, NULL, NULL, ctx)) {
    goto err;
  }
  cb = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pubkey,
                          cb_pubkey, ctx);
err:
  EC_POINT_free(pub);
  EC_GROUP_free(group);
  BN_free(pvt);
  BN_free(order);
  BN_CTX_free(ctx);
  return (int) cb;
}

int ecdh_generate_keypair(int curve, uint8_t *privkey, size_t cb_privkey,
                          uint8_t *pubkey, size_t cb_pubkey) {
  EC_KEY *key = EC_KEY_new_by_curve_name(curve);
  if (key == NULL || !EC_KEY_generate_key(key)) {
    EC_KEY_free(key);
    return 0;
  }
  int len = BN_bn2binpad(EC_KEY_get0_private_key(key), privkey, cb_privkey);
  if (len <= 0) {
    EC_KEY_free(key);
    return 0;
  }
  size_t cb =
    EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                       POINT_CONVERSION_UNCOMPRESSED, pubkey, cb_pubkey, NULL);
  if (cb == 0 || cb > cb_pubkey) {
    EC_KEY_free(key);
    return 0;
  }
  EC_KEY_free(key);
  return len;
}

int ecdh_calculate_secret(int curve, const uint8_t *privkey, size_t cb_privkey,
                          const uint8_t *pubkey, size_t cb_pubkey,
                          uint8_t *secret, size_t cb_secret) {
  EC_KEY *priv = EC_KEY_new_by_curve_name(curve);
  EC_KEY *pub = EC_KEY_new_by_curve_name(curve);
  EC_POINT *point = NULL;
  int len = 0;
  if (priv == NULL || pub == NULL ||
      !EC_KEY_set_private_key(priv, BN_bin2bn(privkey, cb_privkey, NULL))) {
    goto err;
  }
  point = EC_POINT_new(EC_KEY_get0_group(pub));
  if (point == NULL || !EC_POINT_oct2point(EC_KEY_get0_group(pub), point,
                                           pubkey, cb_pubkey, NULL)) {
    goto err;
  }
  if (!EC_KEY_set_public_key(pub, point) || !EC_KEY_check_key(pub)) {
    goto err;
  }
  len = ECDH_compute_key(secret, cb_secret, EC_KEY_get0_public_key(pub), priv,
                         NULL);
err:
  EC_POINT_free(point);
  EC_KEY_free(pub);
  EC_KEY_free(priv);
  return len > 0 ? len : 0;
}

#endif
