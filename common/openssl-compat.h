/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef LIBCRYPTO_COMPAT_H
#define LIBCRYPTO_COMPAT_H

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

int YH_INTERNAL RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
void YH_INTERNAL RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
                              const BIGNUM **d);
void YH_INTERNAL RSA_get0_factors(const RSA *r, const BIGNUM **p,
                                  const BIGNUM **q);
void YH_INTERNAL RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1,
                                     const BIGNUM **dmq1, const BIGNUM **iqmp);

void YH_INTERNAL ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr,
                                const BIGNUM **ps);
int YH_INTERNAL ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

const YH_INTERNAL STACK_OF(X509_EXTENSION) *
  X509_get0_extensions(const X509 *x);

ASN1_OBJECT YH_INTERNAL *X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING YH_INTERNAL *X509_EXTENSION_get_data(X509_EXTENSION *ex);

#endif /* OPENSSL_VERSION_NUMBER */
#endif /* LIBCRYPTO_COMPAT_H */
