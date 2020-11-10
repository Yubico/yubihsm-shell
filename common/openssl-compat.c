/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl-compat.h"

extern int make_iso_compilers_happy;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#include <string.h>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
  /* If the fields n and e in r are NULL, the corresponding input
   * parameters MUST be non-NULL for n and e.  d may be
   * left NULL (in case only the public key is used).
   */
  if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL))
    return 0;

  if (n != NULL) {
    BN_free(r->n);
    r->n = n;
  }
  if (e != NULL) {
    BN_free(r->e);
    r->e = e;
  }
  if (d != NULL) {
    BN_free(r->d);
    r->d = d;
  }

  return 1;
}

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
                  const BIGNUM **d) {
  if (n != NULL)
    *n = r->n;
  if (e != NULL)
    *e = r->e;
  if (d != NULL)
    *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q) {
  if (p != NULL)
    *p = r->p;
  if (q != NULL)
    *q = r->q;
}

void RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp) {
  if (dmp1 != NULL)
    *dmp1 = r->dmp1;
  if (dmq1 != NULL)
    *dmq1 = r->dmq1;
  if (iqmp != NULL)
    *iqmp = r->iqmp;
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
  if ((sig->r == NULL && r == NULL) || (sig->s == NULL && s == NULL)) {
    return 0;
  }

  if (r != NULL) {
    BN_free(sig->r);
    sig->r = r;
  }
  if (s != NULL) {
    BN_free(sig->s);
    sig->s = s;
  }

  return 1;
}
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr,
                    const BIGNUM **ps) {
  if (pr != NULL) {
    *pr = sig->r;
  }
  if (ps != NULL) {
    *ps = sig->s;
  }
}

const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509 *x) {
  return x->cert_info->extensions;
}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex) {
  return ex->object;
}
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ex) {
  return ex->value;
}

#endif /* OPENSSL_VERSION_NUMBER */

int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen) {
  int n = BN_num_bytes(a);
  if (n < 0 || n > tolen) {
    return -1;
  }
  memset(to, 0, tolen - n);
  if (BN_bn2bin(a, to + tolen - n) < 0) {
    return -1;
  }
  return tolen;
}

#endif /* OPENSSL_VERSION_NUMBER */
