#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: ./opensc_test.sh <path to PKCS11 module>"
    echo ""
    echo "This script expects that YUBIHSM_PKCS11_CONF environment variable is defined"
    exit
fi

MODULE=$1
#$env:YUBIHSM_PKCS11_CONF=$YHPKCS11CFG

set -e

echo "******************* Generation Tests ********************* "
pkcs11-tool --module $MODULE --login --pin 0001password --keypairgen --id 100 --key-type EC:secp384r1
pkcs11-tool --module $MODULE --login --pin 0001password --keypairgen --id 2 --key-type EC:prime256v1
pkcs11-tool --module $MODULE --login --pin 0001password --keypairgen --id 4 --key-type rsa:2048
pkcs11-tool --module $MODULE --login --pin 0001password --keypairgen --id 5 --key-type rsa:3072

echo "******************* Signing Tests ********************* "
echo "this is test data" > data.txt
pkcs11-tool --module $MODULE --sign --pin 0001password --id 100 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --pin 0001password --id 4 -m SHA512-RSA-PKCS -i data.txt -o data.sig
pkcs11-tool --module $MODULE --sign --pin 0001password --id 5 -m SHA512-RSA-PKCS -i data.txt -o data.sig
rm data.txt
rm data.sig

echo "******************* Testing RSA Tests ********************* "
pkcs11-tool --module $MODULE --login --pin 0001password --test

#echo "******************* Testing EC Tests ********************* "
#pkcs11-tool --module $MODULE --login --login-type so --so-pin 0001password --test-ec --id 200 --key-type EC:secp256r1

set +e