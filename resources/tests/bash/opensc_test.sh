#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: ./opensc_test.sh <path to PKCS11 module>"
    echo ""
    echo "This script expects that YUBIHSM_PKCS11_CONF environment variable is defined"
    exit
fi

MODULE=$1
#$env:YUBIHSM_PKCS11_CONF=$YHPKCS11CFG

test () {
  set +e
  $1 > output.txt 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo $1
    cat output.txt
    rm output.txt
    exit 1
  else
    echo "$2 ... OK!"
    rm output.txt
  fi
  set -e
}

set -e

echo "this is test data" > data.txt

### Note about pkcs11-tool and object id:
### When generating/importing private keys, an ID has to be specified otherwise, practically a random key will be used
### when, for example, signing. This is because pkcs11-tool, unless a specific ID is set in the command line, it will use
### the first private key it finds to perform the operation. Setting/using a key's label/alias will not have an effect
### because it will not look for a key by label/alias. However, specifying an object to delete by its label/alias seems
### to work just fine.

EC_CURVES=("secp224r1" "secp256r1" "secp384r1" "secp521r1" "secp256k1")

set +e
cat /etc/os-release | grep 'Fedora'
is_fedora=$?
set -e

if [ $is_fedora -ne 0 ]; then
  EC_CURVES=(${EC_CURVES[@]} "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")
fi

for curve in "${EC_CURVES[@]}"; do

  echo "**********************************"
  echo "            $curve"
  echo "**********************************"

#  # Generate key
  test "pkcs11-tool --module $MODULE --login --pin 0001password --keypairgen --id 1 --key-type EC:$curve" "   Generate EC key with curve $curve"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --read-object --id 1 --type pubkey --output-file pubkey.der" "   Get public key of generated key"

  # Sign with generated key
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig" "   Sign with generated key and ECDSA-SHA1"
  test "openssl dgst -sha1 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m ECDSA-SHA256 --signature-format openssl -i data.txt -o data.sig" "   Sign with generated key and ECDSA-SHA256"
  test "openssl dgst -sha256 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m ECDSA-SHA384 --signature-format openssl -i data.txt -o data.sig" "   Sign with generated key and ECDSA-SHA384"
  test "openssl dgst -sha384 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m ECDSA-SHA512 --signature-format openssl -i data.txt -o data.sig" "   Sign with generated key and ECDSA-SHA512"
  test "openssl dgst -sha512 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"

  # Import key
  test "openssl ecparam -genkey -name $curve -noout -out keypair.pem" "   Generate keypair with curve $curve using OpenSSL"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --write-object keypair.pem --id 2 --type privkey --usage-sign" "   Import EC key with curve $curve"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --read-object --id 2 --type pubkey --output-file pubkey_imported.der" "   Get public key of imported key"

  # Sign with imported key
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig" "   Sign with imported key and ECDSA-SHA1"
  test "openssl dgst -sha1 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m ECDSA-SHA256 --signature-format openssl -i data.txt -o data.sig" "   Sign with imported key and ECDSA-SHA256"
  test "openssl dgst -sha256 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m ECDSA-SHA384 --signature-format openssl -i data.txt -o data.sig" "   Sign with imported key and ECDSA-SHA384"
  test "openssl dgst -sha384 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m ECDSA-SHA512 --signature-format openssl -i data.txt -o data.sig" "   Sign with imported key and ECDSA-SHA512"
  test "openssl dgst -sha512 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"

  # Derive ECDH
  test "pkcs11-tool --module $MODULE --login --pin 0001password --derive --id 1 --input-file pubkey_imported.der --output-file ecdh_pkcs11.bin" "   Derive ECDH using pkcs11-tool"
  test "openssl pkeyutl -derive -inkey keypair.pem -peerkey pubkey.der -out ecdh_openssl.bin" "   Derive ECDH using OpenSSL"
  test "cmp ecdh_pkcs11.bin ecdh_openssl.bin" "   Compare the derived ECDH keys"
  test "rm ecdh_pkcs11.bin ecdh_openssl.bin" "   Delete ecdh keys"

  # Requires writable session? yubihsm-pkcs11 only allowed regular users
  #pkcs11-tool --module $MODULE --login --pin 0001password --test-ec --id 200 --key-type EC:secp256r1

  # Delete keys
  test "pkcs11-tool --module $MODULE --login --pin 0001password --delete-object --id 1 --type privkey" "   Delete generated key"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --delete-object --id 2 --type privkey" "   Delete imported key"

done

RSA_LENGTHS=("2048" "3072" "4096")

test "openssl dgst -sha1 -binary -out data.sha1 data.txt" "   Hash data with SHA1 and OpenSSL"
test "openssl dgst -sha256 -binary -out data.sha256 data.txt" "   Hash data with SHA256 and OpenSSL"
test "openssl dgst -sha384 -binary -out data.sha384 data.txt" "   Hash data with SHA384 and OpenSSL"
test "openssl dgst -sha512 -binary -out data.sha512 data.txt" "   Hash data with SHA512 and OpenSSL"

for len in "${RSA_LENGTHS[@]}"; do

  echo "**********************************"
  echo "            RSA$len"
  echo "**********************************"

  # Generate key
  test "pkcs11-tool --module $MODULE --login --pin 0001password --keypairgen --id 1 --key-type rsa:$len --usage-sign --usage-decrypt" "   Generate RSA$len key"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --read-object --id 1 --type pubkey --output-file pubkey.der" "   Get public key of generated key"

  # Sign with generated key and RSA-PKCS
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA1-RSA-PKCS -i data.txt -o data.sig" "   Sign with generated key and SHA1-RSA-PKCS"
  test "openssl dgst -sha1 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA256-RSA-PKCS -i data.txt -o data.sig" "   Sign with generated key and SHA256-RSA-PKCS"
  test "openssl dgst -sha256 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA384-RSA-PKCS -i data.txt -o data.sig" "   Sign with generated key and SHA384-RSA-PKCS"
  test "openssl dgst -sha384 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA512-RSA-PKCS -i data.txt -o data.sig" "   Sign with generated key and SHA512-RSA-PKCS"
  test "openssl dgst -sha512 -verify pubkey.der -signature data.sig data.txt" "   Verify signature with OpenSSL"

  # Sign with generated key and RSA-PSS
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA1-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with generated key and SHA1-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA256-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with generated key and SHA256-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha256 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA384-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with generated key and SHA384-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha384 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 1 -m SHA512-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with generated key and SHA512-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha512 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512" "   Verify signature with OpenSSL"

  # Decrypt with generated key and PKCS1v15
  test "openssl rsautl -encrypt -inkey pubkey.der -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL using PKCS1v15"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 1 -m RSA-PKCS --input-file data.enc --output-file data.dec" "   Decrypt using generated key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"

  # Decrypt with generated key and OAEP
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA1"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA-1  --input-file data.enc --output-file data.dec" "   Decrypt using generated key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA256"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA256  --input-file data.enc --output-file data.dec" "   Decrypt using generated key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 -pkeyopt rsa_mgf1_md:sha384 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA384"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA384  --input-file data.enc --output-file data.dec" "   Decrypt using generated key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 -pkeyopt rsa_mgf1_md:sha512 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA512"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA512  --input-file data.enc --output-file data.dec" "   Decrypt using generated key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"

  # Import key
  test "openssl genrsa -out keypair.pem $len" "   Generate key with OpenSSL"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --write-object keypair.pem --id 2 --type privkey --usage-sign --usage-decrypt" "   Import RSA$len key"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --read-object --id 2 --type pubkey --output-file pubkey_imported.der" "   Get public key of imported key"

  # Sign with imported key and PKCS
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA1-RSA-PKCS -i data.txt -o data.sig" "   Sign with imported key and SHA1-RSA-PKCS"
  test "openssl dgst -sha1 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA256-RSA-PKCS -i data.txt -o data.sig" "   Sign with imported key and SHA256-RSA-PKCS"
  test "openssl dgst -sha256 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA384-RSA-PKCS -i data.txt -o data.sig" "   Sign with imported key and SHA384-RSA-PKCS"
  test "openssl dgst -sha384 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA512-RSA-PKCS -i data.txt -o data.sig" "   Sign with imported key and SHA512-RSA-PKCS"
  test "openssl dgst -sha512 -verify pubkey_imported.der -signature data.sig data.txt" "   Verify signature with OpenSSL"

  # Sign with imported key and RSA-PSS
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA1-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with imported key and SHA1-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA256-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with imported key and SHA256-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha256 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA384-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with imported key and SHA384-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha384 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384" "   Verify signature with OpenSSL"
  test "pkcs11-tool --module $MODULE --sign --pin 0001password --id 2 -m SHA512-RSA-PKCS-PSS -i data.txt -o data.sig" "   Sign with imported key and SHA512-RSA-PKCS-PSS"
  test "openssl pkeyutl -verify -in data.sha512 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512" "   Verify signature with OpenSSL"

  # Decrypt with imported key and PKCS1v15
  test "openssl rsautl -encrypt -inkey pubkey_imported.der -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL using PKCS1v15"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 2 -m RSA-PKCS --input-file data.enc --output-file data.dec" "   Decrypt using imported key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"

  # Decrypt with imported key and OAEP
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA1"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA-1  --input-file data.enc --output-file data.dec" "   Decrypt using imported key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA256"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA256  --input-file data.enc --output-file data.dec" "   Decrypt using imported key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 -pkeyopt rsa_mgf1_md:sha384 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA384"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA384  --input-file data.enc --output-file data.dec" "   Decrypt using imported key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"
  test "openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 -pkeyopt rsa_mgf1_md:sha512 -in data.txt -out data.enc" "   Encrypt with OpenSSL using OAEP and SHA512"
  test "pkcs11-tool --module $MODULE --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA512  --input-file data.enc --output-file data.dec" "   Decrypt using imported key"
  test "cmp data.dec data.txt" "   Compare decrypted data with plain text data"
  test "rm data.enc data.dec" "   Delete test data"

  # Perform pkcs11-tool RSA tests
  pkcs11-tool --module $MODULE --login --pin 0001password --test

  # Delete keys
  test "pkcs11-tool --module $MODULE --login --pin 0001password --delete-object --id 1 --type privkey" "   Delete generated key"
  test "pkcs11-tool --module $MODULE --login --pin 0001password --delete-object --id 2 --type privkey" "   Delete generated key"
done

rm data.sha1 data.sha256 data.sha384 data.sha512 data.sig data.txt
rm keypair.pem pubkey.der pubkey_imported.der

echo "****************************************************"
echo "            Compress X509 Certificate"
echo "****************************************************"
openssl req -x509 -newkey rsa:4096 -out too_large_cert.der -outform DER -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123' > /dev/null 2>&1
test "pkcs11-tool --module $MODULE --login --pin 0001password --write-object too_large_cert.der --id 6464 --type cert" "   Import large X509 certificate"
test "pkcs11-tool --module $MODULE --login --pin 0001password --read-object --id 6464 --type cert --output-file too_large_cert_out.der" "   Get imported certificate"
test "cmp too_large_cert.der too_large_cert_out.der" "   Compare read certificate with the one imported"
test "pkcs11-tool --module $MODULE --login --pin 0001password --delete-object --id 6464 --type cert" "   Delete certificate"

set +e