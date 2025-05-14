#!/bin/bash
set -u

if [ "$#" -ne 1 ]; then
  BIN="yubihsm-shell"
else
  BIN=$1 # path to the yubihsm-shell command line tool
fi

if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
fi
mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
echo test signing and decryption data > data.txt

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

test_with_resp () {
  set +e
  $1 > resp.txt 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo $1
    cat resp.txt
    rm resp.txt
    exit 1
  else
    echo "$2 ... OK!"
  fi
  set -e
}

set -e

echo "====================== RSA keys ===================== "

RSA_KEYSIZE=("2048" "3072" "4096")

for k in ${RSA_KEYSIZE[@]}; do

  echo "**********************************"
  echo "            RSA$k"
  echo "**********************************"
  echo "=== Generate key"
  test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l rsaKey -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa$k" "   Generate key"
  keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-object-info -i $keyid -t asymmetric-key" "   Get object info"
  info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key 2> /dev/null)
  test "echo $info | grep \"id: $keyid\"" "   Object info contains correct ID"
  test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
  test "echo $info | grep \"algorithm: rsa$k\"" "   Object info contains correct algorithm"
  test "echo $info | grep 'label: \"rsaKey\"'" "   Object info contains correct label"
  test "echo $info | grep \"domains: 1\"" "   Object info contains correct domains"
  test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
  test "echo $info | grep \"capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss\"" "   Object info contains correct capabilities"
  test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa$k.pem" "   Get public key"

  echo "=== Import key:"
  test "openssl genrsa -out rsa$k-keypair.pem $k" "   Generate key with OpenSSL"
  test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l rsaKeyImport -d 2 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in=rsa$k-keypair.pem" "   Import key"
  import_keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key" "   Get object info"
  info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key 2> /dev/null)
  test "echo $info | grep \"id: $import_keyid\"" "   Object info contains correct ID"
  test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
  test "echo $info | grep \"algorithm: rsa$k\"" "   Object info contains correct algorithm"
  test "echo $info | grep 'label: \"rsaKeyImport\"'" "   Object info contains correct label"
  test "echo $info | grep \"domains: 2\"" "   Object info contains correct domains"
  test "echo $info | grep \"origin: imported\"" "   Object info contains correct origin"
  test "echo $info | grep \"capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss\"" "   Object info contains correct capabilities"
  test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa$k.imported.pem" "   Get public key"

  echo "=== Signing with generated key:"
  test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.$k-pkcs1sha1gen.sig" "   Sign with rsa-pkcs1-sha1"
  test "openssl dgst -sha1 -verify pubkey_rsa$k.pem -signature data.$k-pkcs1sha1gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.$k-pkcs1sha256gen.sig" "   Sign with rsa-pkcs1-sha256"
  test "openssl dgst -sha256 -verify pubkey_rsa$k.pem -signature data.$k-pkcs1sha256gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.$k-pkcs1sha384gen.sig" "   Sign with rsa-pkcs1-sha384"
  test "openssl dgst -sha384 -verify pubkey_rsa$k.pem -signature data.$k-pkcs1sha384gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.$k-pkcs1sha512gen.sig" "   Sign with rsa-pkcs1-sha512"
  test "openssl dgst -sha512 -verify pubkey_rsa$k.pem -signature data.$k-pkcs1sha512gen.sig data.txt" "   Verify signature with OpenSSL"

  test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --outformat binary --out data.$k-psssha1gen.sig" "   Sign with rsa-pss-sha1"
  test "openssl dgst -sha1 -binary -out data.sha1 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha1 -sigfile data.$k-psssha1gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --outformat binary --out data.$k-psssha256gen.sig" "   Sign with rsa-pss-sha256"
  test "openssl dgst -sha256 -binary -out data.sha256 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha256 -sigfile data.$k-psssha256gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --outformat binary --out data.$k-psssha384gen.sig" "   Sign with rsa-pss-sha384"
  test "openssl dgst -sha384 -binary -out data.sha384 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha384 -sigfile data.$k-psssha384gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --outformat binary --out data.$k-psssha512gen.sig" "   Sign with rsa-pss-sha512"
  test "openssl dgst -sha512 -binary -out data.sha512 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha512 -sigfile data.$k-psssha512gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512" "   Verify signature with OpenSSL"

  echo "=== Signing with imported key:"
  test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.$k-pkcs1sha1import.sig" "   Sign with rsa-pkcs1-sha1"
  test "openssl dgst -sha1 -verify pubkey_rsa$k.imported.pem -signature data.$k-pkcs1sha1import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.$k-pkcs1sha256import.sig" "   Sign with rsa-pkcs1-sha256"
  test "openssl dgst -sha256 -verify pubkey_rsa$k.imported.pem -signature data.$k-pkcs1sha256import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.$k-pkcs1sha384import.sig" "   Sign with rsa-pkcs1-sha384"
  test "openssl dgst -sha384 -verify pubkey_rsa$k.imported.pem -signature data.$k-pkcs1sha384import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.$k-pkcs1sha512import.sig" "   Sign with rsa-pkcs1-sha512"
  test "openssl dgst -sha512 -verify pubkey_rsa$k.imported.pem -signature data.$k-pkcs1sha512import.sig data.txt" "   Verify signature with OpenSSL"

  test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --outformat binary --out data.$k-psssha1import.sig" "   Sign with rsa-pss-sha1"
  test "openssl dgst -sha1 -binary -out data.sha1 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha1 -sigfile data.$k-psssha1import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --outformat binary --out data.$k-psssha256import.sig" "   Sign with rsa-pss-sha256"
  test "openssl dgst -sha256 -binary -out data.sha256 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha256 -sigfile data.$k-psssha256import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --outformat binary --out data.$k-psssha384import.sig" "   Sign with rsa-pss-sha384"
  test "openssl dgst -sha384 -binary -out data.sha384 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha384 -sigfile data.$k-psssha384import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --outformat binary --out data.$k-psssha512import.sig" "   Sign with rsa-pss-sha512"
  test "openssl dgst -sha512 -binary -out data.sha512 data.txt" "   Hash data with OpenSSL"
  test "openssl pkeyutl -verify -in data.sha512 -sigfile data.$k-psssha512import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa$k.imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512" "   Verify signature with OpenSSL"

  echo "=== Make self signed certificate:"
  set +e
  $BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 2>&1 > /dev/null # Some YubiHSMs does not have default attestation certificate
  def_attestation=$?
  set -e
  if [ $def_attestation -eq 0 ]; then
    test "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem" "   Sign attestation cert with default key"
    test "openssl x509 -in cert.pem -out cert.der -outform DER" "   Convert cert format"
    test "$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der" "   Import attestation cert as template cert (same ID as generated key)"
    test "$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der" "   Import attestation cert as template cert (same ID as imported key)"
    test "rm cert.der" "   Cleaning up"
  else
    test "$BIN -p password -a put-opaque -i $keyid -l template_cert_gen -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem" "   Import attestation cert as template cert (same ID as generated key)"
    test "$BIN -p password -a put-opaque -i $import_keyid -l template_cert_imp -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem" "   Import attestation cert as template cert (same ID as imported key)"
  fi
  test "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem" "   Sign attestation with same key (aka. get selfsigned cert)"
  test "$BIN -p password -a delete-object -i $keyid -t opaque" "   Delete template cert"
  test "$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem" "   Import selfsigned cert with same key ID"
  test "rm selfsigned_cert.pem" "   Cleaning up"
  #-- Sign attestation certificate
  test "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.pem" "   Sign attestation cert with imported key"
  test "rm selfsigned_cert.pem" "   Cleaning up"
  test "$BIN -p password -a delete-object -i $import_keyid -t opaque" "   Delete certificate template"
  test "$BIN -p password -a delete-object -i $keyid -t opaque" "   Delete certificate"

  echo "=== Decrypt with generated key and PKCS1v15:"
  test "openssl rsautl -encrypt -inkey pubkey_rsa$k.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
  test "$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
  test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
  test "rm data.dec" "   Clean up"

  echo "=== Decrypt with imported key and PKCS1v15:"
  test "openssl rsautl -encrypt -inkey pubkey_rsa$k.imported.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
  test "$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
  test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
  test "rm data.dec" "   Clean up"

  echo "=== Clean up:"
  test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
  test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"
done

echo "****************************************************"
echo "            Compress X509 Certificate"
echo "****************************************************"

openssl req -x509 -newkey rsa:4096 -out too_large_cert.pem -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123' > /dev/null 2>&1
set +e
resp=$($BIN -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --in too_large_cert.pem --informat PEM 2>&1)
ret=$?
if [ $ret -ne 0 ]; then
  if [[ $resp == *"Failed to store opaque object: Not enough space to store data"* ]]; then
    test "$BIN -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-compressed --in too_large_cert.pem --informat PEM" "   Import compressed X509 certificate"
  else
    echo "$BIN -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --in too_large_cert.pem --informat PEM"
    echo $resp
  fi
else
  echo "   Import too large certificate raw... OK!"
fi
set -e

test "$BIN -p password -a get-opaque -i 100 --outformat=PEM --out too_large_cert_out.pem" "   Read the large certificate from device"
test "cmp too_large_cert.pem too_large_cert_out.pem" "   Compare read certificate with the one imported"
test "$BIN -p password -a delete-object -i 100 -t opaque" "   Delete certificate"

cd ..
rm -rf yubihsm-shell_test_dir

set +e
set +x