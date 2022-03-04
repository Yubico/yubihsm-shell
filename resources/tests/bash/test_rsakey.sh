#!/bin/bash

if [ "$#" -ne 1 ]; then
  BIN="yubihsm-shell"
else
  BIN=$1 # path to the yubico-piv-tool command line tool
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
echo "------------- RSA2048"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l rsaKey -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa2048" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t asymmetric-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key 2> /dev/null)
test "echo $info | grep \"id: $keyid\"" "   Object info contains correct ID"
test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
test "echo $info | grep \"algorithm: rsa2048\"" "   Object info contains correct algorithm"
test "echo $info | grep 'label: \"rsaKey\"'" "   Object info contains correct label"
test "echo $info | grep \"domains: 1\"" "   Object info contains correct domains"
test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
test "echo $info | grep \"capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss\"" "   Object info contains correct capabilities"
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa2048.pem" "   Get public key"

echo "Import key:"
test "openssl genrsa -out rsa2048-keypair.pem 2048" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l rsaKeyImport -d 2 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in=rsa2048-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key 2> /dev/null)
test "echo $info | grep \"id: $import_keyid\"" "   Object info contains correct ID"
test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
test "echo $info | grep \"algorithm: rsa2048\"" "   Object info contains correct algorithm"
test "echo $info | grep 'label: \"rsaKeyImport\"'" "   Object info contains correct label"
test "echo $info | grep \"domains: 2\"" "   Object info contains correct domains"
test "echo $info | grep \"origin: imported\"" "   Object info contains correct origin"
test "echo $info | grep \"capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss\"" "   Object info contains correct capabilities"
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa2048_imported.pem" "   Get public key"

echo "Signing with generated key:"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.2048pkcs1sha1gen.sig" "   Sign with rsa-pkcs1-sha1"
test "openssl dgst -sha1 -verify pubkey_rsa2048.pem -signature data.2048pkcs1sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.2048pkcs1sha256gen.sig" "   Sign with rsa-pkcs1-sha256"
test "openssl dgst -sha256 -verify pubkey_rsa2048.pem -signature data.2048pkcs1sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.2048pkcs1sha384gen.sig" "   Sign with rsa-pkcs1-sha384"
test "openssl dgst -sha384 -verify pubkey_rsa2048.pem -signature data.2048pkcs1sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.2048pkcs1sha512gen.sig" "   Sign with rsa-pkcs1-sha512"
test "openssl dgst -sha512 -verify pubkey_rsa2048.pem -signature data.2048pkcs1sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.2048psssha1gen.sig" "   Sign with rsa-pss-sha1"
#test "openssl dgst -sha1 -verify pubkey_rsa2048.pem -signature data.2048psssha1gen.sig data.txt" "   Verify signature with OpenSSL"
#test "openssl pkeyutl -verify -in data.txt -sigfile data.2048psssha1gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa2048.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1" "   verify"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.2048psssha256gen.sig" "   Sign with rsa-pss-sha256"
#test "openssl dgst -sha256 -verify pubkey_rsa2048.pem -signature data.2048psssha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.2048psssha384gen.sig" "   Sign with rsa-pss-sha384"
#test "openssl dgst -sha384 -verify pubkey_rsa2048.pem -signature data.2048psssha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.2048psssha512gen.sig" "   Sign with rsa-pss-sha512"
#test "openssl dgst -sha512 -verify pubkey_rsa2048.pem -signature data.2048psssha512gen.sig data.txt" "   Verify signature with OpenSSL"

echo "Signing with imported key:"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.2048pkcs1sha1import.sig" "   Sign with rsa-pkcs1-sha1"
test "openssl dgst -sha1 -verify pubkey_rsa2048_imported.pem -signature data.2048pkcs1sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.2048pkcs1sha256import.sig" "   Sign with rsa-pkcs1-sha256"
test "openssl dgst -sha256 -verify pubkey_rsa2048_imported.pem -signature data.2048pkcs1sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.2048pkcs1sha384import.sig" "   Sign with rsa-pkcs1-sha384"
test "openssl dgst -sha384 -verify pubkey_rsa2048_imported.pem -signature data.2048pkcs1sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.2048pkcs1sha512import.sig" "   Sign with rsa-pkcs1-sha512"
test "openssl dgst -sha512 -verify pubkey_rsa2048_imported.pem -signature data.2048pkcs1sha512import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.2048psssha1import.sig" "   Sign with rsa-pss-sha1"
#test "openssl dgst -sha1 -verify pubkey_rsa2048_imported.pem -signature data.2048psssha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.2048psssha256import.sig" "   Sign with rsa-pss-sha256"
#test "openssl dgst -sha256 -verify pubkey_rsa2048_imported.pem -signature data.2048psssha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.2048psssha384import.sig" "   Sign with rsa-pss-sha384"
#test "openssl dgst -sha384 -verify pubkey_rsa2048_imported.pem -signature data.2048psssha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.2048psssha512import.sig" "   Sign with rsa-pss-sha512"
#test "openssl dgst -sha512 -verify pubkey_rsa2048_imported.pem -signature data.2048psssha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Make self signed certificate:"
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

echo "Decrypt with generated key and PKCS1v15:"
test "openssl rsautl -encrypt -inkey pubkey_rsa2048.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
test "$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
test "rm data.dec" "   Clean up"

echo "Decrypt with imported key and PKCS1v15:"
test "openssl rsautl -encrypt -inkey pubkey_rsa2048_imported.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
test "$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
test "rm data.dec" "   Clean up"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

echo "------------- RSA3072"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l rsaKey -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa3072" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t asymmetric-key" "   Get object info"
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa3072.pem" "   Get public key"

echo "Import key:"
test "openssl genrsa -out rsa3072-keypair.pem 3072" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l rsaKeyImport -d 2 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in=rsa3072-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key" "   Get object info"
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa3072_imported.pem" "   Get public key"

echo "Signing with generated key:"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.3072pkcs1sha1gen.sig" "   Sign with rsa-pkcs1-sha1"
test "openssl dgst -sha1 -verify pubkey_rsa3072.pem -signature data.3072pkcs1sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.3072pkcs1sha256gen.sig" "   Sign with rsa-pkcs1-sha256"
test "openssl dgst -sha256 -verify pubkey_rsa3072.pem -signature data.3072pkcs1sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.3072pkcs1sha384gen.sig" "   Sign with sa-pkcs1-sha384"
test "openssl dgst -sha384 -verify pubkey_rsa3072.pem -signature data.3072pkcs1sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.3072pkcs1sha512gen.sig" "   Sign with sa-pkcs1-sha512"
test "openssl dgst -sha512 -verify pubkey_rsa3072.pem -signature data.3072pkcs1sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.3072psssha1gen.sig" "   Sign with rsa-pss-sha1"
#test "openssl dgst -sha1 -verify pubkey_rsa3072.pem -signature data.3072psssha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.3072psssha256gen.sig" "   Sign with rsa-pss-sha256"
#test "openssl dgst -sha256 -verify pubkey_rsa3072.pem -signature data.3072psssha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.3072psssha384gen.sig" "   Sign with rsa-pss-sha384"
#test "openssl dgst -sha384 -verify pubkey_rsa3072.pem -signature data.3072psssha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.3072psssha512gen.sig" "   Sign with rsa-pss-sha512"
#test "openssl dgst -sha512 -verify pubkey_rsa3072.pem -signature data.3072psssha512gen.sig data.txt" "   Verify signature with OpenSSL"

echo "Signing with imported key:"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.3072pkcs1sha1import.sig" "   Sign with rsa-pkcs1-sha1"
test "openssl dgst -sha1 -verify pubkey_rsa3072_imported.pem -signature data.3072pkcs1sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.3072pkcs1sha256import.sig" "   Sign with rsa-pkcs1-sha256"
test "openssl dgst -sha256 -verify pubkey_rsa3072_imported.pem -signature data.3072pkcs1sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.3072pkcs1sha384import.sig" "   Sign with rsa-pkcs1-sha384"
test "openssl dgst -sha384 -verify pubkey_rsa3072_imported.pem -signature data.3072pkcs1sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.3072pkcs1sha512import.sig" "   Sign with rsa-pkcs1-sha512"
test "openssl dgst -sha512 -verify pubkey_rsa3072_imported.pem -signature data.3072pkcs1sha512import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.3072psssha1import.sig" "   Sign with rsa-pss-sha1"
#test "openssl dgst -sha1 -verify pubkey_rsa3072_imported.pem -signature data.3072psssha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.3072psssha256import.sig" "   Sign with rsa-pss-sha256"
#test "openssl dgst -sha256 -verify pubkey_rsa3072_imported.pem -signature data.3072psssha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.3072psssha384import.sig" "   Sign with rsa-pss-sha384"
#test "openssl dgst -sha384 -verify pubkey_rsa3072_imported.pem -signature data.3072psssha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.3072psssha512import.sig" "   Sign with rsa-pss-sha512"
#test "openssl dgst -sha512 -verify pubkey_rsa3072_imported.pem -signature data.3072psssha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Make self signed certificate:"
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

echo "Decrypt with generated key and PKCS1v15:"
test "openssl rsautl -encrypt -inkey pubkey_rsa3072.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
test "$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
test "rm data.dec" "   Clean up"

echo "Decrypt with imported key and PKCS1v15:"
test "openssl rsautl -encrypt -inkey pubkey_rsa3072_imported.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
test "$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
test "rm data.dec" "   Clean up"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

echo "------------- 4096"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l rsaKey -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa4096" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t asymmetric-key" "   Get object info"
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa4096.pem" "   Get public key"

echo "Import key:"
test "openssl genrsa -out rsa4096-keypair.pem 4096" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l rsaKeyImport -d 2 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in=rsa4096-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key" "   Get object info"
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa4096_imported.pem" "   Get public key"

echo "Signing with generated key:"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.4096pkcs1sha1gen.sig" "   Sign with rsa-pkcs1-sha1"
test "openssl dgst -sha1 -verify pubkey_rsa4096.pem -signature data.4096pkcs1sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.4096pkcs1sha256gen.sig" "   Sign with rsa-pkcs1-sha256"
test "openssl dgst -sha256 -verify pubkey_rsa4096.pem -signature data.4096pkcs1sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.4096pkcs1sha384gen.sig" "   Sign with rsa-pkcs1-sha384"
test "openssl dgst -sha384 -verify pubkey_rsa4096.pem -signature data.4096pkcs1sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.4096pkcs1sha512gen.sig" "   Sign with rsa-pkcs1-sha512"
test "openssl dgst -sha512 -verify pubkey_rsa4096.pem -signature data.4096pkcs1sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.4096psssha1gen.sig" "   Sign with rsa-pss-sha1"
#test "openssl dgst -sha1 -verify pubkey_rsa4096.pem -signature data.4096psssha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.4096psssha256gen.sig" "   Sign with rsa-pss-sha256"
#test "openssl dgst -sha256 -verify pubkey_rsa4096.pem -signature data.4096psssha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.4096psssha384gen.sig" "   Sign with rsa-pss-sha384"
#test "openssl dgst -sha384 -verify pubkey_rsa4096.pem -signature data.4096psssha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.4096psssha512gen.sig" "   Sign with rsa-pss-sha512"
#test "openssl dgst -sha512 -verify pubkey_rsa4096.pem -signature data.4096psssha512gen.sig data.txt" "   Verify signature with OpenSSL"

echo "Signing with imported key:"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data.4096pkcs1sha1import.sig" "   Sign with rsa-pkcs1-sha1"
test "openssl dgst -sha1 -verify pubkey_rsa4096_imported.pem -signature data.4096pkcs1sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data.4096pkcs1sha256import.sig" "   Sign with rsa-pkcs1-sha256"
test "openssl dgst -sha256 -verify pubkey_rsa4096_imported.pem -signature data.4096pkcs1sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data.4096pkcs1sha384import.sig" "   Sign with rsa-pkcs1-sha384"
test "openssl dgst -sha384 -verify pubkey_rsa4096_imported.pem -signature data.4096pkcs1sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data.4096pkcs1sha512import.sig" "   Sign with rsa-pkcs1-sha512"
test "openssl dgst -sha512 -verify pubkey_rsa4096_imported.pem -signature data.4096pkcs1sha512import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.4096psssha1import.sig" "   Sign with rsa-pss-sha1"
#test "openssl dgst -sha1 -verify pubkey_rsa4096_imported.pem -signature data.4096psssha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.4096psssha256import.sig" "   Sign with rsa-pss-sha256"
#test "openssl dgst -sha256 -verify pubkey_rsa4096_imported.pem -signature data.4096psssha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.4096psssha384import.sig" "   Sign with rsa-pss-sha384"
#test "openssl dgst -sha384 -verify pubkey_rsa4096_imported.pem -signature data.4096psssha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.4096psssha512import.sig" "   Sign with rsa-pss-sha512"
#test "openssl dgst -sha512 -verify pubkey_rsa4096_imported.pem -signature data.4096psssha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Make self signed certificate:"
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

echo "Decrypt with generated key and PKCS1v15:"
test "openssl rsautl -encrypt -inkey pubkey_rsa4096.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
test "$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
test "rm data.dec" "   Clean up"

echo "Decrypt with imported key and PKCS1v15:"
test "openssl rsautl -encrypt -inkey pubkey_rsa4096_imported.pem -pubin -in data.txt -out data.enc" "   Encryp with OpenSSL"
test "$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec" "   Decrypt with yubihsm-shell"
test "cmp data.txt data.dec" "   Compare decrypted data with plain text data"
test "rm data.dec" "   Clean up"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

cd ..
rm -rf yubihsm-shell_test_dir

set +e
set +x