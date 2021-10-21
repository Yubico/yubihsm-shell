#!/bin/bash

if [ "$#" -ne 1 ]; then
  BIN="yubihsm-shell"
else
  BIN=$1 # path to the yubico-piv-tool command line tool
fi
if [ -e yubihsm-shell_test_dir ];
then
    rm -rf yubihsm-shell_test_dir
fi
mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
echo test signing and decryption data > data.txt
set -e
set -x

echo "---------------------- RSA keys --------------------- "
echo "**********************************"
echo "            RSA2048"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-asymmetric-key -i 0 -l "rsaKey" -d "1" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" -A "rsa2048" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: asymmetric-key"
echo $info | grep "algorithm: rsa2048"
echo $info | grep 'label: "rsaKey"'
echo $info | grep "domains: 1"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"
echo "=== Get public key of generated key"
$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa2048.pem
echo "=== Import into YubiHSM"
openssl genrsa -out rsa2048-keypair.pem 2048
$BIN -p password -a put-asymmetric-key -i 0 -l "rsaKeyImport" -d "2" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" --in=rsa2048-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key)
echo $info | grep "id: $import_keyid"
echo $info | grep "type: asymmetric-key"
echo $info | grep "algorithm: rsa2048"
echo $info | grep 'label: "rsaKeyImport"'
echo $info | grep "domains: 2"
echo $info | grep "origin: imported"
echo $info | grep "capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"
echo "=== Get public key of imported key"
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa2048_imported.pem
echo "=== Signing with generated key and"
echo "===== rsa-pkcs1-sha1"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --out data.2048pkcs1sha1.sig
echo "===== rsa-pkcs1-sha256"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --out data.2048pkcs1sha256.sig
echo "===== rsa-pkcs1-sha384"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --out data.2048pkcs1sha384.sig
echo "===== rsa-pkcs1-sha512"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --out data.2048pkcs1sha512.sig
echo "===== rsa-pss-sha1"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.2048psssha1.sig
echo "===== rsa-pss-sha256"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.2048psssha256.sig
echo "===== rsa-pss-sha384"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.2048psssha384.sig
echo "===== rsa-pss-sha512"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.2048psssha512.sig
echo "=== Signing with imported key and"
echo "===== rsa-pkcs1-sha1"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --out data.2048pkcs1sha1.sig
echo "===== rsa-pkcs1-sha256"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --out data.2048pkcs1sha256.sig
echo "===== rsa-pkcs1-sha384"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --out data.2048pkcs1sha384.sig
echo "===== rsa-pkcs1-sha512"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --out data.2048pkcs1sha512.sig
echo "===== rsa-pss-sha1"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.2048psssha1.sig
echo "===== rsa-pss-sha256"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.2048psssha256.sig
echo "===== rsa-pss-sha384"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.2048psssha384.sig
echo "===== rsa-pss-sha512"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.2048psssha512.sig
#echo "=== Make self signed certificate"
#$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem
#openssl x509 -in cert.pem -out cert.der -outform DER
#$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
#$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem
#$BIN -p password -a delete-object -i $keyid -t opaque
#$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem
echo "=== Sign attestation certificate"
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der
rm cert.pem cert.der selfsigned_cert.pem
echo "=== Decrypt with generated key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey_rsa2048.pem -pubin -in data.txt -out data.enc
$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec
if [[ $(cat data.txt) != $(cat data.dec) ]]; then
  echo "Decrypt failed"
  exit 2
fi
rm data.dec
echo "=== Decrypt with imported key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey_rsa2048_imported.pem -pubin -in data.txt -out data.enc
$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec
if [[ $(cat data.txt) != $(cat data.dec) ]]; then
  echo "Decrypt failed"
  exit 2
fi
rm data.dec
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key


echo "**********************************"
echo "            RSA3072"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-asymmetric-key -i 0 -l "rsaKey" -d "1" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" -A "rsa3072" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key)
echo "=== Get public key of generated key"
$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa3072.pem
echo "=== Import into YubiHSM"
openssl genrsa -out rsa3072-keypair.pem 3072
$BIN -p password -a put-asymmetric-key -i 0 -l "rsaKeyImport" -d "2" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" --in=rsa3072-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key)
echo "=== Get public key of imported key"
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa3072_imported.pem
echo "=== Signing with generated key and"
echo "===== rsa-pkcs1-sha1"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --out data.3072pkcs1sha1.sig
echo "===== rsa-pkcs1-sha256"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --out data.3072pkcs1sha256.sig
echo "===== rsa-pkcs1-sha384"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --out data.3072pkcs1sha384.sig
echo "===== rsa-pkcs1-sha512"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --out data.3072pkcs1sha512.sig
echo "===== rsa-pss-sha1"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.3072psssha1.sig
echo "===== rsa-pss-sha256"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.3072psssha256.sig
echo "===== rsa-pss-sha384"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.3072psssha384.sig
echo "===== rsa-pss-sha512"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.3072psssha512.sig
echo "=== Signing with imported key and"
echo "===== rsa-pkcs1-sha1"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --out data.3072pkcs1sha1.sig
echo "===== rsa-pkcs1-sha256"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --out data.3072pkcs1sha256.sig
echo "===== rsa-pkcs1-sha384"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --out data.3072pkcs1sha384.sig
echo "===== rsa-pkcs1-sha512"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --out data.3072pkcs1sha512.sig
echo "===== rsa-pss-sha1"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.3072psssha1.sig
echo "===== rsa-pss-sha256"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.3072psssha256.sig
echo "===== rsa-pss-sha384"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.3072psssha384.sig
echo "===== rsa-pss-sha512"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.3072psssha512.sig
#echo "=== Make self signed certificate"
#$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem
#openssl x509 -in cert.pem -out cert.der -outform DER
#$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
#$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem
#$BIN -p password -a delete-object -i $keyid -t opaque
#$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem
echo "=== Sign attestation certificate"
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der
rm cert.pem cert.der selfsigned_cert.pem
echo "=== Decrypt with generated key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey_rsa3072.pem -pubin -in data.txt -out data.enc
$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec
if [[ $(cat data.txt) != $(cat data.dec) ]]; then
  echo "Decrypt failed"
  exit 2
fi
rm data.dec
echo "=== Decrypt with imported key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey_rsa3072_imported.pem -pubin -in data.txt -out data.enc
$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec
if [[ $(cat data.txt) != $(cat data.dec) ]]; then
  echo "Decrypt failed"
  exit 2
fi
rm data.dec
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key


# RSA 4096
echo "**********************************"
echo "            RSA4096"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-asymmetric-key -i 0 -l "rsaKey" -d "1" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" -A "rsa4096" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key)
echo "=== Get public key of generated key"
$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey_rsa4096.pem
echo "=== Import into YubiHSM"
openssl genrsa -out rsa4096-keypair.pem 4096
$BIN -p password -a put-asymmetric-key -i 0 -l "rsaKeyImport" -d "2" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" --in=rsa4096-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key)
echo "=== Get public key of imported key"
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_rsa4096_imported.pem
echo "=== Signing with generated key and"
echo "===== rsa-pkcs1-sha1"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --out data.4096pkcs1sha1.sig
echo "===== rsa-pkcs1-sha256"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --out data.4096pkcs1sha256.sig
echo "===== rsa-pkcs1-sha384"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --out data.4096pkcs1sha384.sig
echo "===== rsa-pkcs1-sha512"
$BIN -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --out data.4096pkcs1sha512.sig
echo "===== rsa-pss-sha1"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.4096psssha1.sig
echo "===== rsa-pss-sha256"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.4096psssha256.sig
echo "===== rsa-pss-sha384"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.4096psssha384.sig
echo "===== rsa-pss-sha512"
$BIN -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.4096psssha512.sig
echo "=== Signing with imported key and"
echo "===== rsa-pkcs1-sha1"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --out data.4096pkcs1sha1.sig
echo "===== rsa-pkcs1-sha256"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --out data.4096pkcs1sha256.sig
echo "===== rsa-pkcs1-sha384"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --out data.4096pkcs1sha384.sig
echo "===== rsa-pkcs1-sha512"
$BIN -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --out data.4096pkcs1sha512.sig
echo "===== rsa-pss-sha1"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.4096psssha1.sig
echo "===== rsa-pss-sha256"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.4096psssha256.sig
echo "===== rsa-pss-sha384"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.4096psssha384.sig
echo "===== rsa-pss-sha512"
$BIN -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.4096psssha512.sig
#echo "=== Make self signed certificate"
#$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem
#openssl x509 -in cert.pem -out cert.der -outform DER
#$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
#$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem
#$BIN -p password -a delete-object -i $keyid -t opaque
#$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem
echo "=== Sign attestation certificate"
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der
rm cert.pem cert.der selfsigned_cert.pem
echo "=== Decrypt with generated key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey_rsa4096.pem -pubin -in data.txt -out data.enc
$BIN -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec
if [[ $(cat data.txt) != $(cat data.dec) ]]; then
  echo "Decrypt failed"
  exit 2
fi
rm data.dec
echo "=== Decrypt with imported key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey_rsa4096_imported.pem -pubin -in data.txt -out data.enc
$BIN -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec
if [[ $(cat data.txt) != $(cat data.dec) ]]; then
  echo "Decrypt failed"
  exit 2
fi
rm data.dec
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

cd ..
rm -rf yubihsm-shell_test_dir

set +e
set +x