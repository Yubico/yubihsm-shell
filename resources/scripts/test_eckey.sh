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
echo test signing data > data.txt
set -e
set -x

echo "---------------------- EC keys --------------------- "
# ECP224
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecp224" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: asymmetric-key"
echo $info | grep "algorithm: ecp224"
echo $info | grep 'label: "ecKey"'
echo $info | grep "domains: 5:8:13"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: derive-ecdh:sign-ecdsa"
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name secp224r1 -noout -out secp224r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "2,6,7" -c "sign-ecdsa" --in=secp224r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key)
echo $info | grep "id: $import_keyid"
echo $info | grep "type: asymmetric-key"
echo $info | grep "algorithm: ecp224"
echo $info | grep 'label: "ecKeyImport"'
echo $info | grep "domains: 2:6:7"
echo $info | grep "origin: imported"
echo $info | grep "capabilities: sign-ecdsa"
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp224sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp224sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp224sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp224sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp224sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp224sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp224sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp224sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in secp224r1-keypair.pem -pubout -out secp224r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in secp224r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key



# ECP256
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecp256" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name secp256r1 -noout -out secp256r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=secp256r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp256sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp256sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp256sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp256sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp256sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp256sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp256sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp256sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in secp256r1-keypair.pem -pubout -out secp256r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in secp256r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

# ECP384
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecp384" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name secp384r1 -noout -out secp384r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=secp384r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp384sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp384sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp384sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp384sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp384sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp384sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp384sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp384sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in secp384r1-keypair.pem -pubout -out secp384r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in secp384r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

# ECP512
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecp521" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name secp521r1 -noout -out secp521r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=secp521r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp521sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp521sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp521sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp521sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp521sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp521sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp521sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp521sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in secp521r1-keypair.pem -pubout -out secp521r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in secp521r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

# ECK256
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "eck256" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name secp256k1 -noout -out secp256k1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=secp256k1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.eck256sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.eck256sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.eck256sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.eck256sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.eck256sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.eck256sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.eck256sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.eck256sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in secp256k1-keypair.pem -pubout -out secp256k1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in secp256k1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

# Brainpool256
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecbp256" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name brainpoolP256r1 -noout -out brainpool256r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=brainpool256r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecbp256sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecbp256sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecbp256sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecbp256sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecbp256sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecbp256sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecbp256sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecbp256sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in brainpool256r1-keypair.pem -pubout -out brainpool256r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in brainpool256r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

# Brainpool384
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecbp384" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name brainpoolP384r1 -noout -out brainpool384r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=brainpool384r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecbp384sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecbp384sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecbp384sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecbp384sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecbp384sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecbp384sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecbp384sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecbp384sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in brainpool384r1-keypair.pem -pubout -out brainpool384r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in brainpool384r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

# Brainpool512
#-- Generate
$BIN -p password -a generate-asymmetric-key -i 0 -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh" -A "ecbp512" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $keyid --outformat=PEM
#-- Import
openssl ecparam -genkey -name brainpoolP512r1 -noout -out brainpool512r1-keypair.pem
$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa" --in=brainpool512r1-keypair.pem 2> resp.txt
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM
#-- Sign
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecbp512sha1.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecbp512sha256.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecbp512sha384.sig
$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecbp512sha512.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecbp512sha1.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecbp512sha256.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecbp512sha384.sig
$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecbp512sha512.sig
#-- Get attestation certificate and a selfsigned certificate
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.der
$BIN -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.der
$BIN -p password -a delete-object -i $keyid -t opaque
$BIN -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.der
#-- Sign attestation certificate
$BIN -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der
$BIN -p password -a sign-attestation-certificate -i $import_keyid --attestation-id=$keyid --out selfsigned_cert.der
#-- Derive ECDH
openssl ec -in brainpool512r1-keypair.pem -pubout -out brainpool512r1-pubkey.pem
$BIN -p password -a derive-ecdh -i $keyid --in brainpool512r1-pubkey.pem
#-- Delete
$BIN -p password -a delete-object -i $keyid -t asymmetric-key
$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key

set +e
set +x