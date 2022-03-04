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
echo test signing data > data.txt

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

echo "====================== EC keys ===================== "
set +e
cat /etc/os-release | grep 'CentOS Linux 7'
ret=$?
set -e
if [ $ret -ne 0 ]; then
  echo "------------- ECP224"
  echo "Generate key:"
  test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l \"ecKey\" -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp224" "   Generate key"
  keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-object-info -i $keyid -t asymmetric-key" "   get-object-info"
  info=$($BIN -p password -a get-object-info -i $keyid -t asymmetric-key  2> /dev/null)
  test "echo $info | grep \"id: $keyid\"" "   Object info contains correct ID"
  test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
  test "echo $info | grep \"algorithm: ecp224\"" "   Object info contains correct algorithm"
  test "echo $info | grep 'label: \"ecKey\"'" "   Object info contains correct label"
  test "echo $info | grep \"domains: 5:8:13\"" "   Object info contains correct domains"
  test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
  test "echo $info | grep \"capabilities: derive-ecdh:sign-attestation-certificate:sign-ecdsa\"" "   Object info contains correct capabilities"
  test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out ecp224-gen.pubkey" "   Get public key"

  echo "Import Key:"
  test "openssl ecparam -genkey -name secp224r1 -noout -out secp224r1-keypair.pem" "   Generate key with OpenSSL"
  test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "2,6,7" -c "sign-ecdsa,sign-attestation-certificate" --in=secp224r1-keypair.pem" "   Import key"
  import_keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key" "   get-object-info"
  info=$($BIN -p password -a get-object-info -i $import_keyid -t asymmetric-key 2> /dev/null)
  test "echo $info | grep \"id: $import_keyid\"" "   Object info contains correct ID"
  test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
  test "echo $info | grep \"algorithm: ecp224\"" "   Object info contains correct algorithm"
  test "echo $info | grep 'label: \"ecKeyImport\"'" "   Object info contains correct label"
  test "echo $info | grep \"domains: 2:6:7\"" "   Object info contains correct domains"
  test "echo $info | grep \"origin: imported\"" "   Object info contains correct origin"
  test "echo $info | grep \"capabilities: sign-attestation-certificate:sign-ecdsa\"" "   Object info contains correct capabilities"
  test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out ecp224-import.pubkey" "   Get public key"

  echo "Signing:"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp224sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify ecp224-gen.pubkey -signature data.ecp224sha1gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp224sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify ecp224-gen.pubkey -signature data.ecp224sha256gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp224sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify ecp224-gen.pubkey -signature data.ecp224sha384gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp224sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify ecp224-gen.pubkey -signature data.ecp224sha512gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp224sha1import.sig" "   Sign with imported key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify ecp224-import.pubkey -signature data.ecp224sha1import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp224sha256import.sig" "   Sign with imported key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify ecp224-import.pubkey -signature data.ecp224sha256import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp224sha384import.sig" "   Sign with imported key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify ecp224-import.pubkey -signature data.ecp224sha384import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp224sha512import.sig" "   Sign with imported key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify ecp224-import.pubkey -signature data.ecp224sha512import.sig data.txt" "   Verify signature with OpenSSL"

  echo "Get attestation certificate and a selfsigned certificate:    keyid $keyid    import_keyid $import_keyid"
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

  echo "Derive ECDH:"
  test "openssl ec -in secp224r1-keypair.pem -pubout -out secp224r1-pubkey.pem" "   Get imported key public key with OpenSSL"
  test "$BIN -p password -a derive-ecdh -i $keyid --in secp224r1-pubkey.pem --outformat binary --out secp224ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
  test "openssl pkeyutl -derive -inkey secp224r1-keypair.pem -peerkey ecp224-gen.pubkey -out secp224ecdh-openssl.key" "   Derive ECDH using OpenSSL"
  test "cmp secp224ecdh-openssl.key secp224ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

  echo "Clean up:"
  test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
  test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"
fi

echo "------------- ECP256"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp256" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out ecp256-gen.pubkey" "   Get public key"

echo "Import key:"
test "openssl ecparam -genkey -name secp256r1 -noout -out secp256r1-keypair.pem" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp256r1-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out ecp256-import.pubkey" "   Get public key"

echo "Signing:"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp256sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
test "openssl dgst -sha1 -verify ecp256-gen.pubkey -signature data.ecp256sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp256sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
test "openssl dgst -sha256 -verify ecp256-gen.pubkey -signature data.ecp256sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp256sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
test "openssl dgst -sha384 -verify ecp256-gen.pubkey -signature data.ecp256sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp256sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
test "openssl dgst -sha512 -verify ecp256-gen.pubkey -signature data.ecp256sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp256sha1import.sig" "   Sign with imported key and ecdsa-sha1"
test "openssl dgst -sha1 -verify ecp256-import.pubkey -signature data.ecp256sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp256sha256import.sig" "   Sign with imported key and ecdsa-sha256"
test "openssl dgst -sha256 -verify ecp256-import.pubkey -signature data.ecp256sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp256sha384import.sig" "   Sign with imported key and ecdsa-sha384"
test "openssl dgst -sha384 -verify ecp256-import.pubkey -signature data.ecp256sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp256sha512import.sig" "   Sign with imported key and ecdsa-sha512"
test "openssl dgst -sha512 -verify ecp256-import.pubkey -signature data.ecp256sha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Get attestation certificate and a selfsigned certificate:"
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

echo "Derive ECDH:"
test "openssl ec -in secp256r1-keypair.pem -pubout -out secp256r1-pubkey.pem" "   Get imported key public key with OpenSSL"
test "$BIN -p password -a derive-ecdh -i $keyid --in secp256r1-pubkey.pem --outformat binary --out secp256ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
test "openssl pkeyutl -derive -inkey secp256r1-keypair.pem -peerkey ecp256-gen.pubkey -out secp256ecdh-openssl.key" "   Derive ECDH using OpenSSL"
test "cmp secp256ecdh-openssl.key secp256ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

echo "------------- ECP384"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp384" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out ecp384-gen.pubkey" "   Get public key"

echo "Import key:"
test "openssl ecparam -genkey -name secp384r1 -noout -out secp384r1-keypair.pem" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp384r1-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out ecp384-import.pubkey" "   Get public key"

echo "Signing:"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp384sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
test "openssl dgst -sha1 -verify ecp384-gen.pubkey -signature data.ecp384sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp384sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
test "openssl dgst -sha256 -verify ecp384-gen.pubkey -signature data.ecp384sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp384sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
test "openssl dgst -sha384 -verify ecp384-gen.pubkey -signature data.ecp384sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp384sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
test "openssl dgst -sha512 -verify ecp384-gen.pubkey -signature data.ecp384sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp384sha1import.sig" "   Sign with imported key and ecdsa-sha1"
test "openssl dgst -sha1 -verify ecp384-import.pubkey -signature data.ecp384sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp384sha256import.sig" "   Sign with imported key and ecdsa-sha256"
test "openssl dgst -sha256 -verify ecp384-import.pubkey -signature data.ecp384sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp384sha384import.sig" "   Sign with imported key and ecdsa-sha384"
test "openssl dgst -sha384 -verify ecp384-import.pubkey -signature data.ecp384sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp384sha512import.sig" "   Sign with imported key and ecdsa-sha512"
test "openssl dgst -sha512 -verify ecp384-import.pubkey -signature data.ecp384sha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Get attestation certificate and a selfsigned certificate:"
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

echo "Derive ECDH:"
test "openssl ec -in secp384r1-keypair.pem -pubout -out secp384r1-pubkey.pem" "   Get imported key public key with OpenSSL"
test "$BIN -p password -a derive-ecdh -i $keyid --in secp384r1-pubkey.pem --outformat binary --out secp384ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
test "openssl pkeyutl -derive -inkey secp384r1-keypair.pem -peerkey ecp384-gen.pubkey -out secp384ecdh-openssl.key" "   Derive ECDH using OpenSSL"
test "cmp secp384ecdh-openssl.key secp384ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

echo "------------- ECP521"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp521" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out ecp521-gen.pubkey" "   Get public key"

echo "Import key:"
test "openssl ecparam -genkey -name secp521r1 -noout -out secp521r1-keypair.pem" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp521r1-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out ecp521-import.pubkey" "   Get public key"

echo "Signing:"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out  data.ecp521sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
test "openssl dgst -sha1 -verify ecp521-gen.pubkey -signature data.ecp521sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp521sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
test "openssl dgst -sha256 -verify ecp521-gen.pubkey -signature data.ecp521sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp521sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
test "openssl dgst -sha384 -verify ecp521-gen.pubkey -signature data.ecp521sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp521sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
test "openssl dgst -sha512 -verify ecp521-gen.pubkey -signature data.ecp521sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.ecp521sha1import.sig" "   Sign with imported key and ecdsa-sha1"
test "openssl dgst -sha1 -verify ecp521-import.pubkey -signature data.ecp521sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.ecp521sha256import.sig" "   Sign with imported key and ecdsa-sha256"
test "openssl dgst -sha256 -verify ecp521-import.pubkey -signature data.ecp521sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.ecp521sha384import.sig" "   Sign with imported key and ecdsa-sha384"
test "openssl dgst -sha384 -verify ecp521-import.pubkey -signature data.ecp521sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.ecp521sha512import.sig" "   Sign with imported key and ecdsa-sha512"
test "openssl dgst -sha512 -verify ecp521-import.pubkey -signature data.ecp521sha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Get attestation certificate and a selfsigned certificate:"
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

echo "Derive ECDH:"
test "openssl ec -in secp521r1-keypair.pem -pubout -out secp521r1-pubkey.pem" "   Get imported key public key with OpenSSL"
test "$BIN -p password -a derive-ecdh -i $keyid --in secp521r1-pubkey.pem --outformat binary --out secp521ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
test "openssl pkeyutl -derive -inkey secp521r1-keypair.pem -peerkey ecp521-gen.pubkey -out secp521ecdh-openssl.key" "   Derive ECDH using OpenSSL"
test "cmp secp521ecdh-openssl.key secp521ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

echo "------------- ECK256"
echo "Generate key:"
test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A eck256" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out eck256-gen.pubkey" "   Get public key"

echo "Import key:"
test "openssl ecparam -genkey -name secp256k1 -noout -out secp256k1-keypair.pem" "   Generate key with OpenSSL"
test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp256k1-keypair.pem" "   Import key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out eck256-import.pubkey" "   Get public key"

echo "Signin:"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.eck256sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
test "openssl dgst -sha1 -verify eck256-gen.pubkey -signature data.eck256sha1gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.eck256sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
test "openssl dgst -sha256 -verify eck256-gen.pubkey -signature data.eck256sha256gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.eck256sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
test "openssl dgst -sha384 -verify eck256-gen.pubkey -signature data.eck256sha384gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.eck256sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
test "openssl dgst -sha512 -verify eck256-gen.pubkey -signature data.eck256sha512gen.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.eck256sha1import.sig" "   Sign with imported key and ecdsa-sha1"
test "openssl dgst -sha1 -verify eck256-import.pubkey -signature data.eck256sha1import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.eck256sha256import.sig" "   Sign with imported key and ecdsa-sha256"
test "openssl dgst -sha256 -verify eck256-import.pubkey -signature data.eck256sha256import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.eck256sha384import.sig" "   Sign with imported key and ecdsa-sha384"
test "openssl dgst -sha384 -verify eck256-import.pubkey -signature data.eck256sha384import.sig data.txt" "   Verify signature with OpenSSL"
test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.eck256sha512import.sig" "   Sign with imported key and ecdsa-sha512"
test "openssl dgst -sha512 -verify eck256-import.pubkey -signature data.eck256sha512import.sig data.txt" "   Verify signature with OpenSSL"

echo "Get attestation certificate and a selfsigned certificate:"
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

echo "Derive ECDH:"
test "openssl ec -in secp256k1-keypair.pem -pubout -out secp256k1-pubkey.pem" "   Get imported key public key with OpenSSL"
test "$BIN -p password -a derive-ecdh -i $keyid --in secp256k1-pubkey.pem --outformat binary --out eck256ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
test "openssl pkeyutl -derive -inkey secp256k1-keypair.pem -peerkey eck256-gen.pubkey -out eck256ecdh-openssl.key" "   Derive ECDH using OpenSSL"
test "cmp eck256ecdh-openssl.key eck256ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

echo "Clean up:"
test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

set +e
cat /etc/os-release | grep 'Fedora'
is_fedora=$?
cat /etc/os-release | grep 'CentOS Linux 7'
is_centos7=$?
set -e
if [ $is_fedora -ne 0 ] && [ $is_centos -ne 0 ]; then
  echo "------------- Brainpool256"
  echo "Generate key:"
  test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecbp256" "   Generate key"
  keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out bp256-gen.pubkey" "   Get public key"

  echo "Import key:"
  test "openssl ecparam -genkey -name brainpoolP256r1 -noout -out bp256r1-keypair.pem" "   Generate key with OpenSSL"
  test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=bp256r1-keypair.pem" "   Import key"
  import_keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out bp256-import.pubkey" "   Get public key"

  echo "Signing:"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.bp256sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify bp256-gen.pubkey -signature data.bp256sha1gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.bp256sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify bp256-gen.pubkey -signature data.bp256sha256gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.bp256sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify bp256-gen.pubkey -signature data.bp256sha384gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.bp256sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify bp256-gen.pubkey -signature data.bp256sha512gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.bp256sha1import.sig" "   Sign with imported key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify bp256-import.pubkey -signature data.bp256sha1import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.bp256sha256import.sig" "   Sign with imported key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify bp256-import.pubkey -signature data.bp256sha256import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.bp256sha384import.sig" "   Sign with imported key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify bp256-import.pubkey -signature data.bp256sha384import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.bp256sha512import.sig" "   Sign with imported key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify bp256-import.pubkey -signature data.bp256sha512import.sig data.txt" "   Verify signature with OpenSSL"

  echo "Get attestation certificate and a selfsigned certificate:"
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

  echo "Derive ECDH:"
  test "openssl ec -in bp256r1-keypair.pem -pubout -out bp256r1-pubkey.pem" "   Get imported key public key with OpenSSL"
  test "$BIN -p password -a derive-ecdh -i $keyid --in bp256r1-pubkey.pem --outformat binary --out bp256ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
  test "openssl pkeyutl -derive -inkey bp256r1-keypair.pem -peerkey bp256-gen.pubkey -out bp256ecdh-openssl.key" "   Derive ECDH using OpenSSL"
  test "cmp bp256ecdh-openssl.key bp256ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

  echo "Clean up:"
  test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
  test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

  echo "------------- Brainpool384"
  echo "Generate key:"
  test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecbp384" "   Generate key"
  keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out bp384-gen.pubkey" "   Get public key"

  echo "Import key:"
  test "openssl ecparam -genkey -name brainpoolP384r1 -noout -out bp384r1-keypair.pem" "   Generate key with OpenSSL"
  test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l ecKeyImport -d 1,2,3,4,5 -c sign-ecdsa,sign-attestation-certificate --in=bp384r1-keypair.pem" "   Import key"
  import_keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out bp384-import.pubkey" "   Get public key"

  echo "Signing:"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.bp384sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify bp384-gen.pubkey -signature data.bp384sha1gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.bp384sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify bp384-gen.pubkey -signature data.bp384sha256gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.bp384sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify bp384-gen.pubkey -signature data.bp384sha384gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.bp384sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify bp384-gen.pubkey -signature data.bp384sha512gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.bp384sha1import.sig" "   Sign with imported key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify bp384-import.pubkey -signature data.bp384sha1import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.bp384sha256import.sig" "   Sign with imported key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify bp384-import.pubkey -signature data.bp384sha256import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.bp384sha384import.sig" "   Sign with imported key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify bp384-import.pubkey -signature data.bp384sha384import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.bp384sha512import.sig" "   Sign with imported key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify bp384-import.pubkey -signature data.bp384sha512import.sig data.txt" "   Verify signature with OpenSSL"

  echo "Get attestation certificate and a selfsigned certificate:"
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

  test "$BIN -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der" "   Sign attestation cert with imported key"
  test "rm selfsigned_cert.der" "   Cleaning up"

  echo "Derive ECDH:"
  test "openssl ec -in bp384r1-keypair.pem -pubout -out bp384r1-pubkey.pem" "   Get imported key public key with OpenSSL"
  test "$BIN -p password -a derive-ecdh -i $keyid --in bp384r1-pubkey.pem --outformat binary --out bp384ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
  test "openssl pkeyutl -derive -inkey bp384r1-keypair.pem -peerkey bp384-gen.pubkey -out bp384ecdh-openssl.key" "   Derive ECDH using OpenSSL"
  test "cmp bp384ecdh-openssl.key bp384ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

  echo "Clean up:"
  test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
  test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"

  echo "------------- Brainpool512"
  echo "Generate key:"
  test_with_resp "$BIN -p password -a generate-asymmetric-key -i 0 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecbp512" "   Generate key"
  keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-public-key -i $keyid --outformat=PEM --out bp512-gen.pubkey" "   Get public key"

  echo "Import key:"
  test "openssl ecparam -genkey -name brainpoolP512r1 -noout -out bp512r1-keypair.pem" "   Generate key with OpenSSL"
  test_with_resp "$BIN -p password -a put-asymmetric-key -i 0 -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=bp512r1-keypair.pem" "   Import key"
  import_keyid=$(tail -1 resp.txt | awk '{print $4}')
  test "$BIN -p password -a get-public-key -i $import_keyid --outformat=PEM --out bp512-import.pubkey" "   Get public key"

  echo "Signing:"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.bp512sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify bp512-gen.pubkey -signature data.bp512sha1gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.bp512sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify bp512-gen.pubkey -signature data.bp512sha256gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.bp512sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify bp512-gen.pubkey -signature data.bp512sha384gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.bp512sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify bp512-gen.pubkey -signature data.bp512sha512gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.bp512sha1import.sig" "   Sign with imported key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify bp512-import.pubkey -signature data.bp512sha1import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.bp512sha256import.sig" "   Sign with imported key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify bp512-import.pubkey -signature data.bp512sha256import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.bp512sha384import.sig" "   Sign with imported key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify bp512-import.pubkey -signature data.bp512sha384import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.bp512sha512import.sig" "   Sign with imported key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify bp512-import.pubkey -signature data.bp512sha512import.sig data.txt" "   Verify signature with OpenSSL"

  echo "Get attestation certificate and a selfsigned certificate:"
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

  echo "Derive ECDH:"
  test "openssl ec -in bp512r1-keypair.pem -pubout -out bp512r1-pubkey.pem" "   Get imported key public key with OpenSSL"
  test "$BIN -p password -a derive-ecdh -i $keyid --in bp512r1-pubkey.pem --outformat binary --out bp512ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
  test "openssl pkeyutl -derive -inkey bp512r1-keypair.pem -peerkey bp512-gen.pubkey -out bp512ecdh-openssl.key" "   Derive ECDH using OpenSSL"
  test "cmp bp512ecdh-openssl.key bp512ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

  echo "Clean up:"
  test "$BIN -p password -a delete-object -i $keyid -t asymmetric-key" "   Delete generated key"
  test "$BIN -p password -a delete-object -i $import_keyid -t asymmetric-key" "   Delete imported key"
fi

cd ..
rm -rf yubihsm-shell_test_dir

set +e