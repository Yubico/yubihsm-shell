#!/bin/bash
set -u

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

EC_ALGOS=("ecp224" "ecp256" "ecp384" "ecp521" "eck256")
EC_CURVES=("secp224r1" "secp256r1" "secp384r1" "secp521r1" "secp256k1")

set +e
cat /etc/os-release | grep 'Fedora'
is_fedora=$?
set -e

echo "====================== EC keys ===================== "

if [ $is_fedora -ne 0 ]; then
  EC_ALGOS=(${EC_ALGOS[@]} "ecbp256" "ecbp384" "ecbp512")
  EC_CURVES=(${EC_CURVES[@]} "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")
fi

genkey=100
import_key=200

for i in "${!EC_ALGOS[@]}"; do

  algo=${EC_ALGOS[i]}
  curve=${EC_CURVES[i]}

  echo "**********************************"
  echo "            $algo"
  echo "**********************************"
  echo "=== Generate key"
  test_with_resp "$BIN -p password -a generate-asymmetric-key -i $genkey -l \"ecKey\" -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A $algo" "   Generate key"
  test "$BIN -p password -a get-object-info -i $genkey -t asymmetric-key" "   get-object-info"
  info=$($BIN -p password -a get-object-info -i $genkey -t asymmetric-key  2> /dev/null)
  test "echo $info | grep \"id: $genkey\"" "   Object info contains correct ID"
  test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
  test "echo $info | grep \"algorithm: $algo\"" "   Object info contains correct algorithm"
  test "echo $info | grep 'label: \"ecKey\"'" "   Object info contains correct label"
  test "echo $info | grep \"domains: 5:8:13\"" "   Object info contains correct domains"
  test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
  test "echo $info | grep \"capabilities: derive-ecdh:sign-attestation-certificate:sign-ecdsa\"" "   Object info contains correct capabilities"
  test "$BIN -p password -a get-public-key -i $genkey --outformat=PEM --out $algo-gen.pubkey" "   Get public key"

  echo "=== Import Key"
  test "openssl ecparam -genkey -name $curve -noout -out $curve-keypair.pem" "   Generate key with OpenSSL"
  test_with_resp "$BIN -p password -a put-asymmetric-key -i $import_key -l "ecKeyImport" -d "2,6,7" -c "sign-ecdsa,sign-attestation-certificate" --in=$curve-keypair.pem" "   Import key"
  test "$BIN -p password -a get-object-info -i $import_key -t asymmetric-key" "   get-object-info"
  info=$($BIN -p password -a get-object-info -i $import_key -t asymmetric-key 2> /dev/null)
  test "echo $info | grep \"id: $import_key\"" "   Object info contains correct ID"
  test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
  test "echo $info | grep \"algorithm: $algo\"" "   Object info contains correct algorithm"
  test "echo $info | grep 'label: \"ecKeyImport\"'" "   Object info contains correct label"
  test "echo $info | grep \"domains: 2:6:7\"" "   Object info contains correct domains"
  test "echo $info | grep \"origin: imported\"" "   Object info contains correct origin"
  test "echo $info | grep \"capabilities: sign-attestation-certificate:sign-ecdsa\"" "   Object info contains correct capabilities"
  test "$BIN -p password -a get-public-key -i $import_key --outformat=PEM --out $algo-import.pubkey" "   Get public key"

  echo "=== Signing"
  test "$BIN -p password -a sign-ecdsa -i $genkey -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.$algo-sha1gen.sig" "   Sign with generated key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify $algo-gen.pubkey -signature data.$algo-sha1gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $genkey -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.$algo-sha256gen.sig" "   Sign with generated key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify $algo-gen.pubkey -signature data.$algo-sha256gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $genkey -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.$algo-sha384gen.sig" "   Sign with generated key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify $algo-gen.pubkey -signature data.$algo-sha384gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $genkey -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.$algo-sha512gen.sig" "   Sign with generated key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify $algo-gen.pubkey -signature data.$algo-sha512gen.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_key -A ecdsa-sha1 --in data.txt --outformat=PEM --out data.$algo-sha1import.sig" "   Sign with imported key and ecdsa-sha1"
  test "openssl dgst -sha1 -verify $algo-import.pubkey -signature data.$algo-sha1import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_key -A ecdsa-sha256 --in data.txt --outformat=PEM --out data.$algo-sha256import.sig" "   Sign with imported key and ecdsa-sha256"
  test "openssl dgst -sha256 -verify $algo-import.pubkey -signature data.$algo-sha256import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_key -A ecdsa-sha384 --in data.txt --outformat=PEM --out data.$algo-sha384import.sig" "   Sign with imported key and ecdsa-sha384"
  test "openssl dgst -sha384 -verify $algo-import.pubkey -signature data.$algo-sha384import.sig data.txt" "   Verify signature with OpenSSL"
  test "$BIN -p password -a sign-ecdsa -i $import_key -A ecdsa-sha512 --in data.txt --outformat=PEM --out data.$algo-sha512import.sig" "   Sign with imported key and ecdsa-sha512"
  test "openssl dgst -sha512 -verify $algo-import.pubkey -signature data.$algo-sha512import.sig data.txt" "   Verify signature with OpenSSL"

  echo "=== Get attestation certificate and a selfsigned certificate"
  set +e
  $BIN -p password -a sign-attestation-certificate -i $genkey --attestation-id 0 2>&1 > /dev/null # Some YubiHSMs does not have default attestation certificate
  def_attestation=$?
  set -e
  if [ $def_attestation -eq 0 ]; then
    test "$BIN -p password -a sign-attestation-certificate -i $genkey --attestation-id 0 --out cert.pem" "   Sign attestation cert with default key"
    test "openssl x509 -in cert.pem -out cert.der -outform DER" "   Convert cert format"
    test "$BIN -p password -a put-opaque -i $genkey -l template_cert -A opaque-x509-certificate --in cert.der" "   Import attestation cert as template cert (same ID as generated key)"
    test "$BIN -p password -a put-opaque -i $import_key -l template_cert -A opaque-x509-certificate --in cert.der" "   Import attestation cert as template cert (same ID as imported key)"
    test "rm cert.der" "   Cleaning up"
  else
    test "$BIN -p password -a put-opaque -i $genkey -l template_cert_gen -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem" "   Import attestation cert as template cert (same ID as generated key)"
    test "$BIN -p password -a put-opaque -i $import_key -l template_cert_imp -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem" "   Import attestation cert as template cert (same ID as imported key)"
  fi
  test "$BIN -p password -a sign-attestation-certificate -i $genkey --attestation-id=$genkey --out selfsigned_cert.pem" "   Sign attestation with same key (aka. get selfsigned cert)"
  test "$BIN -p password -a delete-object -i $genkey -t opaque" "   Delete template cert"
  test "$BIN -p password -a put-opaque -i $genkey -l java_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem" "   Import selfsigned cert with same key ID"
  test "rm selfsigned_cert.pem" "   Cleaning up"
  #-- Sign attestation certificate
  test "$BIN -p password -a sign-attestation-certificate -i $genkey --attestation-id=$import_key --out selfsigned_cert.pem" "   Sign attestation cert with imported key"
  test "$BIN -p password -a delete-object -i $genkey -t opaque" "   Delete template cert"
  test "$BIN -p password -a delete-object -i $import_key -t opaque" "   Delete template cert"
  test "rm selfsigned_cert.pem" "   Cleaning up"

  echo "Derive ECDH:"
  test "openssl ec -in $curve-keypair.pem -pubout -out $curve-pubkey.pem" "   Get imported key public key with OpenSSL"
  test "$BIN -p password -a derive-ecdh -i $genkey --in $curve-pubkey.pem --outformat binary --out $algo-ecdh-shell.key" "   Derive ECDH using yubihsm-shell"
  test "openssl pkeyutl -derive -inkey $curve-keypair.pem -peerkey $algo-gen.pubkey -out $algo-ecdh-openssl.key" "   Derive ECDH using OpenSSL"
  test "cmp $algo-ecdh-openssl.key $algo-ecdh-shell.key" "   Compare ECDH value from yubihsm-shell and OpenSSL"

  echo "=== Clean up:"
  test "$BIN -p password -a delete-object -i $genkey -t asymmetric-key" "   Delete generated key"
  test "$BIN -p password -a delete-object -i $import_key -t asymmetric-key" "   Delete imported key"


done