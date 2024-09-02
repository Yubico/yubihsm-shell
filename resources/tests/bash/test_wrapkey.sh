#!/bin/bash
set -u

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

cmp_str_content () {
  set +e
  if [[ $1 == *"$2"* ]]; then
    echo "   $3 in object info ... OK!"
  else
    echo "Wrong $3"
    echo $1
    exit 1
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

test "$BIN -p password -a reset" "   Reset device"
sleep 3

eckey=100
aeskey=200
test "$BIN -p password -a generate-asymmetric-key -i $eckey -l eckey -d 1 -c exportable-under-wrap,sign-ecdsa -A ecp224" "   Generate EC Key to wrap"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 0" "Sequence"
cmp_str_content "$info" "origin: generated" "Origin"

echo "**********************************"
echo "            aes128-ccm-wrap"
echo "**********************************"
echo "=== Generate key"
test_with_resp "$BIN -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A aes128-ccm-wrap" "   Generate wrap key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t wrap-key  2> /dev/null)
cmp_str_content "$info" "algorithm: aes128-ccm-wrap" "Algorithm"
cmp_str_content "$info" "length: 24" "Length"

echo "=== Import key"
test_with_resp "$BIN -p password -a get-pseudo-random --count 16" "   Get random 16 bytes"
wrapkey=$(tail -1 resp.txt | awk '{print $0}')
test_with_resp "$BIN -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in=$wrapkey" "   Import wrap key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t wrap-key  2> /dev/null)
cmp_str_content "$info" "algorithm: aes128-ccm-wrap" "Algorithm"
cmp_str_content "$info" "length: 24" "Length"
cmp_str_content "$info" "origin: imported" "Origin"

echo "=== Wrap and unwrap objects with generated wrap key"
test "$BIN -p password -a get-wrapped --wrap-id $keyid -i 100 -t asymmetric-key --out key.gen_wrapped" "   Wrap EC key"
test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a put-wrapped --wrap-id $keyid --in key.gen_wrapped" "   Wrap EC key"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 1" "Sequence"
cmp_str_content "$info" "origin: generated:imported_wrapped" "Origin"
cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped key"

echo "=== Wrap and unwrap objects with imported wrap key"
test "$BIN -p password -a get-wrapped --wrap-id $import_keyid -i 100 -t asymmetric-key --out key.imp_wrapped" "   Wrap EC key"
test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a put-wrapped --wrap-id $import_keyid --in key.imp_wrapped" "   Wrap EC key"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 2" "Sequence"
cmp_str_content "$info" "origin: generated:imported_wrapped" "Origin"
cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped key"

echo "=== Clean up"
test "$BIN -p password -a delete-object -i $keyid -t wrap-key" "   Delete generated wrap key"
test "$BIN -p password -a delete-object -i $import_keyid -t wrap-key" "   Delete imported wrap key"
rm key.gen_wrapped
rm key.imp_wrapped

echo "**********************************"
echo "            aes192-ccm-wrap"
echo "**********************************"
echo "=== Generate key"
test_with_resp "$BIN -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A aes192-ccm-wrap" "   Generate wrap key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t wrap-key  2> /dev/null)
cmp_str_content "$info" "algorithm: aes192-ccm-wrap" "Algorithm"
cmp_str_content "$info" "length: 32" "Length"

echo "=== Import key"
test_with_resp "$BIN -p password -a get-pseudo-random --count 24" "   Get random 16 bytes"
wrapkey=$(tail -1 resp.txt | awk '{print $0}')
test_with_resp "$BIN -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in=$wrapkey" "   Import wrap key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t wrap-key  2> /dev/null)
cmp_str_content "$info" "algorithm: aes192-ccm-wrap" "Algorithm"
cmp_str_content "$info" "length: 32" "Length"
cmp_str_content "$info" "origin: imported" "Origin"

echo "=== Wrap and unwrap objects with generated wrap key"
test "$BIN -p password -a get-wrapped --wrap-id $keyid -i 100 -t asymmetric-key --out key.gen_wrapped" "   Wrap EC key"
test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a put-wrapped --wrap-id $keyid --in key.gen_wrapped" "   Wrap EC key"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 3" "Sequence"
cmp_str_content "$info" "origin: generated:imported_wrapped" "Origin"
cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped key"

echo "=== Wrap and unwrap objects with imported wrap key"
test "$BIN -p password -a get-wrapped --wrap-id $import_keyid -i 100 -t asymmetric-key --out key.imp_wrapped" "   Wrap EC key"
test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a put-wrapped --wrap-id $import_keyid --in key.imp_wrapped" "   Wrap EC key"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 4" "Sequence"
cmp_str_content "$info" "origin: generated:imported_wrapped" "Origin"
cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped key"

echo "=== Clean up"
test "$BIN -p password -a delete-object -i $keyid -t wrap-key" "   Delete generated wrap key"
test "$BIN -p password -a delete-object -i $import_keyid -t wrap-key" "   Delete imported wrap key"
rm key.gen_wrapped
rm key.imp_wrapped

echo "**********************************"
echo "            aes256-ccm-wrap"
echo "**********************************"
echo "=== Generate key"
test_with_resp "$BIN -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A aes256-ccm-wrap" "   Generate wrap key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t wrap-key  2> /dev/null)
cmp_str_content "$info" "algorithm: aes256-ccm-wrap" "Algorithm"
cmp_str_content "$info" "length: 40" "Length"

echo "=== Import key"
test_with_resp "$BIN -p password -a get-pseudo-random --count 32" "   Get random 16 bytes"
wrapkey=$(tail -1 resp.txt | awk '{print $0}')
test_with_resp "$BIN -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in=$wrapkey" "   Import wrap key"
import_keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $import_keyid -t wrap-key  2> /dev/null)
cmp_str_content "$info" "algorithm: aes256-ccm-wrap" "Algorithm"
cmp_str_content "$info" "length: 40" "Length"
cmp_str_content "$info" "origin: imported" "Origin"

echo "=== Wrap and unwrap objects with generated wrap key"
test "$BIN -p password -a get-wrapped --wrap-id $keyid -i 100 -t asymmetric-key --out key.gen_wrapped" "   Wrap EC key"
test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a put-wrapped --wrap-id $keyid --in key.gen_wrapped" "   Wrap EC key"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 5" "Sequence"
cmp_str_content "$info" "origin: generated:imported_wrapped" "Origin"
cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped key"

echo "=== Wrap and unwrap objects with imported wrap key"
test "$BIN -p password -a get-wrapped --wrap-id $import_keyid -i 100 -t asymmetric-key --out key.imp_wrapped" "   Wrap EC key"
test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a put-wrapped --wrap-id $import_keyid --in key.imp_wrapped" "   Wrap EC key"
info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
cmp_str_content "$info" "sequence: 6" "Sequence"
cmp_str_content "$info" "origin: generated:imported_wrapped" "Origin"
cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped key"

echo "=== Clean up"
test "$BIN -p password -a delete-object -i $keyid -t wrap-key" "   Delete generated wrap key"
test "$BIN -p password -a delete-object -i $import_keyid -t wrap-key" "   Delete imported wrap key"
rm key.gen_wrapped
rm key.imp_wrapped



device_info=$($BIN -p password -a get-device-info 2> /dev/null)
if [[ "$device_info" != *"aes-kwp"* ]]; then
  test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
  exit 0
fi

aes_enabled=false
if [[ "$device_info" == *"aes-cbc"* ]]; then
  aes_enabled=true
  test "$BIN -p password -a generate-symmetric-key -i $aeskey -l aeskey -d 1 -c exportable-under-wrap,encrypt-cbc,decrypt-cbc -A aes128" "   Generate AES Key to wrap"
  test_with_resp "$BIN -p password -a get-pseudo-random --count 16" "   Get random 16 bytes for IV"
  iv=$(tail -1 resp.txt | awk '{print $0}')
  test_with_resp "$BIN -p password -a get-pseudo-random --count 32" "   Get random 32 bytes to test encryption"
  data=$(tail -1 resp.txt | awk '{print $0}')
fi

RSA_KEYSIZE=("2048" "3072" "4096")

seq_ec=6
seq_aes=0

for k in ${RSA_KEYSIZE[@]}; do

  echo "**********************************"
  echo "            RSA$k"
  echo "**********************************"
  echo "=== Generate RSA wrap keys"
  test_with_resp "$BIN -p password -a generate-wrap-key -i 0 -l wrapkey -c import-wrapped  --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc -A rsa$k" "   Generate RSA wrap key"
  keyid=$(tail -1 resp.txt | awk '{print $4}')
  info=$($BIN -p password -a get-object-info -i $keyid -t wrap-key  2> /dev/null)
  cmp_str_content "$info" "algorithm: rsa$k" "Algorithm"
  cmp_str_content "$info" "origin: generated" "Origin"
  test "$BIN -p password -a get-public-key -i $keyid -t wrap-key --out public_wrapkey.pem" "   Export rsa public wrap key"
  test "$BIN -p password -a put-public-wrapkey -i $keyid -c export-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in public_wrapkey.pem" "   Import RSA public wrap key"
  rm public_wrapkey.pem

  echo "=== Wrap and unwrap EC object with generated RSA wrap key"
  test "$BIN -p password -a get-rsa-wrapped --wrap-id $keyid -i $eckey -t asymmetric-key --out rsawrapped.object" "   Export wrapped EC object"
  test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
  test "$BIN -p password -a put-rsa-wrapped --wrap-id $keyid --in rsawrapped.object" "   Import wrapped EC object"
  info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
  seq_ec=$((seq_ec+1))
  cmp_str_content "$info" "sequence: $seq_ec" "Sequence"
  cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
  test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped EC key"
  rm rsawrapped.object

  echo "=== Wrap and unwrap EC key material with generated RSA wrap key"
  test "$BIN -p password -a get-rsa-wrapped-key --wrap-id $keyid -i $eckey -t asymmetric-key --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --out rsawrapped.key" "   Export wrapped EC key material"
  test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
  test "$BIN -p password -a put-rsa-wrapped-key --wrap-id $keyid -i $eckey -t asymmetric-key -A ecp224 -c exportable-under-wrap,sign-ecdsa --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --in rsawrapped.key" "   Import wrapped EC key material"
  info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
  seq_ec=$((seq_ec+1))
  cmp_str_content "$info" "sequence: $seq_ec" "Sequence"
  cmp_str_content "$info" "origin: imported:imported_wrapped" "Origin"
  cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
  test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped EC key"
  rm rsawrapped.key

  if [[ "$aes_enabled" = true ]]; then
    echo "=== Wrap and unwrap AES object with generated RSA wrap key"
    test "$BIN -p password -a get-rsa-wrapped --wrap-id $keyid -i $aeskey -t symmetric-key --out rsawrapped.object" "   Export wrapped AES object"
    test "$BIN -p password -a delete-object -i $aeskey -t symmetric-key" "   Delete AES key"
    test "$BIN -p password -a put-rsa-wrapped --wrap-id $keyid --in rsawrapped.object" "   Import wrapped AES object"
    info=$($BIN -p password -a get-object-info -i $aeskey -t symmetric-key  2> /dev/null)
    seq_aes=$((seq_aes+1))
    cmp_str_content "$info" "sequence: $seq_aes" "Sequence"
    cmp_str_content "$info" "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap" "Capabilities"
    test "$BIN -p password -a encrypt-aescbc -i $aeskey --iv $iv --in $data --out data.enc" "   Perform encryption with imported wrapped AES key"
    test_with_resp "$BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc" "   Perform decryption with imported wrapped AES key"
    data_dec=$(tail -1 resp.txt | awk '{print $0}')
    if [[ "$data" == "$data_dec" ]]; then
      echo "   Compare decrypted data to plain text ... OK!"
    else
      $BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc --out data.dec
      exit
    fi
    rm rsawrapped.object
    rm data.enc

    echo "=== Wrap and unwrap AES key material with generated RSA wrap key"
    test "$BIN -p password -a get-rsa-wrapped-key --wrap-id $keyid -i $aeskey -t symmetric-key --oaep rsa-oaep-sha384 --mgf1 mgf1-sha1 --out rsawrapped.key" "   Export wrapped AES key material"
    test "$BIN -p password -a delete-object -i $aeskey -t symmetric-key" "   Delete AES key"
    test "$BIN -p password -a put-rsa-wrapped-key --wrap-id $keyid -i $aeskey -t symmetric-key -A aes128 -c exportable-under-wrap,decrypt-cbc,encrypt-cbc --oaep rsa-oaep-sha384 --mgf1 mgf1-sha1 --in rsawrapped.key" "   Import wrapped AES key material"
    info=$($BIN -p password -a get-object-info -i $aeskey -t symmetric-key  2> /dev/null)
    seq_aes=$((seq_aes+1))
    cmp_str_content "$info" "sequence: $seq_aes" "Sequence"
    cmp_str_content "$info" "origin: imported:imported_wrapped" "Origin"
    cmp_str_content "$info" "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap" "Capabilities"
    test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped EC key"
    test "$BIN -p password -a encrypt-aescbc -i $aeskey --iv $iv --in $data --out data.enc" "   Perform encryption with imported wrapped AES key"
    test_with_resp "$BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc" "   Perform decryption with imported wrapped AES key"
    data_dec=$(tail -1 resp.txt | awk '{print $0}')
    if [[ "$data" == "$data_dec" ]]; then
      echo "   Compare decrypted data to plain text ... OK!"
    else
      $BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc --out data.dec
      exit
    fi
    rm rsawrapped.key
    rm data.enc
  fi

  echo "=== Import RSA wrap keys"
  test "openssl genrsa -out keypair.pem $k" "   Generate RSA key with OpenSSL"
  test "openssl rsa -in keypair.pem -pubout -out key.pub" "   Extract public key from OpenSSL generated keypair"
  test_with_resp "$BIN -p password -a put-rsa-wrapkey -i 0 -d 1 -c import-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in keypair.pem" "   Import RSA wrap key"
  import_keyid=$(tail -1 resp.txt | awk '{print $4}')
  info=$($BIN -p password -a get-object-info -i $import_keyid -t wrap-key  2> /dev/null)
  cmp_str_content "$info" "algorithm: rsa$k" "Algorithm"
  cmp_str_content "$info" "origin: imported" "Origin"
  test "$BIN -p password -a put-public-wrapkey -i $import_keyid -c export-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in key.pub" "   Import RSA public wrap key"
  rm keypair.pem
  rm key.pub

  echo "=== Wrap and unwrap EC object with imported RSA wrap key"
  test "$BIN -p password -a get-rsa-wrapped --wrap-id $import_keyid -i $eckey -t asymmetric-key --out rsawrapped.object" "   Export wrapped EC object"
  test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
  test "$BIN -p password -a put-rsa-wrapped --wrap-id $import_keyid --in rsawrapped.object" "   Import wrapped EC object"
  info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
  seq_ec=$((seq_ec+1))
  cmp_str_content "$info" "sequence: $seq_ec" "Sequence"
  cmp_str_content "$info" "origin: imported:imported_wrapped" "Origin"
  cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
  test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped EC key"
  rm rsawrapped.object

  echo "=== Wrap and unwrap EC key material with imported RSA wrap key"
  test "$BIN -p password -a get-rsa-wrapped-key --wrap-id $import_keyid -i $eckey -t asymmetric-key --oaep rsa-oaep-sha512 --mgf1 mgf1-sha512 --out rsawrapped.key" "   Export wrapped EC key material"
  test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
  test "$BIN -p password -a put-rsa-wrapped-key --wrap-id $import_keyid -i $eckey -t asymmetric-key -A ecp224 -c exportable-under-wrap,sign-ecdsa --oaep rsa-oaep-sha512 --mgf1 mgf1-sha512 --in rsawrapped.key" "   Import wrapped EC key material"
  info=$($BIN -p password -a get-object-info -i $eckey -t asymmetric-key  2> /dev/null)
  seq_ec=$((seq_ec+1))
  cmp_str_content "$info" "sequence: $seq_ec" "Sequence"
  cmp_str_content "$info" "origin: imported:imported_wrapped" "Origin"
  cmp_str_content "$info" "capabilities: exportable-under-wrap:sign-ecdsa" "Capabilities"
  test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped EC key"
  rm rsawrapped.key

  if [[ "$aes_enabled" = true ]]; then
    echo "=== Wrap and unwrap AES object with imported RSA wrap key"
    test "$BIN -p password -a get-rsa-wrapped --wrap-id $import_keyid -i $aeskey -t symmetric-key --out rsawrapped.object" "   Export wrapped AES object"
    test "$BIN -p password -a delete-object -i $aeskey -t symmetric-key" "   Delete AES key"
    test "$BIN -p password -a put-rsa-wrapped --wrap-id $import_keyid --in rsawrapped.object" "   Import wrapped AES object"
    info=$($BIN -p password -a get-object-info -i $aeskey -t symmetric-key  2> /dev/null)
    seq_aes=$((seq_aes+1))
    cmp_str_content "$info" "sequence: $seq_aes" "Sequence"
    cmp_str_content "$info" "origin: imported:imported_wrapped" "Origin"
    cmp_str_content "$info" "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap" "Capabilities"
    test "$BIN -p password -a encrypt-aescbc -i $aeskey --iv $iv --in $data --out data.enc" "   Perform encryption with imported wrapped AES key"
    test_with_resp "$BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc" "   Perform decryption with imported wrapped AES key"
    data_dec=$(tail -1 resp.txt | awk '{print $0}')
    if [[ "$data" == "$data_dec" ]]; then
      echo "   Compare decrypted data to plain text ... OK!"
    else
      $BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc --out data.dec
      exit
    fi
    rm rsawrapped.object
    rm data.enc

    echo "=== Wrap and unwrap AES key material with imported RSA wrap key"
    test "$BIN -p password -a get-rsa-wrapped-key --wrap-id $import_keyid -i $aeskey -t symmetric-key --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --out rsawrapped.key" "   Export wrapped AES key material"
    test "$BIN -p password -a delete-object -i $aeskey -t symmetric-key" "   Delete AES key"
    test "$BIN -p password -a put-rsa-wrapped-key --wrap-id $import_keyid -i $aeskey -t symmetric-key -A aes128 -c exportable-under-wrap,decrypt-cbc,encrypt-cbc --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --in rsawrapped.key" "   Import wrapped AES key material"
    info=$($BIN -p password -a get-object-info -i $aeskey -t symmetric-key  2> /dev/null)
    seq_aes=$((seq_aes+1))
    cmp_str_content "$info" "sequence: $seq_aes" "Sequence"
    cmp_str_content "$info" "origin: imported:imported_wrapped" "Origin"
    cmp_str_content "$info" "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap" "Capabilities"
    test "$BIN -p password -a sign-ecdsa -i $eckey -A ecdsa-sha1 --in data.txt" "   Perform signature with imported wrapped EC key"
    test "$BIN -p password -a encrypt-aescbc -i $aeskey --iv $iv --in $data --out data.enc" "   Perform encryption with imported wrapped AES key"
    test_with_resp "$BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc" "   Perform decryption with imported wrapped AES key"
    data_dec=$(tail -1 resp.txt | awk '{print $0}')
    if [[ "$data" == "$data_dec" ]]; then
      echo "   Compare decrypted data to plain text ... OK!"
    else
      $BIN -p password -a decrypt-aescbc -i $aeskey --iv $iv --in data.enc --out data.dec
      exit
    fi
    rm rsawrapped.key
    rm data.enc
  fi

  echo "=== Clean up"
  test "$BIN -p password -a delete-object -i $keyid -t wrap-key" "   Delete generated RSA wrap key"
  test "$BIN -p password -a delete-object -i $keyid -t public-wrap-key" "   Delete generated RSA public wrap key"
  test "$BIN -p password -a delete-object -i $import_keyid -t wrap-key" "   Delete imported RSA wrap key"
  test "$BIN -p password -a delete-object -i $import_keyid -t public-wrap-key" "   Delete imported RSA public wrap key"
done

#test "$BIN -p password -a delete-object -i $eckey -t asymmetric-key" "   Delete EC key"
#if [[ "$aes_enabled" = true ]]; then
#  test "$BIN -p password -a delete-object -i $aeskey -t symmetric-key" "   Delete AES key"
#fi
test "$BIN -p password -a reset" "   Reset device"

cd ..
rm -rf yubihsm-shell_test_dir

set +e
