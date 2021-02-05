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


echo "---------------------- HAMC keys --------------------- "
echo "**********************************"
echo "            AEAD Key 128"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-otp-aead-key -i 0 -l "aeadkey" -d "1,2,3" -c "randomize-otp-aead" -A "aes128-yubico-otp" --nonce 0x01020304 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $5}')
info=$($BIN -p password -a get-object-info -i $keyid -t otp-aead-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: otp-aead-key"
echo $info | grep "algorithm: aes128-yubico-otp"
echo $info | grep 'label: "aeadkey"'
echo $info | grep "domains: 1:2:3"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: randomize-otp-aead"
echo "=== Randomize OTP AEAD"
$BIN -p password -a randomize-otp-aead -i $keyid
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t otp-aead-key

echo "**********************************"
echo "            AEAD Key 192"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-otp-aead-key -i 0 -l "aeadkey" -d "1,2,3" -c "randomize-otp-aead" -A "aes192-yubico-otp" --nonce 0x01020304 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $5}')
info=$($BIN -p password -a get-object-info -i $keyid -t otp-aead-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: otp-aead-key"
echo $info | grep "algorithm: aes192-yubico-otp"
echo $info | grep 'label: "aeadkey"'
echo $info | grep "domains: 1:2:3"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: randomize-otp-aead"
echo "=== Randomize OTP AEAD"
$BIN -p password -a randomize-otp-aead -i $keyid
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t otp-aead-key

echo "**********************************"
echo "            AEAD Key 256"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-otp-aead-key -i 0 -l "aeadkey" -d "1,2,3" -c "randomize-otp-aead" -A "aes256-yubico-otp" --nonce 0x01020304 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $5}')
info=$($BIN -p password -a get-object-info -i $keyid -t otp-aead-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: otp-aead-key"
echo $info | grep "algorithm: aes256-yubico-otp"
echo $info | grep 'label: "aeadkey"'
echo $info | grep "domains: 1:2:3"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: randomize-otp-aead"
echo "=== Randomize OTP AEAD"
#$BIN -p password -a randomize-otp-aead -i $keyid
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t otp-aead-key

set +e
