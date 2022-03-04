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


echo "====================== AEAD keys ===================== "
echo "------------- AEAD Key 128"
test_with_resp "$BIN -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A aes128-yubico-otp --nonce 0x01020304" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $5}')
test "$BIN -p password -a get-object-info -i $keyid -t otp-aead-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t otp-aead-key 2> /dev/null)
test "echo $info | grep \"id: $keyid\"" "   Object info contains correct ID"
test "echo $info | grep \"type: otp-aead-key\"" "   Object info contains correct type"
test "echo $info | grep \"algorithm: aes128-yubico-otp\"" "   Object info contains correct algorithm"
test "echo $info | grep 'label: \"aeadkey\"'" "   Object info contains correct label"
test "echo $info | grep \"domains: 1:2:3\"" "   Object info contains correct domains"
test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
test "echo $info | grep \"capabilities: randomize-otp-aead\"" "   Object info contains correct capabilities"
test "$BIN -p password -a randomize-otp-aead -i $keyid" "   Randomize OTP AEAD"
test "$BIN -p password -a delete-object -i $keyid -t otp-aead-key" "   Delete key"

echo "------------- AEAD Key 128"
test_with_resp "$BIN -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A aes192-yubico-otp --nonce 0x01020304" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $5}')
test "$BIN -p password -a get-object-info -i $keyid -t otp-aead-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t otp-aead-key 2> /dev/null)
test "echo $info | grep \"algorithm: aes192-yubico-otp\"" "   Object info contains correct algorithm"
test "$BIN -p password -a randomize-otp-aead -i $keyid" "   Randomize OTP AEAD"
test "$BIN -p password -a delete-object -i $keyid -t otp-aead-key" "   Delete key"

echo "------------- AEAD Key 256"
test_with_resp "$BIN -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A aes256-yubico-otp --nonce 0x01020304" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $5}')
test "$BIN -p password -a get-object-info -i $keyid -t otp-aead-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t otp-aead-key 2> /dev/null)
test "echo $info | grep \"algorithm: aes256-yubico-otp\"" "   Object info contains correct algorithm"
test "$BIN -p password -a randomize-otp-aead -i $keyid" "   Randomize OTP AEAD"
test "$BIN -p password -a delete-object -i $keyid -t otp-aead-key" "   Delete key"

cd ..
rm -rf yubihsm-shell_test_dir

set +e
