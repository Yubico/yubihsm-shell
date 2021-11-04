#!/bin/bash

if [ "$#" -eq 1 ]; then
  BIN=$1 # path to the yubihsm-shell command line tool - using default connector
elif [ "$#" -gt 1 ]; then
  BIN="$1 -C $2" # path to the yubihsm-shell command line tool - using specified connector
else
  BIN="yubihsm-shell"
fi


if [ -e yubihsm-shell_test_dir ];
then
    rm -rf yubihsm-shell_test_dir
fi

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

test "$BIN --version" "yubihsm-shell --version"
test "$BIN --help" "yubihsm-shell --help"
test "$BIN -a get-device-info | grep \"Serial number:\"" "yubihsm-shell -a get-device-info"

echo "********************************************************** "
echo "                    Reset YubiHSM"
echo "********************************************************** "
test "$BIN -p password -a reset"
sleep 3

echo "********************************************************** "
echo "                    Blink"
echo "********************************************************** "
test "$BIN -p password -a blink" "-a blink"
test "$BIN -p password -a blink --duration=5" "-a blink --duration=5"

test "$BIN -p password -a blink-device" "blink-device"
test "$BIN -p password -a blink-device --duration=5" "-a blink-device --duration=5"

echo "********************************************************** "
echo "                    Get Pseudo-random"
echo "********************************************************** "
test "$BIN -p password -a get-pseudo-random | wc -c | grep 513" "get-pseudo-random"  # includes a new line
test "$BIN -p password -a get-pseudo-random --out=random.txt" get-pseudo-random --out=random.txt
length=$(cat random.txt | wc -c)
if [ $length -ne 512 ]; then
  echo "Expected 512 but was $length characters. Without specifying byte count, 256 bytes (=512 characters) pseudo random number should have been produced."
  exit 1;
fi
rm random.txt

test "$BIN -p password -a get-pseudo-random --count=10 | wc -c | grep 21" "get-pseudo-random --count=10" # includes a new line
test "$BIN -p password -a get-pseudo-random --count=10 --out=random.txt" "get-pseudo-random --count=10 --out=random.txt"
length=$(cat random.txt | wc -c)
if [ $length -ne 20 ]; then
  echo "Expected 20 but was $length characters."
  exit 1;
fi
rm random.txt

echo "********************************************************** "
echo "                    Asymmetric Keys"
echo "********************************************************** "
./test_edkey.sh "$BIN"
./test_eckey.sh "$BIN"
./test_rsakey.sh "$BIN"

echo "********************************************************** "
echo "                    HMAC Keys"
echo "********************************************************** "
./test_hmackey.sh "$BIN"

echo "********************************************************** "
echo "                    AEAD Keys"
echo "********************************************************** "
./test_otpaeadkey.sh "$BIN"

echo "********************************************************** "
echo "                    Template"
echo "********************************************************** "

test "$BIN -p password -a get-pseudo-random --count=512 --out=template.txt" "   Generate 512 pseudo random bytes"
test_with_resp "$BIN -p password -a put-template -i 0 -l template -d 1 -A template-ssh --in template.txt" "   Import template"
id=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $id -t template" "   Get object info"
info=$($BIN -p password -a get-object-info -i $id -t template 2> /dev/null)
test "echo $info | grep \"id: $id\"" "   Object info contains correct ID"
test "echo $info | grep \"type: template\"" "   Object info contains correct type"
test "echo $info | grep \"algorithm: template-ssh\"" "   Object info contains correct algorithm"
test "echo $info | grep 'label: \"template\"'" "   Object info contains correct label"
test "echo $info | grep \"domains: 1\"" "   Object info contains correct domains"
test "echo $info | grep \"origin: imported\"" "   Object info contains correct origin"
test "$BIN -p password -a get-template -i $id" "   Get template"
test "$BIN -p password -a delete-object -i $id -t template" "   Delete template"
rm resp.txt
rm template.txt

#echo "********************************************************** "
#echo "                    Wrap Keys"
#echo "********************************************************** "

echo "********************************************************** "
echo "                    List Objects"
echo "********************************************************** "
test "$BIN -p password -a generate-asymmetric-key -i 100 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp224" "   Generate EC key for testing"
test "$BIN -p password -a list-objects -A any -t any -i 100 | grep \"Found 1 object(s)\"" "   List objects by ID"
test "$BIN -p password -a list-objects -A any -t asymmetric-key | grep \"Found 1 object(s)\"" "   List objects by type"
test "$BIN -p password -a list-objects -A any -t any -d 5,8,13 | grep \"Found 2 object(s)\"" "   List objects by domain"
test "$BIN -p password -a list-objects -A any -t any -c sign-ecdsa,derive-ecdh,sign-attestation-certificate | grep \"Found 2 object(s)\"" "   List objects by capabilities"
test "$BIN -p password -a list-objects -A ecp224 -t any | grep \"Found 1 object(s)\"" "   List objects by algorithm"
test "$BIN -p password -a list-objects -A any -t any -l ecKey | grep \"Found 1 object(s)\"" "   List objects by label"
test "$BIN -p password -a delete-object -i 100 -t asymmetric-key" "   Delete key"

echo "********************************************************** "
echo "                    Label Size"
echo "********************************************************** "
# Label 0 chars
test "$BIN -p password -a generate-asymmetric-key -i 300 -d 5,8,13 -c sign-ecdsa -A ecp224" "   Create key with no label"
test "$BIN -p password -a get-object-info -i 300 -t asymmetric-key | grep 'label: \"\"'" "   Object info contains empty label"
#$BIN -p password -a list-objects -A any -t any -l "" | grep "Found 1 object(s)"
# Label 39 chars
test "$BIN -p password -a generate-asymmetric-key -i 200 -l abcdefghijklmnopqrstuvwxyz0123456789abc -d 5,8,13 -c sign-ecdsa -A ecp224" "   Create object with 39 characters label"
test "$BIN -p password -a get-object-info -i 200 -t asymmetric-key | grep 'label: \"abcdefghijklmnopqrstuvwxyz0123456789abc\"'" "   Object info contains correct lable with 39 characters"
test "$BIN -p password -a list-objects -A any -t any -l abcdefghijklmnopqrstuvwxyz0123456789abc | grep \"Found 1 object(s)\"" "   list-objects found object with 39 characters"
# Label 40 chars
test "$BIN -p password -a generate-asymmetric-key -i 100 -l abcdefghijklmnopqrstuvwxyz0123456789abcd -d 5,8,13 -c sign-ecdsa -A ecp224" "   Create object with 40 characters label"
test "$BIN -p password -a get-object-info -i 100 -t asymmetric-key | grep 'label: \"abcdefghijklmnopqrstuvwxyz0123456789abcd\"'" "   Object info contains correct lable with 40 characters"
test "$BIN -p password -a list-objects -A any -t any -l abcdefghijklmnopqrstuvwxyz0123456789abcd | grep \"Found 1 object(s)\"" "   list-objects found object with 40 characters"
# Label 41 chars
(set +e; $BIN -p password -a generate-asymmetric-key -i 400 -l "abcdefghijklmnopqrstuvwxyz0123456789abcde" -d "5,8,13" -c "sign-ecdsa" -A "ecp224"; true) 2>&1 >/dev/null | grep "Failed to generate asymmetric key: Invalid argument to a function"
# Label doesn't exist
test "$BIN -p password -a list-objects -A any -t any -l doesnotexist | grep \"Found 0 object(s)\"" "   List objects by label that does not exist"

test "$BIN -p password -a delete-object -i 100 -t asymmetric-key" "   Clean up"
test "$BIN -p password -a delete-object -i 200 -t asymmetric-key" "   Clean up"
test "$BIN -p password -a delete-object -i 300 -t asymmetric-key" "   Clean up"

echo "********************************************************** "
echo "                    Authentication Keys"
echo "********************************************************** "
test_with_resp "$BIN -p password -a put-authentication-key -i 0 -l authkey -d 1,2,3 -c all --delegated all --new-password foo123" "   Create new authentication key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN --authkey $keyid -p foo123 -a get-object-info -i 1 -t authentication-key" "   Login using new authetication key"
test "$BIN -p password -a delete-object -i $keyid -t authentication-key" "   Delete new authentication key"

cd ..
rm -rf yubihsm-shell_test_dir

set +e