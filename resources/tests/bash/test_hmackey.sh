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

echo "====================== HMAC keys ===================== "
echo "------------- hmac-sha1"
test_with_resp "$BIN -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha1" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t hmac-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key 2> /dev/null)
test "echo $info | grep \"id: $keyid\"" "   Object info contains correct ID"
test "echo $info | grep \"type: hmac-key\"" "   Object info contains correct type"
test "echo $info | grep \"algorithm: hmac-sha1\"" "   Object info contains correct algorithm"
test "echo $info | grep 'label: \"hmackey\"'" "   Object info contains correct label"
test "echo $info | grep \"domains: 1:2:3\"" "   Object info contains correct domains"
test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
test "echo $info | grep \"capabilities: sign-hmac\"" "   Object info contains correct capabilities"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
test "$BIN -p password -a delete-object -i $keyid -t hmac-key" "   Delete key"

echo "------------- hmac-sha256"
test_with_resp "$BIN -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha256" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t hmac-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key 2> /dev/null)
test "echo $info | grep \"algorithm: hmac-sha256\"" "   Object info contains correct algorithm"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
test "$BIN -p password -a delete-object -i $keyid -t hmac-key" "   Delete key"

echo "------------- hmac-sha384"
test_with_resp "$BIN -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha384" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t hmac-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key 2> /dev/null)
test "echo $info | grep \"algorithm: hmac-sha384\"" "   Object info contains correct algorithm"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
test "$BIN -p password -a delete-object -i $keyid -t hmac-key" "   Delete key"

echo "------------- hmac-sha512"
test_with_resp "$BIN -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha512" "   Generate key"
keyid=$(tail -1 resp.txt | awk '{print $4}')
test "$BIN -p password -a get-object-info -i $keyid -t hmac-key" "   Get object info"
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key 2> /dev/null)
test "echo $info | grep \"algorithm: hmac-sha512\"" "   Object info contains correct algorithm"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
test "$BIN -p password -a delete-object -i $keyid -t hmac-key" "   Delete key"

cd ..
rm -rf yubihsm-shell_test_dir

set +e