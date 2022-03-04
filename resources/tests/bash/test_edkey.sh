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

set -e

echo "====================== ED keys ===================== "
# Generate
echo "Generate key:"
test "$BIN -p password -a generate-asymmetric-key -i 100 -l \"edKey\" -d 1,2,3 -c sign-eddsa -A ed25519" "   Generate key"
test "$BIN -p password -a get-object-info -i 100 -t asymmetric-key" "   get-object-info"
info=$($BIN -p password -a get-object-info -i 100 -t asymmetric-key 2>&1)
test "echo $info | grep \"id: 0x0064\"" "   Object info contains correct ID"
test "echo $info | grep \"type: asymmetric-key\"" "   Object info contains correct type"
test "echo $info | grep \"algorithm: ed25519\"" "   Object info contains correct algorithm"
test "echo $info | grep 'label: \"edKey\"'" "   Object info contains correct label"
test "echo $info | grep \"domains: 1:2:3\"" "   Object info contains correct domains"
test "echo $info | grep \"origin: generated\"" "   Object info contains correct origin"
test "echo $info | grep \"capabilities: sign-eddsa\"" "   Object info contains correct capabilities"

# Import
#ssh-keygen -t ed25519 -C "test@yubihsm.se" -f edkey -N foo123
#$BIN --verbose=5 -p password -a put-asymmetric-key -i 200 -l "edKey_imported" -d "5" -c "sign-eddsa" --in=edkey

# Get public key
echo "Get public key:"
test "$BIN -p password -a get-public-key -i 100" "   Get public key to stdout"
$BIN -p password -a get-public-key -i 100 > edkey1.pub 2>/dev/null
test "$BIN -p password -a get-public-key -i 100 --out edkey2.pub" "   Get public key to file"
test "cmp edkey1.pub edkey2.pub" "   Match public key in stdout and file"

# Signing
echo "Signing:"
test "$BIN -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt" "   Sign to stdout"
$BIN -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt > data.ed1.sig 2>/dev/null
test "$BIN -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt --out data.ed2.sig" "   Sign to file"
if [[ $(cat data.ed1.sig) != $(cat data.ed2.sig) ]]; then
  echo "Signature in stdout and file are different"
  exit 2
fi
echo "   Matching signature in stdout and file ... OK"

# Delete
echo "Clean up:"
test "$BIN -p password -a delete-object -i 100 -t asymmetric-key" "   Delete key"

cd ..
rm -rf yubihsm-shell_test_dir

set +e