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

echo "---------------------- ED keys --------------------- "
# Generate
$BIN -p password -a generate-asymmetric-key -i 100 -l "edKey" -d "1,2,3" -c "sign-eddsa" -A "ed25519"
info=$($BIN -p password -a get-object-info -i 100 -t asymmetric-key)
echo $info | grep "id: 0x0064"
echo $info | grep "type: asymmetric-key"
echo $info | grep "algorithm: ed25519"
echo $info | grep 'label: "edKey"'
echo $info | grep "domains: 1:2:3"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: sign-eddsa"

# Import
#ssh-keygen -t ed25519 -C "test@yubihsm.se" -f edkey -N foo123
#$BIN --verbose=5 -p password -a put-asymmetric-key -i 200 -l "edKey_imported" -d "5" -c "sign-eddsa" --in=edkey

# Get public key
$BIN -p password -a get-public-key -i 100 > edkey1.pub
$BIN -p password -a get-public-key -i 100 --out edkey2.pub
if [[ $(cat edkey1.pub) != $(cat edkey2.pub) ]]; then
  echo "Public key in stdout and file are different"
  exit 2
fi

# Signing
$BIN -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt > data.ed1.sig
$BIN -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt --out data.ed2.sig
if [[ $(cat data.ed1.sig) != $(cat data.ed2.sig) ]]; then
  echo "Signature in stdout and file are different"
  exit 2
fi

# Delete
$BIN -p password -a delete-object -i 100 -t asymmetric-key

cd ..
rm -rf yubihsm-shell_test_dir

set +e
set +x