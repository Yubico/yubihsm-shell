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
set -e
#set -x

echo "**********************************"
echo "            aes128-ccm-wrap"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-wrap-key -i 0 -l "wrapkey" -d "1" -c "export-wrapped,import-wrapped" --delegated "export-wrapped,import-wrapped" -A "aes128-ccm-wrap"
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t wrap-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: wrap-key"
echo $info | grep "algorithm: aes128-ccm-wrap"
echo $info | grep 'label: "wrapkey"'
echo $info | grep "domains: 1"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: export-wrapped:import-wrapped"
echo $info | grep "delegated_capabilities: export-wrapped:import-wrapped"
echo "=== Delete key"
$BIN -p password -a delete-object -i $keyid -t wrap-key

cd ..
rm -rf yubihsm-shell_test_dir

set +e