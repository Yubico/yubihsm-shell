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
echo "            hmac-sha1"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-hmac-key -i 0 -l "hmackey" -d "1,2,3" -c "sign-hmac" -A "hmac-sha1" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: hmac-key"
echo $info | grep "algorithm: hmac-sha1"
echo $info | grep 'label: "hmackey"'
echo $info | grep "domains: 1:2:3"
echo $info | grep "origin: generated"
echo $info | grep "capabilities: sign-hmac"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t hmac-key

echo "**********************************"
echo "            hmac-sha256"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-hmac-key -i 0 -l "hmackey" -d "1,2,3" -c "sign-hmac" -A "hmac-sha256" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key)
echo $info | grep "algorithm: hmac-sha256"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t hmac-key

echo "**********************************"
echo "            hmac-sha384"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-hmac-key -i 0 -l "hmackey" -d "1,2,3" -c "sign-hmac" -A "hmac-sha384" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key)
echo $info | grep "algorithm: hmac-sha384"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t hmac-key

echo "**********************************"
echo "            hmac-sha512"
echo "**********************************"
echo "=== Generate on YubiHSM"
$BIN -p password -a generate-hmac-key -i 0 -l "hmackey" -d "1,2,3" -c "sign-hmac" -A "hmac-sha512" 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t hmac-key)
echo $info | grep "algorithm: hmac-sha512"
#$BIN -p password -a sign-hmac -i $keyid --in data.txt
echo "=== Delete keys"
$BIN -p password -a delete-object -i $keyid -t hmac-key

cd ..
rm -rf yubihsm-shell_test_dir

set +e