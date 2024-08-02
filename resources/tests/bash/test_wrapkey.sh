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


echo "**********************************"
echo "            aes128-ccm-wrap"
echo "**********************************"
echo "=== Generate on YubiHSM"
keyid=0x0005
$BIN -p password -a generate-wrap-key -i $keyid -l "wrapkey" -d "1" -c "export-wrapped,import-wrapped" --delegated "export-wrapped,import-wrapped" -A "aes128-ccm-wrap"
echo keyid: $keyid
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

echo "**********************************"
echo "            aes128-ccm-wrap"
echo "**********************************"
test "$BIN -p password -a generate-asymmetric-key -i 100 -l ecKey -d 5,8,13 -c exportable-under-wrap -A ecp224" "   Generate EC Key to wrap"
test "$BIN -p password -a generate-wrap-key -i 200 -l wrapkey -d 5,8,13 -c all --delegated all -A rsa2048" "   Generate RSA wrap key"
test "$BIN -p password -a get-public-key -i 200 -t wrap-key --out public_wrapkey.pem" "   Export rsa public wrap key"
test "$BIN -p password -a put-public-wrapkey -i 200 --delegated all -c all --in public_wrapkey.pem" "   Import RSA public wrap key"
test "$BIN -p password -a get-rsa-wrapped --wrap-id 200 -i 100 -t asymmetric-key --out rsawrapped.object" "   Export wrapped EC object"
test "$BIN -p password -a get-rsa-wrapped-key --wrap-id 200 -i 100 -t asymmetric-key --out rsawrapped.key" "   Export wrapped EC key"
test "$BIN -p password -a delete-object -i 100 -t asymmetric-key" "   Delete original EC key"
test "$BIN -p password -a put-rsa-wrapped --wrap-id 200 --in rsawrapped.object" "   Import wrapped EC object"
test "$BIN -p password -a put-rsa-wrapped-key --wrap-id 200 -i 300 -t asymmetric-key -A ecp224 --in rsawrapped.key" "   Import wrapped EC key"
test "$BIN -p password -a delete-object -i 100 -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a delete-object -i 300 -t asymmetric-key" "   Delete EC key"
test "$BIN -p password -a delete-object -i 200 -t wrap-key" "   Delete RSA wrap key"
test "$BIN -p password -a delete-object -i 200 -t public-wrap-key" "   Delete public RSA wrap key"


cd ..
rm -rf yubihsm-shell_test_dir

set +e
