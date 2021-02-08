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

$BIN --version
$BIN --help
$BIN -a get-device-info | grep "Serial number:"

echo "********************** Reset YubiHSM ********************* "
$BIN -p password -a reset
sleep 10

echo "********************** Blink ********************* "
$BIN -p password -a blink
$BIN -p password -a blink --duration=5

$BIN -p password -a blink-device
$BIN -p password -a blink-device --duration=5

echo "********************** Get Pseudo-random ********************* "
$BIN -p password -a get-pseudo-random | wc -c | grep 513 # includes a new line
$BIN -p password -a get-pseudo-random --out=random.txt
length=$(cat random.txt | wc -c)
if [ $length -ne 512 ]; then
  echo "Expected 512 but was $length characters. Without specifying byte count, 256 bytes (=512 characters) pseudo random number should have been produced."
  exit 1;
fi
rm random.txt

$BIN -p password -a get-pseudo-random --count=10 | wc -c | grep 21 # includes a new line
$BIN -p password -a get-pseudo-random --count=10 --out=random.txt
length=$(cat random.txt | wc -c)
if [ $length -ne 20 ]; then
  echo "Expected 20 but was $length characters."
  exit 1;
fi
rm random.txt


echo "********************** Asym keys ********************* "
../test_edkey.sh "$BIN"
../test_eckey.sh "$BIN"
../test_rsakey.sh "$BIN"

echo "********************** HMAC keys ********************* "
../test_hmackey.sh "$BIN"

echo "********************** AEAD keys ********************* "
../test_otpaeadkey.sh "$BIN"

echo "********************** Template ********************* "
echo "=== Import template"
$BIN -p password -a get-pseudo-random --count=512 --out=template.txt
$BIN -p password -a put-template -i 0 -l template -d 1 -A template-ssh --in template.txt 2> resp.txt
cat resp.txt
id=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $id -t template)
echo $info | grep "id: $id"
echo $info | grep "type: template"
echo $info | grep "algorithm: template-ssh"
echo $info | grep 'label: "template"'
echo $info | grep "domains: 1"
echo $info | grep "origin: imported"
echo "=== Get template"
$BIN -p password -a get-template -i $id  > resp.txt
echo "=== Delete template"
$BIN -p password -a delete-object -i $id -t template

#echo "********************** Wrap keys ********************* "

echo "********************** Authentication keys ********************* "
echo "=== Create new authentication key"
$BIN -p password -a put-authentication-key -i 0 -l authkey -d 1,2,3 -c all --new-password foo123 2> resp.txt
cat resp.txt
keyid=$(tail -1 resp.txt | awk '{print $4}')
info=$($BIN -p password -a get-object-info -i $keyid -t authentication-key)
echo $info | grep "id: $keyid"
echo $info | grep "type: template"
echo $info | grep "algorithm: aes128-yubico-authentication"
echo $info | grep 'label: "authkey"'
echo $info | grep "domains: 1:2:3"
echo $info | grep "origin: imported"
echo "=== Login using new authetication key"
$BIN --authkey $keyid -p foo123 -a get-object-info -i 1 -t authentication-key
echo "=== Delete new authentication key"
$BIN -p password -a delete-object -i $keyid -t authentication-key

set +e