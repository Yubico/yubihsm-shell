#!/usr/bin/env bash

#
# Copyright 2015-2018 Yubico AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -eo pipefail

p11="`pwd`/../yubihsm_pkcs11.so"

os=`uname`
if [ "x$os" = "xDarwin" ]; then
  echo "mac os not supported yet"
  exit 0
elif [ "x$os" = "xLinux" ]; then
  if [ -f "/usr/lib/ssl/engines/libpkcs11.so" ]; then
    engine="/usr/lib/ssl/engines/libpkcs11.so"
  elif [ -f "/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so" ]; then
    engine="/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so"
  fi
  ssl_cnf="/etc/ssl/openssl.cnf"
else
  echo "$os is unknown and not supported"
  exit 0
fi

if [ ! -f $engine ]; then
  echo "No engine found at $engine, failure."
  exit 1
fi

if [ -z ${DEFAULT_CONNECTOR_URL} ]; then
  DEFAULT_CONNECTOR_URL="http://127.0.0.1:12345"
fi

dir=`mktemp -d /tmp/yubihsmtest.XXXXXX`
trap 'rm -rf "$dir"' INT TERM EXIT

cat > $dir/engine.conf <<-EOF
openssl_conf = openssl_init
EOF

cat $ssl_cnf >> $dir/engine.conf

cat >> $dir/engine.conf <<-EOF
[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = $engine
MODULE_PATH = $p11
PIN = 0001password
init = 0
EOF

cat > $dir/p11.conf <<-EOF
connector = ${DEFAULT_CONNECTOR_URL}
EOF

export YUBIHSM_PKCS11_CONF=$dir/p11.conf
export OPENSSL_CONF=$dir/engine.conf

test_rsa_sig() {
  local bits=$1
  local label=`openssl rand -engine pkcs11 -base64 16`
  pkcs11-tool --module=$p11 --keypairgen --key-type rsa:${bits} --label="$label" --login --pin 0001password
  pkcs11-tool --module=$p11 --read-object --label="$label" -l --pin 0001password -y pubkey --output-file=$dir/pubkey.der

  dd if=/dev/urandom of=$dir/data bs=1 count=32

  openssl dgst -engine pkcs11 -keyform engine -sha256 -sign label_${label} -out $dir/sign $dir/data
  openssl dgst -keyform der -sha256 -verify $dir/pubkey.der -signature $dir/sign $dir/data

  pkcs11-tool --module=$p11 --delete-object --label="$label" -l --pin 0001password -y privkey
}

test_ecdsa_sig() {
  local curve=$1
  local label=`openssl rand -engine pkcs11 -base64 16`
  pkcs11-tool --module=$p11 --keypairgen --key-type EC:${curve} --label="$label" --login --pin 0001password
  pkcs11-tool --module=$p11 --read-object --label="$label" -l --pin 0001password -y pubkey --output-file=$dir/pubkey.der

  dd if=/dev/urandom of=$dir/data bs=1 count=32

  openssl dgst -engine pkcs11 -keyform engine -sha256 -sign label_${label} -out $dir/sign $dir/data
  openssl dgst -keyform der -sha256 -verify $dir/pubkey.der -signature $dir/sign $dir/data

  pkcs11-tool --module=$p11 --delete-object --label="$label" -l --pin 0001password -y privkey
}

test_ecdh_derive() {
  local curve=$1
  local label=`openssl rand -engine pkcs11 -base64 16`
  pkcs11-tool --module=$p11 --keypairgen --key-type EC:${curve} --label="$label" --usage-derive --login --pin 0001password
  pkcs11-tool --module=$p11 --read-object --label="$label" -l --pin 0001password -y pubkey --output-file=$dir/pubkey.der

  openssl ecparam -name $curve -genkey -noout -out $dir/${curve}-priv.pem
  openssl ec -in $dir/${curve}-priv.pem -pubout -outform DER -out $dir/${curve}.der

  openssl pkeyutl -inkey $dir/${curve}-priv.pem -derive -peerkey $dir/pubkey.der -peerform der | openssl dgst -out $dir/${curve}-internal
  openssl pkeyutl -engine pkcs11 -keyform engine -inkey label_${label} -derive -peerkey $dir/${curve}.der -peerform der | openssl dgst -out $dir/${curve}-pkcs11

  cmp $dir/${curve}-internal $dir/${curve}-pkcs11

  pkcs11-tool --module=$p11 --delete-object --label="$label" -l --pin 0001password -y privkey
}

test_rsa_sig 2048
for curve in secp224r1 prime256v1 secp256k1 secp384r1 secp521r1; do
  test_ecdsa_sig $curve
  test_ecdh_derive $curve
done
