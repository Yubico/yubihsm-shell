#!/bin/bash

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

set -e
set -x
TMPDIR=$(mktemp -d)
#trap 'rm -rf "$TMPDIR"' INT TERM EXIT
DATA="$TMPDIR/data"
SIG="$TMPDIR/sig"
BIN_SIG="$TMPDIR/bin_sig"
PUBLIC_KEY="$TMPDIR/public"

if [ -z ${DEFAULT_CONNECTOR_URL} ]; then
  DEFAULT_CONNECTOR_URL="http://127.0.0.1:12345"
fi
PROG="../yubihsm-shell --connector=${DEFAULT_CONNECTOR_URL}"

echo "Hello World!" >"$DATA"
OUTPUT=$($PROG -a generate-asymmetric -A ecp256 -csign-ecdsa -p password 2>&1)
OBJ_ID=$(echo "$OUTPUT" | grep -o -E '0x[a-f0-9]{4}$')

$PROG -a sign-ecdsa -i $OBJ_ID -A ecdsa-sha256 --in "$DATA" --out "$SIG" -p password
base64 --decode "$SIG" >"$BIN_SIG"
$PROG -a get-public-key -i $OBJ_ID --out "$PUBLIC_KEY" -p password
openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$BIN_SIG" "$DATA"

truncate -s 0 "$SIG"
truncate -s 0 "$PUBLIC_KEY"
#$PROG -a generate-asymmetric -i 0x1234 -A ecp256 -csign_ecdsa
$PROG -a sign-ecdsa -i $OBJ_ID -A ecdsa-sha1 --in "$DATA" --out "$SIG" -p password
base64 --decode "$SIG" >"$BIN_SIG"
$PROG -a get-public-key -i $OBJ_ID --out "$PUBLIC_KEY" -p password
openssl dgst -sha1 -verify "$PUBLIC_KEY" -signature "$BIN_SIG" "$DATA"

truncate -s 0 "$SIG"
truncate -s 0 "$PUBLIC_KEY"
OUTPUT=$($PROG -a generate-asymmetric -A ecp384 -csign-ecdsa -p password 2>&1)
OBJ_ID=$(echo "$OUTPUT" | grep -o -E '0x[a-f0-9]{4}$')
$PROG -a sign-ecdsa -i $OBJ_ID -A ecdsa-sha384 --in "$DATA" --out "$SIG" -p password
base64 --decode "$SIG" >"$BIN_SIG"
$PROG -a get-public-key -i $OBJ_ID --out "$PUBLIC_KEY" -p password
openssl dgst -sha384 -verify "$PUBLIC_KEY" -signature "$BIN_SIG" "$DATA"

truncate -s 0 "$SIG"
truncate -s 0 "$PUBLIC_KEY"
OUTPUT=$($PROG -a generate-asymmetric -A ecp521 -csign-ecdsa -p password 2>&1)
OBJ_ID=$(echo "$OUTPUT" | grep -o -E '0x[a-f0-9]{4}$')
$PROG -a sign-ecdsa -i $OBJ_ID -A ecdsa-sha512 --in "$DATA" --out "$SIG" -p password
base64 --decode "$SIG" >"$BIN_SIG"
$PROG -a get-public-key -i $OBJ_ID --out "$PUBLIC_KEY" -p password
openssl dgst -sha512 -verify "$PUBLIC_KEY" -signature "$BIN_SIG" "$DATA"

$PROG -a blink-device -p password

$PROG -a get-device-info

$PROG -a get-storage-info -p password
