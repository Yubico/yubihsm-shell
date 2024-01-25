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

if [[ ! -z "$DEBUG" ]]; then
  set -x
fi
set -eo pipefail

if [ -z ${DEFAULT_CONNECTOR_URL} ]; then
  DEFAULT_CONNECTOR_URL="http://localhost:12345"
fi

readonly TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' INT TERM EXIT
echo ">>> TMPDIR=$TMPDIR"

readonly YHSHELL="../yubihsm-shell --connector=${DEFAULT_CONNECTOR_URL}"
readonly YHWRAP="../../yhwrap/yubihsm-wrap"

put_yhwrapped_authkey() {
  local -r wrapid="0xdead"
  local -r wrapkey="$TMPDIR/${FUNCNAME[0]}_wrapkey"
  local -r authid="0xbeef"
  local -r authkey="$TMPDIR/${FUNCNAME[0]}_authkey"
  local -r passfile="$TMPDIR/${FUNCNAME[0]}_passfile"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$wrapid" --object-type="wrap-key" && {
    echo "${FUNCNAME[0]}: delete wrapkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$wrapid" --object-type="wrap-key"
  }

  echo "${FUNCNAME[0]}: put-wrap-key"
  openssl rand 32 > "$wrapkey"
  $YHSHELL --action="put-wrap-key" --password="password" --authkey="1"        \
    --object-id="$wrapid" --label="${FUNCNAME[0]}" --domains="all"             \
    --capabilities="all" --delegated="all" --in="$wrapkey" --informat="binary"

  echo "${FUNCNAME[0]}: creating authkey"
  echo "password" > "$passfile"
  $YHWRAP --algorithm="aes128-yubico-authentication" --capabilities="all"    \
    --delegated="all" --domains="all" --id="$authid" --in="$passfile"          \
    --out="$authkey" --label="${FUNCNAME[0]}" --wrapkey="$wrapkey"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$authid" --object-type="authentication-key" && {
    echo "${FUNCNAME[0]}: delete authkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$authid" --object-type="authentication-key"
  }

  echo "${FUNCNAME[0]}: put-wrapped authkey"
  $YHSHELL --action="put-wrapped" --password="password" --authkey="1"         \
    --wrap-id="$wrapid" --in="$authkey" --informat="base64"

  echo "${FUNCNAME[0]}: using put-wrapped authkey"
  $YHSHELL --action="get-pseudo-random" --password="$passfile" --authkey="$authid"     \
    --count=1 --out=/dev/null
}

put_yhwrapped_authkey_fail_cap() {
  local -r wrapid="0xdead"
  local -r wrapkey="$TMPDIR/${FUNCNAME[0]}_wrapkey"
  local -r authid="0xbeef"
  local -r authkey="$TMPDIR/${FUNCNAME[0]}_authkey"
  local -r passfile="$TMPDIR/${FUNCNAME[0]}_passfile"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$wrapid" --object-type="wrap-key" && {
    echo "${FUNCNAME[0]}: delete wrapkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$wrapid" --object-type="wrap-key"
  }

  openssl rand 16 > "$wrapkey"
  echo "${FUNCNAME[0]}: creating wrapkey"
  $YHSHELL --action="put-wrap-key" --password="password" --authkey="1"        \
    --object-id="$wrapid" --label="${FUNCNAME[0]}" --domains="all"             \
    --capabilities="all" --delegated="none"                                    \
    --in="$wrapkey" --informat="binary"

  echo "${FUNCNAME[0]}: creating authkey"
  echo "password" > "$passfile"
  $YHWRAP --algorith="aes128-yubico-authentication"                          \
    --capabilities="all" --delegated="all"                                     \
    --domains="all" --id="$authid" --in="$passfile" --out="$authkey"           \
    --label="${FUNCNAME[0]}" --wrapkey="$wrapkey"

  echo "${FUNCNAME[0]}: put-wrapped authkey"
  ! $YHSHELL --action="put-wrapped" --password="password" --authkey="1"       \
    --wrap-id="$wrapid" --in="$authkey" --informat="base64"
  if [[ "${PIPESTATUS[0]}" != "1" ]]; then
    echo "put_yhwrapped_authkey_fail_caps: put-wrapped should have failed"
    exit 1
  fi
}

put_yhwrapped_authkey_fail_domain() {
  local -r wrapid="0xdead"
  local -r wrapkey="$TMPDIR/${FUNCNAME[0]}_wrapkey"
  local -r authid="0xbeef"
  local -r authkey="$TMPDIR/${FUNCNAME[0]}_authkey"
  local -r passfile="$TMPDIR/${FUNCNAME[0]}_passfile"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$wrapid" --object-type="wrap-key" && {
    echo "${FUNCNAME[0]}: delete wrapkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$wrapid" --object-type="wrap-key"
  }

  echo "${FUNCNAME[0]}: creating restricted wrapkey"
  openssl rand 24 > "$wrapkey"
  $YHSHELL --action="put-wrap-key" --password="password" --authkey="1"        \
    --object-id="$wrapid" --label="${FUNCNAME[0]}" --domains="2"               \
    --capabilities="all" --delegated="all"                                     \
    --in="$wrapkey" --informat="binary"

  echo "${FUNCNAME[0]}: creating authkey"
  echo "password" > "$passfile"
  $YHWRAP --algorith="aes128-yubico-authentication"                          \
    --capabilities="all" --delegated="all"                                     \
    --domains="all" --id="$authid" --in="$passfile" --out="$authkey"           \
    --label="${FUNCNAME[0]}" --wrapkey="$wrapkey"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$authid" --object-type="authentication-key" && {
    echo "${FUNCNAME[0]}: delete authkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$authid" --object-type="authentication-key"
  }

  echo "${FUNCNAME[0]}: put-wrapped authkey"
  $YHSHELL --action="put-wrapped" --password="password" --authkey="1"         \
    --wrap-id="$wrapid" --in="$authkey" --informat="base64"

  # NOTE(thorduri): Domains just get filtered.
  local domains
  domains="$(
    $YHSHELL --action="get-object-info" --password="password"                \
    --authkey="1" --object-type="authentication-key" --object-id="$authid" | grep "^id"    \
    | awk -F: '{print $7}' | awk -F, '{print $1}' | tr -d '[:space:]'
  )"
  if [[ "$domains" != "2" ]]; then
    echo "${FUNCNAME[0]}: domains not filtered: expected 2 got $domains"
    exit 1
  fi
}

put_yhwrapped_asymmetric_rsa() {
  local -r wrapid="0xdead"
  local -r wrapkey="$TMPDIR/${FUNCNAME[0]}_wrapkey"
  local -r keyid="0xfefe"
  local -r keyfile="$TMPDIR/${FUNCNAME[0]}_keyfile.pem"
  local -r keyfilew="$TMPDIR/${FUNCNAME[0]}_keyfile.wrapped"
  local -r sigbuf="$TMPDIR/${FUNCNAME[0]}_sigbuf"
  local -r signature="$TMPDIR/${FUNCNAME[0]}_signature"
  
  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$wrapid" --object-type="wrap-key" && {
    echo "${FUNCNAME[0]}: delete wrapkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$wrapid" --object-type="wrap-key"
  }

  echo "${FUNCNAME[0]}: creating wrapkey"
  openssl rand 16 > "$wrapkey"
  $YHSHELL --action="put-wrap-key" --password="password" --authkey="1"        \
    --object-id="$wrapid" --label="${FUNCNAME[0]}" --domains="all"             \
    --capabilities="all" --delegated="all"                                     \
    --in="$wrapkey" --informat="binary"

  local -r rsa=(
    "2048"
    "3072"
    "4096"
  )
  for size in "${rsa[@]}"; do
    $YHSHELL --action="get-object-info" --password="password" --authkey="1"   \
      --object-id="$keyid" --object-type="asymmetric-key" && {
      echo "${FUNCNAME[0]}: delete rsa key"
      $YHSHELL --action="delete-object" --password="password" --authkey="1"   \
        --object-id="$keyid" --object-type="asymmetric-key"
    }

    echo "${FUNCNAME[0]}: creating rsa$size key"
    openssl genrsa -out "$keyfile.$size" $size
    $YHWRAP --algorithm="rsa$size"                                           \
      --capabilities="all" --delegated="all"                                   \
      --domains="all" --id="$keyid" --in="$keyfile.$size"                      \
      --out="$keyfilew.$size" --label="${FUNCNAME[0]}" --wrapkey="$wrapkey"

    echo "${FUNCNAME[0]}: put-wrapped rsa$size asymmetric"
    $YHSHELL --action="put-wrapped" --password="password" --authkey="1"       \
      --wrap-id="$wrapid" --in="$keyfilew.$size" --informat="base64"

    echo "${FUNCNAME[0]}: comparing pubs rsa$size"
    openssl rsa -in "$keyfile.$size" -pubout > "$keyfile.$size.pub"
    $YHSHELL --action="get-public-key" --password="password" --authkey="1"        \
      --object-id="$keyid" --out="$keyfile.$size.pub.shell"
    diff -u "$keyfile.$size.pub" "$keyfile.$size.pub.shell"

    openssl rand 1024 > "$sigbuf"
  
    echo "${FUNCNAME[0]}: sign-pkcs1v15 rsa$size rsa-pkcs1-sha256"
    $YHSHELL --action="sign-pkcs1v15" --password="password" --authkey="1"       \
      --object-id="$keyid" --algorithm "rsa-pkcs1-sha256" --in="$sigbuf" --out "$signature.$size" --outformat="bin"

    echo "${FUNCNAME[0]}: verifying rsa$size sha256 signature"
    openssl dgst -sha256 -verify "$keyfile.$size" -signature "$signature.$size" "$sigbuf"

  done
}


put_yhwrapped_asymmetric_ecdsa() {
  local -r wrapid="0xdead"
  local -r wrapkey="$TMPDIR/${FUNCNAME[0]}_wrapkey"
  local -r keyid="0xfefe"
  local -r keyfile="$TMPDIR/${FUNCNAME[0]}_keyfile.pem"
  local -r keyfilew="$TMPDIR/${FUNCNAME[0]}_keyfile.wrapped"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$wrapid" --object-type="wrap-key" && {
    echo "${FUNCNAME[0]}: delete wrapkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$wrapid" --object-type="wrap-key"
  }

  echo "${FUNCNAME[0]}: creating wrapkey"
  openssl rand 16 > "$wrapkey"
  $YHSHELL --action="put-wrap-key" --password="password" --authkey="1"        \
    --object-id="$wrapid" --label="${FUNCNAME[0]}" --domains="all"             \
    --capabilities="all" --delegated="all"                                     \
    --in="$wrapkey" --informat="binary"

  curves="secp256k1 secp384r1 secp521r1 prime256v1"
  secp256k1=eck256
  secp384r1=ecp384
  secp521r1=ecp521
  prime256v1=ecp256

  if openssl ecparam -list_curves | grep -q brainpoolP256r1; then
    curves="$curves brainpoolP256r1 brainpoolP384r1 brainpoolP512r1"
    brainpoolP256r1=ecbp256
    brainpoolP384r1=ecbp384
    brainpoolP512r1=ecbp512
  fi
  for curve in $curves; do
    $YHSHELL --action="get-object-info" --password="password" --authkey="1"   \
      --object-id="$keyid" --object-type="asymmetric-key" && {
      echo "${FUNCNAME[0]}: delete ec key"
      $YHSHELL --action="delete-object" --password="password" --authkey="1"   \
        --object-id="$keyid" --object-type="asymmetric-key"
    }
    echo "${FUNCNAME[0]}: creating ${!curve} key"
    openssl ecparam -genkey -noout -name $curve > "$keyfile.$curve"
    $YHWRAP --algorithm="${!curve}"                                            \
      --capabilities="all" --delegated="all"                                   \
      --domains="all" --id="$keyid" --in="$keyfile.$curve"                     \
      --out="$keyfilew.$curve" --label="${FUNCNAME[0]}" --wrapkey="$wrapkey"

    echo "${FUNCNAME[0]}: put-wrapped ${!curve}"
    $YHSHELL --action="put-wrapped" --password="password" --authkey="1"       \
      --wrap-id="$wrapid" --in="$keyfilew.$curve" --informat="base64"

    echo "${FUNCNAME[0]}: comparing pubs ${!curve}"
    openssl ec -in "$keyfile.$curve" -pubout > "$keyfile.$curve.pub"
    $YHSHELL --action="get-public-key" --password="password" --authkey="1"        \
      --object-id="$keyid" --out="$keyfile.$curve.pub.shell"
    diff -u "$keyfile.$curve.pub" "$keyfile.$curve.pub.shell"
  done
}

put_yhwrapped_asymmetric_eddsa() {
  if [ $(openssl list -public-key-methods | grep -i ed25519 -c) -eq 0 ]; then
    echo "OpenSSL version without Ed25519, skipping put_yhwrapped_asymmetric_eddsa"
    return
  fi

  local -r edkeyid="0xeded"
  local -r wrapid="0xdead"
  local -r wrapkey="$TMPDIR/${FUNCNAME[0]}_wrapkey"
  local -r keyid="0xfefe"
  local -r keyfile="$TMPDIR/${FUNCNAME[0]}_keyfile.pem"
  local -r keyfilew="$TMPDIR/${FUNCNAME[0]}_keyfile.wrapped"
  local -r sigfile1="$TMPDIR/${FUNCNAME[0]}_sig_1"
  local -r sigfile2="$TMPDIR/${FUNCNAME[0]}_sig_2"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"     \
    --object-id="$wrapid" --object-type="wrap-key" && {
    echo "${FUNCNAME[0]}: delete wrapkey"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"     \
      --object-id="$wrapid" --object-type="wrap-key"
  }

  echo "${FUNCNAME[0]}: creating wrapkey"
  openssl rand 16 > "$wrapkey"
  $YHSHELL --action="put-wrap-key" --password="password" --authkey="1"        \
    --object-id="$wrapid" --label="${FUNCNAME[0]}" --domains="all"             \
    --capabilities="all" --delegated="all"                                     \
    --in="$wrapkey" --informat="binary"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"   \
    --object-id="$keyid" --object-type="asymmetric-key" && {
    echo "${FUNCNAME[0]}: delete ed key"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"   \
      --object-id="$keyid" --object-type="asymmetric-key"
  }
  echo "${FUNCNAME[0]}: creating ed key"
  openssl genpkey -algorithm Ed25519 -out "$keyfile"

  $YHSHELL --action="get-object-info" --password="password" --authkey="1"   \
    --object-id="$edkeyid" --object-type="asymmetric-key" && {
    echo "${FUNCNAME[0]}: delete imported ed key"
    $YHSHELL --action="delete-object" --password="password" --authkey="1"   \
      --object-id="$edkeyid" --object-type="asymmetric-key"
  }
  echo "${FUNCNAME[0]}: importing ed key"
  $YHSHELL --action="put-asymmetric-key" --password="password" --authkey="1"        \
    --object-id="$edkeyid" --label="${FUNCNAME[0]}" --domains="all"             \
    --capabilities="all"                                                     \
    --in="$keyfile" --informat="binary"

  echo "${FUNCNAME[0]}: signing with ed key"
  rm -f $sigfile1
  $YHSHELL --action="sign-eddsa" --object-id="$edkeyid" --algorithm="ed25519" --in="$wrapkey" --out="$sigfile1" --password="password"

  $YHWRAP --algorithm="ed25519"                                              \
    --capabilities="all" --delegated="all"                                   \
    --domains="all" --id="$keyid" --in="$keyfile"                            \
    --out="$keyfilew" --label="${FUNCNAME[0]}" --wrapkey="$wrapkey"

  echo "${FUNCNAME[0]}: put-wrapped ed25519"
  $YHSHELL --action="put-wrapped" --password="password" --authkey="1"       \
    --wrap-id="$wrapid" --in="$keyfilew" --informat="base64"

  echo "${FUNCNAME[0]}: comparing pubs ed25519"
  openssl pkey -in "$keyfile" -pubout > "$keyfile.pub"
  $YHSHELL --action="get-public-key" --password="password" --authkey="1"        \
    --object-id="$keyid" --out="$keyfile.pub.shell"

  diff -u "$keyfile.pub" "$keyfile.pub.shell"

  echo "${FUNCNAME[0]}: signing with wrapped ed key"
  rm -f "$sigfile2"
  $YHSHELL --action="sign-eddsa" --object-id="$keyid" --algorithm="ed25519" --in="$wrapkey" --out="$sigfile2" --password="password"

  diff -u "$sigfile1" "$sigfile2"
}

main() {
  put_yhwrapped_authkey
  put_yhwrapped_authkey_fail_cap
  put_yhwrapped_authkey_fail_domain

  put_yhwrapped_asymmetric_rsa
  put_yhwrapped_asymmetric_ecdsa
  put_yhwrapped_asymmetric_eddsa
}

main "$@"
