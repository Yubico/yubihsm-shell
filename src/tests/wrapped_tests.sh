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
  DEFAULT_CONNECTOR_URL="http://127.0.0.1:12345"
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

main() {
  put_yhwrapped_authkey
  put_yhwrapped_authkey_fail_cap
  put_yhwrapped_authkey_fail_domain

  put_yhwrapped_asymmetric_rsa
  put_yhwrapped_asymmetric_ecdsa
}

main "$@"
