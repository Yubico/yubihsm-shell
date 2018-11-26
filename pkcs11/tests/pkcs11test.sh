#!/usr/bin/bash

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

if [ -z $PKCS11TEST_PATH ]; then
  bin="pkcs11test"
else
  bin="${PKCS11TEST_PATH}/pkcs11test"
fi

dir=`mktemp -d /tmp/yubihsmtest.XXXXXX`
trap 'rm -rf "$dir"' INT TERM EXIT

if [ -z ${DEFAULT_CONNECTOR_URL} ]; then
  DEFAULT_CONNECTOR_URL="http://127.0.0.1:12345"
fi

cat > $dir/p11.conf <<-EOF
connector = ${DEFAULT_CONNECTOR_URL}
EOF

export YUBIHSM_PKCS11_CONF=$dir/p11.conf

env

$bin -myubihsm_pkcs11.${LIBEXT} -l${BINDIR}/pkcs11 -u0001password --gtest_filter=-${SKIPPED_TESTS}
