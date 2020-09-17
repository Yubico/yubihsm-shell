#!/bin/bash
# Script to produce the source distribution package

VERSION=$1 # Full yubihsm-shell version, tex 2.1.0

mkdir dist_build; cd dist_build
cmake ..
make
cd ..
rm -r dist_build

set +e
set -x

tar --exclude README                  \
    --exclude .git                    \
    --exclude .github                 \
    --exclude .gitignore              \
    --exclude .ci                     \
    --exclude .clang-format           \
    --exclude .pre-commit-config.yaml \
    --exclude .travis.yml             \
    --transform="s/^\./yubihsm-shell-$VERSION/" -czf yubihsm-shell-$VERSION.tar.gz .
exitcode=$?
if [ "$exitcode" != "1" ] && [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

set -e