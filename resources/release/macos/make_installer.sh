#!/bin/bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory
set -x

ARCH=$1
SRC_PATH=$2

MAC_DIR=$PWD
PKG_DIR=$MAC_DIR/pkg
PKG_COMP=$PKG_DIR/comp
PKG_RESOURCES=$PKG_DIR/resources/English.lproj
mkdir -p $PKG_COMP $PKG_RESOURCES

asciidoctor -o $PKG_RESOURCES/license.html $MAC_DIR/license.adoc

pkgbuild --root="$SRC_PATH" --identifier "com.yubico.yubihsm2-sdk" "$PKG_COMP/yubihsm2-sdk.pkg"
productbuild  --package-path "$PKG_COMP" --distribution "$MAC_DIR/distribution.xml" --resources $PKG_RESOURCES "$MAC_DIR/yubihsm2-sdk-darwin-$ARCH.pkg"

#clean up
rm -rf $PKG_DIR
