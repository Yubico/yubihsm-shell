#!/usr/bin/env bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory
# asciidoctor -o $PKG_RESOURCES/license.html $MAC_DIR/license.adoc

if [ "$#" -ne 3 ]; then
    echo "This script assembles the already signed binaries from the yubihsm2-sdk 3 components to make .pkg installer. Output files will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_release_binaries.sh <amd|arm|universal> <RELEASE VERSION> <SHELL PKG DIRECTORY> <SETUP PKG DIRECTORY> <CONNECTOR PKG DIRECTORY>"
    echo "";
    exit 0
fi

set -e -o pipefail

ARCH=$1 # amd, arm or universal
RELEASE_VERSION=$2
SHELL_PKG_DIR=$3
SETUP_PKG_DIR=$4
CONNECTOR_PKG_DIR=$5

echo "Path to yubihsm-shell binaries: $SHELL_PKG_DIR"
echo "Path to yubihsm-setup binaries: $SETUP_PKG_DIR"
echo "Path to yubihsm-connector binaries: $CONNECTOR_PKG_DIR"
read -p "Press Enter to continue"

cp -av $SHELL_PKG_DIR .
cp $SETUP_PKG_DIR/root/usr/local/bin/yubihsm-setup $SHELL_PKG_DIR/root/usr/local/bin/
cp $CONNECTOR_PKG_DIR/root/usr/local/bin/yubihsm-connector $SHELL_PKG_DIR/root/usr/local/bin/

mv $SHELL_PKG_DIR/root/usr/local/share/yubihsm-shell $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk
mkdir $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk/yubihsm-connector
mkdir $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk/yubihsm-setup

cp -r $CONNECTOR_PKG_DIR/root/usr/local/share/yubihsm-connector/licenses/* $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk/yubihsm-connector/
cp -r $SETUP_PKG_DIR/root/usr/local/share/yubihsm-setup/licenses/* $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk/yubihsm-setup/

rm $SHELL_PKG_DIR/comp/*

ls -l $SHELL_PKG_DIR/root/usr/local/
echo "\n"
ls -l $SHELL_PKG_DIR/root/usr/local/bin
echo "\n"
ls -l $SHELL_PKG_DIR/root/usr/local/lib
echo "\n"
ls -l $SHELL_PKG_DIR/root/usr/local/share
echo "\n"
ls -l $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk
echo "\n"
ls -l $SHELL_PKG_DIR/root/usr/local/share/yubihsm2-sdk/licenses

echo "\nMake sure all expected files are in the right place"
read -p "Press Enter to continue"

# Made installer
pkgbuild --root=$SHELL_PKG_DIR/root --identifier "com.yubico.yubihsm2-sdk" $SHELL_PKG_DIR/comp/yubihsm2-sdk.pkg
productbuild  --package-path $SHELL_PKG_DIR/comp/yubihsm2-sdk.pkg --distribution distribution.xml --resources $SHELL_PKG_DIR/resources yubihsm2-sdk-$RELEASE_VERSION-$ARCH.pkg

read -p "DO NOW: Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubihsm-shell-$RELEASE_VERSION-$ARCH.pkg yubihsm-shell-$RELEASE_VERSION-$ARCH-signed.pkg
echo "\nDO NOW: Remove signing key"