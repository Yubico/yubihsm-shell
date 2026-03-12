#!/usr/bin/env bash
# Script to produce an OS X installer .pkg
# This script has to be run from the source directory
# asciidoctor -o $PKG_RESOURCES/license.html $MAC_DIR/license.adoc

if [ "$#" -ne 4 ]; then
    echo "This script is a guide to build a .pkg installer. Output installer will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_installer.sh <amd|arm> <SO VERSION> <RELEASE_VERSION> <BINARIES DIRECTORY>"
    echo "";
    exit 0
fi

set -e -o pipefail

ARCH=$1 # amd or arm
SO_VERSION=$2
RELEASE_VERSION=$3
SRC_DIR=$4 #path to unsigned binaries structured /usr/local/...

echo "ARCH: $ARCH"
echo "Release version: $RELEASE_VERSION"
echo "Binaries: $SRC_DIR"
echo "Working directory: $PWD"

read -p "Press Enter to continue"

MAC_DIR=$PWD
PKG_DIR=$MAC_DIR/pkg_$ARCH

mkdir -p $PKG_DIR/root $PKG_DIR/comp
cp -r resources $PKG_DIR/
cp -r $SRC_DIR/ $PKG_DIR/root/

echo "\nDO NOW: Update data inside distribution.xml if necessary"
read -p "Press Enter to continue"

echo "\n===================== Removing symbolic links ====================="
cd $PKG_DIR/root/usr/local/lib
rm libykhsmauth.$SO_VERSION.dylib
rm libykhsmauth.dylib
rm libyubihsm.$SO_VERSION.dylib
rm libyubihsm.dylib
rm libyubihsm_http.$SO_VERSION.dylib
rm libyubihsm_http.dylib
rm libyubihsm_usb.$SO_VERSION.dylib
rm libyubihsm_usb.dylib

echo "\n===================== Make binaries executable ====================="
cd ..
chmod +x bin/*
chmod +x lib/*

# ── Verify paths are correct (read-only, no modifications needed) ──
echo "\n===================== Verify binary paths ====================="
for f in bin/yubihsm-shell bin/yubihsm-auth bin/yubihsm-wrap \
         lib/pkcs11/yubihsm_pkcs11.dylib lib/libykhsmauth.dylib; do
  echo "--- $f ---"
  otool -L "$f"
  otool -l "$f" | grep LC_RPATH -A 3
  echo ""
  read -p "Press Enter to continue"
done
read -p "Verify paths are correct, then press Enter to continue"


echo "\n===================== Sign binaries ====================="
read -p "DO NOW: Insert signing key then press Enter to continue"
for f in bin/* lib/pkcs11/yubihsm_pkcs11.dylib lib/*.dylib; do
  echo "--- codesign $f ---"
  codesign -f --timestamp --options runtime --sign 'Application' $f
done

echo "\nDO NOW: Remove signing key"
read -p "Press Enter to continue"

echo "\n===================== Verify signature ====================="
for f in bin/* lib/pkcs11/yubihsm_pkcs11.dylib lib/*.dylib; do
  echo "--- codesign $f ---"
  codesign -dv --verbose=4 $f
  read -p "Press Enter to continue"
done

echo "\n===================== Fixing symbolic links ====================="
cd lib
ln -s libcrypto.3.dylib libcrypto.dylib
ln -s libykhsmauth.$RELEASE_VERSION.dylib libykhsmauth.$SO_VERSION.dylib
ln -s libykhsmauth.$SO_VERSION.dylib libykhsmauth.dylib
ln -s libyubihsm.$RELEASE_VERSION.dylib libyubihsm.$SO_VERSION.dylib
ln -s libyubihsm.$SO_VERSION.dylib libyubihsm.dylib
ln -s libyubihsm_http.$RELEASE_VERSION.dylib libyubihsm_http.$SO_VERSION.dylib
ln -s libyubihsm_http.$SO_VERSION.dylib libyubihsm_http.dylib
ln -s libyubihsm_usb.$RELEASE_VERSION.dylib libyubihsm_usb.$SO_VERSION.dylib
ln -s libyubihsm_usb.$SO_VERSION.dylib libyubihsm_usb.dylib
cd ..


# Include licenses
# ls share/licenses/yubihsm-shell
# echo "\nDO NOW: Make sure that the share/licenses/yubihsm-shell directory includes licenses for yubihsm-shell, OpenSSL and libusb"
# read -p "Press Enter to continue"


echo "\n===================== Make installer ====================="
cd $MAC_DIR
pkgbuild --root=$PKG_DIR/root --identifier "com.yubico.yubihsm-shell" $PKG_DIR/comp/yubihsm-shell.pkg
productbuild  --package-path $PKG_DIR/comp/yubihsm-shell.pkg --distribution distribution.xml --resources $PKG_DIR/resources yubihsm-shell-$RELEASE_VERSION-$ARCH.pkg

read -p "DO NOW: Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubihsm-shell-$RELEASE_VERSION-$ARCH.pkg yubihsm-shell-$RELEASE_VERSION-$ARCH-signed.pkg
echo "\nDO NOW: Remove signing key"
read -p "Press Enter to continue"
echo "\nALL DONE!!"