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
# OLD_RELEASE_VERSION=$4
SRC_DIR=$4 #path to unsigned binaries structured /usr/local/...

echo "ARCH: $ARCH"
# echo "Previous release version: $OLD_RELEASE_VERSION"
echo "Release version: $RELEASE_VERSION"
echo "Binaries: $SRC_DIR"
# echo "Working directory: $PWD"

read -p "Press Enter to continue"

MAC_DIR=$PWD
PKG_DIR=$MAC_DIR/pkg_$ARCH

mkdir -p $PKG_DIR/root $PKG_DIR/comp
cp -r resources $PKG_DIR/
cp -r $SRC_DIR/ $PKG_DIR/root/

echo "\nDO NOW: Update data inside distribution.xml if necessary"
read -p "Press Enter to continue"


# Fix symbolic links
echo "Fixing symbolic links"
cd $PKG_DIR/root/usr/local/lib
# rm libcrypto.dylib
# rm libykhsmauth.$SO_VERSION.dylib
# rm libykhsmauth.dylib
# rm libyubihsm.$SO_VERSION.dylib
# rm libyubihsm.dylib
# rm libyubihsm_http.$SO_VERSION.dylib
# rm libyubihsm_http.dylib
# rm libyubihsm_usb.$SO_VERSION.dylib
# rm libyubihsm_usb.dylib
ln -s libcrypto.3.dylib libcrypto.dylib
ln -s libykhsmauth.$RELEASE_VERSION.dylib libykhsmauth.$SO_VERSION.dylib
ln -s libykhsmauth.$SO_VERSION.dylib libykhsmauth.dylib
ln -s libyubihsm.$RELEASE_VERSION.dylib libyubihsm.$SO_VERSION.dylib
ln -s libyubihsm.$SO_VERSION.dylib libyubihsm.dylib
ln -s libyubihsm_http.$RELEASE_VERSION.dylib libyubihsm_http.$SO_VERSION.dylib
ln -s libyubihsm_http.$SO_VERSION.dylib libyubihsm_http.dylib
ln -s libyubihsm_usb.$RELEASE_VERSION.dylib libyubihsm_usb.$SO_VERSION.dylib
ln -s libyubihsm_usb.$SO_VERSION.dylib libyubihsm_usb.dylib

# Fix file permissions
cd ..
chmod +x bin/*
chmod +x lib/*

ls -l bin
ls -l lib
echo "\nDO NOW: Make sure that the files in bin/ and lib/ directories are correct."
echo "\nThe files in lib/ should includelibcrypto*.dylib, libusb*.dylib and libz*.dylib files."
read -p "Press Enter to continue"

if [ "$ARCH" == "amd" ]; then
  BREW_LIB="/usr/local/opt"
  #BREW_CELLAR="/usr/local/Cellar"
elif [ "$ARCH" == "arm" ]; then
  BREW_LIB="/opt/homebrew/opt"
  #BREW_CELLAR="/opt/homebrew/Cellar"
else
  echo "Unknown architecture"
  exit
fi

# Checking files's paths
echo "\nChecking binary files' paths using 'otool -L FILE' and 'otool -l FILE'"
install_name_tool -id @loader_path/../lib/libusb-1.0.0.dylib lib/libusb-1.0.0.dylib

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib bin/yubihsm-shell
install_name_tool -rpath /Users/runner/work/yubihsm-shell/yubihsm-shell/yubihsm-shell-$RELEASE_VERSION/resources/release/macos/yubihsm-shell-darwin-$ARCH-$RELEASE_VERSION/usr/local/lib @loader_path/../lib bin/yubihsm-shell
otool -L bin/yubihsm-shell
otool -l bin/yubihsm-shell | grep LC_RPATH -A 3
read -p "Press Enter to continue"

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib bin/yubihsm-auth
install_name_tool -rpath /Users/runner/work/yubihsm-shell/yubihsm-shell/yubihsm-shell-$RELEASE_VERSION/resources/release/macos/yubihsm-shell-darwin-$ARCH-$RELEASE_VERSION/usr/local/lib @loader_path/../lib bin/yubihsm-auth
otool -L bin/yubihsm-auth
otool -l bin/yubihsm-auth | grep LC_RPATH -A 3
read -p "Press Enter to continue"

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib bin/yubihsm-wrap
install_name_tool -rpath /Users/runner/work/yubihsm-shell/yubihsm-shell/yubihsm-shell-$RELEASE_VERSION/resources/release/macos/yubihsm-shell-darwin-$ARCH-$RELEASE_VERSION/usr/local/lib @loader_path/../lib bin/yubihsm-wrap
otool -L bin/yubihsm-wrap
otool -l bin/yubihsm-wrap | grep LC_RPATH -A 3
read -p "Press Enter to continue"


otool -L lib/libcrypto.dylib
#otool -l lib/libcrypto.dylib | grep LC_RPATH -A 3 # does not have rpath reference
read -p "Press Enter to continue"

install_name_tool -rpath /Users/runner/work/yubihsm-shell/yubihsm-shell/yubihsm-shell-$RELEASE_VERSION/resources/release/macos/yubihsm-shell-darwin-$ARCH-$RELEASE_VERSION/usr/local/lib @loader_path/../lib lib/libykhsmauth.dylib
otool -L lib/libykhsmauth.dylib
otool -l lib/libykhsmauth.dylib | grep LC_RPATH -A 3
read -p "Press Enter to continue"

otool -L lib/libyubihsm.dylib
#otool -l lib/libyubihsm.dylib | grep LC_RPATH -A 3 # does not have rpath reference
read -p "Press Enter to continue"

otool -L lib/libyubihsm_http.dylib
#otool -l lib/libyubihsm_http.dylib | grep LC_RPATH -A 3  # does not have rpath reference
read -p "Press Enter to continue"

otool -L lib/libyubihsm_usb.dylib
#otool -l lib/libyubihsm_usb.dylib | grep LC_RPATH -A 3  # does not have rpath reference
read -p "Press Enter to continue"

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib lib/pkcs11/yubihsm_pkcs11.dylib
install_name_tool -rpath /Users/runner/work/yubihsm-shell/yubihsm-shell/yubihsm-shell-$RELEASE_VERSION/resources/release/macos/yubihsm-shell-darwin-$ARCH-$RELEASE_VERSION/usr/local/lib @loader_path/../lib lib/pkcs11/yubihsm_pkcs11.dylib
otool -L lib/pkcs11/yubihsm_pkcs11.dylib
otool -l lib/pkcs11/yubihsm_pkcs11.dylib | grep LC_RPATH -A 3
read -p "Press Enter to continue"

otool -L lib/libz.1.dylib
otool -l lib/libz.1.dylib | grep LC_RPATH -A 3 # does not have rpath reference
read -p "Press Enter to continue"

# Sign binaries
read -p "DO NOW: Insert signing key then press Enter to continue"
codesign -f --timestamp --options runtime --sign 'Application' lib/libcrypto.3.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libusb-1.0.0.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libz-1.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libykhsmauth.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libyubihsm.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libyubihsm_http.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/libyubihsm_usb.$RELEASE_VERSION.dylib
codesign -f --timestamp --options runtime --sign 'Application' lib/pkcs11/yubihsm_pkcs11.dylib
codesign -f --timestamp --options runtime --sign 'Application' bin/yubihsm-shell
codesign -f --timestamp --options runtime --sign 'Application' bin/yubihsm-auth
codesign -f --timestamp --options runtime --sign 'Application' bin/yubihsm-wrap
echo "\nDO NOW: Remove signing key"
read -p "Press Enter to continue"

# Verify signature
codesign -dv --verbose=4 lib/libcrypto.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libusb-1.0.0.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libz.1.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libykhsmauth.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libyubihsm.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libyubihsm_http.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/libyubihsm_usb.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 lib/pkcs11/yubihsm_pkcs11.dylib
read -p "Press Enter to continue"
codesign -dv --verbose=4 bin/yubihsm-shell
read -p "Press Enter to continue"
codesign -dv --verbose=4 bin/yubihsm-auth
read -p "Press Enter to continue"
codesign -dv --verbose=4 bin/yubihsm-wrap
read -p "Press Enter to continue"

# Include licenses
ls share/licenses/yubihsm-shell
echo "\nDO NOW: Make sure that the share/licenses/yubihsm-shell directory includes licenses for yubihsm-shell, OpenSSL and libusb"
read -p "Press Enter to continue"

# Made installer
cd $MAC_DIR
pkgbuild --root=$PKG_DIR/root --identifier "com.yubico.yubihsm-shell" $PKG_DIR/comp/yubihsm-shell.pkg
productbuild  --package-path $PKG_DIR/comp/yubihsm-shell.pkg --distribution distribution.xml --resources $PKG_DIR/resources yubihsm-shell-$RELEASE_VERSION-$ARCH.pkg

read -p "DO NOW: Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubihsm-shell-$RELEASE_VERSION-$ARCH.pkg yubihsm-shell-$RELEASE_VERSION-$ARCH-signed.pkg
echo "\nDO NOW: Remove signing key"