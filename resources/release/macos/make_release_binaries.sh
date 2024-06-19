#!/usr/bin/env bash
set -e -o pipefail
set -x

ARCH=$1 # amd or arm
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SO_VERSION=$3

BREW_LIB="/opt/homebrew/opt"

export PKG_CONFIG_PATH=$BREW_LIB/openssl/lib/pkgconfig

SOURCE_DIR=$PWD
MAC_DIR=$SOURCE_DIR/resources/release/macos
OUTPUT=$MAC_DIR/yubihsm-shell-darwin-$ARCH-$VERSION/usr/local
LICENSE_DIR=$OUTPUT/licenses

cd $SOURCE_DIR
mkdir build; cd build
cmake -DRELEASE_BUILD=1 -DWITHOUT_YKYH=1 -DWITHOUT_MANPAGES=1 -DCMAKE_INSTALL_PREFIX="$OUTPUT/" ..
make install
cd $OUTPUT/lib
ln -s "libcrypto.3.dylib" "libcrypto.dylib"
cp "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "$OUTPUT/lib"
chmod +w "$OUTPUT/lib/libcrypto.3.dylib"
cp -r $BREW_LIB/openssl/include/openssl "$OUTPUT/include"

install_name_tool -id "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/lib/libcrypto.3.dylib"

install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/lib/libyubihsm.dylib"
install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/lib/libyubihsm.$VERSION.dylib"
install_name_tool -change "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/lib/libyubihsm.$SO_VERSION.dylib"

install_name_tool -change "$BREW_LIB/libusb/lib/libusb-1.0.0.dylib"  "@loader_path/../lib/libusb-1.0.0.dylib" "$OUTPUT/lib/libyubihsm_usb.dylib"
install_name_tool -change "$BREW_LIB/libusb/lib/libusb-1.0.0.dylib"  "@loader_path/../lib/libusb-1.0.0.dylib" "$OUTPUT/lib/libyubihsm_usb.$VERSION.dylib"
install_name_tool -change "$BREW_LIB/libusb/lib/libusb-1.0.0.dylib"  "@loader_path/../lib/libusb-1.0.0.dylib" "$OUTPUT/lib/libyubihsm_usb.$SO_VERSION.dylib"

install_name_tool -change "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/lib/pkcs11/yubihsm_pkcs11.dylib"

install_name_tool -change "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/bin/yubihsm-shell"
install_name_tool -change "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/bin/yubihsm-wrap"
install_name_tool -change "$BREW_LIB/openssl/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "$OUTPUT/bin/yubihsm-auth"

for file in `find $OUTPUT/lib $OUTPUT/bin -type f`; do
  if otool -L $file | grep -q '$OUTPUT'; then
    echo "ERROR: $file is incorrectly linked, paths contain $OUTPUT"
    exit 1
  fi
done