#!/usr/bin/env bash
set -e -o pipefail
set -x

ARCH=$1 # amd or arm
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SO_VERSION=$3

if [ "$ARCH" == "amd" ]; then
  BREW_LIB="/usr/local/opt"
  BREW_CELLAR="/usr/local/Cellar"
elif [ "$ARCH" == "arm" ]; then
  BREW_LIB="/opt/homebrew/opt"
  BREW_CELLAR="/opt/homebrew/Cellar"
else
  echo "Unknown architecture"
  exit
fi

brew install cmake pkg-config gengetopt help2man openssl

export PKG_CONFIG_PATH=$BREW_LIB/openssl/lib/pkgconfig

SOURCE_DIR=$PWD
MAC_DIR=$SOURCE_DIR/resources/macos
OUTPUT=$MAC_DIR/yubihsm-shell-darwin-$ARCH-$VERSION/usr/local
LICENSE_DIR=$OUTPUT/licenses

cd $SOURCE_DIR
mkdir build; cd build
cmake -DRELEASE_BUILD=1 -DWITHOUT_YKYH=1 -DWITHOUT_MANPAGES=1 -DCMAKE_INSTALL_PREFIX="$OUTPUT/" ..
make install
cd $OUTPUT/lib
ln -s "libcrypto.1.1.dylib" "libcrypto.dylib"
cp "$BREW_LIB/openssl/lib/libcrypto.1.1.dylib" "$OUTPUT/lib"
chmod +w "$OUTPUT/lib/libcrypto.1.1.dylib"
cp -r $BREW_CELLAR/openssl@1.1/1.1.1*/include/openssl "$OUTPUT/include"

install_name_tool -id "@loader_path/../lib/libyubihsm.2.dylib" "$OUTPUT/lib/libyubihsm.2.dylib"
install_name_tool -id "@loader_path/../lib/libyubihsm_usb.2.dylib" "$OUTPUT/lib/libyubihsm_usb.2.dylib"
install_name_tool -id "@loader_path/../lib/libyubihsm_http.2.dylib" "$OUTPUT/lib/libyubihsm_http.2.dylib"
install_name_tool -id "@loader_path/../lib/libykhsmauth.2.dylib" "$OUTPUT/lib/libykhsmauth.2.dylib"
install_name_tool -id "@loader_path/../lib/pkcs11/yubihsm_pkcs11.dylib" "$OUTPUT/lib/pkcs11/yubihsm_pkcs11.dylib"
install_name_tool -id "@loader_path/../lib/libcrypto.1.1.dylib" "$OUTPUT/lib/libcrypto.1.1.dylib"

install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/lib/libyubihsm.2.dylib"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/lib/libyubihsm_usb.2.dylib"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/lib/libyubihsm_http.2.dylib"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/lib/libykhsmauth.2.dylib"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/lib/pkcs11/yubihsm_pkcs11.2.dylib"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/bin/yubihsm-shell"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/bin/yubihsm-wrap"
install_name_tool -add_rpath "@loader_path/../lib" "$OUTPUT/bin/yubihsm-auth"

install_name_tool -change "$BREW_LIB/openssl@1.1/lib/libcrypto.1.1.dylib" "@loader_path/../lib/libcrypto.1.1.dylib" "$OUTPUT/lib/libyubihsm.2.dylib"

install_name_tool -change "$OUTPUT/lib/libyubihsm.2.dylib" "@loader_path/../lib/libyubihsm.2.dylib" "$OUTPUT/lib/pkcs11/yubihsm_pkcs11.dylib"
install_name_tool -change "$BREW_LIB/openssl@1.1/lib/libcrypto.1.1.dylib" "@loader_path/../lib/libcrypto.1.1.dylib" "$OUTPUT/lib/pkcs11/yubihsm_pkcs11.dylib"

install_name_tool -change "$BREW_LIB/openssl@1.1/lib/libcrypto.1.1.dylib" "@loader_path/../lib/libcrypto.1.1.dylib" "$OUTPUT/bin/yubihsm-wrap"
install_name_tool -change "$OUTPUT/lib/libyubihsm.2.dylib" "@loader_path/../lib/libyubihsm.2.dylib" "$OUTPUT/bin/yubihsm-wrap"

install_name_tool -change "$BREW_LIB/openssl@1.1/lib/libcrypto.1.1.dylib" "@loader_path/../lib/libcrypto.1.1.dylib" "$OUTPUT/bin/yubihsm-shell"
install_name_tool -change "$OUTPUT/lib/libyubihsm.2.dylib" "@loader_path/../lib/libyubihsm.2.dylib" "$OUTPUT/bin/yubihsm-shell"
install_name_tool -delete_rpath "$OUTPUT/lib/" "$OUTPUT/bin/yubihsm-shell"

install_name_tool -change "$BREW_LIB/openssl@1.1/lib/libcrypto.1.1.dylib" "@loader_path/../lib/libcrypto.1.1.dylib" "$OUTPUT/bin/yubihsm-auth"
install_name_tool -change "$OUTPUT/lib/libykhsmauth.2.dylib" "@loader_path/../lib/libykhsmauth.2.dylib" "$OUTPUT/bin/yubihsm-auth"
install_name_tool -delete_rpath "$OUTPUT/lib/" "$OUTPUT/bin/yubihsm-auth"rkblvvfevvkdltdnhfjtfujlvncjeivu


for file in `find $OUTPUT/lib $OUTPUT/bin -type f`; do
  if otool -L $file | grep -q '$OUTPUT'; then
    echo "ERROR: $file is incorrectly linked, paths contain $OUTPUT"
    exit 1
  fi
done