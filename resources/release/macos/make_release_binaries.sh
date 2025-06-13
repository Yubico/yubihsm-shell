#!/usr/bin/env bash
set -e -o pipefail
set -x

ARCH=$1 # amd or arm
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SO_VERSION=$3
SOURCE_DIR=$4 # Path to the source tarball, e.g. yubihsm-shell-2.1.0.tar.gz

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

echo "BREW_LIB: $BREW_LIB"
export PKG_CONFIG_PATH=$BREW_LIB/openssl/lib/pkgconfig

OUTPUT=$PWD/yubihsm-shell-darwin-$ARCH-$VERSION/usr/local
LICENSE_DIR=$OUTPUT/licenses

cd $SOURCE_DIR
mkdir build; cd build
cmake -DRELEASE_BUILD=1 -DWITHOUT_YKYH=1 -DWITHOUT_MANPAGES=1 -DCMAKE_INSTALL_PREFIX="$OUTPUT/" ..
make install

cd $OUTPUT

cp -r $BREW_LIB/openssl/include/openssl include/
cp $BREW_LIB/openssl/lib/libcrypto.3.dylib lib/
cp $BREW_LIB/libusb/lib/libusb-1.0.0.dylib lib/
cp $BREW_LIB/zlib/lib/libz.1.dylib lib/

chmod +w $OUTPUT/lib/libcrypto.3.dylib
chmod +w $OUTPUT/lib/libusb-1.0.0.dylib
chmod +w $OUTPUT/lib/libz.1.dylib

install_name_tool -id @loader_path/../lib/libcrypto.3.dylib lib/libcrypto.3.dylib
otool -L lib/libcrypto.3.dylib
#otool -l lib/libcrypto.3.dyli/b | grep LC_RPATH -A 3

install_name_tool -id @loader_path/../lib/libusb-1.0.0.dylib lib/libusb-1.0.0.dylib
otool -L lib/libusb-1.0.0.dylib

install_name_tool -id @loader_path/../lib/libz.1.dylib lib/libz.1.dylib
otool -L lib/libz.1.dylib

install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib lib/libyubihsm.$VERSION.dylib
install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "lib/libyubihsm.$VERSION.dylib"
otool -L lib/libyubihsm.$VERSION.dylib
#otool -l lib/libyubihsm.$VERSION.dylib | grep LC_RPATH -A 3

install_name_tool -change $BREW_LIB/libusb/lib/libusb-1.0.0.dylib  @loader_path/../lib/libusb-1.0.0.dylib lib/libyubihsm_usb.$VERSION.dylib
otool -L lib/libyubihsm_usb.$VERSION.dylib
#otool -l lib/libyubihsm_usb.$VERSION.dylib | grep LC_RPATH -A 3

install_name_tool -rpath $OUTPUT/lib @loader_path/../lib lib/pkcs11/yubihsm_pkcs11.dylib
install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "lib/pkcs11/yubihsm_pkcs11.dylib"
install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "lib/pkcs11/yubihsm_pkcs11.dylib"
otool -L lib/pkcs11/yubihsm_pkcs11.dylib
otool -l lib/pkcs11/yubihsm_pkcs11.dylib | grep LC_RPATH -A 3

install_name_tool -rpath $OUTPUT/lib @loader_path/../lib lib/libykhsmauth.dylib
otool -L lib/libykhsmauth.dylib
otool -l lib/libykhsmauth.dylib | grep LC_RPATH -A 3

install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubihsm-shell
install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "bin/yubihsm-shell"
install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "bin/yubihsm-shell"
otool -L bin/yubihsm-shell
otool -l bin/yubihsm-shell | grep LC_RPATH -A 3

install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubihsm-wrap
install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "bin/yubihsm-wrap"
install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "bin/yubihsm-wrap"
otool -L bin/yubihsm-wrap
otool -l bin/yubihsm-wrap | grep LC_RPATH -A 3

install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubihsm-auth
install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "bin/yubihsm-auth"
otool -L bin/yubihsm-auth
otool -l bin/yubihsm-auth | grep LC_RPATH -A 3

for file in `find $OUTPUT/lib $OUTPUT/bin -type f`; do
  if otool -L $file | grep -q '$OUTPUT'; then
    echo "ERROR: $file is incorrectly linked, paths contain $OUTPUT"
    exit 1
  fi
done