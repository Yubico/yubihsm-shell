#!/usr/bin/env bash
# ── Rewrite references to third-party deps in our own libraries ──
fix_deps() {
  local binary="$1"
  third_party_deps=(
  	"$BREW_LIB/openssl@3/lib/libcrypto.3.dylib:@rpath/libcrypto.3.dylib"
  	"$BREW_LIB/openssl/lib/libcrypto.3.dylib:@rpath/libcrypto.3.dylib"
  	"/usr/lib/libz.1.dylib:@rpath/libz.1.dylib"
  	"$BREW_LIB/libusb/lib/libusb-1.0.0.dylib:@rpath/libusb-1.0.0.dylib"
  	"$BREW_LIB/zlib/lib/libz.1.dylib:@rpath/libz.1.dylib")
  # Only change paths that are actually present in the binary
  for change in "${!third_party_deps[@]}"; do
    old="${change%%:*}"
    new="${change##*:}"
    # install_name_tool fails if the old path isn't found, so check first
    if otool -L "$binary" | grep -qF "$old"; then
      install_name_tool -change "$old" "$new" "$binary"
    fi
  done
}

fix_rpath() {
  local binary="$1"
  local new_rpath="$2"

  # Find and replace the absolute build-time rpath
  local old_rpath
  old_rpath=$(otool -l "$binary" | grep -A2 'LC_RPATH' | grep 'path ' | awk '{print $2}' | head -1)

  if [ -n "$old_rpath" ] && [ "$old_rpath" != "$new_rpath" ]; then
    install_name_tool -rpath "$old_rpath" "$new_rpath" "$binary"
  fi
}


if [ "$#" -ne 3 ]; then
    echo "This script builds release binaries for MacOS. Output files will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_release_binaries.sh <amd|arm> <RELEASE VERSION> <SOURCECODE DIRECTORY>"
    echo "";
    exit 0
fi

set -e -o pipefail
set -x

ARCH=$1 # amd or arm
VERSION=$2 # Full yubico-piv-tool version, tex 2.1.0
SOURCE_DIR=$3 # Path to the source tarball, e.g. yubihsm-shell-2.1.0.tar.gz

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

# ── Fix third-party dylib install names to use @rpath ──
install_name_tool -id @rpath/libcrypto.3.dylib lib/libcrypto.3.dylib
install_name_tool -id @rpath/libusb-1.0.0.dylib lib/libusb-1.0.0.dylib
install_name_tool -id @rpath/libz.1.dylib lib/libz.1.dylib

# Fix all our dylibs and executables
for f in \
  lib/libyubihsm.${VERSION}.dylib \
  lib/libyubihsm_usb.${VERSION}.dylib \
  lib/libyubihsm_http.${VERSION}.dylib \
  lib/libykhsmauth.dylib \
  lib/pkcs11/yubihsm_pkcs11.dylib \
  bin/yubihsm-shell \
  bin/yubihsm-wrap \
  bin/yubihsm-auth
do
  [ -f "$f" ] && fix_deps "$f"
done

# Executables in bin/ → libs in ../lib
for f in bin/yubihsm-shell bin/yubihsm-wrap bin/yubihsm-auth; do
  [ -f "$f" ] && fix_rpath "$f" "@loader_path/../lib"
done

# PKCS#11 module in lib/pkcs11/ → libs in ..
fix_rpath "lib/pkcs11/yubihsm_pkcs11.dylib" "@loader_path/.."

# Libraries in lib/ that have an rpath (libykhsmauth)
for f in lib/libykhsmauth.dylib; do
  [ -f "$f" ] && fix_rpath "$f" "@loader_path/../lib"
done

# ── Verify: no absolute paths should remain ──
echo ""
echo "=== Verification ==="
ERRORS=0
for file in $(find "$OUTPUT/lib" "$OUTPUT/bin" -type f -name '*.dylib' -o -name 'yubihsm-*'); do
  if otool -L "$file" 2>/dev/null | grep -qE '^\s+(\/usr\/local|\/opt\/homebrew|\/Users\/)'; then
    echo "ERROR: $file has absolute dependency paths:"
    otool -L "$file" | grep -E '^\s+(\/usr\/local|\/opt\/homebrew|\/Users\/)'
    ERRORS=1
  fi
  if otool -l "$file" 2>/dev/null | grep -A2 'LC_RPATH' | grep -qE 'path\s+(\/usr\/local|\/opt\/homebrew|\/Users\/)'; then
    echo "ERROR: $file has absolute rpath:"
    otool -l "$file" | grep -A2 'LC_RPATH'
    ERRORS=1
  fi
done

if [ "$ERRORS" -eq 1 ]; then
  echo "FAILED: Some binaries still have absolute paths"
  exit 1
else
  echo "OK: All binaries have relative paths"
fi

# install_name_tool -id @loader_path/../lib/libcrypto.3.dylib lib/libcrypto.3.dylib
# otool -L lib/libcrypto.3.dylib
# #otool -l lib/libcrypto.3.dyli/b | grep LC_RPATH -A 3
#
# install_name_tool -id @loader_path/../lib/libusb-1.0.0.dylib lib/libusb-1.0.0.dylib
# otool -L lib/libusb-1.0.0.dylib
#
# install_name_tool -id @loader_path/../lib/libz.1.dylib lib/libz.1.dylib
# otool -L lib/libz.1.dylib
#
# install_name_tool -change $BREW_LIB/openssl@3/lib/libcrypto.3.dylib @loader_path/../lib/libcrypto.3.dylib lib/libyubihsm.$VERSION.dylib
# install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "lib/libyubihsm.$VERSION.dylib"
# otool -L lib/libyubihsm.$VERSION.dylib
# #otool -l lib/libyubihsm.$VERSION.dylib | grep LC_RPATH -A 3
#
# install_name_tool -change $BREW_LIB/libusb/lib/libusb-1.0.0.dylib  @loader_path/../lib/libusb-1.0.0.dylib lib/libyubihsm_usb.$VERSION.dylib
# otool -L lib/libyubihsm_usb.$VERSION.dylib
# #otool -l lib/libyubihsm_usb.$VERSION.dylib | grep LC_RPATH -A 3
#
# install_name_tool -rpath $OUTPUT/lib @loader_path/../lib lib/pkcs11/yubihsm_pkcs11.dylib
# install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "lib/pkcs11/yubihsm_pkcs11.dylib"
# install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "lib/pkcs11/yubihsm_pkcs11.dylib"
# otool -L lib/pkcs11/yubihsm_pkcs11.dylib
# otool -l lib/pkcs11/yubihsm_pkcs11.dylib | grep LC_RPATH -A 3
#
# install_name_tool -rpath $OUTPUT/lib @loader_path/../lib lib/libykhsmauth.dylib
# otool -L lib/libykhsmauth.dylib
# otool -l lib/libykhsmauth.dylib | grep LC_RPATH -A 3
#
# install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubihsm-shell
# install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "bin/yubihsm-shell"
# install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "bin/yubihsm-shell"
# otool -L bin/yubihsm-shell
# otool -l bin/yubihsm-shell | grep LC_RPATH -A 3
#
# install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubihsm-wrap
# install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "bin/yubihsm-wrap"
# install_name_tool -change "/usr/lib/libz.1.dylib" "@loader_path/../lib/libz.1.dylib" "bin/yubihsm-wrap"
# otool -L bin/yubihsm-wrap
# otool -l bin/yubihsm-wrap | grep LC_RPATH -A 3
#
# install_name_tool -rpath $OUTPUT/lib @loader_path/../lib bin/yubihsm-auth
# install_name_tool -change "$BREW_LIB/openssl@3/lib/libcrypto.3.dylib" "@loader_path/../lib/libcrypto.3.dylib" "bin/yubihsm-auth"
# otool -L bin/yubihsm-auth
# otool -l bin/yubihsm-auth | grep LC_RPATH -A 3
#
# for file in `find $OUTPUT/lib $OUTPUT/bin -type f`; do
#   if otool -L $file | grep -q '$OUTPUT'; then
#     echo "ERROR: $file is incorrectly linked, paths contain $OUTPUT"
#     exit 1
#   fi
# done