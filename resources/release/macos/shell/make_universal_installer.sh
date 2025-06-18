#!/bin/bash

# Script to produce universal binaries for OSX by combining 2 binary sets
if [ "$#" -ne 3 ]; then
    echo "This script combines x86_64 and arm64 binaries into universal binaries for MacOS. Output files will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_universal_binaries.sh <path/to/x86_64_binaries> <path/to/arm64_binaries> <version number>"
    echo "";
    exit 0
fi

X86_64_DIR=$1 #pkg_amd
ARM64_DIR=$2 # pkg_arm
RELEASE_VERSION=$3

#set -x

cp -av $ARM64_DIR pkg_universal

lipo -create -output pkg_universal/root/usr/local/bin/yubihsm-shell  $X86_64_DIR/root/usr/local/bin/yubihsm-shell $ARM64_DIR/root/usr/local/bin/yubihsm-shell
lipo -create -output pkg_universal/root/usr/local/bin/yubihsm-auth  $X86_64_DIR/root/usr/local/bin/yubihsm-auth $ARM64_DIR/root/usr/local/bin/yubihsm-auth
lipo -create -output pkg_universal/root/usr/local/bin/yubihsm-wrap  $X86_64_DIR/root/usr/local/bin/yubihsm-wrap $ARM64_DIR/root/usr/local/bin/yubihsm-wrap

lipo -create -output pkg_universal/root/usr/local/lib/libcrypto.3.dylib  $X86_64_DIR/root/usr/local/lib/libcrypto.3.dylib $ARM64_DIR/root/usr/local/lib/libcrypto.3.dylib
lipo -create -output pkg_universal/root/usr/local/lib/libusb-1.0.0.dylib  $X86_64_DIR/root/usr/local/lib/libusb-1.0.0.dylib $ARM64_DIR/root/usr/local/lib/libusb-1.0.0.dylib
lipo -create -output pkg_universal/root/usr/local/lib/libz.1.dylib  $X86_64_DIR/root/usr/local/lib/libz.1.dylib $ARM64_DIR/root/usr/local/lib/libz.1.dylib
lipo -create -output pkg_universal/root/usr/local/lib/libykhsmauth.$RELEASE_VERSION.dylib  $X86_64_DIR/root/usr/local/lib/libykhsmauth.$RELEASE_VERSION.dylib $ARM64_DIR/root/usr/local/lib/libykhsmauth.$RELEASE_VERSION.dylib
lipo -create -output pkg_universal/root/usr/local/lib/libyubihsm.$RELEASE_VERSION.dylib  $X86_64_DIR/root/usr/local/lib/libyubihsm.$RELEASE_VERSION.dylib $ARM64_DIR/root/usr/local/lib/libyubihsm.$RELEASE_VERSION.dylib
lipo -create -output pkg_universal/root/usr/local/lib/libyubihsm_http.$RELEASE_VERSION.dylib  $X86_64_DIR/root/usr/local/lib/libyubihsm_http.$RELEASE_VERSION.dylib $ARM64_DIR/root/usr/local/lib/libyubihsm_http.$RELEASE_VERSION.dylib
lipo -create -output pkg_universal/root/usr/local/lib/libyubihsm_usb.$RELEASE_VERSION.dylib  $X86_64_DIR/root/usr/local/lib/libyubihsm_usb.$RELEASE_VERSION.dylib $ARM64_DIR/root/usr/local/lib/libyubihsm_usb.$RELEASE_VERSION.dylib
lipo -create -output pkg_universal/root/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib  $X86_64_DIR/root/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib $ARM64_DIR/root/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib

ls -l pkg_universal/root/usr/local/lib
read -p "Press Enter to continue"


lipo -archs pkg_universal/root/usr/local/bin/yubihsm-shell
lipo -archs pkg_universal/root/usr/local/bin/yubihsm-auth
lipo -archs pkg_universal/root/usr/local/bin/yubihsm-wrap
lipo -archs pkg_universal/root/usr/local/lib/libcrypto.dylib
lipo -archs pkg_universal/root/usr/local/lib/libusb-1.0.0.dylib
lipo -archs pkg_universal/root/usr/local/lib/libz.1.dylib
lipo -archs pkg_universal/root/usr/local/lib/libykhsmauth.dylib
lipo -archs pkg_universal/root/usr/local/lib/libyubihsm.dylib
lipo -archs pkg_universal/root/usr/local/lib/libyubihsm_http.dylib
lipo -archs pkg_universal/root/usr/local/lib/libyubihsm_usb.dylib
lipo -archs pkg_universal/root/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib
read -p "Press Enter to continue"

rm pkg_universal/comp/*

pkgbuild --root=pkg_universal/root --identifier "com.yubico.yubihsm-shell" --version "$RELEASE_VERSION" pkg_universal/comp/yubihsm-shell.pkg

productbuild  --package-path pkg_universal/comp --distribution distribution.xml yubihsm-shell-$RELEASE_VERSION-mac-universal.pkg

read -p "Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubihsm-shell-$RELEASE_VERSION-mac-universal.pkg yubihsm-shell-$RELEASE_VERSION-mac-universal-signed.pkg

#set +x