#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update && sudo  apt-get dist-upgrade -y
sudo apt-get install -y build-essential      \
                        chrpath              \
                        git                  \
                        cmake                \
                        pkg-config           \
                        gengetopt            \
                        help2man             \
                        libedit-dev          \
                        libcurl4-openssl-dev \
                        liblzma-dev          \
                        libssl-dev           \
                        libseccomp-dev       \
                        libusb-1.0.0-dev     \
                        dh-exec              \
                        git-buildpackage     \
                        curl                 \
                        libpcsclite-dev




export INPUT=/shared/
export OUTPUT=/shared/resources/release/linux/build/$PLATFORM/yubihsm-shell
rm -rf $OUTPUT
mkdir -p $OUTPUT

pushd "/tmp" &>/dev/null
  rm -rf yubihsm-shell
  git clone "$INPUT" yubihsm-shell
  pushd "yubihsm-shell" &>/dev/null
    if [ "${PLATFORM:0:6}" == "debian" ] || [ "$PLATFORM" == "ubuntu1804" ]; then
      dpkg-buildpackage -b --no-sign
    else
      dpkg-buildpackage
    fi

  popd &>/dev/null
  cp *.deb $OUTPUT
popd &>/dev/null

LICENSE_DIR="$OUTPUT/share/yubihsm-shell"
mkdir -p $LICENSE_DIR
pushd "/shared" &>/dev/null
  cp -r resources/release/linux/licenses $LICENSE_DIR/
  for lf in $LICENSE_DIR/licenses/*; do
	  chmod 644 $lf
  done

  pushd "$OUTPUT" &>/dev/null
    rm -f yubihsm-shell-$PLATFORM-amd64.tar.gz
    tar -C .. -zcvf ../yubihsm-shell-$PLATFORM-amd64.tar.gz yubihsm-shell
    rm -f *.deb
    rm -rf licenses
    rm -rf ../yubihsm-shell
  popd &>/dev/null
popd &>/dev/null