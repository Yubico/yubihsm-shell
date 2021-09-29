#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1

if [ "$PLATFORM" == "centos7" ]; then
  sudo yum -y install centos-release-scl
  sudo yum -y update && sudo yum -y upgrade
  sudo yum -y install devtoolset-7-gcc     \
                      devtoolset-7-gcc-c++ \
                      devtoolset-7-make    \
                      chrpath              \
                      git                  \
                      cmake                \
                      openssl-devel        \
                      libedit-devel        \
                      libcurl-devel        \
                      libusbx-devel        \
                      rpm-build            \
                      redhat-rpm-config    \
                      pcsc-lite-devel

  . /opt/rh/devtoolset-7/enable

  GENGETOPT_VER=2.23
  curl -o gengetopt-${GENGETOPT_VER}.rpm https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/g/gengetopt-2.23-1.el7.x86_64.rpm
  sudo yum -y install ./gengetopt-${GENGETOPT_VER}.rpm

  export CMAKE="cmake"

elif [ "$PLATFORM" == "centos8" ]; then
  sudo yum -y install epel-release
  sudo yum -y update && sudo yum -y upgrade

  sudo dnf group -y install "Development Tools"
  sudo dnf config-manager -y --set-enabled powertools

sudo yum -y install chrpath              \
                    git                  \
                    cmake3               \
                    gengetopt            \
                    libedit-devel        \
                    libcurl-devel        \
                    libusbx-devel        \
                    openssl-devel        \
                    pcsc-lite-devel

  export CMAKE="cmake3"

elif [ "${PLATFORM:0:6}" == "fedora" ]; then
  sudo dnf -y update
  sudo dnf -y install binutils         \
                      git              \
                      chrpath          \
                      cmake            \
                      gengetopt        \
                      openssl-devel    \
                      libusb-devel     \
                      libedit-devel    \
                      libcurl-devel    \
                      rpmdevtools      \
                      pcsc-lite-devel

  export CMAKE="cmake"
fi


export INPUT=/shared
export OUTPUT=/shared/resources/release/linux/build/$PLATFORM/yubihsm-shell
rm -rf $OUTPUT
mkdir -p $OUTPUT

# These 2 lines can be replaced by the command "rpmdev-setuptree", but this command seems to add macros that force check paths that do not exist
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

export RPM_DIR=~/rpmbuild
cp /shared/resources/release/linux/yubihsm-shell.spec $RPM_DIR/SPECS/

QA_SKIP_BUILD_ROOT=1 rpmbuild -bb $RPM_DIR/SPECS/yubihsm-shell.spec
cp $RPM_DIR/RPMS/x86_64/*.rpm $OUTPUT

LICENSE_DIR="$OUTPUT/share/yubihsm-shell"
mkdir -p $LICENSE_DIR
pushd "/shared" &>/dev/null
  cp -r resources/release/linux/licenses $LICENSE_DIR/
  for lf in $LICENSE_DIR/licenses/*; do
	  chmod 644 $lf
  done

  pushd "$OUTPUT" &>/dev/null
    rm -f "yubihsm-shell-$PLATFORM-amd64.tar.gz"
    tar -C ".." -zcvf "../yubihsm-shell-$PLATFORM-amd64.tar.gz" "yubihsm-shell"
    rm -f *.rpm
    rm -rf licenses
    rm -rf ../yubihsm-shell
  popd &>/dev/null
popd &>/dev/null
