#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1

if [ "$PLATFORM" == "centos7" ]; then
  yum -y install centos-release-scl
  yum -y update && yum -y upgrade

  # devtoolset-7-gcc devtoolset-7-gcc-c++
#  yum -y install gcc gcc-c++          \
#                 devtoolset-7-make    \
#                 chrpath              \
#                 git                  \
#                 cmake                \
#                 openssl-devel        \
#                 libedit-devel        \
#                 libcurl-devel        \
#                 libusbx-devel        \
#                 rpm-build            \
#                 redhat-rpm-config    \
#                 pcsc-lite-devel

  yum -y install gcc gcc-c++     \
                 cmake           \
                 gengetopt       \
                 openssl         \
                 openssl-devel   \
                 libedit-devel   \
                 libcurl-devel   \
                 libusbx-devel   \
                 pcsc-lite-devel \
                 help2man        \
                 chrpath         \
                 rpm-build       \
                 redhat-rpm-config

#  . /opt/rh/devtoolset-7/enable

  GENGETOPT_VER=2.23
  curl -o gengetopt-${GENGETOPT_VER}.rpm https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/g/gengetopt-2.23-1.el7.x86_64.rpm
  yum -y install ./gengetopt-${GENGETOPT_VER}.rpm

  export CMAKE="cmake"

elif [ "$PLATFORM" == "centos8" ]; then
  yum -y install epel-release
  yum -y update && yum -y upgrade

  dnf group -y install "Development Tools"
  dnf config-manager -y --set-enabled powertools

  yum -y install chrpath              \
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
  dnf -y update
  dnf -y install binutils         \
                 gcc              \
                 gcc-c++          \
                 chrpath          \
                 cmake            \
                 gengetopt        \
                 openssl-devel    \
                 libedit-devel    \
                 libcurl-devel    \
                 rpmdevtools      \
                 pcsc-lite-devel

  if [ $PLATFORM == "fedora37" ]; then
    dnf -y install libusb1-devel
  else
    dnf -y install libusb-devel
  fi

  export CMAKE="cmake"
fi
