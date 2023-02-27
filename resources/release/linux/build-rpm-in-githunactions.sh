#!/usr/bin/env bash
set -e -o pipefail
set -x

PLATFORM=$1

if [ "$PLATFORM" == "centos7" ]; then
  yum -y install centos-release-scl
  yum -y update && yum -y upgrade
  yum -y install devtoolset-7-gcc     \
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
                      libusb-devel     \
                      libedit-devel    \
                      libcurl-devel    \
                      rpmdevtools      \
                      pcsc-lite-devel

  export CMAKE="cmake"
fi


export INPUT=$GITHUB_WORKSPACE
export OUTPUT=$GITHUB_WORKSPACE/$PLATFORM/yubihsm-shell
rm -rf $OUTPUT
mkdir -p $OUTPUT

# These 2 lines can be replaced by the command "rpmdev-setuptree", but this command seems to add macros that force check paths that do not exist
mkdir -p $GITHUB_WORKSPACE/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo '%_topdir %(echo $HOME)/rpmbuild' > $GITHUB_WORKSPACE/.rpmmacros

RPM_DIR=$GITHUB_WORKSPACE/rpmbuild

echo "INPUT=$INPUT"
echo "OUTPUT=$OUTPUT"
ls $INPUT
echo "---------"
sleep 5
ls $INPUT/yubihsm-shell
echo "---------"
sleep 5



cp yubihsm-shell-in-githubactions.spec $RPM_DIR/SPECS/

QA_SKIP_BUILD_ROOT=1 QA_RPATHS=$(( 0x0001|0x0010 )) rpmbuild -bb $RPM_DIR/SPECS/yubihsm-shell-in-githubactions.spec
sleep 5
ls
sleep 5
cp /github/home/rpmbuild/RPMS/x86_64/*.rpm $OUTPUT
sleep 5
LICENSE_DIR="$OUTPUT/share/yubihsm-shell"
mkdir -p $LICENSE_DIR

cd $INPUT
cp -r yubihsm-shell/resources/release/linux/licenses $LICENSE_DIR/
for lf in $LICENSE_DIR/licenses/*; do
 chmod 644 $lf
done

cd $OUTPUT
rm -f "yubihsm-shell-$PLATFORM-amd64.tar.gz"
tar -C ".." -zcvf "../yubihsm-shell-$PLATFORM-amd64.tar.gz" "yubihsm-shell"
rm -f *.rpm
rm -rf licenses
rm -rf ../yubihsm-shell
