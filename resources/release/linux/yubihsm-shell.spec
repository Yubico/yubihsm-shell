%global _yubihsm yubihsm

Name:		yubihsm-shell
Version:	2.3.1
Release:	1%{?dist}
Summary:	Tools to interact with YubiHSM 2

License:	Apache 2.0
URL:        https://github.com/Yubico/yubihsm-shell

%description
This package contains most of the components used to interact with the YubiHSM 2 at both a user-facing and
programmatic level. It contains the libyubihsm, yubihsm-shell, yubihsm-pkcs11, yubihsm-wrap and yubihsm-auth

%package -n %{_yubihsm}-devel
Summary: Development tools for interacting with YubiHSM 2

%description -n %{_yubihsm}-devel
Development libraries for working with yubihsm 2.

%prep
cd %{_builddir}
rm -rf *
git clone $INPUT/ .


%build
rm -rf build
mkdir build && cd build
$CMAKE -DRELEASE_BUILD=1 -DWITHOUT_YKYH=1 -DWITHOUT_MANPAGES=1 -DYUBIHSM_INSTALL_LIB_DIR="%{buildroot}/%{_prefix}/lib64/" -DYUBIHSM_INSTALL_INC_DIR="%{buildroot}/%{_prefix}/include/" -DYUBIHSM_INSTALL_BIN_DIR="%{buildroot}/%{_prefix}/bin/" -DYUBIHSM_INSTALL_MAN_DIR="%{buildroot}/%{_prefix}/man/" -DYUBIHSM_INSTALL_PKGCONFIG_DIR="%{buildroot}/%{_prefix}/lib64/pkgconfig/" ..
make

#Would be nice to use %license, but that macro does not seem to work on Centos, so the license needs to be installed manually

%install
rm -rf %{buildroot}
mkdir -p  %{buildroot}
cd build
make install
chrpath -r %{_libdir} %{buildroot}/%{_bindir}/yubihsm-shell
chrpath -r %{_libdir} %{buildroot}/%{_bindir}/yubihsm-wrap
chrpath -r %{_libdir} %{buildroot}/%{_bindir}/yubihsm-auth
chrpath -r %{_libdir} %{buildroot}/%{_libdir}/pkcs11/yubihsm_pkcs11.so
mkdir -p %{buildroot}/%{_prefix}/share/licenses/%{name}
install -m 0644 ../LICENSE %{buildroot}/%{_prefix}/share/licenses/%{name}


%files
%{_prefix}/share/licenses/%{name}/LICENSE
%{_bindir}/yubihsm-shell
%{_bindir}/yubihsm-wrap
%{_bindir}/yubihsm-auth
%{_libdir}/libyubihsm.so.2
%{_libdir}/libyubihsm.so.2.*
%{_libdir}/libyubihsm_http.so.2
%{_libdir}/libyubihsm_http.so.2.*
%{_libdir}/libyubihsm_usb.so.2
%{_libdir}/libyubihsm_usb.so.2.*
%{_libdir}/libykhsmauth.so.2
%{_libdir}/libykhsmauth.so.2.*
%dir %{_libdir}/pkcs11
%{_libdir}/pkcs11/yubihsm_pkcs11.so
%files -n %{_yubihsm}-devel
%{_libdir}/libyubihsm.so
%{_libdir}/libyubihsm_http.so
%{_libdir}/libyubihsm_usb.so
%{_libdir}/libykhsmauth.so
%{_includedir}/yubihsm.h
%{_includedir}/ykhsmauth.h
%dir %{_includedir}/pkcs11
%{_includedir}/pkcs11/pkcs11.h
%{_includedir}/pkcs11/pkcs11y.h
%{_libdir}/pkgconfig/yubihsm.pc
%{_libdir}/pkgconfig/ykhsmauth.pc


%changelog
* Wed Dec 1 2021 Aveen Ismail <aveen.ismail@yubico.com> - 2.3.0
- Releasing version 2.3.0
