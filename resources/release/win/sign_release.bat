SETLOCAL

set CROSSCERT="C:\Program Files (x86)\Windows Kits\10\crosscertificates\DigiCert_High_Assurance_EV_Root_CA.crt"
set CERTHASH="e3d2c802499e8837c3affdb6ca3c4448497ae317"
set CERTHASHSTD="DD86A2E1383B0E4E1C823B606DDBBCC26E1FF82D"

set SIGNCMD=signtool sign /ph /fd "SHA256" /ac %CROSSCERT% /sha1 %CERTHASH% /t "http://timestamp.digicert.com"
set SIGNCMDSTD=signtool sign /ph /fd "SHA256" /sha1 %CERTHASHSTD% /t "http://timestamp.digicert.com"

rem Sign x64 components
%SIGNCMD% yubihsm-shell-x64\bin\libyubihsm.dll
%SIGNCMD% yubihsm-shell-x64\bin\libyubihsm_http.dll
%SIGNCMD% yubihsm-shell-x64\bin\libyubihsm_usb.dll
%SIGNCMD% yubihsm-shell-x64\bin\pkcs11\yubihsm_pkcs11.dll
%SIGNCMD% yubihsm-shell-x64\bin\ykhsmauth.dll
%SIGNCMD% /d "YubiHSM Authenication" yubihsm-shell-x64\bin\yubihsm-auth.exe
%SIGNCMD% /d "YubiHSM Shell" yubihsm-shell-x64\bin\yubihsm-shell.exe
%SIGNCMD% /d "YubiHSM Wrap" yubihsm-shell-x64\bin\yubihsm-wrap.exe

rem Sign x86 components
%SIGNCMD% yubihsm-shell-x86\bin\libyubihsm.dll
%SIGNCMD% yubihsm-shell-x86\bin\libyubihsm_http.dll
%SIGNCMD% yubihsm-shell-x86\bin\libyubihsm_usb.dll
%SIGNCMD% yubihsm-shell-x86\bin\pkcs11\yubihsm_pkcs11.dll
%SIGNCMD% yubihsm-shell-x86\bin\ykhsmauth.dll
%SIGNCMD% /d "YubiHSM Authenication" yubihsm-shell-x86\bin\yubihsm-auth.exe
%SIGNCMD% /d "YubiHSM Shell" yubihsm-shell-x86\bin\yubihsm-shell.exe
%SIGNCMD% /d "YubiHSM Wrap" yubihsm-shell-x86\bin\yubihsm-wrap.exe

rem Sign "standard open source" components (not from Yubico Source)
%SIGNCMDSTD% yubihsm-shell-x64\bin\getopt.dll
%SIGNCMDSTD% yubihsm-shell-x64\bin\libcrypto-3-x64.dll
%SIGNCMDSTD% yubihsm-shell-x86\bin\getopt.dll
%SIGNCMDSTD% yubihsm-shell-x86\bin\libcrypto-3.dll
