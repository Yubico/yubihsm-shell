SETLOCAL

set CROSSCERT="C:\Program Files (x86)\Windows Kits\10\crosscertificates\DigiCert_High_Assurance_EV_Root_CA.crt"
set CERTHASH="e3d2c802499e8837c3affdb6ca3c4448497ae317"
set SIGNCMD=signtool sign /ph /fd "SHA256" /ac %CROSSCERT% /sha1 %CERTHASH% /t "http://timestamp.digicert.com"

%SIGNCMD% /d "YubiHSM Shell Installer (x64)" yubihsm-shell-x64.msi
%SIGNCMD% /d "YubiHSM Shell Installer (x86)" yubihsm-shell-x86.msi