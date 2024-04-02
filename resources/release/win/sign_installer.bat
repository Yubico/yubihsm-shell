SETLOCAL

set CERTHASH="107533FA07911D8BB375459B804DABA89CC61E77"
set SIGNCMD=signtool sign /ph /fd "SHA256" /sha1 %CERTHASH% /t "http://timestamp.digicert.com"

%SIGNCMD% /d "YubiHSM Shell Installer (x64)" yubihsm-shell-x64.msi
%SIGNCMD% /d "YubiHSM Shell Installer (x86)" yubihsm-shell-x86.msi