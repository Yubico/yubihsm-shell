# This script runs on Powershell. If running tests on the current Powershell terminal is not permitted, run the
# following command to allow it only on the current terminal:
#       >> Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

if($args.length -eq 0) {
    echo "Usage: ./opensc_tests.ps1 <path to PKCS11 module>"
    echo ""
    echo "This script expects that libyubihsm.dll and the libcrypto.dll are on PATH and YUBIHSM_PKCS11_CONF environment variable is defined"
    exit
}

if ((Get-Command "pkcs11-tool.exe" -ErrorAction SilentlyContinue) -eq $null)
{
    $env:Path +=";C:\Program Files\OpenSC Project\OpenSC\tools"
}

$MODULE=$args[0]
#$YHPKCS11CFG=$args[2]

#$env:YUBIHSM_PKCS11_CONF=$YHPKCS11CFG

Set-PSDebug -Trace 1

echo "******************* Generation Tests ********************* "
pkcs11-tool.exe --module $MODULE --login --pin 0001password --keypairgen --id 100 --key-type EC:secp384r1
pkcs11-tool.exe --module $MODULE --login --pin 0001password --keypairgen --id 2 --key-type EC:prime256v1
pkcs11-tool.exe --module $MODULE --login --pin 0001password --keypairgen --id 4 --key-type rsa:2048
pkcs11-tool.exe --module $MODULE --login --pin 0001password --keypairgen --id 5 --key-type rsa:3072
#Set-PSDebug -Trace 0
#exit
echo "******************* Signing Tests ********************* "
echo "this is test data" > Z:/data.txt
pkcs11-tool.exe --module $MODULE --sign --pin 0001password --id 100 -m ECDSA-SHA1 --signature-format openssl -i Z:/data.txt -o Z:/data.sig
pkcs11-tool.exe --module $MODULE --sign --pin 0001password --id 2 -m ECDSA-SHA1 --signature-format openssl -i Z:/data.txt -o Z:/data.sig
pkcs11-tool.exe --module $MODULE --sign --pin 0001password --id 4 -m SHA512-RSA-PKCS -i Z:/data.txt -o Z:/data.sig
pkcs11-tool.exe --module $MODULE --sign --pin 0001password --id 5 -m SHA512-RSA-PKCS -i Z:/data.txt -o Z:/data.sig
rm Z:/data.txt
rm Z:/data.sig

echo "******************* Testing RSA Tests ********************* "
pkcs11-tool.exe --module $MODULE --login --pin 0001password --test

#echo "******************* Testing EC Tests ********************* "
#pkcs11-tool.exe --module $MODULE --login --login-type so --so-pin 0001password --test-ec --id 200 --key-type EC:secp256r1

Set-PSDebug -Trace 0