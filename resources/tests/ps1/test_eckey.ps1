$ARCH=$args[0]
if($ARCH -eq "x86")
{
    if ((Get-Command "yubihsm-shell.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files (x86)/Yubico/YubiHSM Shell/bin;C:/Users/dev/vcpkg/vcpkg-master/packages/openssl-windows_x86-windows/bin"
    }
}
elseif ($ARCH -eq "x64")
{
    if ((Get-Command "yubihsm-shell.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files/Yubico/YubiHSM Shell/bin;C:/Users/dev/vcpkg/vcpkg-master/packages/openssl-windows_x64-windows/bin"
    }
}
else {
    echo "Usage: ./cmdline_test.ps1 <x86|x64>"
    echo ""
    echo "This is a test script that uses the yubihsm-shell command line tool to reset the conncted YubiHSM and then
           different commands."
    echo ""
    echo "   x86        expects that yubihsm-shell.exe is installed in 'C:/Program Files (x86)/Yubico/Yubico PIV Tool/bin'"
    echo "   x64        expects that yubhsm-shell.exe is installed in 'C:/Program Files/Yubico/Yubico PIV Tool/bin'"
    exit
}

$env:Path += ";C:\Users\dev\vcpkg\vcpkg-master\packages\openssl-windows_x64-windows\tools\openssl"

echo "Running commands on $ARCH architecture"

$TEST_DIR = "yubihsm-shell_test_dir"
Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue
New-Item $TEST_DIR -type Directory -Force
cd $TEST_DIR
echo "test signing data" > data.txt
Set-PSDebug -Trace 1
$ErrorActionPreference = "Stop"

function CheckExitStatus {
    param (
        $ECode
    )
    if(!$ECode) {
        echo "Fail!"
        exit
    }
}

$keyid=100
$import_keyid=200

echo "---------------------- EC keys --------------------- "
# ECP224
echo "**********************************"
echo "            ECP224"
echo "**********************************"
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecp224"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t asymmetric-key > info.txt; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "id: 0x0064"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "type: asymmetric-key"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "algorithm: ec224df"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern 'label: "ecKey"'; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "domains: 5:8:13"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "origin: generated"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "capabilities: derive-ecdh:sign-attestation-certificate:sign-ecdsa"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name secp224r1 -noout -out secp224r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "2,6,7" -c "sign-ecdsa,sign-attestation-certificate" --in=secp224r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
# -- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp224sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp224sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp224sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp224sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp224sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp224sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp224sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp224sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?

#-- Derive ECDH
openssl.exe ec -in secp224r1-keypair.pem -pubout -out secp224r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in secp224r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            ECP256"
echo "**********************************"
# ECP256
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecp256"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name secp256r1 -noout -out secp256r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp256r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp256sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp256sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp256sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp256sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp256sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp256sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp256sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp256sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in secp256r1-keypair.pem -pubout -out secp256r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in secp256r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            ECP384"
echo "**********************************"
# ECP384
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecp384"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name secp384r1 -noout -out secp384r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp384r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp384sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp384sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp384sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp384sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp384sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp384sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp384sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp384sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in secp384r1-keypair.pem -pubout -out secp384r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in secp384r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            ECP512"
echo "**********************************"
# ECP512
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecp521"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl ecparam -genkey -name secp521r1 -noout -out secp521r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp521r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecp521sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecp521sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecp521sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecp521sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecp521sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecp521sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecp521sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecp521sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in secp521r1-keypair.pem -pubout -out secp521r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in secp521r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            ECK256"
echo "**********************************"
# ECK256
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "eck256"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name secp256k1 -noout -out secp256k1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=secp256k1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.eck256sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.eck256sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.eck256sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.eck256sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.eck256sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.eck256sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.eck256sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.eck256sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in secp256k1-keypair.pem -pubout -out secp256k1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in secp256k1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            Brainpool256"
echo "**********************************"
# Brainpool256
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecbp256"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name brainpoolP256r1 -noout -out brainpool256r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=brainpool256r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecbp256sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecbp256sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecbp256sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecbp256sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecbp256sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecbp256sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecbp256sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecbp256sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in brainpool256r1-keypair.pem -pubout -out brainpool256r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in brainpool256r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            Brainpool384"
echo "**********************************"
# Brainpool384
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecbp384"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name brainpoolP384r1 -noout -out brainpool384r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=brainpool384r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecbp384sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecbp384sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecbp384sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecbp384sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecbp384sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecbp384sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecbp384sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecbp384sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in brainpool384r1-keypair.pem -pubout -out brainpool384r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in brainpool384r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

echo "**********************************"
echo "            Brainpool512"
echo "**********************************"
# Brainpool512
#-- Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "ecKey" -d "5,8,13" -c "sign-ecdsa,derive-ecdh,sign-attestation-certificate" -A "ecbp512"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Import
openssl.exe ecparam -genkey -name brainpoolP512r1 -noout -out brainpool512r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "ecKeyImport" -d "1,2,3,4,5" -c "sign-ecdsa,sign-attestation-certificate" --in=brainpool512r1-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM; CheckExitStatus -ECode $?
#-- Sign
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha1 --in data.txt > data.ecbp512sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha256 --in data.txt > data.ecbp512sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha384 --in data.txt > data.ecbp512sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $keyid -A ecdsa-sha512 --in data.txt > data.ecbp512sha512.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha1 --in data.txt > data.ecbp512sha1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha256 --in data.txt > data.ecbp512sha256.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha384 --in data.txt > data.ecbp512sha384.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-ecdsa -i $import_keyid -A ecdsa-sha512 --in data.txt > data.ecbp512sha512.sig; CheckExitStatus -ECode $?
#-- Get attestation certificate and a selfsigned certificate
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
rm selfsigned_cert.pem
#-- Sign attestation certificate
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
#-- Derive ECDH
openssl.exe ec -in brainpool512r1-keypair.pem -pubout -out brainpool512r1-pubkey.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a derive-ecdh -i $keyid --in brainpool512r1-pubkey.pem; CheckExitStatus -ECode $?
#-- Delete
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?

cd ..
Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue

Set-PSDebug -Trace 0