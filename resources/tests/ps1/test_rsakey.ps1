$ARCH=$args[0]
if($ARCH -eq "x86")
{
    if ((Get-Command "yubihsm-shell.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files (x86)/Yubico/YubiHSM Shell/bin"
    }
}
elseif ($ARCH -eq "x64")
{
    if ((Get-Command "yubihsm-shell.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        $env:Path += ";C:/Program Files/Yubico/YubiHSM Shell/bin"
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

echo "---------------------- RSA keys --------------------- "
echo "**********************************"
echo "            RSA2048"
echo "**********************************"
echo "=== Generate on YubiHSM"
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "rsaKey" -d "1" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" -A "rsa2048"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t asymmetric-key > info.txt; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "id: 0x0064"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "type: asymmetric-key"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "algorithm: rsa2048"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern 'label: "rsaKey"'; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "domains: 1"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "origin: generated"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"; CheckExitStatus -ECode $?
rm info.txt
echo "=== Get public key of generated key"
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey.pem; CheckExitStatus -ECode $?
echo "=== Import into YubiHSM"
openssl.exe genrsa -out rsa2048-keypair.pem 2048; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "rsaKeyImport" -d "2" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" --in=rsa2048-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $import_keyid -t asymmetric-key > info.txt; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "id: 0x00c8"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "type: asymmetric-key"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "algorithm: rsa2048"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern 'label: "rsaKeyImport"'; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "domains: 2"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "origin: imported"; CheckExitStatus -ECode $?
Select-String -Path "info.txt" -Pattern "capabilities: decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"; CheckExitStatus -ECode $?
echo "=== Get public key of imported key"
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_imported.pem; CheckExitStatus -ECode $?
echo "=== Signing with generated key and"
echo "===== rsa-pkcs1-sha1"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --out data.2048pkcs1sha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha256"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --out data.2048pkcs1sha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha384"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --out data.2048pkcs1sha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha512"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --out data.2048pkcs1sha512.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha1"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.2048psssha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha256"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.2048psssha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha384"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.2048psssha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha512"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.2048psssha512.sig; CheckExitStatus -ECode $?
echo "=== Signing with imported key and"
echo "===== rsa-pkcs1-sha1"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --out data.2048pkcs1sha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha256"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --out data.2048pkcs1sha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha384"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --out data.2048pkcs1sha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha512"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --out data.2048pkcs1sha512.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha1"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.2048psssha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha256"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.2048psssha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha384"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.2048psssha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha512"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.2048psssha512.sig; CheckExitStatus -ECode $?
echo "=== Make self signed certificate"
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
echo "=== Sign attestation certificate"
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
echo "=== Decrypt with generated key and PKCS1v15"
openssl.exe rsautl -encrypt -inkey pubkey.pem -pubin -in data.txt -out data.enc; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec; CheckExitStatus -ECode $?
if (@(Compare-Object $(Get-Content "data.txt") $(Get-Content "data.dec") -sync 0).length -ne 0)
{
    echo "Decrypt failed"
    exit 2
}
rm data.dec
echo "=== Decrypt with imported key and PKCS1v15"
openssl.exe rsautl -encrypt -inkey pubkey_imported.pem -pubin -in data.txt -out data.enc; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec; CheckExitStatus -ECode $?
if (@(Compare-Object $(Get-Content "data.txt") $(Get-Content "data.dec") -sync 0).length -ne 0)
{
    echo "Decrypt failed"
    exit 2
}
rm data.dec
echo "=== Delete keys"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?


echo "**********************************"
echo "            RSA3072"
echo "**********************************"
echo "=== Generate on YubiHSM"
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "rsaKey" -d "1" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" -A "rsa3072"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
echo "=== Get public key of generated key"
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey.pem; CheckExitStatus -ECode $?
echo "=== Import into YubiHSM"
openssl.exe genrsa -out rsa3072-keypair.pem 3072; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "rsaKeyImport" -d "2" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" --in=rsa3072-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
echo "=== Get public key of imported key"
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_imported.pem; CheckExitStatus -ECode $?
echo "=== Signing with generated key and"
echo "===== rsa-pkcs1-sha1"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --out data.3072pkcs1sha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha256"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --out data.3072pkcs1sha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha384"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --out data.3072pkcs1sha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha512"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --out data.3072pkcs1sha512.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha1"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.3072psssha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha256"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.3072psssha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha384"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.3072psssha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha512"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.3072psssha512.sig; CheckExitStatus -ECode $?
echo "=== Signing with imported key and"
echo "===== rsa-pkcs1-sha1"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --out data.3072pkcs1sha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha256"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --out data.3072pkcs1sha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha384"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --out data.3072pkcs1sha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha512"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --out data.3072pkcs1sha512.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha1"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.3072psssha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha256"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.3072psssha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha384"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.3072psssha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha512"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.3072psssha512.sig; CheckExitStatus -ECode $?
echo "=== Make self signed certificate"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
#yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
echo "=== Sign attestation certificate"
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
<# echo "=== Decrypt with generated key and PKCS1v15"
openssl rsautl -encrypt -inkey pubkey.pem -pubin -in data.txt -out data.enc
yubihsm-shell.exe -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec
if (@(Compare-Object $(Get-Content "data.txt") $(Get-Content "data.dec") -sync 0).length -ne 0)
{
    echo "Decrypt failed"
    exit 2
}
rm data.dec
echo "=== Decrypt with imported key and PKCS1v15"
openssl.exe rsautl -encrypt -inkey pubkey_imported.pem -pubin -in data.txt -out data.enc
yubihsm-shell.exe -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec
<#
if (@(Compare-Object $(Get-Content "data.txt") $(Get-Content "data.dec") -sync 0).length -ne 0)
{
    echo "Decrypt failed"
    exit 2
}
rm data.dec #>
echo "=== Delete keys"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?


# RSA 4096
echo "**********************************"
echo "            RSA4096"
echo "**********************************"
echo "=== Generate on YubiHSM"
yubihsm-shell.exe -p password -a generate-asymmetric-key -i $keyid -l "rsaKey" -d "1" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" -A "rsa4096"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
echo "=== Get public key of generated key"
yubihsm-shell.exe -p password -a get-public-key -i $keyid --outformat=PEM --out pubkey.pem; CheckExitStatus -ECode $?
echo "=== Import into YubiHSM"
openssl.exe genrsa -out rsa4096-keypair.pem 4096; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-asymmetric-key -i $import_keyid -l "rsaKeyImport" -d "2" -c "sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate" --in=rsa4096-keypair.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?
echo "=== Get public key of imported key"
yubihsm-shell.exe -p password -a get-public-key -i $import_keyid --outformat=PEM --out pubkey_imported.pem; CheckExitStatus -ECode $?
echo "=== Signing with generated key and"
echo "===== rsa-pkcs1-sha1"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha1 --in data.txt --out data.4096pkcs1sha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha256"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha256 --in data.txt --out data.4096pkcs1sha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha384"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha384 --in data.txt --out data.4096pkcs1sha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha512"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $keyid -A rsa-pkcs1-sha512 --in data.txt --out data.4096pkcs1sha512.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha1"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha1 --in data.txt --out data.4096psssha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha256"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha256 --in data.txt --out data.4096psssha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha384"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha384 --in data.txt --out data.4096psssha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha512"
yubihsm-shell.exe -p password -a sign-pss -i $keyid -A rsa-pss-sha512 --in data.txt --out data.4096psssha512.sig; CheckExitStatus -ECode $?
echo "=== Signing with imported key and"
echo "===== rsa-pkcs1-sha1"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha1 --in data.txt --out data.4096pkcs1sha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha256"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha256 --in data.txt --out data.4096pkcs1sha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha384"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha384 --in data.txt --out data.4096pkcs1sha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pkcs1-sha512"
yubihsm-shell.exe -p password -a sign-pkcs1v15 -i $import_keyid -A rsa-pkcs1-sha512 --in data.txt --out data.4096pkcs1sha512.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha1"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha1 --in data.txt --out data.4096psssha1.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha256"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha256 --in data.txt --out data.4096psssha256.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha384"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha384 --in data.txt --out data.4096psssha384.sig; CheckExitStatus -ECode $?
echo "===== rsa-pss-sha512"
yubihsm-shell.exe -p password -a sign-pss -i $import_keyid -A rsa-pss-sha512 --in data.txt --out data.4096psssha512.sig; CheckExitStatus -ECode $?
echo "=== Make self signed certificate"
#yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id 0 --out cert.pem; CheckExitStatus -ECode $?
openssl.exe x509 -in cert.pem -out cert.der -outform DER; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$keyid --out selfsigned_cert.pem; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $keyid -t opaque; CheckExitStatus -ECode $?
#yubihsm-shell.exe -p password -a put-opaque -i $keyid -l java_cert -A opaque-x509-certificate --in selfsigned_cert.pem; CheckExitStatus -ECode $?
echo "=== Sign attestation certificate"
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t opaque; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a put-opaque -i $import_keyid -l template_cert -A opaque-x509-certificate --in cert.der; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-attestation-certificate -i $keyid --attestation-id=$import_keyid --out selfsigned_cert.der; CheckExitStatus -ECode $?
<# echo "=== Decrypt with generated key and PKCS1v15"
openssl.exe rsautl -encrypt -inkey pubkey.pem -pubin -in data.txt -out data.enc
yubihsm-shell.exe -p password -a decrypt-pkcs1v15 -i $keyid --in data.enc --out data.dec
if (@(Compare-Object $(Get-Content "data.txt") $(Get-Content "data.dec") -sync 0).length -ne 0)
{
    echo "Decrypt failed"
    exit 2
}
rm data.dec
echo "=== Decrypt with imported key and PKCS1v15"
openssl.exe rsautl -encrypt -inkey pubkey_imported.pem -pubin -in data.txt -out data.enc
yubihsm-shell.exe -p password -a decrypt-pkcs1v15 -i $import_keyid --in data.enc --out data.dec
if (@(Compare-Object $(Get-Content "data.txt") $(Get-Content "data.dec") -sync 0).length -ne 0)
{
    echo "Decrypt failed"
    exit 2
}
rm data.dec #>
echo "=== Delete keys"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t asymmetric-key; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a delete-object -i $import_keyid -t asymmetric-key; CheckExitStatus -ECode $?

cd ..
Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue

Set-PSDebug -Trace 0