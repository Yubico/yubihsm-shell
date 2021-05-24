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

$keyid=100

echo "---------------------- HAMC keys --------------------- "
echo "**********************************"
echo "            AEAD Key 128"
echo "**********************************"
echo "=== Generate on YubiHSM"
yubihsm-shell.exe -p password -a generate-otp-aead-key -i $keyid -l "aeadkey" -d "1,2,3" -c "randomize-otp-aead" -A "aes128-yubico-otp" --nonce 0x01020304
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t hmac-key > info.txt
Select-String -Path "info.txt" -Pattern "id: 0x0064"
Select-String -Path "info.txt" -Pattern "type: otp-aead-key"
Select-String -Path "info.txt" -Pattern "algorithm: aes128-yubico-otp"
Select-String -Path "info.txt" -Pattern 'label: "aeadkey"'
Select-String -Path "info.txt" -Pattern "domains: 1:2:3"
Select-String -Path "info.txt" -Pattern "origin: generated"
Select-String -Path "info.txt" -Pattern "capabilities: randomize-otp-aead"
echo "=== Randomize OTP AEAD"
yubihsm-shell.exe -p password -a randomize-otp-aead -i $keyid
echo "=== Delete keys"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t otp-aead-key

echo "**********************************"
echo "            AEAD Key 192"
echo "**********************************"
echo "=== Generate on YubiHSM"
yubihsm-shell.exe -p password -a generate-otp-aead-key -i $keyid -l "aeadkey" -d "1,2,3" -c "randomize-otp-aead" -A "aes192-yubico-otp" --nonce 0x01020304
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t hmac-key > info.txt
Select-String -Path "info.txt" -Pattern "id: 0x0064"
Select-String -Path "info.txt" -Pattern "type: otp-aead-key"
Select-String -Path "info.txt" -Pattern "algorithm: aes192-yubico-otp"
Select-String -Path "info.txt" -Pattern 'label: "aeadkey"'
Select-String -Path "info.txt" -Pattern "domains: 1:2:3"
Select-String -Path "info.txt" -Pattern "origin: generated"
Select-String -Path "info.txt" -Pattern "capabilities: randomize-otp-aead"
echo "=== Randomize OTP AEAD"
yubihsm-shell.exe -p password -a randomize-otp-aead -i $keyid
echo "=== Delete keys"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t otp-aead-key

echo "**********************************"
echo "            AEAD Key 256"
echo "**********************************"
echo "=== Generate on YubiHSM"
yubihsm-shell.exe -p password -a generate-otp-aead-key -i $keyid -l "aeadkey" -d "1,2,3" -c "randomize-otp-aead" -A "aes256-yubico-otp" --nonce 0x01020304
yubihsm-shell.exe -p password -a get-object-info -i $keyid -t hmac-key > info.txt
Select-String -Path "info.txt" -Pattern "id: 0x0064"
Select-String -Path "info.txt" -Pattern "type: otp-aead-key"
Select-String -Path "info.txt" -Pattern "algorithm: aes256-yubico-otp"
Select-String -Path "info.txt" -Pattern 'label: "aeadkey"'
Select-String -Path "info.txt" -Pattern "domains: 1:2:3"
Select-String -Path "info.txt" -Pattern "origin: generated"
Select-String -Path "info.txt" -Pattern "capabilities: randomize-otp-aead"
echo "=== Randomize OTP AEAD"
yubihsm-shell.exe -p password -a randomize-otp-aead -i $keyid
echo "=== Delete keys"
yubihsm-shell.exe -p password -a delete-object -i $keyid -t otp-aead-key

cd ..
Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue

Set-PSDebug -Trace 0
