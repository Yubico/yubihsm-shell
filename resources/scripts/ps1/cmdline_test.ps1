$ARCH=$args[0]
if($ARCH -eq "x86")
{
    if ((Get-Command "yubihsm-shell.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        #$env:Path += ";C:/Program Files (x86)/Yubico/YubiHSM Shell/bin"
        $env:Path += ";Z:\yubihsm-shell\build_winx86\release\bin"
    }
}
elseif ($ARCH -eq "x64")
{
    if ((Get-Command "yubihsm-shell.exe" -ErrorAction SilentlyContinue) -eq $null)
    {
        #$env:Path += ";C:/Program Files/Yubico/YubiHSM Shell/bin"
        $env:Path += ";Z:\yubihsm-shell\build_winx64\release\bin"
    }
}
else {
    echo "Usage: ./cmdline_test.ps1 <x86|x64>"
    echo ""
    echo "This is a test script that uses the yubihsm-shell command line tool to reset the conncted YubiHSM and then
           different com    mands."
    echo ""
    echo "   x86        expects that yubihsm-shell.exe is installed in 'C:/Program Files (x86)/Yubico/Yubico PIV Tool/bin'"
    echo "   x64        expects that yubhsm-shell.exe is installed in 'C:/Program Files/Yubico/Yubico PIV Tool/bin'"
    exit
}

echo "Running commands on $ARCH architecture"

$TEST_DIR = "yubihsm-shell_test_dir"
Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue
New-Item $TEST_DIR -type Directory -Force
echo "test signing data" > $TEST_DIR/data.txt
Set-PSDebug -Trace 1
$ErrorActionPreference = "Stop"


yubihsm-shell.exe --version
yubihsm-shell.exe --help
yubihsm-shell.exe -a get-device-info

echo "********************** Reset YubiHSM ********************* "
yubihsm-shell.exe -p password -a reset
Start-Sleep -s 10

echo "********************** Blink ********************* "
yubihsm-shell.exe -p password -a blink
yubihsm-shell.exe -p password -a blink --duration=5

yubihsm-shell.exe -p password -a blink-device
yubihsm-shell.exe -p password -a blink-device --duration=5

echo "********************** Get Pseudo-random ********************* "
yubihsm-shell.exe -p password -a get-pseudo-random
yubihsm-shell.exe -p password -a get-pseudo-random --count=10
yubihsm-shell.exe -p password -a get-pseudo-random --count=10 --out=random.txt
rm random.txt

echo "********************** Asym keys ********************* "
& "$PSScriptRoot\test_edkey.ps1" "$ARCH"
& "$PSScriptRoot\test_eckey.ps1" "$ARCH"
& "$PSScriptRoot\test_rsakey.ps1" "$ARCH"
exit
echo "********************** HMAC keys ********************* "
& "$PSScriptRoot\test_hmackey.ps1" "$ARCH"

echo "********************** AEAD keys ********************* "
& "$PSScriptRoot\test_otpaeadkey.ps1" "$ARCH"

echo "********************** Template ********************* "
echo "=== Import template"
$id=100
yubihsm-shell.exe -p password -a get-pseudo-random --count=512 --out=$TEST_DIR/template.txt
yubihsm-shell.exe -p password -a put-template -i $id -l template -d 1 -A template-ssh --in $TEST_DIR/template.txt
yubihsm-shell.exe -p password -a get-object-info -i $id -t template
echo "=== Get template"
yubihsm-shell.exe -p password -a get-template -i $id
echo "=== Delete template"
yubihsm-shell.exe -p password -a delete-object -i $id -t template

#echo "********************** Wrap keys ********************* "

echo "********************** Authentication keys ********************* "
echo "=== Create new authentication key"
$id=200
yubihsm-shell.exe -p password -a put-authentication-key -i $id -l authkey -d 1,2,3 -c all --new-password foo123
yubihsm-shell.exe -p password -a get-object-info -i $id -t authentication-key
echo "=== Login using new authetication key"
yubihsm-shell.exe --authkey $id -p foo123 -a get-object-info -i 1 -t authentication-key
echo "=== Delete new authentication key"
yubihsm-shell.exe -p password -a delete-object -i $id -t authentication-key

Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue

Set-PSDebug -Trace 0