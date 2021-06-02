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

echo "---------------------- ED keys --------------------- "
# Generate
yubihsm-shell.exe -p password -a generate-asymmetric-key -i 100 -l "edKey" -d "1,2,3" -c "sign-eddsa" -A "ed25519"; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-object-info -i 100 -t asymmetric-key; CheckExitStatus -ECode $?


# Get public key
yubihsm-shell.exe -p password -a get-public-key -i 100 > edkey1.pub; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a get-public-key -i 100 --out edkey2.pub; CheckExitStatus -ECode $?

# Signing
yubihsm-shell.exe -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt > data.ed1.sig; CheckExitStatus -ECode $?
yubihsm-shell.exe -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt --out data.ed2.sig; CheckExitStatus -ECode $?

# Delete
yubihsm-shell.exe -p password -a delete-object -i 100 -t asymmetric-key; CheckExitStatus -ECode $?

cd ..
Remove-Item -Path "$TEST_DIR" -Recurse -ErrorAction SilentlyContinue

Set-PSDebug -Trace 0