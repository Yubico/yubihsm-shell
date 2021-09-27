if($args.length -lt 3)
{
    echo "Usage: ./repack_installer.ps1 <x86|x64> <WIX_PATH> <MERGE_MODULE_PATH> [<SIGNED_BINARIES_PATH>]"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm"
    echo ""
    echo "   x86                    builds the installer for X86 architecture"
    echo "   x64                    builds the installer for X64 architecture"
    echo ""
    echo "   WIX_PATH               Absolute path to the directory where WIX Tools binaries (heat.exe, candle.exe and light.exe) are located"
    echo "   MERGE_MODULE_PATH      Absolute path to the redistribution module (tex Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm)"
    echo "   SIGNED_BINARIES_PATH   (Optional) Absolute path to signed binaries. If not spacified, YUBIHSM-SHELL/resources/release/win/yubihsm-shell-[x86|x64] is assumed"
    exit
}

$ARCH=$args[0]
$WIX_PATH=$args[1] # Absolute path to the WixTools binaries
$MERGE_MODULE=$args[2] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm

$WIN_DIR = "$PSScriptRoot"
$SOURCE_DIR="$PSScriptRoot/../../.."

if($args.length -eq 4)
{
    $RELEASE_DIR=$args[3]
}
else
{
    $RELEASE_DIR="$WIN_DIR/yubihsm-shell-$ARCH"
}

Set-PSDebug -Trace 1

# Build MSI
cd $WIN_DIR
$env:PATH += ";$WIX_PATH"
$env:SRCDIR = $RELEASE_DIR
$env:MERGEDPATH = $MERGE_MODULE

heat.exe dir $RELEASE_DIR -out fragment.wxs -gg -scom -srd -sfrag -sreg -dr INSTALLDIR -cg ApplicationFiles -var env.SRCDIR
candle.exe fragment.wxs "yubihsm-shell_$ARCH.wxs" -ext WixUtilExtension  -arch $ARCH
light.exe fragment.wixobj "yubihsm-shell_$ARCH.wixobj" -ext WixUIExtension -ext WixUtilExtension -o "yubihsm-shell-$ARCH.msi"

#cleanup
rm fragment.wxs
rm fragment.wixobj
rm "yubihsm-shell_$ARCH.wixobj"
rm "yubihsm-shell-$ARCH.wixpdb"

Set-PSDebug -Trace 0
