if($args.length -lt 3)
{
    echo "Usage: ./repack_installer.ps1 <Win32|x64> <WIX_PATH> <MERGE_MODULE_PATH>"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm"
    echo ""
    echo "   Win32                  builds using X86 architecture by adding '-A Win32' argument to the cmake command"
    echo "   x64                    builds using X64 architecture by adding '-A x64' argument to the cmake command"
    echo ""
    echo "   WIX_PATH               Absolute path to the directory where WIX Tools binaries (heat.exe, candle.exe and light.exe) are located"
    echo "   MERGE_MODULE_PATH      Absolute path to the redistribution module (tex Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm)"
    exit
}

$CMAKE_ARCH=$args[0]
$WIX_PATH=$args[1] # Absolute path to the WixTools binaries
$MERGE_MODULE=$args[2] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm


if($CMAKE_ARCH -eq "Win32") {
    $ARCH="x86"
} else {
    $ARCH="x64"
}

$WIN_DIR = "$PSScriptRoot"
$SOURCE_DIR="$PSScriptRoot/../.."
$RELEASE_DIR="$WIN_DIR/yubihsm-shell-$ARCH"

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
