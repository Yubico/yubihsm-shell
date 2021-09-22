if($args.length -lt 4)
{
    echo "Usage: ./make_installer.ps1 <x86|x64> <SRC_PATH> <WIX_PATH> <MERGE_MODULE_PATH>"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm"
    echo ""
    echo "   x86                    builds the installer for X86 architecture"
    echo "   x64                    builds the installer for X64 architecture"
    echo ""
    echo "   SRC_PATH               Absolute path to the directory containing the signed binaries"
    echo "   WIX_PATH               Absolute path to the directory where WIX Tools binaries (heat.exe, candle.exe and light.exe) are located"
    echo "   MERGE_MODULE_PATH      Absolute path to the redistribution module (tex Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm)"
    exit
}

$ARCH=$args[0]
$SRC_PATH=$args[1]
$WIX_PATH=$args[2] # Absolute path to the WixTools binaries
$MERGE_MODULE=$args[3] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm

$WIN_DIR = "$PSScriptRoot"

Set-PSDebug -Trace 1

# Build MSI
cd $WIN_DIR
$env:PATH += ";$WIX_PATH"
$env:SRCDIR = $SRC_PATH
$env:MERGEDPATH = $MERGE_MODULE

heat.exe dir $SRC_PATH -out fragment.wxs -gg -scom -srd -sfrag -sreg -dr INSTALLDIR -cg ApplicationFiles -var env.SRCDIR
candle.exe fragment.wxs "yubihsm-shell_$ARCH.wxs" -ext WixUtilExtension  -arch $ARCH
light.exe fragment.wixobj "yubihsm-shell_$ARCH.wixobj" -ext WixUIExtension -ext WixUtilExtension -o "yubihsm-shell-$ARCH.msi"

#cleanup
rm fragment.wxs
rm fragment.wixobj
rm "yubihsm-shell_$ARCH.wixobj"
rm "yubihsm-shell-$ARCH.wixpdb"

Set-PSDebug -Trace 0
