Set-PSDebug -Trace 1

$SOURCE_DIR=$args[0] # Directory containing the binaries
$RELEASE_VERSION=$args[1] # yubihsm-shell version
$ARCH=$args[2] # x86 or x64
$WIX_PATH=$args[3] # Absolute path to the WixTools binaries
$MERGE_MODULE=$args[4] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm

$WD="$PSScriptRoot"
$env:PATH += ";$WIX_PATH"
$env:SRCDIR = $SOURCE_DIR
$env:MERGEDPATH = $MERGE_MODULE

heat.exe dir $SOURCE_DIR -out fragment.wxs -gg -scom -srd -sfrag -sreg -dr INSTALLDIR -cg ApplicationFiles -var env.SRCDIR
candle.exe fragment.wxs "yubihsm-shell_$ARCH.wxs" -ext WixUtilExtension  -arch $ARCH
light.exe fragment.wixobj "yubihsm-shell_$ARCH.wixobj" -ext WixUIExtension -ext WixUtilExtension -o "yubihsm-shell-$RELEASE_VERSION-$ARCH.msi"

#cleanup
rm fragment.wxs
rm fragment.wixobj
rm "yubihsm-shell_$ARCH.wixobj"
rm "yubihsm-shell-$RELEASE_VERSION-$ARCH.wixpdb"

Set-PSDebug -Trace 0