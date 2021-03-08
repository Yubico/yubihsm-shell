if($args.length -lt 4)
{
    echo "Usage: ./make_installer.ps1 <Win32|x64> <VCPKG_PATH> <WIX_PATH> <MERGE_MODULE_PATH>"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm"
    echo ""
    echo "   Win32                  builds using X86 architecture by adding '-A Win32' argument to the cmake command"
    echo "   x64                    builds using X64 architecture by adding '-A x64' argument to the cmake command"
    echo ""
    echo "   VCPKG_PATH             Absolute path to the directory where vcpkg.exe is located"
    echo "   WIX_PATH               Absolute path to the directory where WIX Tools binaries (heat.exe, candle.exe and light.exe) are located"
    echo "   MERGE_MODULE_PATH      Absolute path to the redistribution module (tex Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm)"
    exit
}

$CMAKE_ARCH=$args[0]
$VCPKG_PATH=$args[1]
$WIX_PATH=$args[2] # Absolute path to the WixTools binaries
$MERGE_MODULE=$args[3] # Absolute path containing Microsoft_VC142_CRT_x86.msm or Microsoft_VC142_CRT_x64.msm


if($CMAKE_ARCH -eq "Win32") {
    $ARCH="x86"
} else {
    $ARCH="x64"
}

$WIN_DIR = "$PSScriptRoot"
$SOURCE_DIR="$PSScriptRoot/../.."
$BUILD_DIR="$WIN_DIR/build_release"
$RELEASE_DIR="$WIN_DIR/yubihsm-shell-$ARCH"
$LICENSES_DIR="$RELEASE_DIR/licenses"

Set-PSDebug -Trace 1

# Install prerequisites
cd $VCPKG_PATH
.\vcpkg.exe install openssl:$ARCH-windows
.\vcpkg.exe install getopt:$ARCH-windows

$env:OPENSSL_ROOT_DIR ="$VCPKG_PATH/packages/openssl_$ARCH-windows"

# Build binaries
mkdir $BUILD_DIR; cd $BUILD_DIR
cmake -S $SOURCE_DIR -A "$CMAKE_ARCH" -DGETOPT_LIB_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/lib" -DGETOPT_INCLUDE_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/include" -DCMAKE_INSTALL_PREFIX="$RELEASE_DIR"
cmake --build . --config Release --target install

# Copy openssl and getopt libraries
cd $RELEASE_DIR/bin
if($ARCH -eq "x86")
{
    cp $VCPKG_PATH/packages/openssl_x86-windows/bin/libcrypto-1_1.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x86-windows/bin/getopt.dll .
}
else
{
    cp $VCPKG_PATH/packages/openssl_x64-windows/bin/libcrypto-1_1-x64.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x64-windows/bin/getopt.dll .
}

# Create missing directories
Remove-Item -Path $LICENSES_DIR -Force -Recurse -ErrorAction SilentlyContinue
mkdir -p $LICENSES_DIR

# Copy licenses
$license=(Get-ChildItem -Path $SOURCE_DIR -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR/yubihsm-shell.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\openssl\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\openssl.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\getopt-win32\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\getopt.txt

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
rm -r $BUILD_DIR

Set-PSDebug -Trace 0
