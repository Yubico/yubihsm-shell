if($args.length -lt 2)
{
    echo "Usage: ./make_installer.ps1 <Win32|x64> <VCPKG_PATH>"
    echo ""
    echo "This is a script to build an MSI installer for yubihsm"
    echo ""
    echo "   Win32                  builds using X86 architecture by adding '-A Win32' argument to the cmake command"
    echo "   x64                    builds using X64 architecture by adding '-A x64' argument to the cmake command"
    echo ""
    echo "   VCPKG_PATH             Absolute path to the directory where vcpkg.exe is located"
    exit
}

$CMAKE_ARCH=$args[0]
$VCPKG_PATH=$args[1]

if($CMAKE_ARCH -eq "Win32") {
    $ARCH="x86"
} else {
    $ARCH="x64"
}

$WIN_DIR = "$PSScriptRoot"
$SOURCE_DIR="$PSScriptRoot/../../.."
$BUILD_DIR="$WIN_DIR/build_release"
$RELEASE_DIR="$WIN_DIR/yubihsm-shell-$ARCH"
$LICENSES_DIR="$RELEASE_DIR/licenses"

Set-PSDebug -Trace 1

# Install prerequisites
cd $VCPKG_PATH
.\vcpkg.exe update
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
    cp $VCPKG_PATH/packages/openssl_x86-windows/bin/libcrypto-3.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x86-windows/bin/getopt.dll .
}
else
{
    cp $VCPKG_PATH/packages/openssl_x64-windows/bin/libcrypto-3-x64.dll .
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

#cd $WIN_DIR
#Compress-Archive -LiteralPath "$WIN_DIR/yubihsm-shell-$ARCH" -DestinationPath "$WIN_DIR/yubihsm-shell-$ARCH.zip"
rm -r $BUILD_DIR

Set-PSDebug -Trace 0
