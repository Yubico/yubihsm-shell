Set-PSDebug -Trace 1

$RELEASE_VERSION=$args[0]
$CMAKE_ARCH=$args[1]
$VCPKG_PATH=$args[2]

if($CMAKE_ARCH -eq "Win32") {
    $ARCH="x86"
} else {
    $ARCH="x64"
}

$SOURCE_DIR="$PSScriptRoot/../.."
$BUILD_DIR="$SOURCE_DIR/build_release"
$RELEASE_DIR="$SOURCE_DIR/yubihsm-shell-$RELEASE_VERSION-$ARCH"
$LICENSES_DIR="$RELEASE_DIR/licenses"


# Install prerequisites
cd $VCPKG_PATH
.\vcpkg.exe install openssl:$ARCH-windows
.\vcpkg.exe install getopt:$ARCH-windows

$env:OPENSSL_ROOT_DIR ="$VCPKG_PATH/packages/openssl-windows_$ARCH-windows"

# Build binaries
cd $SOURCE_DIR
mkdir $BUILD_DIR; cd $BUILD_DIR
cmake -A "$CMAKE_ARCH" -DGETOPT_LIB_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/lib" -DGETOPT_INCLUDE_DIR="$VCPKG_PATH/packages/getopt-win32_$ARCH-windows/include" -DCMAKE_INSTALL_PREFIX="$RELEASE_DIR" ..
Get-Content .\lib\version.rc | Out-File -encoding ASCII .\lib\version.rc
Get-Content .\lib\version_winhttp.rc | Out-File -encoding ASCII .\lib\version_winhttp.rc
Get-Content .\lib\version_winusb.rc | Out-File -encoding ASCII .\lib\version_winusb.rc
Get-Content .\src\version.rc | Out-File -encoding ASCII .\src\version.rc
Get-Content .\yhwrap\version.rc | Out-File -encoding ASCII .\yhwrap\version.rc
cmake --build . -v --config Release --target install
cd $RELEASE_DIR/bin
if($ARCH -eq "x86")
{
    cp $VCPKG_PATH/packages/openssl-windows_x86-windows/bin/libcrypto-1_1.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x86-windows/bin/getopt.dll .
}
else
{
    cp $VCPKG_PATH/packages/openssl-windows_x64-windows/bin/libcrypto-1_1-x64.dll .
    cp $VCPKG_PATH/packages/getopt-win32_x64-windows/bin/getopt.dll .
}

# Create missing directories
Remove-Item -Path $LICENSES_DIR -Force -Recurse -ErrorAction SilentlyContinue
mkdir -p $LICENSES_DIR

# Copy licenses
$license=(Get-ChildItem -Path $SOURCE_DIR -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR/yubihsm-shell.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\openssl-windows\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\openssl.txt

$license=(Get-ChildItem -Path $VCPKG_PATH\buildtrees\getopt-win32\src\ -Filter LICENSE -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName})
cp $license $LICENSES_DIR\getopt.txt

# Clean directory
cd $SOURCE_DIR
rm -r $BUILD_DIR
Set-PSDebug -Trace 0
