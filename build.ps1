<#
Set-PSDebug -Trace 1
rm -r build_win32; mkdir build_win32; cd build_win32
cmake -A Win32 -DGETOPT_LIB_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x86-windows/lib -DGETOPT_INCLUDE_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x86-windows/include ..
Get-Content .\lib\version.rc | Out-File -encoding ASCII .\lib\version.rc
Get-Content .\lib\version_winhttp.rc | Out-File -encoding ASCII .\lib\version_winhttp.rc
Get-Content .\lib\version_winusb.rc | Out-File -encoding ASCII .\lib\version_winusb.rc
Get-Content .\src\version.rc | Out-File -encoding ASCII .\src\version.rc
Get-Content .\yhwrap\version.rc | Out-File -encoding ASCII .\yhwrap\version.rc
cmake --build . -v#>


<#
Set-PSDebug -Trace 1
rm -r build_win64; mkdir build_win64; cd build_win64
cmake -A x64 -DGETOPT_LIB_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x64-windows/lib -DGETOPT_INCLUDE_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x64-windows/include ..
Get-Content .\lib\version.rc | Out-File -encoding ASCII .\lib\version.rc
Get-Content .\lib\version_winhttp.rc | Out-File -encoding ASCII .\lib\version_winhttp.rc
Get-Content .\lib\version_winusb.rc | Out-File -encoding ASCII .\lib\version_winusb.rc
Get-Content .\src\version.rc | Out-File -encoding ASCII .\src\version.rc
Get-Content .\yhwrap\version.rc | Out-File -encoding ASCII .\yhwrap\version.rc
cmake --build . -v
#>


$ARCH=$args[0]
Set-PSDebug -Trace 1

if($ARCH -eq "x86")
{
    $env:OPENSSL_ROOT_DIR ="C:/Users/test/vcpkg-master/packages/openssl-windows_x86-windows"
    rm -r build_win32; mkdir build_win32; cd build_win32
    cmake -A Win32 -DGETOPT_LIB_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x86-windows/lib -DGETOPT_INCLUDE_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x86-windows/include ..
}
elseif ($ARCH -eq "x64")
{
    $env:OPENSSL_ROOT_DIR ="C:/Users/test/vcpkg-master/packages/openssl-windows_x64-windows"
    rm -r build_win64; mkdir build_win64; cd build_win64
    cmake -A x64 -DGETOPT_LIB_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x64-windows/lib -DGETOPT_INCLUDE_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x64-windows/include ..
}

Get-Content .\lib\version.rc | Out-File -encoding ASCII .\lib\version.rc
Get-Content .\lib\version_winhttp.rc | Out-File -encoding ASCII .\lib\version_winhttp.rc
Get-Content .\lib\version_winusb.rc | Out-File -encoding ASCII .\lib\version_winusb.rc
Get-Content .\src\version.rc | Out-File -encoding ASCII .\src\version.rc
Get-Content .\yhwrap\version.rc | Out-File -encoding ASCII .\yhwrap\version.rc
cmake --build . -v
