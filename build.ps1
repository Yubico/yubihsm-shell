Set-PSDebug -Trace 1
rm -r build_win; mkdir build_win; cd build_win
cmake -A Win32 -DGETOPT_LIB_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x86-windows/lib -DGETOPT_INCLUDE_DIR=C:/Users/test/vcpkg-master/packages/getopt-win32_x86-windows/include ..
Get-Content .\lib\version.rc | Out-File -encoding ASCII .\lib\version.rc
Get-Content .\lib\version_winhttp.rc | Out-File -encoding ASCII .\lib\version_winhttp.rc
Get-Content .\lib\version_winusb.rc | Out-File -encoding ASCII .\lib\version_winusb.rc
Get-Content .\src\version.rc | Out-File -encoding ASCII .\src\version.rc
Get-Content .\yhwrap\version.rc | Out-File -encoding ASCII .\yhwrap\version.rc
cmake --build . -v