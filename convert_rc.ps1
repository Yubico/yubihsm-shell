Set-PSDebug -Trace 1
Get-Content .\lib\version.rc | Out-File -encoding ASCII .\lib\version.rc
Get-Content .\lib\version_winhttp.rc | Out-File -encoding ASCII .\lib\version_winhttp.rc
Get-Content .\lib\version_winusb.rc | Out-File -encoding ASCII .\lib\version_winusb.rc
Get-Content .\src\version.rc | Out-File -encoding ASCII .\src\version.rc
Get-Content .\yhwrap\version.rc | Out-File -encoding ASCII .\yhwrap\version.rc
Set-PSDebug -Trace 0