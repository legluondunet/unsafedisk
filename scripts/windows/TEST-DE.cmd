@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0TEST-DE.ps1"
set "RESULT=%ERRORLEVEL%"
echo.
echo Test log: "%~dp0TEST-DE.log"
pause
exit /b %RESULT%
