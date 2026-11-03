@echo off
setlocal
cd /d "%~dp0"
set "APP="
if exist build\Release\CampusLMS.exe set "APP=build\Release\CampusLMS.exe"
if not defined APP if exist build\Debug\CampusLMS.exe set "APP=build\Debug\CampusLMS.exe"
if not defined APP if exist build\CampusLMS.exe set "APP=build\CampusLMS.exe"
if not defined APP (
    echo Campus LMS has not been built yet.
    echo Run build.bat first.
    pause
    exit /b 1
)
"%APP%"
if errorlevel 1 (
    echo.
    echo Campus LMS closed with an error.
    pause
)
endlocal
