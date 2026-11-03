@echo off
setlocal
cd /d "%~dp0"
where cmake >nul 2>nul
if errorlevel 1 (
    echo CMake was not found. Install CMake and a C++17 compiler, then try again.
    pause
    exit /b 1
)
cmake -S . -B build -A x64
if errorlevel 1 goto failed
cmake --build build --config Release
if errorlevel 1 goto failed
echo.
echo Build completed. Run start.bat to launch Campus LMS.
pause
exit /b 0
:failed
echo.
echo Build failed. Check the messages above.
pause
exit /b 1
