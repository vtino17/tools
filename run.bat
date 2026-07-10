@echo off
REM HackerAI Tools Launcher (Windows)
REM Quick access ke master menu

title HackerAI Tools - Master Launcher
cd /d "%~dp0"

echo ============================================================
echo   HackerAI Tools - Penetration Testing Suite
echo ============================================================
echo.
echo [1] Install dependencies
echo [2] Run master menu
echo [3] Run specific tool
echo [0] Exit
echo.

set /p choice="Select option: "

if "%choice%"=="1" (
    echo [*] Installing dependencies...
    pip install -r requirements.txt
    pause
) else if "%choice%"=="2" (
    python hackerai.py
) else if "%choice%"=="3" (
    python hackerai.py %2 %3 %4 %5 %6 %7 %8 %9
) else (
    echo Goodbye!
)

pause

