@echo off
title ARES - Anti-Malware
echo.
echo  ╔═══════════════════════════════════════╗
echo  ║     ARES Anti-Malware - Starting      ║
echo  ╚═══════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Download from python.org
    pause
    exit /b 1
)

REM Install dependencies if needed
echo [*] Checking dependencies...
pip install -r requirements.txt --quiet

echo [*] Starting server...
echo [*] Opening browser at http://127.0.0.1:5000
echo.
python app.py

pause
