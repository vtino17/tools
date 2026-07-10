@echo off
REM OCySec OSINT Framework - Windows launcher
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo [+] Membuat virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    echo [+] Install dependencies...
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)
python run.py %*

