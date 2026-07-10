#!/usr/bin/env bash
# OCySec OSINT Framework - Linux/macOS launcher
set -e
cd "$(dirname "$0")"
if [ ! -d ".venv" ]; then
    echo "[+] Membuat virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo "[+] Install dependencies..."
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi
python run.py "$@"

