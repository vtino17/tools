#!/bin/bash
# HackerAI Tools Launcher (Linux/Mac)
# Quick access ke master menu

cd "$(dirname "$0")"

echo "============================================================"
echo "  HackerAI Tools - Penetration Testing Suite"
echo "============================================================"
echo ""
echo "[1] Install dependencies"
echo "[2] Run master menu"
echo "[3] Run specific tool"
echo "[0] Exit"
echo ""

read -p "Select option: " choice

case $choice in
    1)
        echo "[*] Installing dependencies..."
        pip3 install -r requirements.txt
        read -p "Press Enter to continue..."
        ;;
    2)
        python3 hackerai.py
        ;;
    3)
        python3 hackerai.py "${@:2}"
        ;;
    *)
        echo "Goodbye!"
        ;;
esac

