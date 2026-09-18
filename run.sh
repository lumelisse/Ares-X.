#!/bin/bash
echo ""
echo " ╔═══════════════════════════════════════╗"
echo " ║     ARES Anti-Malware - Starting      ║"
echo " ╚═══════════════════════════════════════╝"
echo ""
echo "[*] Installing dependencies..."
pip install -r requirements.txt -q
echo "[*] Starting server at http://127.0.0.1:5000"
echo ""
python3 app.py
