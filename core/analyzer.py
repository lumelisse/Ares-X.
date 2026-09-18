"""
core/analyzer.py
Central analysis engine — orchestrates all modules.
Always returns a complete, valid result dict (never raises).
"""

import time
from pathlib import Path

from utils.hash    import calculate_hashes
from utils.entropy import calculate_entropy
from core.pe       import analyze_pe
from core.packer   import detect_packers
from core.ioc      import extract_iocs
from core.yara     import scan_with_yara
from core.strings  import extract_strings
from core.risk     import compute_risk


def detect_filetype(data: bytes) -> str:
    sigs = {
        b"MZ":            "PE (Windows Executable)",
        b"\x7fELF":       "ELF (Linux Executable)",
        b"\xfe\xed\xfa":  "Mach-O (macOS)",
        b"\xce\xfa\xed":  "Mach-O (macOS)",
        b"PK\x03\x04":   "ZIP Archive",
        b"Rar!":          "RAR Archive",
        b"7z\xbc\xaf":   "7-Zip Archive",
        b"%PDF":          "PDF Document",
        b"\xd0\xcf\x11":  "OLE2 (Office/DOC)",
        b"MThd":          "MIDI File",
    }
    for sig, name in sigs.items():
        if data[:len(sig)] == sig:
            return name

    # Script detection by content
    try:
        head = data[:512].decode("utf-8", errors="ignore").lower()
        if "powershell" in head or "$env:" in head:
            return "PowerShell Script"
        if "vbscript" in head or "wscript" in head or "createobject" in head:
            return "VBScript"
        if "#!/bin/bash" in head or "#!/bin/sh" in head:
            return "Shell Script"
        if "<html" in head or "<!doctype html" in head:
            return "HTML Document"
        if "@echo off" in head or "cmd /c" in head:
            return "Batch Script"
    except Exception:
        pass

    return "Unknown Binary"


def analyze_file(filename: str, data: bytes) -> dict:
    """
    Run full static analysis on raw bytes.
    Always returns a complete result dict with 'risk' key populated.
    Never raises — catches all exceptions internally.
    """
    t0 = time.time()

    result = {
        "filename": filename,
        "size":     len(data),
        "size_kb":  round(len(data) / 1024, 2),
        "filetype": detect_filetype(data),
        "hashes":   {},
        "entropy":  0.0,
        "packers":  [],
        "pe":       {},
        "yara_hits": [],
        "strings":  {"ascii": [], "unicode": [], "total": 0},
        "iocs":     {},
        "scan_time": 0.0,
        "risk": {
            "score": 0,
            "verdict": "CLEAN",
            "color": "#4fd18a",
            "reasons": []
        }
    }

    # ── Step 1: Hashes ────────────────────────────────────────────────────────
    try:
        result["hashes"] = calculate_hashes(data)
    except Exception as e:
        result["hashes"] = {"md5": "err", "sha1": "err", "sha256": "err",
                            "sha512": "err", "error": str(e)}

    # ── Step 2: Entropy ───────────────────────────────────────────────────────
    try:
        result["entropy"] = calculate_entropy(data)
    except Exception as e:
        result["entropy"] = 0.0

    # ── Step 3: PE Analysis (only for PE files) ───────────────────────────────
    try:
        if data[:2] == b"MZ":
            result["pe"] = analyze_pe(data)
        else:
            result["pe"] = {}
    except Exception as e:
        result["pe"] = {"error": str(e)}

    # ── Step 4: Packer Detection ──────────────────────────────────────────────
    try:
        result["packers"] = detect_packers(data, result["entropy"])
    except Exception as e:
        result["packers"] = []

    # ── Step 5: String Extraction ─────────────────────────────────────────────
    try:
        strings = extract_strings(data)
        result["strings"] = strings
    except Exception as e:
        result["strings"] = {"ascii": [], "unicode": [], "total": 0}

    # ── Step 6: IOC Extraction ────────────────────────────────────────────────
    try:
        all_strings = result["strings"].get("ascii", []) + result["strings"].get("unicode", [])
        result["iocs"] = extract_iocs(all_strings)
    except Exception as e:
        result["iocs"] = {}

    # ── Step 7: YARA Scanning ─────────────────────────────────────────────────
    try:
        result["yara_hits"] = scan_with_yara(data)
    except Exception as e:
        result["yara_hits"] = []

    # ── Step 8: Risk Scoring ──────────────────────────────────────────────────
    try:
        result["risk"] = compute_risk(result)
    except Exception as e:
        # Fallback risk if compute_risk crashes
        result["risk"] = {
            "score":   0,
            "verdict": "UNKNOWN",
            "color":   "#5a6480",
            "reasons": [f"Risk computation error: {str(e)}"]
        }

    result["scan_time"] = round(time.time() - t0, 3)
    return result
