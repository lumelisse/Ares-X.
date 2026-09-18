"""
ARES — Anti-Malware Triage Workstation
Main Application Entry Point
"""

import os, sys, time, threading, webbrowser
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

# ─── Module imports ───────────────────────────────────────────────────────────
from core.analyzer import analyze_file
from workers.queue import add_task, get_status

try:
    from config import config
except ImportError:
    config = None

# ─── App Setup ────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
UPLOAD_DIR = Path((config.UPLOAD_DIR if config and getattr(config, "UPLOAD_DIR", None) else BASE_DIR / "uploads"))
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = (
    config.MAX_CONTENT_LENGTH if config and getattr(config, "MAX_CONTENT_LENGTH", None) else 256 * 1024 * 1024
)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis endpoint.
    Receives a file, runs full static analysis, returns structured JSON.
    Always returns a valid JSON with 'risk' key.
    """
    try:
        file = request.files.get("file")
        if not file or file.filename == "":
            return jsonify({"error": "No file provided"}), 400

        filename = secure_filename(file.filename)
        data = file.read()

        if len(data) == 0:
            return jsonify({"error": "File is empty"}), 400

        # Run full analysis — always returns complete result
        result = analyze_file(filename, data)
        return jsonify(result)

    except Exception as e:
        # Never return a broken response — always include 'risk'
        return jsonify({
            "error": str(e),
            "filename": file.filename if file else "unknown",
            "size": 0,
            "size_kb": 0,
            "filetype": "Error",
            "hashes": {"md5": "—", "sha1": "—", "sha256": "—", "sha512": "—"},
            "entropy": 0,
            "packers": [],
            "pe": {},
            "yara_hits": [],
            "strings": {"ascii": [], "unicode": [], "total": 0},
            "iocs": {},
            "scan_time": 0,
            "risk": {
                "score": 0,
                "verdict": "ERROR",
                "color": "#5a6480",
                "reasons": [f"Analysis failed: {str(e)}"]
            }
        }), 200  # Return 200 so frontend can handle it gracefully

@app.route("/virustotal", methods=["POST"])
def virustotal():
    """Query VirusTotal API for file reputation."""
    try:
        import requests as req
        body    = request.json or {}
        api_key = body.get("api_key", "").strip() or (config.VIRUSTOTAL_API_KEY if config and getattr(config, "VIRUSTOTAL_API_KEY", "") else "")
        sha256  = body.get("sha256", "").strip()

        if not api_key:
            return jsonify({"error": "No API key provided. Get a free key at virustotal.com"}), 400
        if not sha256:
            return jsonify({"error": "No SHA256 hash provided"}), 400

        resp = req.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=15
        )
        if resp.status_code == 200:
            d     = resp.json()
            attrs = d.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return jsonify({
                "found":       True,
                "detected":    stats.get("malicious", 0),
                "total":       sum(stats.values()),
                "stats":       stats,
                "threat_name": attrs.get("popular_threat_name", "Unknown"),
                "permalink":   f"https://www.virustotal.com/gui/file/{sha256}",
                "first_seen":  attrs.get("first_submission_date", ""),
                "last_seen":   attrs.get("last_analysis_date", ""),
                "tags":        attrs.get("tags", []),
            })
        elif resp.status_code == 404:
            return jsonify({"found": False, "message": "Not found in VirusTotal database"})
        elif resp.status_code == 401:
            return jsonify({"error": "Invalid API key"}), 401
        else:
            return jsonify({"error": f"VirusTotal returned: {resp.status_code}"}), 500

    except ImportError:
        return jsonify({"error": "requests library not installed. Run: pip install requests"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/malwarebazaar", methods=["POST"])
def malwarebazaar():
    """Query MalwareBazaar for file reputation (no API key needed)."""
    try:
        import requests as req
        body   = request.json or {}
        sha256 = body.get("sha256", "").strip()
        if not sha256:
            return jsonify({"error": "No SHA256"}), 400

        resp = req.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=10
        )
        d = resp.json()
        if d.get("query_status") == "ok":
            info = d["data"][0]
            return jsonify({
                "found":      True,
                "signature":  info.get("signature", "Unknown"),
                "file_type":  info.get("file_type", ""),
                "first_seen": info.get("first_seen", ""),
                "reporter":   info.get("reporter", ""),
                "tags":       info.get("tags", []),
            })
        return jsonify({"found": False})
    except ImportError:
        return jsonify({"error": "requests not installed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    auto_open = getattr(config, "AUTO_OPEN_BROWSER", True) if config else True
    if auto_open:
        def _open_browser():
            time.sleep(1.5)
            webbrowser.open("http://127.0.0.1:5000")
        threading.Thread(target=_open_browser, daemon=True).start()

    host = getattr(config, "HOST", "127.0.0.1") if config else "127.0.0.1"
    port = getattr(config, "PORT", 5000) if config else 5000
    debug = getattr(config, "DEBUG", False) if config else False

    print("\n" + "═" * 56)
    print("  ╔═╗╦═╗ ╦╦═╗╔═╗╔╗ ╔═╗╦  ╔═╗")
    print("  ╚═╗║╔╩╦╝╠╦╝║╣ ╠╩╗║╣ ║  ╚═╗")
    print("  ╚═╝╩╩ ╚═╩╚═╚═╝╚═╝╚═╝╩═╝╚═╝")
    print("  ARES — Anti-Malware Triage Workstation")
    print("═" * 56)
    print(f"  ▶  http://{host}:{port}")
    print("═" * 56 + "\n")

    app.run(host=host, port=port, debug=debug)
