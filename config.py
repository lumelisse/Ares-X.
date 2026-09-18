"""
config.py
Configuration management — loads settings from environment variables.
"""

import os


class Config:
    """Application configuration from environment variables."""

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # Server
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 5000))

    # File upload
    MAX_CONTENT_MB = int(os.environ.get("MAX_CONTENT_MB", 256))
    MAX_CONTENT_LENGTH = MAX_CONTENT_MB * 1024 * 1024

    # Upload directory
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "uploads"))

    # VirusTotal (optional)
    VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")

    # YARA rules directory
    RULES_DIR = os.environ.get("RULES_DIR", os.path.join(os.path.dirname(__file__), "rules"))

    # Auto-open browser
    AUTO_OPEN_BROWSER = os.environ.get("AUTO_OPEN_BROWSER", "true").lower() == "true"


config = Config()
