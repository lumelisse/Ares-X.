"""
core/yara.py
YARA scanning engine with graceful fallback if yara-python not installed.
"""

import os
import glob
from pathlib import Path

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

RULES_DIR = Path(__file__).parent.parent / "rules"


def scan_with_yara(data: bytes) -> list:
    """
    Scan raw bytes against all .yar / .yara rule files in the rules/ folder.
    Returns list of hit dicts. Returns [] if yara-python not installed.
    """
    if not HAS_YARA:
        return []

    hits = []
    rule_files = (
        list(RULES_DIR.glob("*.yar")) +
        list(RULES_DIR.glob("*.yara"))
    )

    for rule_file in rule_files:
        try:
            rules   = yara.compile(str(rule_file))
            matches = rules.match(data=data)
            for m in matches:
                hits.append({
                    "rule":    m.rule,
                    "tags":    list(m.tags),
                    "meta":    dict(m.meta) if m.meta else {},
                    "strings": [
                        {"offset": hex(s.instances[0].offset), "id": s.identifier}
                        for s in m.strings[:5]
                    ] if m.strings else [],
                    "source":  rule_file.name,
                })
        except Exception:
            # Skip invalid rule files silently
            pass

    return hits
