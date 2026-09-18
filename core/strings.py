"""
core/strings.py
String extraction from binary data.
"""

import re
import base64


SUSPICIOUS_PATTERNS = [
    r'powershell',
    r'cmd\.exe',
    r'\\run\\',
    r'regsvr32',
    r'schtasks',
    r'wscript',
    r'cscript',
    r'base64',
    r'shellcode',
    r'VirtualAlloc',
    r'WriteProcess',
    r'CreateRemote',
    r'https?://',
    r'\\AppData\\',
    r'\\Temp\\',
    r'wget',
    r'mimikatz',
    r'invoke\-',
    r'\-encodedcommand',
    r'bypass',
    r'amsi',
]

_SUSP_RE = re.compile('|'.join(SUSPICIOUS_PATTERNS), re.IGNORECASE)


def _try_decode_b64(s: str):
    """Attempt to decode a base64 string. Returns decoded text or None."""
    try:
        padded = s + "=" * (4 - len(s) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
        if any(c.isalpha() for c in decoded) and len(decoded) >= 8:
            return decoded
    except Exception:
        pass
    return None


def extract_strings(data: bytes, min_len: int = 5) -> dict:
    """
    Extract ASCII, Unicode strings and detect suspicious content.
    Returns: {"ascii": [...], "unicode": [...], "suspicious": [...],
              "b64_decoded": [...], "total": int}
    """
    # ASCII strings
    ascii_re   = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    # Wide-char Unicode strings (UTF-16 LE pattern)
    unicode_re = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')

    ascii_strings   = [s.decode("ascii", errors="ignore")
                       for s in ascii_re.findall(data)]
    unicode_strings = [s.decode("utf-16-le", errors="ignore")
                       for s in unicode_re.findall(data)]

    all_strings = ascii_strings + unicode_strings

    # Suspicious strings
    suspicious = [s for s in all_strings if _SUSP_RE.search(s)]

    # Try to decode base64 blobs
    b64_re  = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    b64_decoded = []
    seen_b64 = set()
    for s in all_strings:
        for match in b64_re.findall(s):
            if match not in seen_b64:
                seen_b64.add(match)
                decoded = _try_decode_b64(match)
                if decoded:
                    b64_decoded.append({
                        "encoded": match[:60],
                        "decoded": decoded[:300],
                    })
        if len(b64_decoded) >= 20:
            break

    return {
        "ascii":       ascii_strings[:1000],
        "unicode":     unicode_strings[:300],
        "suspicious":  suspicious[:100],
        "b64_decoded": b64_decoded,
        "total":       len(all_strings),
    }
