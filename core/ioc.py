"""
core/ioc.py
IOC (Indicator of Compromise) extraction from string lists.
"""

import re


# ── Regex patterns ────────────────────────────────────────────────────────────
_DOMAIN_RE  = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|xyz|io|ru|cn|tk|cc|info|biz|top|online|site|app|dev|me|co|uk|de|fr)\b'
)
_URL_RE     = re.compile(r'https?://[^\s"\'<>]{8,}')
_IPV4_RE    = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_EMAIL_RE   = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_REGKEY_RE  = re.compile(r'(?:HKEY_[A-Z_]+|HKCU|HKLM|HKCR|HKU|HKCC)(?:\\[^\n"\'\\]{1,80})+')
_MUTEX_RE   = re.compile(r'(?:Global|Local)\\[^\n"\']{4,80}')
_WALLET_RE  = re.compile(r'\b(?:1[a-zA-HJ-NP-Z0-9]{25,34}|3[a-zA-HJ-NP-Z0-9]{25,34}|bc1[a-z0-9]{39,59})\b')
_UA_RE      = re.compile(r'Mozilla/[0-9.]+[^\n"\']{10,200}')


_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.", "0.0.0.0", "255.255.", "169.254."
)
_PRIVATE_172 = range(16, 32)


def _is_public_ip(ip: str) -> bool:
    for pfx in _PRIVATE_PREFIXES:
        if ip.startswith(pfx):
            return False
    parts = ip.split(".")
    if parts[0] == "172":
        try:
            if int(parts[1]) in _PRIVATE_172:
                return False
        except ValueError:
            pass
    return True


def extract_iocs(strings_list: list) -> dict:
    """
    Extract and categorize IOCs from a list of strings.
    Returns dict with categorized lists.
    """
    text = "\n".join(strings_list)

    domains = list(dict.fromkeys(_DOMAIN_RE.findall(text)))
    urls    = list(dict.fromkeys(_URL_RE.findall(text)))
    ipv4    = [ip for ip in dict.fromkeys(_IPV4_RE.findall(text)) if _is_public_ip(ip)]
    emails  = list(dict.fromkeys(_EMAIL_RE.findall(text)))
    regkeys = list(dict.fromkeys(_REGKEY_RE.findall(text)))
    mutexes = list(dict.fromkeys(_MUTEX_RE.findall(text)))
    wallets = list(dict.fromkeys(_WALLET_RE.findall(text)))
    uas     = list(dict.fromkeys(_UA_RE.findall(text)))

    return {
        "domains": domains[:40],
        "urls":    urls[:30],
        "ips":     ipv4[:30],
        "emails":  emails[:20],
        "regkeys": regkeys[:20],
        "mutexes": mutexes[:20],
        "wallets": wallets[:10],
        "useragents": uas[:5],
    }
