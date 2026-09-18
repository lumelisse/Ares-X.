"""
utils/hash.py
Hash computation from raw bytes.
"""

import hashlib

try:
    import ssdeep as _ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False


def calculate_hashes(data: bytes) -> dict:
    """Calculate MD5, SHA1, SHA256, SHA512 and optionally ssdeep fuzzy hash."""
    result = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }

    if HAS_SSDEEP:
        try:
            result["ssdeep"] = _ssdeep.hash(data)
        except Exception:
            result["ssdeep"] = "unavailable"
    else:
        result["ssdeep"] = "install python-ssdeep for fuzzy hashing"

    return result
