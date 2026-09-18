"""
core/packer.py
Packer and obfuscator detection via signature matching + entropy.
Works on raw bytes.
"""

PACKER_SIGNATURES = [
    # (byte_signature, name, base_confidence)
    (b"UPX0",                "UPX",              95),
    (b"UPX1",                "UPX",              95),
    (b"UPX!",                "UPX",              95),
    (b".aspack",             "ASPack",            90),
    (b"ASPack",              "ASPack",            88),
    (b"MPRESS1",             "MPRESS",            90),
    (b"MPRESS2",             "MPRESS",            90),
    (b"PECompact2",          "PECompact",         85),
    (b"Themida",             "Themida",           85),
    (b"WinLicense",          "Themida/WinLicense",83),
    (b"VMProtect",           "VMProtect",         85),
    (b"VMP0",                "VMProtect",         85),
    (b"Obsidium",            "Obsidium",          80),
    (b"Armadillo",           "Armadillo",         80),
    (b"Enigma Protector",    "Enigma Protector",  80),
    (b".enigma1",            "Enigma Protector",  78),
    (b"PETITE ",             "Petite",            82),
    (b"nSpack",              "nSpack",            80),
    (b"yC ",                 "yoda's Crypter",    75),
]


def detect_packers(data: bytes, entropy: float) -> list:
    """
    Detect known packers by byte signatures.
    Also flags high-entropy files as likely packed even without known sig.

    Returns: list of {"name": str, "confidence": int, "detected": True}
    """
    found = []
    seen  = set()

    for sig, name, base_conf in PACKER_SIGNATURES:
        if sig in data and name not in seen:
            # Boost confidence based on entropy
            conf = base_conf
            if entropy > 7.5:
                conf = min(99, conf + 4)
            elif entropy > 7.0:
                conf = min(99, conf + 2)

            found.append({
                "name":       name,
                "confidence": conf,
                "detected":   True,
            })
            seen.add(name)

    # Generic high-entropy detection (no known sig)
    if not found and entropy > 7.5:
        found.append({
            "name":       "Unknown Packer / Obfuscator",
            "confidence": min(88, int((entropy / 8) * 92)),
            "detected":   True,
        })

    return found
