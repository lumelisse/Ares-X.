"""
core/pe.py
PE (Portable Executable) analysis module.
Works on raw bytes — no temp files needed.
"""

from datetime import datetime

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

SUSPICIOUS_APIS = {
    # Injection
    "VirtualAllocEx":           ("Injection",             "T1055.001", "critical"),
    "WriteProcessMemory":        ("Injection",             "T1055.002", "critical"),
    "CreateRemoteThread":        ("Injection",             "T1055",     "critical"),
    "NtUnmapViewOfSection":      ("Injection",             "T1055.012", "critical"),
    "SetThreadContext":           ("Injection",             "T1055",     "critical"),
    # Keylogging
    "SetWindowsHookExA":         ("Keylogging",            "T1056.001", "critical"),
    "SetWindowsHookExW":         ("Keylogging",            "T1056.001", "critical"),
    "GetAsyncKeyState":          ("Keylogging",            "T1056.001", "high"),
    "GetKeyState":               ("Keylogging",            "T1056.001", "high"),
    # Persistence
    "RegSetValueExA":            ("Persistence",           "T1547.001", "critical"),
    "RegSetValueExW":            ("Persistence",           "T1547.001", "critical"),
    "CreateServiceA":            ("Persistence",           "T1543.003", "critical"),
    "CreateServiceW":            ("Persistence",           "T1543.003", "critical"),
    "ChangeServiceConfigA":      ("Persistence",           "T1543.003", "high"),
    # Anti-Debug
    "IsDebuggerPresent":         ("Anti-Debug",            "T1622",     "medium"),
    "CheckRemoteDebuggerPresent":("Anti-Debug",            "T1622",     "medium"),
    "NtQueryInformationProcess": ("Anti-Debug",            "T1622",     "medium"),
    "OutputDebugStringA":        ("Anti-Debug",            "T1622",     "low"),
    # Network / C2
    "HttpSendRequestA":          ("Network/C2",            "T1071.001", "high"),
    "HttpSendRequestW":          ("Network/C2",            "T1071.001", "high"),
    "InternetConnectA":          ("Network/C2",            "T1071.001", "high"),
    "WSAConnect":                ("Network/C2",            "T1071.001", "high"),
    "URLDownloadToFileA":        ("Downloader",            "T1105",     "high"),
    "URLDownloadToFileW":        ("Downloader",            "T1105",     "high"),
    # Execution
    "ShellExecuteA":             ("Execution",             "T1059",     "medium"),
    "ShellExecuteW":             ("Execution",             "T1059",     "medium"),
    "WinExec":                   ("Execution",             "T1059",     "high"),
    "CreateProcessA":            ("Execution",             "T1059",     "medium"),
    # Screenshot
    "BitBlt":                    ("Screenshot",            "T1113",     "medium"),
    "PrintWindow":               ("Screenshot",            "T1113",     "medium"),
    # Credentials
    "CryptUnprotectData":        ("Credential Access",     "T1555.003", "high"),
    "CredEnumerateA":            ("Credential Access",     "T1555",     "high"),
    # Evasion
    "SleepEx":                   ("Evasion/Timing",        "T1497.003", "low"),
    "GetTickCount":              ("Evasion/Timing",        "T1497.003", "low"),
    "LoadLibraryA":              ("Dynamic Loading",       "T1574",     "medium"),
    "GetProcAddress":            ("Dynamic Loading",       "T1027",     "medium"),
    # Privilege
    "AdjustTokenPrivileges":     ("Privilege Escalation",  "T1068",     "high"),
    "OpenProcessToken":          ("Privilege Escalation",  "T1068",     "medium"),
}

MACHINE_MAP = {
    0x14c:  "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x1c0:  "ARM (32-bit)",
    0xaa64: "ARM64",
    0x200:  "IA-64",
}


def analyze_pe(data: bytes) -> dict:
    """Analyze PE binary from raw bytes. Returns empty dict if not PE or pefile missing."""
    if not HAS_PEFILE:
        return {"error": "pefile not installed — run: pip install pefile"}

    try:
        pe = pefile.PE(data=data)

        # ── Basic info ────────────────────────────────────────────────────────
        machine   = MACHINE_MAP.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        timestamp = ""
        try:
            timestamp = datetime.fromtimestamp(
                pe.FILE_HEADER.TimeDateStamp
            ).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            timestamp = hex(pe.FILE_HEADER.TimeDateStamp)

        # ── Sections ──────────────────────────────────────────────────────────
        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            ent  = round(s.get_entropy(), 2)
            sections.append({
                "name":        name,
                "entropy":     ent,
                "rsize":       s.SizeOfRawData,
                "vsize":       s.Misc_VirtualSize,
                "vaddr":       hex(s.VirtualAddress),
                "suspicious":  ent > 7.0,
            })

        # ── Imports & Capabilities ────────────────────────────────────────────
        imports      = []
        capabilities = []
        seen_caps    = set()

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("ascii", errors="ignore") if entry.dll else "?"
                for imp in entry.imports:
                    if imp.name:
                        fn = imp.name.decode("ascii", errors="ignore")
                        imports.append({"dll": dll, "function": fn})
                        if fn in SUSPICIOUS_APIS and fn not in seen_caps:
                            cat, mitre, sev = SUSPICIOUS_APIS[fn]
                            capabilities.append({
                                "api":      fn,
                                "category": cat,
                                "mitre":    mitre,
                                "severity": sev,
                            })
                            seen_caps.add(fn)

        # ── Exports ───────────────────────────────────────────────────────────
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("ascii", errors="ignore"))

        # ── ImpHash ───────────────────────────────────────────────────────────
        imphash = ""
        try:
            imphash = pe.get_imphash()
        except Exception:
            pass

        # ── Signature ─────────────────────────────────────────────────────────
        is_signed = (
            hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
            and pe.DIRECTORY_ENTRY_SECURITY is not None
        )

        # ── Rich Header ───────────────────────────────────────────────────────
        has_rich_header = hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER is not None

        # ── Overlay ───────────────────────────────────────────────────────────
        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_size   = 0
        if overlay_offset:
            overlay_size = len(data) - overlay_offset

        return {
            "machine":         machine,
            "timestamp":       timestamp,
            "num_sections":    len(pe.sections),
            "is_signed":       is_signed,
            "has_rich_header": has_rich_header,
            "imphash":         imphash,
            "entry_point":     hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base":      hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem":       pe.OPTIONAL_HEADER.Subsystem,
            "overlay_offset":  hex(overlay_offset) if overlay_offset else None,
            "overlay_size":    overlay_size,
            "sections":        sections,
            "imports":         imports[:200],
            "exports":         exports[:50],
            "capabilities":    capabilities,
        }

    except Exception as e:
        return {"error": str(e), "sections": [], "capabilities": []}
