"""
core/risk.py
Risk scoring engine — aggregates findings into a final threat score.
Input: full analysis result dict
Output: {"score": 0-100, "verdict": str, "color": str, "reasons": list}
"""


VERDICT_MAP = [
    (80, "CRITICAL THREAT", "#f05562"),
    (60, "HIGH RISK",        "#f0855a"),
    (40, "LIKELY MALICIOUS", "#f0c55a"),
    (20, "SUSPICIOUS",       "#5ab8f0"),
    (0,  "CLEAN",            "#4fd18a"),
]

SEV_SCORES = {
    "critical": 18,
    "high":     10,
    "medium":    5,
    "low":       2,
    "info":      0,
}


def compute_risk(analysis: dict) -> dict:
    """
    Compute overall risk score from the full analysis result.
    Always returns a valid dict — never raises.
    """
    score   = 0
    reasons = []

    # ── Capabilities / suspicious imports ────────────────────────────────────
    caps = []
    pe   = analysis.get("pe", {})
    if isinstance(pe, dict):
        caps = pe.get("capabilities", []) or []

    for cap in caps:
        sev = cap.get("severity", "low")
        pts = SEV_SCORES.get(sev, 2)
        score += pts
        reasons.append(f"{cap.get('category','API')}: {cap.get('api','')} [{sev}]")

    # ── Section entropy anomalies ─────────────────────────────────────────────
    sections = pe.get("sections", []) if isinstance(pe, dict) else []
    for sec in sections:
        ent = sec.get("entropy", 0)
        if ent > 7.5:
            score += 15
            reasons.append(f"Critical entropy in {sec.get('name','?')}: {ent}")
        elif ent > 7.0:
            score += 8
            reasons.append(f"High entropy in {sec.get('name','?')}: {ent}")
        elif ent > 6.5:
            score += 3

    # ── Overall file entropy ──────────────────────────────────────────────────
    file_ent = analysis.get("entropy", 0)
    if file_ent > 7.5:
        score += 10
        reasons.append(f"File entropy critically high: {file_ent}")
    elif file_ent > 7.0:
        score += 5

    # ── Packers ───────────────────────────────────────────────────────────────
    packers = analysis.get("packers", []) or []
    for pk in packers:
        pts = max(8, int(pk.get("confidence", 80) / 6))
        score += pts
        reasons.append(f"Packer detected: {pk.get('name', 'Unknown')} ({pk.get('confidence', 0)}% confidence)")

    # ── YARA hits ─────────────────────────────────────────────────────────────
    yara_hits = analysis.get("yara_hits", []) or []
    score += len(yara_hits) * 12
    for hit in yara_hits:
        reasons.append(f"YARA match: {hit.get('rule', 'unknown')}")

    # ── IOC quality ───────────────────────────────────────────────────────────
    iocs = analysis.get("iocs", {}) or {}
    domains = iocs.get("domains", []) or []
    ips     = iocs.get("ips",     []) or []
    urls    = iocs.get("urls",    []) or []
    mutexes = iocs.get("mutexes", []) or []
    regkeys = iocs.get("regkeys", []) or []

    score += min(len(domains) * 3, 15)
    score += min(len(ips)     * 2, 10)
    score += min(len(urls)    * 4, 15)
    score += min(len(mutexes) * 6, 18)
    score += min(len(regkeys) * 4, 12)

    if domains:  reasons.append(f"{len(domains)} suspicious domain(s) extracted")
    if ips:      reasons.append(f"{len(ips)} IP address(es) extracted")
    if mutexes:  reasons.append(f"{len(mutexes)} mutex name(s) found")
    if regkeys:  reasons.append(f"{len(regkeys)} registry key(s) found")

    # ── PE unsigned binary ────────────────────────────────────────────────────
    if isinstance(pe, dict) and pe and not pe.get("is_signed", True) and not pe.get("error"):
        score += 3
        reasons.append("Binary is unsigned")

    # ── Overlay ───────────────────────────────────────────────────────────────
    if isinstance(pe, dict) and pe.get("overlay_size", 0) > 0:
        score += 5
        reasons.append(f"Overlay data detected: {pe['overlay_size']} bytes")

    # ── Clamp and verdict ─────────────────────────────────────────────────────
    score = min(score, 100)

    verdict = "CLEAN"
    color   = "#4fd18a"
    for threshold, label, clr in VERDICT_MAP:
        if score >= threshold:
            verdict = label
            color   = clr
            break

    return {
        "score":   score,
        "verdict": verdict,
        "color":   color,
        "reasons": reasons[:12],
    }
