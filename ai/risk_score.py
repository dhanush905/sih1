"""Explainable 0-100 risk score with weighted components."""
from __future__ import annotations

from typing import Any

from utils.constants import RISK_WEIGHTS
from utils.helpers import risk_level


def calculate_risk(
    ai_result: dict[str, Any],
    header_findings: list[dict],
    url_results: list[dict],
    attachment_results: list[dict],
    threat_intel: list[dict],
) -> dict[str, Any]:
    """Calculate weighted risk score and return full breakdown."""
    components: dict[str, dict[str, Any]] = {}

    # AI detection (40%)
    ai_score, ai_reasons = _ai_score(ai_result)
    components["ai_detection"] = {
        "raw": ai_score,
        "weighted": ai_score * RISK_WEIGHTS["ai_detection"],
        "weight": RISK_WEIGHTS["ai_detection"],
        "reasons": ai_reasons[:5],
    }

    # Header forensics (20%)
    hdr_score, hdr_reasons = _header_score(header_findings)
    components["header_forensics"] = {
        "raw": hdr_score,
        "weighted": hdr_score * RISK_WEIGHTS["header_forensics"],
        "weight": RISK_WEIGHTS["header_forensics"],
        "reasons": hdr_reasons,
    }

    # URL analysis (15%)
    url_score, url_reasons = _url_score(url_results)
    components["url_analysis"] = {
        "raw": url_score,
        "weighted": url_score * RISK_WEIGHTS["url_analysis"],
        "weight": RISK_WEIGHTS["url_analysis"],
        "reasons": url_reasons,
    }

    # Threat intelligence (15%)
    ti_score, ti_reasons = _threat_intel_score(threat_intel)
    components["threat_intelligence"] = {
        "raw": ti_score,
        "weighted": ti_score * RISK_WEIGHTS["threat_intelligence"],
        "weight": RISK_WEIGHTS["threat_intelligence"],
        "reasons": ti_reasons,
    }

    # Attachment analysis (10%)
    att_score, att_reasons = _attachment_score(attachment_results)
    components["attachment_analysis"] = {
        "raw": att_score,
        "weighted": att_score * RISK_WEIGHTS["attachment_analysis"],
        "weight": RISK_WEIGHTS["attachment_analysis"],
        "reasons": att_reasons,
    }

    total = sum(c["weighted"] for c in components.values())
    total = min(100, max(0, round(total)))
    level = risk_level(total)

    increasing = []
    decreasing = []
    for name, comp in components.items():
        if comp["raw"] >= 50:
            increasing.extend(comp["reasons"])
        elif comp["raw"] > 0 and comp["raw"] < 25:
            decreasing.append(f"{name.replace('_', ' ').title()}: low ({int(comp['raw'])})")

    return {
        "score": total,
        "level": level,
        "components": components,
        "increasing": increasing,
        "decreasing": decreasing,
    }


def _ai_score(ai: dict) -> tuple[int, list[str]]:
    label = (ai.get("label") or "").upper()
    conf = ai.get("confidence", 0)
    mapping = {"BENIGN": 5, "SPAM": 30, "SUSPICIOUS": 55, "PHISHING": 85, "MALWARE": 95}
    base = mapping.get(label, 50)
    # adjust by confidence
    score = int(base * (0.6 + 0.4 * conf))
    return min(100, score), ai.get("explanation", [])


def _header_score(findings: list[dict]) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    sev_weight = {"CRITICAL": 25, "HIGH": 18, "MEDIUM": 10, "LOW": 5, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        w = sev_weight.get(sev, 0)
        if w > 0:
            score += w
            reasons.append(f"{f.get('finding', '')} ({sev})")
    return min(100, score), reasons


def _url_score(urls: list[dict]) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    for u in urls:
        sev = u.get("severity", "INFO")
        w = {"CRITICAL": 30, "HIGH": 22, "MEDIUM": 12, "LOW": 5, "INFO": 0}.get(sev, 0)
        if w > 0:
            score += w
            reasons.append(f"URL {u.get('domain', '')} ({sev})")
    return min(100, score), reasons


def _threat_intel_score(ti: list[dict]) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    for t in ti:
        rep = (t.get("reputation") or "").upper()
        if rep == "MALICIOUS":
            score += 40
            reasons.append(f"Malicious: {t.get('indicator', '')}")
        elif rep == "SUSPICIOUS":
            score += 20
            reasons.append(f"Suspicious: {t.get('indicator', '')}")
    return min(100, score), reasons


def _attachment_score(atts: list[dict]) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    for a in atts:
        sev = a.get("severity", "INFO")
        w = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "INFO": 0}.get(sev, 0)
        if w > 0:
            score += w
            reasons.append(f"Attachment {a.get('filename', '')} ({sev})")
    return min(100, score), reasons
