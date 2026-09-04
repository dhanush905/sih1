"""Evidence engine — converts findings into structured evidence items."""
from __future__ import annotations

from typing import Any

from utils.helpers import generate_evidence_id, now_iso


def build_evidence(
    header_findings: list[dict],
    url_results: list[dict],
    attachment_results: list[dict],
    ip_results: list[dict],
    threat_intel: list[dict],
    ai_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Convert all suspicious findings into structured evidence items."""
    evidence: list[dict[str, Any]] = []
    idx = 1

    # Header findings (only LOW and above)
    for f in header_findings:
        sev = f.get("severity", "INFO")
        if sev == "INFO":
            continue
        evidence.append(_item(
            idx, "Header", f.get("finding", ""), sev,
            f.get("explanation", ""), f.get("evidence", "")
        ))
        idx += 1

    # URL findings
    for u in url_results:
        sev = u.get("severity", "INFO")
        if sev in ("INFO", "LOW"):
            continue
        evidence.append(_item(
            idx, "URL", f"Suspicious URL: {u.get('domain', '')}", sev,
            "; ".join(u.get("reasons", [])) or "Suspicious URL pattern detected",
            u.get("url", "")
        ))
        idx += 1

    # Attachment findings
    for a in attachment_results:
        sev = a.get("severity", "INFO")
        if sev == "INFO":
            continue
        evidence.append(_item(
            idx, "Attachment", f"Suspicious attachment: {a.get('filename', '')}", sev,
            "; ".join(a.get("reasons", [])) or "Suspicious attachment detected",
            f"SHA-256: {a.get('sha256', '')}"
        ))
        idx += 1

    # Threat intel
    for t in threat_intel:
        rep = (t.get("reputation") or "").upper()
        if rep not in ("MALICIOUS", "SUSPICIOUS"):
            continue
        sev = "CRITICAL" if rep == "MALICIOUS" else "HIGH"
        evidence.append(_item(
            idx, "Threat Intelligence",
            f"{rep} indicator: {t.get('indicator', '')}", sev,
            t.get("evidence", ""),
            f"Source: {t.get('source', '')}"
        ))
        idx += 1

    # AI prediction
    label = (ai_result.get("label") or "").upper()
    if label in ("PHISHING", "MALWARE", "SUSPICIOUS"):
        sev = "CRITICAL" if label == "MALWARE" else "HIGH" if label == "PHISHING" else "MEDIUM"
        evidence.append(_item(
            idx, "AI Classification",
            f"AI predicted: {label}", sev,
            "; ".join(ai_result.get("explanation", [])) or "AI model classified this email as threatening",
            f"Confidence: {ai_result.get('confidence', 0):.0%}"
        ))
        idx += 1

    return evidence


def _item(idx: int, etype: str, finding: str, severity: str, desc: str, evidence: str) -> dict[str, Any]:
    return {
        "id": generate_evidence_id(idx),
        "type": etype,
        "finding": finding,
        "severity": severity,
        "description": desc,
        "evidence": evidence,
        "timestamp": now_iso(),
    }
