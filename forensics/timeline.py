"""Forensic timeline generation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from utils.helpers import now_iso


def build_timeline(
    parsed: dict[str, Any] | None = None,
    ip_results: list[dict] | None = None,
    url_results: list[dict] | None = None,
    attachment_results: list[dict] | None = None,
    threat_intel: list[dict] | None = None,
    ai_result: dict | None = None,
    risk_result: dict | None = None,
) -> list[dict[str, Any]]:
    """Build a chronological investigation timeline."""
    timeline: list[dict[str, Any]] = []
    step = 0

    def _add(event: str, detail: str = "", ts: str | None = None) -> None:
        nonlocal step
        step += 1
        timeline.append({
            "step": step,
            "event": event,
            "detail": detail,
            "timestamp": ts or now_iso(),
        })

    # Email date as starting point
    email_date = ""
    if parsed and parsed.get("date"):
        email_date = parsed["date"]
        _add("Email received", f"Date header: {email_date}", email_date if _parse_date(email_date) else None)
    else:
        _add("Email received", "No date header")

    _add("Email headers parsed", f"From: {parsed.get('from', 'N/A')}" if parsed else "")
    _add("Source IP identified", f"{len(ip_results or [])} IP(s) extracted")
    _add("IP geolocated", f"{sum(1 for g in (ip_results or []) if g.get('lat'))} location(s) resolved")
    _add("URLs extracted", f"{len(url_results or [])} URL(s) found")
    _add("Domains analyzed", "")
    _add("Threat intelligence queried", f"{len(threat_intel or [])} indicator(s) checked")
    _add("Attachments hashed", f"{len(attachment_results or [])} attachment(s)")
    _add("AI classification performed", f"Label: {ai_result.get('label', 'N/A') if ai_result else 'N/A'}")
    _add("Risk score calculated", f"Score: {risk_result.get('score', 'N/A')}/100 ({risk_result.get('level', 'N/A')})" if risk_result else "")
    _add("Evidence generated", "")
    _add("Investigation complete", "")

    return timeline


def _parse_date(date_str: str) -> str | None:
    """Try to parse an email date and return ISO format."""
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S", "%d %b %Y %H:%M:%S %z"):
        try:
            dt = datetime.strptime(date_str[:31], fmt)
            return dt.isoformat()
        except (ValueError, TypeError):
            continue
    return None
