"""Utility helpers for the email forensics platform."""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .constants import (
    SEVERITY_ORDER,
    SEVERITY_RANK,
    THREAT_LABELS,
)


def generate_investigation_id() -> str:
    """Return a unique investigation identifier."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    short = uuid.uuid4().hex[:8]
    return f"INV-{stamp}-{short}"


def generate_evidence_id(index: int) -> str:
    """Return a human-readable evidence identifier."""
    return f"EVD-{index:04d}"


def now_iso() -> str:
    """Return current UTC time in ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    """Return MD5 hex digest of raw bytes."""
    return hashlib.md5(data).hexdigest()


def safe_get(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dict keys."""
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur if cur is not None else default


def truncate(text: str, limit: int = 500) -> str:
    """Truncate long text for display."""
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "..."


def sanitize_filename(name: str) -> str:
    """Remove path separators and dangerous characters from a filename."""
    if not name:
        return "unknown"
    # take basename only
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:200]


def severity_rank(sev: str) -> int:
    """Return numeric rank for a severity label (higher = worse)."""
    return SEVERITY_RANK.get((sev or "").upper(), 0)


def sort_findings_by_severity(findings: list[dict]) -> list[dict]:
    """Sort findings from most to least severe."""
    return sorted(findings, key=lambda f: severity_rank(f.get("severity", "INFO")), reverse=True)


def threat_label_color(label: str) -> str:
    """Return a hex color for a threat label."""
    return THREAT_LABELS.get((label or "").upper(), "#6e7681")


def severity_color(sev: str) -> str:
    """Return a hex color for a severity level."""
    colors = {
        "INFO": "#00d4ff",
        "LOW": "#3fb950",
        "MEDIUM": "#d29922",
        "HIGH": "#db6d28",
        "CRITICAL": "#f85149",
    }
    return colors.get((sev or "").upper(), "#6e7681")


def risk_level(score: int | float) -> str:
    """Map a 0-100 risk score to a risk level."""
    s = int(score)
    if s <= 25:
        return "LOW"
    if s <= 50:
        return "MEDIUM"
    if s <= 75:
        return "HIGH"
    return "CRITICAL"


def risk_color(level: str) -> str:
    """Return hex color for a risk level."""
    return {
        "LOW": "#3fb950",
        "MEDIUM": "#d29922",
        "HIGH": "#db6d28",
        "CRITICAL": "#f85149",
    }.get((level or "").upper(), "#6e7681")


def format_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore
    return f"{n:.1f} TB"


def extract_domain_from_email(addr: str) -> str:
    """Extract the domain portion from an email address."""
    if not addr:
        return ""
    m = re.search(r"@([\w.-]+)", addr)
    return m.group(1).lower() if m else ""


def extract_email_address(raw: str) -> str:
    """Extract bare email address from a From/To header value."""
    if not raw:
        return ""
    m = re.search(r"<([^>]+)>", raw)
    if m:
        return m.group(1).strip().lower()
    m = re.search(r"[\w.+-]+@[\w.-]+", raw)
    return m.group(0).lower() if m else raw.strip().lower()
