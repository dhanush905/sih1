"""Reputation normalization helpers."""
from __future__ import annotations

from typing import Any


def normalize_reputation(raw: str | int | None, source: str = "") -> str:
    """Normalize various reputation signals into MALICIOUS/SUSPICIOUS/UNKNOWN/CLEAN."""
    if raw is None:
        return "UNKNOWN"
    s = str(raw).lower().strip()
    if any(w in s for w in ("malicious", "malware", "phishing", "positive", "detected")):
        return "MALICIOUS"
    if any(w in s for w in ("suspicious", "susp", "abuse", "flagged", "spam")):
        return "SUSPICIOUS"
    if any(w in s for w in ("clean", "harmless", "undetected", "negative", "pass")):
        return "CLEAN"
    return "UNKNOWN"


def confidence_from_score(score: float, max_score: float = 100.0) -> float:
    """Return a 0-1 confidence from a score."""
    if max_score <= 0:
        return 0.0
    return min(1.0, score / max_score)
