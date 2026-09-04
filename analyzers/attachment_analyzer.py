"""Attachment forensics — hashing, extension analysis, never executes."""
from __future__ import annotations

import re
from typing import Any

from utils.constants import DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS
from utils.helpers import format_bytes, sanitize_filename
from .email_parser import Attachment


def analyze_attachment(att: Attachment) -> dict[str, Any]:
    """Return forensic metadata for an attachment."""
    safe_name = sanitize_filename(att.filename)
    ext = _extension(safe_name)
    result: dict[str, Any] = {
        "filename": safe_name,
        "extension": ext,
        "mime_type": att.content_type,
        "size": att.size,
        "size_human": format_bytes(att.size),
        "sha256": att.sha256,
        "md5": att.md5,
        "is_dangerous": ext in DANGEROUS_EXTENSIONS,
        "is_macro": ext in MACRO_EXTENSIONS,
        "double_extension": _has_double_extension(safe_name),
        "suspicious_name": _suspicious_filename(safe_name),
        "severity": "INFO",
        "reasons": [],
    }

    if result["is_dangerous"]:
        result["reasons"].append(f"Dangerous extension: .{ext}")
    if result["is_macro"]:
        result["reasons"].append(f"Macro-enabled Office file: .{ext}")
    if result["double_extension"]:
        result["reasons"].append("Double extension detected")
    if result["suspicious_name"]:
        result["reasons"].append("Suspicious filename pattern")

    result["severity"] = _severity(result)
    return result


def analyze_attachments(attachments: list[Attachment]) -> list[dict[str, Any]]:
    """Analyze all attachments."""
    return [analyze_attachment(a) for a in attachments]


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _has_double_extension(filename: str) -> bool:
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    exts = [p.lower() for p in parts[1:]]
    # e.g. invoice.pdf.exe
    dangerous = DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS
    return any(e in dangerous for e in exts)


def _suspicious_filename(filename: str) -> bool:
    lower = filename.lower()
    patterns = ["invoice", "payment", "receipt", "document", "statement",
                "confirm", "secure", "update", "alert", "verify"]
    return any(p in lower for p in patterns)


def _severity(r: dict[str, Any]) -> str:
    if r["is_dangerous"] or r["double_extension"]:
        return "CRITICAL"
    if r["is_macro"]:
        return "HIGH"
    if r["suspicious_name"]:
        return "MEDIUM"
    return "INFO"
