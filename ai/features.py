"""Feature engineering for email threat classification."""
from __future__ import annotations

from typing import Any

from analyzers.email_parser import ParsedEmail
from utils.constants import URGENCY_KEYWORDS


def extract_features(
    parsed: ParsedEmail,
    header_findings: list[dict],
    url_results: list[dict],
    attachment_results: list[dict],
    threat_intel: list[dict],
) -> dict[str, Any]:
    """Return a flat feature dict used by both the ML model and risk engine."""
    features: dict[str, Any] = {}

    # Subject features
    subject_lower = (parsed.subject or "").lower()
    features["subject_urgency"] = int(any(k in subject_lower for k in URGENCY_KEYWORDS))
    features["subject_security_keyword"] = int(any(
        k in subject_lower for k in ("security", "verify", "password", "account", "alert", "suspend", "unlock")
    ))
    features["subject_length"] = len(parsed.subject or "")

    # Sender features
    from_domain = _domain(parsed.from_)
    reply_domain = _domain(parsed.reply_to)
    rp_domain = _domain(parsed.return_path)
    features["sender_domain"] = from_domain
    features["reply_to_mismatch"] = int(
        bool(parsed.reply_to) and reply_domain != from_domain and reply_domain != ""
    )
    features["return_path_mismatch"] = int(
        bool(parsed.return_path) and rp_domain != from_domain and rp_domain != ""
    )

    # Authentication features
    features["spf_fail"] = int(_auth_state(header_findings, "SPF") == "FAIL")
    features["dkim_fail"] = int(_auth_state(header_findings, "DKIM") == "FAIL")
    features["dmarc_fail"] = int(_auth_state(header_findings, "DMARC") == "FAIL")
    features["auth_fail_count"] = (
        features["spf_fail"] + features["dkim_fail"] + features["dmarc_fail"]
    )
    features["missing_auth"] = int(
        not bool(parsed.auth_headers)
    )

    # URL features
    features["num_urls"] = len(url_results)
    features["num_suspicious_urls"] = sum(
        1 for u in url_results if u.get("severity") in ("HIGH", "CRITICAL")
    )
    features["has_ip_url"] = int(any(u.get("is_ip") for u in url_results))
    features["max_url_length"] = max((u.get("length", 0) for u in url_results), default=0)
    features["has_suspicious_tld"] = int(any(u.get("suspicious_tld") for u in url_results))
    features["has_shortener"] = int(any(u.get("is_shortener") for u in url_results))
    features["has_non_https"] = int(any(not u.get("is_https") for u in url_results))

    # Attachment features
    features["num_attachments"] = len(attachment_results)
    features["dangerous_attachment"] = int(any(a.get("is_dangerous") for a in attachment_results))
    features["macro_attachment"] = int(any(a.get("is_macro") for a in attachment_results))
    features["double_extension"] = int(any(a.get("double_extension") for a in attachment_results))

    # Body features
    body_lower = (parsed.body_text or "").lower()
    features["html_present"] = int(bool(parsed.body_html))
    features["body_length"] = len(parsed.body_text or "")
    features["urgency_in_body"] = int(any(k in body_lower for k in URGENCY_KEYWORDS))
    features["suspicious_keyword_count"] = sum(
        1 for k in ("verify", "password", "account", "login", "confirm", "update", "secure")
        if k in body_lower
    )

    # Threat intelligence
    features["threat_intel_hits"] = sum(
        1 for t in threat_intel if t.get("reputation") in ("MALICIOUS", "SUSPICIOUS")
    )
    features["threat_intel_malicious"] = sum(
        1 for t in threat_intel if t.get("reputation") == "MALICIOUS"
    )

    return features


def _domain(addr: str) -> str:
    import re
    if not addr:
        return ""
    m = re.search(r"@([\w.-]+)", addr)
    return m.group(1).lower() if m else ""


def _auth_state(findings: list[dict], label: str) -> str:
    """Extract PASS/FAIL/etc from header findings."""
    for f in findings:
        name = f.get("finding", "").lower()
        if label.lower() in name:
            if "pass" in name:
                return "PASS"
            if "fail" in name:
                return "FAIL"
            if "softfail" in name:
                return "SOFTFAIL"
            if "neutral" in name:
                return "NEUTRAL"
            if "none" in name or "missing" in name:
                return "NONE"
            return "UNKNOWN"
    return "UNKNOWN"
