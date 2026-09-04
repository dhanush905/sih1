"""Email header forensics: SPF / DKIM / DMARC and spoofing checks."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from .email_parser import ParsedEmail
from utils.constants import FREE_MAIL_PROVIDERS
from utils.helpers import extract_email_address, extract_domain_from_email


def analyze_headers(parsed: ParsedEmail) -> list[dict[str, Any]]:
    """Return a list of header-forensic findings.

    Each finding is a dict with keys: finding, severity, explanation, evidence.
    """
    findings: list[dict[str, Any]] = []

    # Authentication
    findings.extend(_check_spf(parsed))
    findings.extend(_check_dkim(parsed))
    findings.extend(_check_dmarc(parsed))

    # Spoofing checks
    findings.extend(_check_reply_to_mismatch(parsed))
    findings.extend(_check_return_path_mismatch(parsed))
    findings.extend(_check_display_name_spoof(parsed))
    findings.extend(_check_free_mail_sender(parsed))
    findings.extend(_check_message_id_domain(parsed))

    # Routing
    findings.extend(_check_received_headers(parsed))
    findings.extend(_check_private_ips(parsed))
    findings.extend(_check_timestamp_anomalies(parsed))

    # Missing auth
    findings.extend(_check_missing_auth(parsed))

    return findings


def _check_spf(parsed: ParsedEmail) -> list[dict]:
    results = []
    auth = parsed.auth_headers.get("Authentication-Results", "")
    received_spf = parsed.auth_headers.get("Received-SPF", "")
    combined = (auth + " " + received_spf).lower()

    if not combined.strip():
        return [_finding("Missing SPF record", "MEDIUM",
                         "No SPF authentication header present.",
                         "Authentication-Results / Received-SPF absent")]

    spf_state = _detect_state(combined, "spf")
    if spf_state == "pass":
        results.append(_finding("SPF pass", "INFO",
                                "Sender Policy Framework validated the sending IP.",
                                f"SPF={spf_state}"))
    elif spf_state == "fail":
        results.append(_finding("SPF failure", "HIGH",
                                "The sending IP is not authorised by the sender domain.",
                                f"SPF={spf_state}"))
    elif spf_state == "softfail":
        results.append(_finding("SPF softfail", "MEDIUM",
                                "Sending IP is suspicious but not hard-rejected.",
                                f"SPF={spf_state}"))
    elif spf_state == "neutral":
        results.append(_finding("SPF neutral", "LOW",
                                "Domain published no explicit SPF policy.",
                                f"SPF={spf_state}"))
    elif spf_state == "none":
        results.append(_finding("SPF none", "LOW",
                                "No SPF record published for the sender domain.",
                                f"SPF={spf_state}"))
    else:
        results.append(_finding("SPF unknown", "MEDIUM",
                                "SPF result could not be determined.",
                                f"raw={combined[:200]}"))
    return results


def _check_dkim(parsed: ParsedEmail) -> list[dict]:
    results = []
    auth = parsed.auth_headers.get("Authentication-Results", "").lower()
    dkim_sig = parsed.auth_headers.get("DKIM-Signature", "")

    if "dkim" not in auth and not dkim_sig:
        return [_finding("Missing DKIM signature", "MEDIUM",
                         "No DKIM signature present — email integrity not guaranteed.",
                         "DKIM-Signature absent")]

    if "dkim=pass" in auth or "dkim=pass" in auth:
        results.append(_finding("DKIM pass", "INFO",
                                "DKIM signature verified successfully.",
                                "DKIM=pass"))
    elif "dkim=fail" in auth:
        results.append(_finding("DKIM failure", "HIGH",
                                "DKIM signature verification failed.",
                                "DKIM=fail"))
    elif dkim_sig and "dkim" not in auth:
        results.append(_finding("DKIM present but unverified", "MEDIUM",
                                "DKIM-Signature header exists but no Authentication-Results.",
                                "DKIM-Signature present"))
    else:
        results.append(_finding("DKIM unknown", "LOW",
                                "DKIM result could not be determined.",
                                "raw"))
    return results


def _check_dmarc(parsed: ParsedEmail) -> list[dict]:
    results = []
    auth = parsed.auth_headers.get("Authentication-Results", "").lower()

    if "dmarc" not in auth:
        return [_finding("Missing DMARC", "MEDIUM",
                         "No DMARC authentication result present.",
                         "DMARC absent")]

    if "dmarc=pass" in auth:
        results.append(_finding("DMARC pass", "INFO",
                                "DMARC alignment validated.",
                                "DMARC=pass"))
    elif "dmarc=fail" in auth:
        results.append(_finding("DMARC failure", "HIGH",
                                "DMARC alignment failed — possible domain spoofing.",
                                "DMARC=fail"))
    else:
        results.append(_finding("DMARC unknown", "MEDIUM",
                                "DMARC result could not be determined.",
                                "raw"))
    return results


def _check_reply_to_mismatch(parsed: ParsedEmail) -> list[dict]:
    if not parsed.reply_to:
        return []
    from_addr = extract_email_address(parsed.from_)
    reply_addr = extract_email_address(parsed.reply_to)
    if from_addr and reply_addr and from_addr != reply_addr:
        return [_finding("Reply-To mismatch", "HIGH",
                         "Reply-To address differs from the From address — common in phishing.",
                         f"From={from_addr}  Reply-To={reply_addr}")]
    return []


def _check_return_path_mismatch(parsed: ParsedEmail) -> list[dict]:
    if not parsed.return_path:
        return []
    from_addr = extract_email_address(parsed.from_)
    rp_addr = extract_email_address(parsed.return_path)
    if from_addr and rp_addr and from_addr != rp_addr:
        return [_finding("Return-Path mismatch", "MEDIUM",
                         "Return-Path differs from From — may indicate forwarding or spoofing.",
                         f"From={from_addr}  Return-Path={rp_addr}")]
    return []


def _check_display_name_spoof(parsed: ParsedEmail) -> list[dict]:
    """Detect display-name spoofing (e.g. 'PayPal <user@evil.com>')."""
    raw = parsed.from_
    if "<" not in raw or ">" not in raw:
        return []
    m = re.match(r"^\s*(.+?)\s*<(.+)>", raw)
    if not m:
        return []
    display = m.group(1).strip().strip('"').lower()
    addr = m.group(2).lower()
    domain = extract_domain_from_email(addr)

    # Extract the base registered domain (e.g. "apple" from "apple-account-verify.xyz")
    # by taking the part before the TLD, then splitting on hyphens
    domain_parts = domain.rsplit(".", 1)
    base_domain = domain_parts[0] if len(domain_parts) == 2 else domain
    # Split on hyphens to get individual words in the domain
    domain_words = set(base_domain.replace("-", " ").split())

    # known brand names and their legitimate domains
    brand_domains = {
        "paypal": {"paypal.com"},
        "apple": {"apple.com", "icloud.com"},
        "microsoft": {"microsoft.com", "outlook.com", "live.com", "hotmail.com"},
        "google": {"google.com", "gmail.com"},
        "amazon": {"amazon.com"},
        "netflix": {"netflix.com"},
        "facebook": {"facebook.com"},
        "instagram": {"instagram.com"},
        "linkedin": {"linkedin.com"},
        "dhl": {"dhl.com"},
        "fedex": {"fedex.com"},
    }
    for brand, legit_domains in brand_domains.items():
        if brand in display and domain not in legit_domains:
            return [_finding("Display-name spoofing", "HIGH",
                             f"Display name '{display}' impersonates '{brand}' but the sender domain is '{domain}'.",
                             f"Display='{display}'  Domain={domain}")]
    return []


def _check_free_mail_sender(parsed: ParsedEmail) -> list[dict]:
    domain = extract_domain_from_email(parsed.from_)
    if domain and domain in FREE_MAIL_PROVIDERS:
        return [_finding("Free-mail sender", "LOW",
                         f"Sender uses a free-mail provider ({domain}). Legitimate organisations usually send from their own domain.",
                         f"Domain={domain}")]
    return []


def _check_message_id_domain(parsed: ParsedEmail) -> list[dict]:
    if not parsed.message_id:
        return [_finding("Missing Message-ID", "LOW",
                         "No Message-ID header — unusual for legitimate email.",
                         "Message-ID absent")]
    mid_domain = ""
    m = re.search(r"@([\w.-]+)", parsed.message_id)
    if m:
        mid_domain = m.group(1).lower()
    from_domain = extract_domain_from_email(parsed.from_)
    if mid_domain and from_domain and mid_domain != from_domain:
        return [_finding("Message-ID domain mismatch", "MEDIUM",
                         f"Message-ID domain ({mid_domain}) differs from sender domain ({from_domain}).",
                         f"MID={mid_domain}  From={from_domain}")]
    return []


def _check_received_headers(parsed: ParsedEmail) -> list[dict]:
    findings = []
    if not parsed.received_headers:
        findings.append(_finding("No Received headers", "MEDIUM",
                                 "Missing routing trail — email provenance cannot be verified.",
                                 "Received headers absent"))
        return findings
    # check for unusual number of hops
    if len(parsed.received_headers) > 10:
        findings.append(_finding("Excessive routing hops", "MEDIUM",
                                f"{len(parsed.received_headers)} Received headers — unusually complex routing.",
                                f"count={len(parsed.received_headers)}"))
    return findings


def _check_private_ips(parsed: ParsedEmail) -> list[dict]:
    findings = []
    for ip in parsed.all_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                findings.append(_finding(f"Private/internal IP in headers: {ip}", "INFO",
                                         "Private IP addresses in routing are normal for internal mail infrastructure.",
                                         f"IP={ip}"))
        except ValueError:
            pass
    return findings


def _check_timestamp_anomalies(parsed: ParsedEmail) -> list[dict]:
    findings = []
    if not parsed.date:
        return findings
    try:
        dt = datetime.strptime(parsed.date[:31], "%a, %d %b %Y %H:%M:%S %z")
    except (ValueError, TypeError):
        try:
            dt = datetime.strptime(parsed.date[:25], "%a, %d %b %Y %H:%M:%S")
        except (ValueError, TypeError):
            return findings
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    diff = abs((now - dt).total_seconds())
    # future-dated or > 1 year old
    if dt > now:
        findings.append(_finding("Future-dated email", "MEDIUM",
                                "Email Date header is in the future.",
                                f"Date={parsed.date}"))
    return findings


def _check_missing_auth(parsed: ParsedEmail) -> list[dict]:
    findings = []
    if not parsed.auth_headers:
        findings.append(_finding("No authentication headers", "HIGH",
                                "No SPF, DKIM, or DMARC headers present — email is unauthenticated.",
                                "All auth headers absent"))
    return findings


def _detect_state(text: str, label: str) -> str:
    """Detect SPF/DKIM/DMARC state from header text."""
    for state in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
        if f"{label}={state}" in text:
            return state
    # fallback
    if "pass" in text:
        return "pass"
    if "fail" in text:
        return "fail"
    if "soft" in text:
        return "softfail"
    return "unknown"


def _finding(name: str, sev: str, explanation: str, evidence: str) -> dict[str, Any]:
    return {
        "finding": name,
        "severity": sev,
        "explanation": explanation,
        "evidence": evidence,
    }


def auth_summary(findings: list[dict]) -> dict[str, dict[str, str]]:
    """Extract a compact SPF/DKIM/DMARC summary from findings."""
    summary: dict[str, dict[str, str]] = {}
    for f in findings:
        name = f["finding"].lower()
        sev = f["severity"]
        if "spf" in name and "spf" not in summary:
            summary["SPF"] = {"result": _state_from_finding(name), "severity": sev}
        elif "dkim" in name and "dkim" not in summary:
            summary["DKIM"] = {"result": _state_from_finding(name), "severity": sev}
        elif "dmarc" in name and "dmarc" not in summary:
            summary["DMARC"] = {"result": _state_from_finding(name), "severity": sev}
    return summary


def _state_from_finding(name: str) -> str:
    if "pass" in name:
        return "PASS"
    if "fail" in name:
        return "FAIL"
    if "softfail" in name:
        return "SOFTFAIL"
    if "neutral" in name:
        return "NEUTRAL"
    if "none" in name:
        return "NONE"
    return "UNKNOWN"
