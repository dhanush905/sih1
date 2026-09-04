"""Domain analysis — extraction, DNS lookups (safe, with fallback)."""
from __future__ import annotations

import re
import socket
from typing import Any

from utils.constants import SUSPICIOUS_TLDS, FREE_MAIL_PROVIDERS


def extract_domains(text: str) -> list[str]:
    """Extract unique domain names from text."""
    if not text:
        return []
    pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    found = re.findall(pattern, text, re.IGNORECASE)
    domains = set()
    for d in found:
        d = d.lower().rstrip(".")
        if d not in FREE_MAIL_PROVIDERS:
            domains.add(d)
    return sorted(domains)


def domain_tld(domain: str) -> str:
    """Return the TLD of a domain."""
    if "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1].lower()


def is_suspicious_domain(domain: str) -> bool:
    """Heuristic: suspicious TLD."""
    return domain_tld(domain) in SUSPICIOUS_TLDS


def analyze_domain(domain: str) -> dict[str, Any]:
    """Return analysis for a domain (DNS resolution is best-effort)."""
    result: dict[str, Any] = {
        "domain": domain,
        "tld": domain_tld(domain),
        "suspicious_tld": is_suspicious_domain(domain),
        "resolved_ips": [],
        "dns_error": None,
        "severity": "INFO",
    }
    try:
        ips = socket.gethostbyname_ex(domain)
        result["resolved_ips"] = ips[2]
    except Exception as e:
        result["dns_error"] = str(e)
    if result["suspicious_tld"]:
        result["severity"] = "MEDIUM"
    if result["dns_error"]:
        result["severity"] = "MEDIUM" if result["severity"] == "INFO" else result["severity"]
    return result


def analyze_domains(domains: list[str]) -> list[dict[str, Any]]:
    """Analyze a list of domains."""
    return [analyze_domain(d) for d in domains]
