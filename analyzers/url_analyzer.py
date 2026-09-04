"""Passive URL analysis — never visits URLs."""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

import tldextract

from utils.constants import SHORTENERS, SUSPICIOUS_TLDS, URL_KEYWORDS


def analyze_url(url: str) -> dict[str, Any]:
    """Return a comprehensive passive analysis of a single URL."""
    result: dict[str, Any] = {
        "url": url,
        "protocol": "",
        "domain": "",
        "registered_domain": "",
        "subdomain": "",
        "path": "",
        "query_params": {},
        "fragment": "",
        "is_ip": False,
        "is_https": False,
        "length": len(url),
        "num_subdomains": 0,
        "suspicious_tld": False,
        "suspicious_keywords": [],
        "encoded_chars": False,
        "is_shortener": False,
        "display_url": "",
        "severity": "INFO",
        "reasons": [],
    }

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        result["severity"] = "MEDIUM"
        result["reasons"].append("Malformed URL")
        return result

    result["protocol"] = parsed.scheme or ""
    result["is_https"] = parsed.scheme.lower() == "https"
    host = (parsed.hostname or "").lower()
    result["domain"] = host
    result["path"] = parsed.path or ""
    result["fragment"] = parsed.fragment or ""

    try:
        qs = urllib.parse.parse_qs(parsed.query or "")
        result["query_params"] = qs
    except Exception:
        result["query_params"] = {}

    # IP-based URL
    if _is_ip(host):
        result["is_ip"] = True
        result["reasons"].append("URL uses raw IP address instead of domain")

    # registered domain via tldextract
    try:
        ext = tldextract.extract(host)
        result["registered_domain"] = f"{ext.domain}.{ext.suffix}" if ext.suffix else host
        result["subdomain"] = ext.subdomain
        result["num_subdomains"] = len([p for p in ext.subdomain.split(".") if p]) if ext.subdomain else 0
    except Exception:
        result["registered_domain"] = host

    # suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        result["suspicious_tld"] = True
        result["reasons"].append(f"Suspicious TLD: .{tld}")

    # shortener
    if host in SHORTENERS:
        result["is_shortener"] = True
        result["reasons"].append(f"URL shortener detected: {host}")

    # suspicious keywords
    lower_url = url.lower()
    for kw in URL_KEYWORDS:
        if kw in lower_url:
            result["suspicious_keywords"].append(kw)
    if result["suspicious_keywords"]:
        result["reasons"].append(f"Keywords: {', '.join(result['suspicious_keywords'])}")

    # encoded chars
    if "%" in url and re.search(r"%[0-9a-fA-F]{2}", url):
        result["encoded_chars"] = True
        result["reasons"].append("URL-encoded characters present")

    # long URL
    if len(url) > 100:
        result["reasons"].append(f"Unusually long URL ({len(url)} chars)")

    # not HTTPS
    if not result["is_https"]:
        result["reasons"].append("Non-HTTPS URL")

    # severity
    result["severity"] = _severity(result)
    return result


def analyze_urls(urls: list[str]) -> list[dict[str, Any]]:
    """Analyze a list of URLs."""
    return [analyze_url(u) for u in urls]


def _severity(r: dict[str, Any]) -> str:
    score = 0
    if r["is_ip"]:
        score += 2
    if r["suspicious_tld"]:
        score += 2
    if r["is_shortener"]:
        score += 1
    if not r["is_https"]:
        score += 1
    if len(r["suspicious_keywords"]) >= 3:
        score += 2
    elif r["suspicious_keywords"]:
        score += 1
    if r["encoded_chars"]:
        score += 1
    if r["length"] > 100:
        score += 1
    if score >= 5:
        return "CRITICAL"
    if score >= 3:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def _is_ip(host: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
