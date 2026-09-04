"""Unified threat intelligence engine with optional API support + local fallback."""
from __future__ import annotations

import os
from typing import Any

import requests

from .reputation import normalize_reputation, confidence_from_score


def _get_secret(key: str) -> str:
    """Read a secret from env or Streamlit secrets."""
    val = os.environ.get(key, "")
    if not val:
        try:
            import streamlit as st
            val = st.secrets.get(key, "")
        except Exception:
            pass
    return val


def check_ip_reputation(ip: str) -> dict[str, Any]:
    """Check IP reputation via AbuseIPDB if available, else local heuristic."""
    from analyzers.ip_analyzer import is_public, classify_ip
    if not is_public(ip):
        return {
            "indicator": ip,
            "type": "IP",
            "source": "Local",
            "reputation": "CLEAN",
            "confidence": 0.0,
            "evidence": f"IP classified as {classify_ip(ip)} — not queried externally.",
            "last_checked": _now(),
        }

    api_key = _get_secret("ABUSEIPDB_API_KEY")
    if api_key:
        try:
            return _abuseipdb_lookup(ip, api_key)
        except Exception:
            pass

    return _local_ip_heuristic(ip)


def check_hash_reputation(sha256: str) -> dict[str, Any]:
    """Check file hash reputation via VirusTotal if available."""
    api_key = _get_secret("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            return _virustotal_hash_lookup(sha256, api_key)
        except Exception:
            pass

    return {
        "indicator": sha256,
        "type": "File Hash",
        "source": "Local",
        "reputation": "UNKNOWN",
        "confidence": 0.0,
        "evidence": "No API key configured — hash provided for manual lookup.",
        "last_checked": _now(),
    }


def check_domain_reputation(domain: str) -> dict[str, Any]:
    """Check domain reputation."""
    api_key = _get_secret("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            return _virustotal_domain_lookup(domain, api_key)
        except Exception:
            pass

    from analyzers.domain_analyzer import is_suspicious_domain
    if is_suspicious_domain(domain):
        return {
            "indicator": domain,
            "type": "Domain",
            "source": "Local heuristic",
            "reputation": "SUSPICIOUS",
            "confidence": 0.5,
            "evidence": "Domain uses a suspicious TLD.",
            "last_checked": _now(),
        }
    return {
        "indicator": domain,
        "type": "Domain",
        "source": "Local heuristic",
        "reputation": "UNKNOWN",
        "confidence": 0.0,
        "evidence": "No API key — domain appears normal by local heuristics.",
        "last_checked": _now(),
    }


def check_url_reputation(url: str) -> dict[str, Any]:
    """Check URL reputation via VirusTotal if available."""
    api_key = _get_secret("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            return _virustotal_url_lookup(url, api_key)
        except Exception:
            pass

    return {
        "indicator": url,
        "type": "URL",
        "source": "Local heuristic",
        "reputation": "UNKNOWN",
        "confidence": 0.0,
        "evidence": "No API key — passive URL analysis only.",
        "last_checked": _now(),
    }


def query_indicator(indicator: str, itype: str | None = None) -> dict[str, Any]:
    """Auto-detect indicator type and query reputation."""
    if itype is None:
        itype = _detect_type(indicator)

    if itype == "IP":
        return check_ip_reputation(indicator)
    elif itype == "Domain":
        return check_domain_reputation(indicator)
    elif itype == "URL":
        return check_url_reputation(indicator)
    elif itype == "Hash":
        return check_hash_reputation(indicator)
    return {
        "indicator": indicator,
        "type": itype or "Unknown",
        "source": "Local",
        "reputation": "UNKNOWN",
        "confidence": 0.0,
        "evidence": "Unrecognized indicator type.",
        "last_checked": _now(),
    }


def _detect_type(val: str) -> str:
    """Detect if a value is an IP, hash, URL, or domain."""
    import ipaddress
    try:
        ipaddress.ip_address(val)
        return "IP"
    except ValueError:
        pass
    if val.startswith("http://") or val.startswith("https://"):
        return "URL"
    if len(val) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in val):
        return "Hash"
    if "." in val and " " not in val:
        return "Domain"
    return "Unknown"


def _abuseipdb_lookup(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(url, headers=headers, params=params, timeout=5)
    resp.raise_for_status()
    data = resp.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    if score >= 75:
        rep = "MALICIOUS"
    elif score >= 25:
        rep = "SUSPICIOUS"
    elif score == 0:
        rep = "CLEAN"
    else:
        rep = "UNKNOWN"
    return {
        "indicator": ip,
        "type": "IP",
        "source": "AbuseIPDB",
        "reputation": rep,
        "confidence": confidence_from_score(score),
        "evidence": f"Abuse score: {score}/100, {data.get('totalReports', 0)} reports, usage: {data.get('usageType', 'unknown')}",
        "last_checked": _now(),
        "raw": data,
    }


def _virustotal_hash_lookup(sha256: str, api_key: str) -> dict[str, Any]:
    """Query VirusTotal for a file hash."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    if malicious >= 5:
        rep = "MALICIOUS"
    elif malicious > 0:
        rep = "SUSPICIOUS"
    elif total > 0:
        rep = "CLEAN"
    else:
        rep = "UNKNOWN"
    return {
        "indicator": sha256,
        "type": "File Hash",
        "source": "VirusTotal",
        "reputation": rep,
        "confidence": confidence_from_score(malicious, max(total, 1)),
        "evidence": f"{malicious}/{total} engines flagged as malicious",
        "last_checked": _now(),
        "raw": stats,
    }


def _virustotal_domain_lookup(domain: str, api_key: str) -> dict[str, Any]:
    """Query VirusTotal for a domain."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    if malicious >= 3:
        rep = "MALICIOUS"
    elif malicious > 0:
        rep = "SUSPICIOUS"
    elif total > 0:
        rep = "CLEAN"
    else:
        rep = "UNKNOWN"
    return {
        "indicator": domain,
        "type": "Domain",
        "source": "VirusTotal",
        "reputation": rep,
        "confidence": confidence_from_score(malicious, max(total, 1)),
        "evidence": f"{malicious}/{total} engines flagged domain as malicious",
        "last_checked": _now(),
        "raw": stats,
    }


def _virustotal_url_lookup(url: str, api_key: str) -> dict[str, Any]:
    """Query VirusTotal for a URL (uses v3 API with URL ID)."""
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    resp = requests.get(api_url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    if malicious >= 3:
        rep = "MALICIOUS"
    elif malicious > 0:
        rep = "SUSPICIOUS"
    elif total > 0:
        rep = "CLEAN"
    else:
        rep = "UNKNOWN"
    return {
        "indicator": url,
        "type": "URL",
        "source": "VirusTotal",
        "reputation": rep,
        "confidence": confidence_from_score(malicious, max(total, 1)),
        "evidence": f"{malicious}/{total} engines flagged URL as malicious",
        "last_checked": _now(),
        "raw": stats,
    }


def _local_ip_heuristic(ip: str) -> dict[str, Any]:
    """Local heuristic when no API is available."""
    return {
        "indicator": ip,
        "type": "IP",
        "source": "Local heuristic",
        "reputation": "UNKNOWN",
        "confidence": 0.0,
        "evidence": "No API key configured — IP provided for manual lookup.",
        "last_checked": _now(),
    }


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
