"""IP geolocation with API + offline fallback."""
from __future__ import annotations

import os
from typing import Any

import requests


def get_api_token() -> str:
    """Return the IPInfo token from env or Streamlit secrets."""
    token = os.environ.get("IPINFO_TOKEN", "")
    if not token:
        try:
            import streamlit as st
            token = st.secrets.get("IPINFO_TOKEN", "")
        except Exception:
            pass
    return token


def geolocate_ip(ip: str) -> dict[str, Any]:
    """Return geolocation data for a public IP. Falls back to local estimate."""
    from analyzers.ip_analyzer import is_public
    if not is_public(ip):
        return {
            "ip": ip,
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "lat": None,
            "lon": None,
            "asn": "N/A",
            "org": "N/A",
            "source": "Local (private/reserved IP)",
        }

    token = get_api_token()
    if token:
        try:
            return _ipinfo_lookup(ip, token)
        except Exception:
            pass

    return _offline_estimate(ip)


def _ipinfo_lookup(ip: str, token: str) -> dict[str, Any]:
    """Query ipinfo.io."""
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token}
    resp = requests.get(url, params=params, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    loc = data.get("loc", "").split(",")
    return {
        "ip": ip,
        "country": data.get("country", "Unknown"),
        "region": data.get("region", "Unknown"),
        "city": data.get("city", "Unknown"),
        "lat": float(loc[0]) if len(loc) == 2 else None,
        "lon": float(loc[1]) if len(loc) == 2 else None,
        "asn": data.get("org", "").split()[0] if data.get("org") else "N/A",
        "org": data.get("org", "N/A"),
        "source": "ipinfo.io",
    }


def _offline_estimate(ip: str) -> dict[str, Any]:
    """Return a placeholder when no API is available."""
    return {
        "ip": ip,
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "lat": None,
        "lon": None,
        "asn": "Unknown",
        "org": "Unknown",
        "source": "Local heuristic (API unavailable)",
    }


def geolocate_ips(ips: list[str]) -> list[dict[str, Any]]:
    """Geolocate a list of public IPs."""
    return [geolocate_ip(ip) for ip in ips]
