"""IP address extraction and classification."""
from __future__ import annotations

import ipaddress
from typing import Any


def classify_ip(ip: str) -> str:
    """Classify an IP as private, loopback, reserved, multicast, or public."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    return "public"


def is_public(ip: str) -> bool:
    """Return True if the IP is public/routable."""
    return classify_ip(ip) == "public"


def analyze_ip(ip: str) -> dict[str, Any]:
    """Return classification for an IP address."""
    kind = classify_ip(ip)
    return {
        "ip": ip,
        "classification": kind,
        "is_public": kind == "public",
        "version": "IPv6" if ":" in ip else "IPv4",
    }


def analyze_ips(ips: list[str]) -> list[dict[str, Any]]:
    """Classify a list of IPs."""
    seen = set()
    results: list[dict[str, Any]] = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        results.append(analyze_ip(ip))
    return results


def extract_public_ips(ips: list[str]) -> list[str]:
    """Return only public IPs from a list."""
    return [ip for ip in ips if is_public(ip)]
