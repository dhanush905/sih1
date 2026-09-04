"""Tests for the IP analyzer."""
from __future__ import annotations

from analyzers.ip_analyzer import classify_ip, is_public, analyze_ip, analyze_ips, extract_public_ips


class TestIPAnalyzer:
    def test_public_ip(self) -> None:
        assert classify_ip("8.8.8.8") == "public"
        assert is_public("8.8.8.8") is True

    def test_private_ip(self) -> None:
        assert classify_ip("192.168.1.1") == "private"
        assert is_public("192.168.1.1") is False

    def test_loopback(self) -> None:
        assert classify_ip("127.0.0.1") == "loopback"
        assert is_public("127.0.0.1") is False

    def test_reserved(self) -> None:
        assert classify_ip("0.0.0.0") in ("reserved", "private")
        assert is_public("0.0.0.0") is False

    def test_invalid_ip(self) -> None:
        assert classify_ip("not.an.ip") == "invalid"
        assert is_public("999.999.999.999") is False

    def test_analyze_ip(self) -> None:
        result = analyze_ip("8.8.8.8")
        assert result["is_public"] is True
        assert result["version"] == "IPv4"

    def test_analyze_ips_dedup(self) -> None:
        results = analyze_ips(["8.8.8.8", "8.8.8.8", "192.168.1.1"])
        assert len(results) == 2

    def test_extract_public_ips(self) -> None:
        ips = ["8.8.8.8", "192.168.1.1", "1.1.1.1"]
        public = extract_public_ips(ips)
        assert "8.8.8.8" in public
        assert "192.168.1.1" not in public
        assert "1.1.1.1" in public
