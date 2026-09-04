"""Tests for the URL analyzer."""
from __future__ import annotations

from analyzers.url_analyzer import analyze_url, analyze_urls


class TestURLAnalyzer:
    def test_normal_url(self) -> None:
        result = analyze_url("https://www.example.com/page")
        assert result["is_https"] is True
        assert result["domain"] == "www.example.com"
        assert result["registered_domain"] == "example.com"
        assert result["is_ip"] is False

    def test_suspicious_url(self) -> None:
        result = analyze_url("http://login-verify-account.xyz/secure?token=abc")
        assert result["is_https"] is False
        assert result["suspicious_tld"] is True
        assert "login" in result["suspicious_keywords"]
        assert "verify" in result["suspicious_keywords"]
        assert result["severity"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_ip_url(self) -> None:
        result = analyze_url("http://192.168.1.1/admin")
        assert result["is_ip"] is True

    def test_encoded_url(self) -> None:
        result = analyze_url("https://example.com/path?redirect=%2Fadmin%2F")
        assert result["encoded_chars"] is True

    def test_malformed_url(self) -> None:
        result = analyze_url("not a url at all")
        # should not crash
        assert "url" in result

    def test_shortener(self) -> None:
        result = analyze_url("https://bit.ly/abc123")
        assert result["is_shortener"] is True

    def test_https_detection(self) -> None:
        result = analyze_url("https://secure-site.com/")
        assert result["is_https"] is True

    def test_url_list(self) -> None:
        urls = ["https://example.com", "http://evil.xyz/login"]
        results = analyze_urls(urls)
        assert len(results) == 2

    def test_subdomain_count(self) -> None:
        result = analyze_url("https://a.b.c.example.com/page")
        assert result["num_subdomains"] >= 2
