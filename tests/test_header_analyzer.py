"""Tests for the header analyzer."""
from __future__ import annotations

from analyzers.email_parser import parse_email
from analyzers.header_analyzer import analyze_headers, auth_summary


SPF_FAIL_EML = b"""From: "Apple" <noreply@apple-verify.xyz>
To: victim@example.com
Subject: Urgent
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <fake@apple-verify.xyz>
Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail
Return-Path: <bounce@evil.xyz>
Reply-To: <support@verify-account.tk>

Body text here.
"""

SPF_PASS_EML = b"""From: sender@company.com
To: recipient@example.org
Subject: Normal
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <real@company.com>
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass
Return-Path: <sender@company.com>
Reply-To: <sender@company.com>

Body text.
"""

REPLY_MISMATCH_EML = b"""From: sender@company.com
To: recipient@example.org
Subject: Test
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <test@company.com>
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass
Reply-To: <attacker@evil.com>

Body.
"""

NO_AUTH_EML = b"""From: sender@unknown.com
To: recipient@example.org
Subject: No Auth
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <test@unknown.com>

Body.
"""


class TestHeaderAnalyzer:
    def test_spf_fail(self) -> None:
        parsed = parse_email(SPF_FAIL_EML)
        findings = analyze_headers(parsed)
        spf_findings = [f for f in findings if "spf" in f["finding"].lower()]
        assert any("fail" in f["finding"].lower() for f in spf_findings)

    def test_spf_pass(self) -> None:
        parsed = parse_email(SPF_PASS_EML)
        findings = analyze_headers(parsed)
        spf_findings = [f for f in findings if "spf" in f["finding"].lower()]
        assert any("pass" in f["finding"].lower() for f in spf_findings)

    def test_dkim_fail(self) -> None:
        parsed = parse_email(SPF_FAIL_EML)
        findings = analyze_headers(parsed)
        dkim_findings = [f for f in findings if "dkim" in f["finding"].lower()]
        assert any("fail" in f["finding"].lower() for f in dkim_findings)

    def test_dmarc_fail(self) -> None:
        parsed = parse_email(SPF_FAIL_EML)
        findings = analyze_headers(parsed)
        dmarc_findings = [f for f in findings if "dmarc" in f["finding"].lower()]
        assert any("fail" in f["finding"].lower() for f in dmarc_findings)

    def test_reply_to_mismatch(self) -> None:
        parsed = parse_email(REPLY_MISMATCH_EML)
        findings = analyze_headers(parsed)
        assert any("reply-to mismatch" in f["finding"].lower() for f in findings)

    def test_return_path_mismatch(self) -> None:
        parsed = parse_email(SPF_FAIL_EML)
        findings = analyze_headers(parsed)
        assert any("return-path mismatch" in f["finding"].lower() for f in findings)

    def test_missing_auth(self) -> None:
        parsed = parse_email(NO_AUTH_EML)
        findings = analyze_headers(parsed)
        assert any("no authentication" in f["finding"].lower() for f in findings)

    def test_auth_summary(self) -> None:
        parsed = parse_email(SPF_FAIL_EML)
        findings = analyze_headers(parsed)
        summary = auth_summary(findings)
        assert "SPF" in summary
        assert summary["SPF"]["result"] == "FAIL"

    def test_display_name_spoof(self) -> None:
        parsed = parse_email(SPF_FAIL_EML)
        findings = analyze_headers(parsed)
        assert any("display-name" in f["finding"].lower() for f in findings)
