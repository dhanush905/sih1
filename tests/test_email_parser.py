"""Tests for the email parser."""
from __future__ import annotations

import pytest

from analyzers.email_parser import parse_email


SIMPLE_EML = b"""From: sender@example.com
To: recipient@example.org
Subject: Test Email
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello, this is a test email.
Visit https://example.com/page for more info.
"""

MULTIPART_EML = b"""From: sender@example.com
To: recipient@example.org
Subject: Multipart Test
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <multi123@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundaryXYZ"

--boundaryXYZ
Content-Type: text/plain; charset=utf-8

This is the plain text body.
https://safe-site.com/info

--boundaryXYZ
Content-Type: text/html; charset=utf-8

<html><body><a href="https://link-test.com/click">Click</a></body></html>

--boundaryXYZ
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

SGVsbG8gV29ybGQ=

--boundaryXYZ--
"""

MALFORMED_EML = b"This is not an email at all, just random text with no headers."

MISSING_HEADERS_EML = b"""Content-Type: text/plain

Body without From/To/Subject.
"""


class TestEmailParser:
    def test_simple_email(self) -> None:
        parsed = parse_email(SIMPLE_EML)
        assert parsed.from_ == "sender@example.com"
        assert parsed.to == "recipient@example.org"
        assert parsed.subject == "Test Email"
        assert "test email" in parsed.body_text
        assert len(parsed.urls) >= 1

    def test_multipart_email(self) -> None:
        parsed = parse_email(MULTIPART_EML)
        assert parsed.subject == "Multipart Test"
        assert "plain text body" in parsed.body_text
        assert "<html>" in parsed.body_html
        assert len(parsed.attachments) == 1
        assert parsed.attachments[0].filename == "report.pdf"
        assert len(parsed.urls) >= 2

    def test_malformed_email(self) -> None:
        parsed = parse_email(MALFORMED_EML)
        # should not crash; fields may be empty
        assert parsed.from_ == ""
        assert parsed.subject == ""

    def test_missing_headers(self) -> None:
        parsed = parse_email(MISSING_HEADERS_EML)
        assert parsed.from_ == ""
        assert "Body without" in parsed.body_text

    def test_url_extraction(self) -> None:
        parsed = parse_email(SIMPLE_EML)
        assert any("example.com" in u for u in parsed.urls)

    def test_attachment_hashes(self) -> None:
        parsed = parse_email(MULTIPART_EML)
        att = parsed.attachments[0]
        assert len(att.sha256) == 64
        assert len(att.md5) == 32

    def test_to_dict(self) -> None:
        parsed = parse_email(SIMPLE_EML)
        d = parsed.to_dict()
        assert d["from"] == "sender@example.com"
        assert "payload" not in str(d.get("attachments", []))

    def test_string_input(self) -> None:
        parsed = parse_email(SIMPLE_EML.decode("utf-8"))
        assert parsed.subject == "Test Email"
