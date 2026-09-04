"""Tests for the attachment analyzer."""
from __future__ import annotations

from analyzers.email_parser import Attachment
from analyzers.attachment_analyzer import analyze_attachment, analyze_attachments


def _make_att(filename: str, content_type: str = "application/octet-stream") -> Attachment:
    payload = b"fake content for testing"
    import hashlib
    return Attachment(
        filename=filename,
        content_type=content_type,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        payload=payload,
    )


class TestAttachmentAnalyzer:
    def test_safe_attachment(self) -> None:
        att = _make_att("report.pdf", "application/pdf")
        result = analyze_attachment(att)
        assert result["extension"] == "pdf"
        assert result["is_dangerous"] is False
        assert result["severity"] == "INFO"

    def test_dangerous_extension(self) -> None:
        att = _make_att("malware.exe")
        result = analyze_attachment(att)
        assert result["is_dangerous"] is True
        assert result["severity"] == "CRITICAL"

    def test_double_extension(self) -> None:
        att = _make_att("invoice.pdf.exe")
        result = analyze_attachment(att)
        assert result["double_extension"] is True
        assert result["severity"] == "CRITICAL"

    def test_macro_extension(self) -> None:
        att = _make_att("spreadsheet.xlsm")
        result = analyze_attachment(att)
        assert result["is_macro"] is True
        assert result["severity"] == "HIGH"

    def test_hash_generation(self) -> None:
        att = _make_att("doc.pdf")
        result = analyze_attachment(att)
        assert len(result["sha256"]) == 64
        assert len(result["md5"]) == 32

    def test_suspicious_filename(self) -> None:
        att = _make_att("invoice_urgent.pdf")
        result = analyze_attachment(att)
        assert result["suspicious_name"] is True

    def test_attachment_list(self) -> None:
        atts = [_make_att("a.pdf"), _make_att("b.exe")]
        results = analyze_attachments(atts)
        assert len(results) == 2
