"""Integration test — full pipeline end-to-end with demo phishing email."""
from __future__ import annotations

from pathlib import Path

from analyzers.email_parser import parse_email
from analyzers.header_analyzer import analyze_headers
from analyzers.url_analyzer import analyze_urls
from analyzers.attachment_analyzer import analyze_attachments
from analyzers.ip_analyzer import analyze_ips
from ai.classifier import classify_email
from ai.risk_score import calculate_risk
from forensics.evidence import build_evidence
from forensics.timeline import build_timeline

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_emails"


class TestIntegration:
    def test_phishing_pipeline(self) -> None:
        raw = (SAMPLE_DIR / "phishing.eml").read_bytes()
        parsed = parse_email(raw)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        ip_results = analyze_ips(parsed.all_ips)
        threat_intel = []
        ai_result = classify_email(parsed, header_findings, url_results, attachment_results, threat_intel)
        risk = calculate_risk(ai_result, header_findings, url_results, attachment_results, threat_intel)
        evidence = build_evidence(header_findings, url_results, attachment_results, ip_results, threat_intel, ai_result)
        timeline = build_timeline(parsed=parsed.to_dict(), ip_results=ip_results, url_results=url_results,
                                   attachment_results=attachment_results, threat_intel=threat_intel,
                                   ai_result=ai_result, risk_result=risk)

        assert ai_result["label"] in ("PHISHING", "SUSPICIOUS", "MALWARE")
        assert ai_result["confidence"] > 0
        assert 0 <= risk["score"] <= 100
        assert risk["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(evidence) > 0
        assert len(timeline) >= 10

    def test_benign_pipeline(self) -> None:
        raw = (SAMPLE_DIR / "benign.eml").read_bytes()
        parsed = parse_email(raw)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        ip_results = analyze_ips(parsed.all_ips)
        threat_intel = []
        ai_result = classify_email(parsed, header_findings, url_results, attachment_results, threat_intel)
        risk = calculate_risk(ai_result, header_findings, url_results, attachment_results, threat_intel)

        assert ai_result["label"] in ("BENIGN", "SPAM", "SUSPICIOUS")
        assert risk["score"] < 60

    def test_suspicious_pipeline(self) -> None:
        raw = (SAMPLE_DIR / "suspicious.eml").read_bytes()
        parsed = parse_email(raw)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        ip_results = analyze_ips(parsed.all_ips)
        threat_intel = []
        ai_result = classify_email(parsed, header_findings, url_results, attachment_results, threat_intel)
        risk = calculate_risk(ai_result, header_findings, url_results, attachment_results, threat_intel)
        evidence = build_evidence(header_findings, url_results, attachment_results, ip_results, threat_intel, ai_result)
        timeline = build_timeline(parsed=parsed.to_dict())

        assert ai_result["label"] in ("SUSPICIOUS", "PHISHING", "MALWARE", "SPAM")
        assert 0 <= risk["score"] <= 100
        assert len(timeline) >= 10
        # Should have at least some evidence due to dangerous attachment
        assert len(evidence) > 0

    def test_malformed_email_pipeline(self) -> None:
        raw = b"this is not an email"
        parsed = parse_email(raw)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        threat_intel = []
        ai_result = classify_email(parsed, header_findings, url_results, attachment_results, threat_intel)
        risk = calculate_risk(ai_result, header_findings, url_results, attachment_results, threat_intel)

        # should not crash
        assert ai_result["label"] in ("BENIGN", "SPAM", "SUSPICIOUS", "PHISHING", "MALWARE")
        assert 0 <= risk["score"] <= 100
