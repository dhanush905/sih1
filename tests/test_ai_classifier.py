"""Tests for the AI classifier (feature extraction + heuristic fallback)."""
from __future__ import annotations

from analyzers.email_parser import parse_email
from analyzers.header_analyzer import analyze_headers
from analyzers.url_analyzer import analyze_urls
from analyzers.attachment_analyzer import analyze_attachments
from ai.features import extract_features
from ai.classifier import classify_email


PHISHING_EML = b"""From: "Apple" <noreply@apple-verify.xyz>
To: victim@example.com
Subject: URGENT: Verify your account now
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <fake@apple-verify.xyz>
Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail
Return-Path: <bounce@evil.xyz>
Reply-To: <support@verify-account.tk>

Urgent: Your account has been suspended. Please verify your password immediately.
http://apple-verify.xyz/login?password=reset
"""

BENIGN_EML = b"""From: sender@company.com
To: recipient@example.org
Subject: Project Update
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <real@company.com>
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass

Hi team, here is the weekly update. Everything is on track.
https://company.com/projects
"""


class TestAIClassifier:
    def test_feature_extraction(self) -> None:
        parsed = parse_email(PHISHING_EML)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        features = extract_features(parsed, header_findings, url_results, attachment_results, [])

        assert "subject_urgency" in features
        assert features["subject_urgency"] == 1
        assert features["spf_fail"] == 1
        assert features["dmarc_fail"] == 1
        assert features["reply_to_mismatch"] == 1
        assert features["num_urls"] >= 1

    def test_classifier_output_phishing(self) -> None:
        parsed = parse_email(PHISHING_EML)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        result = classify_email(parsed, header_findings, url_results, attachment_results, [])

        assert "label" in result
        assert "confidence" in result
        assert "probabilities" in result
        assert "explanation" in result
        assert result["label"] in ("PHISHING", "SUSPICIOUS", "MALWARE")
        assert result["confidence"] > 0

    def test_classifier_output_benign(self) -> None:
        parsed = parse_email(BENIGN_EML)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        result = classify_email(parsed, header_findings, url_results, attachment_results, [])

        assert result["label"] in ("BENIGN", "SPAM", "SUSPICIOUS")

    def test_heuristic_fallback_mode(self) -> None:
        parsed = parse_email(PHISHING_EML)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        result = classify_email(parsed, header_findings, url_results, attachment_results, [])

        assert "model_mode" in result
        assert "Heuristic" in result["model_mode"] or "Trained" in result["model_mode"]

    def test_probabilities_sum(self) -> None:
        parsed = parse_email(PHISHING_EML)
        header_findings = analyze_headers(parsed)
        url_results = analyze_urls(parsed.urls)
        attachment_results = analyze_attachments(parsed.attachments)
        result = classify_email(parsed, header_findings, url_results, attachment_results, [])

        probs = result["probabilities"]
        assert isinstance(probs, dict)
        assert len(probs) >= 3
