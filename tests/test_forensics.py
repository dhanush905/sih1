"""Tests for the forensics module (evidence, timeline, reports)."""
from __future__ import annotations

from forensics.evidence import build_evidence
from forensics.timeline import build_timeline
from forensics.report_generator import generate_json_report, generate_csv_reports, generate_html_report


class TestEvidence:
    def test_evidence_creation(self) -> None:
        header_findings = [
            {"finding": "SPF fail", "severity": "HIGH", "explanation": "test", "evidence": "raw"},
            {"finding": "SPF pass", "severity": "INFO", "explanation": "ok", "evidence": "raw"},
        ]
        url_results = [{"url": "http://evil.xyz", "domain": "evil.xyz", "severity": "CRITICAL", "reasons": ["test"]}]
        attachment_results = [{"filename": "a.exe", "severity": "CRITICAL", "sha256": "x", "is_dangerous": True, "reasons": []}]
        ip_results = []
        threat_intel = [{"indicator": "1.2.3.4", "reputation": "MALICIOUS", "evidence": "test", "source": "test"}]
        ai_result = {"label": "PHISHING", "confidence": 0.9, "explanation": ["test"]}

        evidence = build_evidence(header_findings, url_results, attachment_results, ip_results, threat_intel, ai_result)
        assert len(evidence) >= 4
        assert all("id" in e for e in evidence)
        assert all("severity" in e for e in evidence)

    def test_evidence_excludes_info(self) -> None:
        header_findings = [{"finding": "pass", "severity": "INFO", "explanation": "", "evidence": ""}]
        evidence = build_evidence(header_findings, [], [], [], [], {})
        assert len(evidence) == 0

    def test_evidence_ids_unique(self) -> None:
        header_findings = [
            {"finding": "fail1", "severity": "HIGH", "explanation": "", "evidence": ""},
            {"finding": "fail2", "severity": "HIGH", "explanation": "", "evidence": ""},
        ]
        evidence = build_evidence(header_findings, [], [], [], [], {})
        ids = [e["id"] for e in evidence]
        assert len(ids) == len(set(ids))


class TestTimeline:
    def test_timeline_creation(self) -> None:
        parsed = {"from": "test@example.com", "date": "Mon, 15 Sep 2025 10:30:00 +0000"}
        timeline = build_timeline(parsed=parsed)
        assert len(timeline) >= 10
        assert all("step" in t for t in timeline)
        assert all("event" in t for t in timeline)

    def test_timeline_ordering(self) -> None:
        timeline = build_timeline()
        steps = [t["step"] for t in timeline]
        assert steps == sorted(steps)

    def test_timeline_no_date(self) -> None:
        parsed = {"from": "test@example.com"}
        timeline = build_timeline(parsed=parsed)
        assert len(timeline) > 0


class TestReports:
    def _make_state(self) -> dict:
        return {
            "investigation_id": "INV-TEST-001",
            "parsed_email": {"from": "a@b.com", "to": "c@d.com", "subject": "test", "date": "2025-01-01", "message_id": "1"},
            "header_findings": [{"finding": "SPF fail", "severity": "HIGH", "explanation": "test", "evidence": "raw"}],
            "url_results": [{"url": "http://evil.xyz", "domain": "evil.xyz", "severity": "HIGH", "is_https": False}],
            "attachment_results": [],
            "ip_results": [{"ip": "8.8.8.8", "classification": "public", "is_public": True}],
            "geo_results": [],
            "threat_intel": [],
            "ai_result": {"label": "PHISHING", "confidence": 0.9, "model_mode": "Heuristic", "explanation": ["test"]},
            "risk_result": {"score": 75, "level": "HIGH", "components": {}, "increasing": [], "decreasing": []},
            "evidence": [{"id": "EVD-0001", "type": "Header", "finding": "SPF fail", "severity": "HIGH", "description": "test", "evidence": "raw"}],
            "timeline": [{"step": 1, "event": "Email received", "detail": "test", "timestamp": "2025-01-01"}],
        }

    def test_json_report(self) -> None:
        report = generate_json_report(self._make_state())
        assert "INV-TEST-001" in report
        assert "PHISHING" in report

    def test_csv_reports(self) -> None:
        state = self._make_state()
        csvs = generate_csv_reports(state)
        assert "urls.csv" in csvs
        assert "evidence.csv" in csvs
        assert "evil.xyz" in csvs["urls.csv"]

    def test_html_report(self) -> None:
        report = generate_html_report(self._make_state())
        assert "<html>" in report
        assert "INV-TEST-001" in report
        assert "disclaimer" in report.lower()

    def test_html_contains_recommendations(self) -> None:
        report = generate_html_report(self._make_state())
        assert "Recommendations" in report
