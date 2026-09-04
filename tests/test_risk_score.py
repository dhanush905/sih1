"""Tests for the risk score engine."""
from __future__ import annotations

from ai.risk_score import calculate_risk
from utils.helpers import risk_level


class TestRiskScore:
    def _make_state(
        self,
        ai_label: str = "PHISHING",
        ai_conf: float = 0.9,
        header_sev: str = "HIGH",
        url_sev: str = "HIGH",
        att_sev: str = "INFO",
        ti_rep: str = "MALICIOUS",
    ) -> dict:
        ai = {
            "label": ai_label,
            "confidence": ai_conf,
            "explanation": ["test"],
            "model_mode": "Heuristic fallback",
        }
        header_findings = [{"finding": "SPF fail", "severity": header_sev, "explanation": "", "evidence": ""}]
        url_results = [{"url": "http://evil.xyz", "domain": "evil.xyz", "severity": url_sev, "is_https": False}]
        attachment_results = [{"filename": "a.pdf", "severity": att_sev, "sha256": "x", "is_dangerous": False}]
        threat_intel = [{"indicator": "8.8.8.8", "reputation": ti_rep, "evidence": "", "source": "test"}]
        return {
            "ai_result": ai,
            "header_findings": header_findings,
            "url_results": url_results,
            "attachment_results": attachment_results,
            "threat_intel": threat_intel,
        }

    def test_risk_calculation(self) -> None:
        state = self._make_state()
        result = calculate_risk(
            state["ai_result"], state["header_findings"], state["url_results"],
            state["attachment_results"], state["threat_intel"],
        )
        assert 0 <= result["score"] <= 100
        assert result["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_benign_low_score(self) -> None:
        state = self._make_state(
            ai_label="BENIGN", ai_conf=0.9, header_sev="INFO", url_sev="INFO", att_sev="INFO", ti_rep="CLEAN",
        )
        result = calculate_risk(
            state["ai_result"], state["header_findings"], state["url_results"],
            state["attachment_results"], state["threat_intel"],
        )
        assert result["score"] <= 50

    def test_phishing_high_score(self) -> None:
        state = self._make_state(
            ai_label="PHISHING", ai_conf=0.95, header_sev="HIGH", url_sev="CRITICAL", ti_rep="MALICIOUS",
        )
        result = calculate_risk(
            state["ai_result"], state["header_findings"], state["url_results"],
            state["attachment_results"], state["threat_intel"],
        )
        assert result["score"] >= 45

    def test_components_present(self) -> None:
        state = self._make_state()
        result = calculate_risk(
            state["ai_result"], state["header_findings"], state["url_results"],
            state["attachment_results"], state["threat_intel"],
        )
        assert "ai_detection" in result["components"]
        assert "header_forensics" in result["components"]
        assert "url_analysis" in result["components"]
        assert "threat_intelligence" in result["components"]
        assert "attachment_analysis" in result["components"]

    def test_risk_level_boundaries(self) -> None:
        assert risk_level(0) == "LOW"
        assert risk_level(25) == "LOW"
        assert risk_level(26) == "MEDIUM"
        assert risk_level(50) == "MEDIUM"
        assert risk_level(51) == "HIGH"
        assert risk_level(75) == "HIGH"
        assert risk_level(76) == "CRITICAL"
        assert risk_level(100) == "CRITICAL"

    def test_explanation_present(self) -> None:
        state = self._make_state()
        result = calculate_risk(
            state["ai_result"], state["header_findings"], state["url_results"],
            state["attachment_results"], state["threat_intel"],
        )
        assert isinstance(result["increasing"], list)
        assert isinstance(result["decreasing"], list)
