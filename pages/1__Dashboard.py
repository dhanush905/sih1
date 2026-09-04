"""Investigation Dashboard page — detailed metrics and overview."""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from utils.helpers import risk_color, threat_label_color, severity_color
from analyzers.header_analyzer import auth_summary
from app import (
    inject_css,
    _metric_card,
    _risk_gauge,
    _risk_component_chart,
    _evidence_severity_chart,
    _url_severity_chart,
    _auth_chart,
    _hex_rgb,
)


def main() -> None:
    init_session()
    inject_css()

    st.markdown(
        '<div class="section-header fade-in">Investigation Dashboard</div>',
        unsafe_allow_html=True,
    )

    if not has_investigation():
        st.warning("No active investigation. Please upload or load a demo email from the main page.")
        st.page_link("app.py", label="Go to Dashboard", icon="🏠")
        return

    risk = get("risk_result", {})
    ai = get("ai_result", {})
    urls = get("url_results", [])
    ips = get("ip_results", [])
    attachments = get("attachment_results", [])
    evidence = get("evidence", [])
    header_findings = get("header_findings", [])

    score = risk.get("score", 0)
    level = risk.get("level", "N/A")
    label = ai.get("label", "N/A")
    confidence = ai.get("confidence", 0)

    # Metric cards
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        _metric_card("Threat Verdict", label, threat_label_color(label))
    with m2:
        _metric_card("Risk Score", f"{score}/100", risk_color(level))
    with m3:
        _metric_card("AI Confidence", f"{confidence:.0%}", "#00d4ff")
    with m4:
        _metric_card("Evidence Count", str(len(evidence)), "#a371f7")

    m5, m6, m7, m8 = st.columns(4)
    with m5:
        _metric_card("URLs Detected", str(len(urls)), "#58a6ff")
    with m6:
        public_count = sum(1 for ip in ips if ip.get("is_public"))
        _metric_card("Public IPs", str(public_count), "#f85149")
    with m7:
        susp = sum(1 for f in header_findings if f.get("severity") in ("HIGH", "CRITICAL"))
        _metric_card("Suspicious Indicators", str(susp), "#db6d28")
    with m8:
        _metric_card("Attachments", str(len(attachments)), "#d29922")

    st.divider()

    vcol, gcol = st.columns([1, 1])
    with vcol:
        st.markdown("### Threat Verdict")
        st.markdown(
            f"""
            <div class="verdict-card fade-in" style="border-color:{risk_color(level)};background:rgba({_hex_rgb(risk_color(level))},0.05);">
                <div class="verdict-label" style="color:{threat_label_color(label)};">{label}</div>
                <div class="verdict-sub" style="color:{risk_color(level)};">{level} RISK — Score {score}/100</div>
                <div class="verdict-sub" style="color:#8b949e;">Confidence: {confidence:.0%}</div>
                <div class="verdict-sub" style="color:#8b949e;font-size:0.8rem;">{ai.get('model_mode', '')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with gcol:
        st.markdown("### Risk Score Gauge")
        _risk_gauge(score, level)

    st.divider()

    c1, c2 = st.columns(2)
    with c1:
        _risk_component_chart(risk)
    with c2:
        _evidence_severity_chart(evidence)

    c3, c4 = st.columns(2)
    with c3:
        _url_severity_chart(urls)
    with c4:
        _auth_chart(header_findings)

    # Risk explanation
    st.divider()
    st.markdown("### Risk Score Explanation")
    if risk.get("increasing"):
        st.markdown("**Factors increasing risk:**")
        for r in risk["increasing"][:10]:
            st.markdown(f"- {r}")
    if risk.get("decreasing"):
        st.markdown("**Factors decreasing risk:**")
        for r in risk["decreasing"][:5]:
            st.markdown(f"- {r}")

    # Component weights
    st.markdown("**Component weights:** AI Detection 40% · Header Forensics 20% · URL Analysis 15% · Threat Intelligence 15% · Attachment Analysis 10%")


if __name__ == "__main__":
    main()
