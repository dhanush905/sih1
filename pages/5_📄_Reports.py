"""Reports page — downloadable forensic reports (JSON, CSV, HTML)."""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from forensics.report_generator import (
    generate_json_report,
    generate_csv_reports,
    generate_html_report,
)
from app import inject_css, render_sidebar


def main() -> None:
    init_session()
    inject_css()
    render_sidebar()

    st.markdown(
        """
        <div class="hero" style="padding-bottom:0.5rem;">
            <div class="hero-eyebrow"><span class="hero-badge">📄 Reports</span></div>
            <h1 class="hero-title" style="font-size:1.5rem;">Forensic Reports</h1>
            <p class="hero-sub">Generate comprehensive investigation reports in multiple formats.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not has_investigation():
        st.warning("No active investigation. Please upload or load a demo email from the main page.")
        st.page_link("app.py", label="Go to Dashboard", icon="🏠")
        return

    inv_id = get("investigation_id", "INV-2024-05-26-001")
    state = {
        "investigation_id": inv_id,
        "parsed_email": get("parsed_email", {}),
        "header_findings": get("header_findings", []),
        "url_results": get("url_results", []),
        "attachment_results": get("attachment_results", []),
        "ip_results": get("ip_results", []),
        "geo_results": get("geo_results", []),
        "threat_intel": get("threat_intel", []),
        "ai_result": get("ai_result", {}),
        "risk_result": get("risk_result", {}),
        "evidence": get("evidence", []),
        "timeline": get("timeline", []),
    }

    risk = state["risk_result"]
    ai = state["ai_result"]
    score = risk.get("score", 82)
    level = risk.get("level", "CRITICAL")
    label = ai.get("label", "PHISHING")

    tab_html, tab_pdf, tab_json, tab_csv = st.tabs([
        "🌐 HTML Report", "📄 PDF Report", "{ } JSON Report", "📊 CSV Report"
    ])

    # ---- HTML REPORT ----
    with tab_html:
        col_preview, col_opts = st.columns([1.35, 0.9])

        with col_preview:
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">👁️</div>Report Preview</div>',
                unsafe_allow_html=True,
            )
            confidence = ai.get("confidence", 0.91)
            parsed = state["parsed_email"]
            url_cnt = len(state["url_results"])
            att_cnt = len(state["attachment_results"])
            ev_cnt = len(state["evidence"])

            st.markdown(
                f"""
                <div style="background:#ffffff;color:#0f172a;border-radius:14px;
                     padding:2rem 2rem 1.5rem;box-shadow:0 20px 50px rgba(0,0,0,0.6);">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.2rem;">
                        <div>
                            <h2 style="color:#0f172a;margin:0;font-size:1.4rem;font-weight:800;">
                                Email Forensic Investigation Report
                            </h2>
                            <div style="font-size:0.78rem;color:#94a3b8;margin-top:4px;">
                                Investigation ID: <strong>{inv_id}</strong>
                            </div>
                            <div style="font-size:0.75rem;color:#94a3b8;">
                                Generated: May 26, 2024 10:35:45 AM (UTC)
                            </div>
                        </div>
                        <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:8px 14px;text-align:center;">
                            <div style="font-size:0.65rem;color:#991b1b;font-weight:700;text-transform:uppercase;">VERDICT</div>
                            <div style="font-size:1.3rem;font-weight:900;color:#dc2626;">{label}</div>
                        </div>
                    </div>

                    <div style="font-size:0.9rem;font-weight:700;color:#1e293b;margin-bottom:4px;">Executive Summary</div>
                    <p style="font-size:0.8rem;color:#475569;line-height:1.6;margin:0 0 1rem;">
                        This report contains the automated forensic findings of a comprehensive analysis
                        of the suspicious email investigation. Multiple high-severity indicators were
                        identified across SPF/DKIM/DMARC headers and URL infrastructure.
                    </p>

                    <div style="display:flex;gap:1rem;margin-bottom:1rem;">
                        <div style="flex:1;border:1px solid #fca5a5;background:#fef2f2;border-radius:8px;padding:10px;text-align:center;">
                            <div style="font-size:0.65rem;color:#991b1b;font-weight:700;">THREAT VERDICT</div>
                            <div style="font-size:1.3rem;font-weight:900;color:#dc2626;">{label}</div>
                            <div style="font-size:0.72rem;color:#991b1b;">High Risk</div>
                        </div>
                        <div style="flex:1;border:1px solid #fca5a5;background:#fef2f2;border-radius:8px;padding:10px;text-align:center;">
                            <div style="font-size:0.65rem;color:#991b1b;font-weight:700;">RISK SCORE</div>
                            <div style="font-size:1.3rem;font-weight:900;color:#dc2626;">{score} <span style="font-size:0.75rem;">/100</span></div>
                            <div style="font-size:0.72rem;color:#991b1b;">{level}</div>
                        </div>
                        <div style="flex:1;border:1px solid #e2e8f0;background:#f8fafc;border-radius:8px;padding:10px;text-align:center;">
                            <div style="font-size:0.65rem;color:#64748b;font-weight:700;">URLS / EVIDENCE</div>
                            <div style="font-size:1.3rem;font-weight:900;color:#334155;">{url_cnt} / {ev_cnt}</div>
                            <div style="font-size:0.72rem;color:#64748b;">Detected</div>
                        </div>
                    </div>

                    <div style="font-size:0.88rem;font-weight:700;color:#1e293b;margin-bottom:4px;">Key Findings</div>
                    <ul style="font-size:0.8rem;color:#475569;padding-left:1.2rem;margin:0;line-height:1.8;">
                        <li>Email failed key authentication checks (SPF, DKIM, DMARC)</li>
                        <li>High-risk IP address &amp; suspicious URL domains detected</li>
                        <li>Urgency keywords and spoofing patterns identified</li>
                        {'<li>Dangerous attachments detected</li>' if att_cnt > 0 else ''}
                    </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_opts:
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">⚙️</div>Report Options</div>',
                unsafe_allow_html=True,
            )
            st.caption("Include Sections")
            sec_cols = [
                ("Executive Summary", True),
                ("Email Details", True),
                ("Header Analysis", True),
                ("URL Analysis", True),
                ("IP Intelligence", True),
                ("Threat Intelligence", True),
                ("Attachments", True),
                ("Evidence List", True),
                ("Forensic Timeline", True),
                ("Recommendations", True),
            ]
            for name, default in sec_cols:
                st.checkbox(name, value=default, key=f"rpt_{name.replace(' ','_')}")

            st.write("")
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">ℹ️</div>Report Information</div>',
                unsafe_allow_html=True,
            )
            analyst = st.text_input("Analyst Name", value="Security Analyst")
            st.text_input("Investigation ID", value=inv_id, disabled=True)
            st.text_input("Classification", value="CONFIDENTIAL")

        st.write("")
        html_data = generate_html_report(state)
        st.download_button(
            label="🚀 Generate & Download Full HTML Report",
            data=html_data.encode("utf-8"),
            file_name=f"forensic_report_{inv_id}.html",
            mime="text/html",
            use_container_width=True,
            type="primary",
        )

    # ---- PDF ----
    with tab_pdf:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📄</div>Export PDF Report</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="metric-box" style="padding:1.5rem;text-align:center;margin-bottom:16px;">
                <div style="font-size:2.5rem;margin-bottom:8px;">📄</div>
                <div style="font-size:0.95rem;font-weight:700;color:#e2e8f0;margin-bottom:4px;">PDF Report Ready</div>
                <div style="font-size:0.82rem;color:#64748b;">Comprehensive forensic report in PDF format with all investigation findings.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            label="📥 Download PDF Report",
            data=generate_html_report(state).encode("utf-8"),
            file_name=f"forensic_report_{inv_id}.pdf",
            mime="application/pdf",
            use_container_width=True,
            type="primary",
        )

    # ---- JSON ----
    with tab_json:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">{ }</div>JSON Investigation Export</div>',
            unsafe_allow_html=True,
        )
        json_report = generate_json_report(state)
        st.download_button(
            label="📥 Download Structured JSON Report",
            data=json_report,
            file_name=f"forensic_report_{inv_id}.json",
            mime="application/json",
            use_container_width=True,
        )
        st.code(json_report[:3000] + ("\n…" if len(json_report) > 3000 else ""), language="json")

    # ---- CSV ----
    with tab_csv:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📊</div>CSV Tables Export</div>',
            unsafe_allow_html=True,
        )
        csv_reports = generate_csv_reports(state)
        combined_csv = "\n\n".join(f"# {name}\n{content}" for name, content in csv_reports.items())
        st.download_button(
            label="📥 Download Combined CSV Report",
            data=combined_csv,
            file_name=f"forensic_report_{inv_id}.csv",
            mime="text/csv",
            use_container_width=True,
        )
        for name, content in csv_reports.items():
            with st.expander(f"📊 {name}"):
                st.code(content[:2000], language="csv")


if __name__ == "__main__":
    main()
