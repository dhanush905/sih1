"""Email Analysis page — summary, authentication, URLs, attachments, IPs."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from utils.helpers import severity_color, threat_label_color, risk_color, truncate
from analyzers.header_analyzer import auth_summary
from app import inject_css, render_sidebar


def main() -> None:
    init_session()
    inject_css()
    render_sidebar()

    st.markdown(
        """
        <div class="hero" style="padding-bottom:0.5rem;">
            <div class="hero-eyebrow"><span class="hero-badge">📧 Deep Analysis</span></div>
            <h1 class="hero-title" style="font-size:1.5rem;">Email Analysis</h1>
            <p class="hero-sub">Deep analysis of email headers, content, and structure.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not has_investigation():
        st.warning("No active investigation. Please upload or load a demo email from the main page.")
        st.page_link("app.py", label="Go to Dashboard", icon="🏠")
        return

    parsed = get("parsed_email", {})
    header_findings = get("header_findings", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    ip_results = get("ip_results", [])
    risk = get("risk_result", {})
    ai = get("ai_result", {})

    score = risk.get("score", 0)
    level = risk.get("level", "N/A")
    label = ai.get("label", "N/A")
    confidence = ai.get("confidence", 0)

    tab_summary, tab_headers, tab_content, tab_urls, tab_att = st.tabs([
        "📋 Email Summary",
        "🔍 Headers Analysis",
        "📝 Content Analysis",
        f"🌐 URLs ({len(url_results)})",
        f"📎 Attachments ({len(attachment_results)})",
    ])

    # ---- EMAIL SUMMARY ----
    with tab_summary:
        col_left, col_right = st.columns([1.1, 0.9])

        with col_left:
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">📋</div>Email Metadata</div>',
                unsafe_allow_html=True,
            )
            fields = [
                ("From", parsed.get("from", "N/A"), "#38bdf8"),
                ("To", parsed.get("to", "N/A"), "#e2e8f0"),
                ("CC", parsed.get("cc", "N/A"), "#94a3b8"),
                ("Subject", parsed.get("subject", "N/A"), "#f8fafc"),
                ("Date", parsed.get("date", "N/A"), "#94a3b8"),
                ("Message-ID", parsed.get("message_id", "N/A"), "#64748b"),
                ("Reply-To", parsed.get("reply_to", "N/A"), "#f97316"),
                ("Return-Path", parsed.get("return_path", "N/A"), "#94a3b8"),
            ]
            rows_html = ""
            for fname, fval, fcolor in fields:
                rows_html += f"""
                <div style="display:flex;padding:8px 0;border-bottom:1px solid #161d2e;">
                    <div style="width:100px;font-size:0.75rem;font-weight:700;color:#475569;flex-shrink:0;">{fname}</div>
                    <div style="font-size:0.8rem;color:{fcolor};word-break:break-all;">{fval}</div>
                </div>
                """
            badges = f"""
            <div style="display:flex;gap:6px;margin-top:10px;">
                <span class="badge badge-INFO">MIME: {parsed.get('mime_type','1.0')}</span>
                <span class="badge badge-INFO">Type: {parsed.get('content_type','text/plain')}</span>
            </div>
            """
            st.markdown(
                f'<div class="metric-box" style="padding:1.2rem;">{rows_html}{badges}</div>',
                unsafe_allow_html=True,
            )
            st.write("")
            _risk_time_chart(score)

        with col_right:
            # Threat Verdict
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">🎯</div>Threat Verdict</div>',
                unsafe_allow_html=True,
            )
            border = risk_color(level)
            txt = threat_label_color(label)
            st.markdown(
                f"""
                <div style="background:#0d1117;border:2px solid {border}30;border-radius:14px;
                     padding:1.6rem;text-align:center;box-shadow:0 0 20px {border}10;margin-bottom:14px;">
                    <div style="font-size:2rem;font-weight:900;color:{txt};letter-spacing:1px;">{label}</div>
                    <div style="font-size:1rem;font-weight:700;color:{risk_color(level)};margin-top:6px;">{confidence:.0%} Confidence</div>
                    <div style="margin-top:8px;"><span class="badge badge-{level}">{level} RISK</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            _risk_donut_chart(risk)
            st.write("")
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">🔑</div>Authentication Results</div>',
                unsafe_allow_html=True,
            )
            _render_auth_table(header_findings)

    # ---- HEADERS ----
    with tab_headers:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">🔍</div>Header Forensic Findings</div>',
            unsafe_allow_html=True,
        )
        if header_findings:
            for f in header_findings:
                sev = f.get("severity", "INFO")
                col_border = severity_color(sev)
                with st.expander(f"[{sev}] {f.get('check','')} — {f.get('finding','')}"):
                    st.markdown(
                        f"""
                        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px;">
                            <span class="badge badge-{sev}">{sev}</span>
                            <span style="font-size:0.78rem;color:#64748b;">Check: <strong style="color:#94a3b8;">{f.get('check','')}</strong></span>
                        </div>
                        <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:4px;">{f.get('detail','')}</div>
                        <code style="font-size:0.75rem;color:#38bdf8;">{f.get('evidence','')}</code>
                        """,
                        unsafe_allow_html=True,
                    )
        else:
            st.info("No header findings — headers appear clean.")

    # ---- CONTENT ----
    with tab_content:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📝</div>Body Content</div>',
            unsafe_allow_html=True,
        )
        body = parsed.get("body_text") or parsed.get("body_html") or "(No body content)"
        st.text_area("Email Body", value=body[:5000], height=320, disabled=True, label_visibility="collapsed")

        ai_expl = ai.get("explanation", [])
        if ai_expl:
            st.markdown(
                '<div class="section-hdr" style="margin-top:14px;"><div class="section-hdr-icon">🤖</div>AI Explanation</div>',
                unsafe_allow_html=True,
            )
            for exp in ai_expl:
                st.markdown(f"- {exp}")

    # ---- URLS ----
    with tab_urls:
        st.markdown(
            f'<div class="section-hdr"><div class="section-hdr-icon">🌐</div>URL Analysis — {len(url_results)} URLs Detected</div>',
            unsafe_allow_html=True,
        )
        if url_results:
            for u in url_results:
                sev = u.get("severity", "INFO")
                col = severity_color(sev)
                with st.expander(f"[{sev}] {truncate(u.get('url',''), 80)}"):
                    st.markdown(
                        f"""
                        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
                            <span class="badge badge-{sev}">{sev}</span>
                            {''.join(f'<span class="badge badge-HIGH">{t}</span>' for t in u.get("tags",[])) }
                        </div>
                        <div style="font-size:0.8rem;color:#38bdf8;word-break:break-all;margin-bottom:6px;">{u.get('url','')}</div>
                        <div style="font-size:0.78rem;color:#64748b;">Domain: <strong style="color:#94a3b8;">{u.get('domain','N/A')}</strong> | TLD: {u.get('tld','N/A')} | Score: {u.get('score',0)}</div>
                        """,
                        unsafe_allow_html=True,
                    )
        else:
            st.info("No URLs detected in this email.")

    # ---- ATTACHMENTS ----
    with tab_att:
        st.markdown(
            f'<div class="section-hdr"><div class="section-hdr-icon">📎</div>Attachments — {len(attachment_results)} Found</div>',
            unsafe_allow_html=True,
        )
        if attachment_results:
            for a in attachment_results:
                dangerous = a.get("is_dangerous") or a.get("is_macro")
                sev = "HIGH" if dangerous else "INFO"
                with st.expander(f"[{sev}] {a.get('filename','Unknown')}"):
                    st.markdown(
                        f"""
                        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
                            <span class="badge badge-{sev}">{sev}</span>
                            {'<span class="badge badge-HIGH">Dangerous</span>' if a.get("is_dangerous") else ''}
                            {'<span class="badge badge-MEDIUM">Macro</span>' if a.get("is_macro") else ''}
                        </div>
                        <div style="font-size:0.78rem;color:#64748b;line-height:1.6;">
                            <div>Extension: <strong style="color:#94a3b8;">{a.get('extension','N/A')}</strong></div>
                            <div>Size: <strong style="color:#94a3b8;">{a.get('size',0)} bytes</strong></div>
                            <div>MD5: <code style="color:#38bdf8;">{a.get('md5','N/A')}</code></div>
                            <div>SHA256: <code style="color:#38bdf8;">{a.get('sha256','N/A')[:48]}…</code></div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
        else:
            st.info("No attachments found.")


# ---------------------------------------------------------------------------
# Helper charts for email analysis page
# ---------------------------------------------------------------------------
def _risk_time_chart(score: int) -> None:
    """Simulated risk-over-time sparkline using Plotly."""
    import plotly.graph_objects as go
    import random

    random.seed(score)
    x = [f"10:{30+i:02d}" for i in range(7)]
    y = [max(0, score - random.randint(5, 25)) for _ in range(6)] + [score]

    fig = go.Figure(go.Scatter(
        x=x, y=y, fill="tozeroy",
        line={"color": "#ef4444", "width": 2},
        fillcolor="rgba(239,68,68,0.08)",
        mode="lines",
    ))
    fig.update_layout(
        title={"text": "Risk Score Over Time", "font": {"color": "#e2e8f0", "size": 12}, "x": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 10},
        height=160, margin={"l": 20, "r": 10, "t": 35, "b": 20},
    )
    fig.update_xaxes(color="#475569", showgrid=False)
    fig.update_yaxes(color="#475569", showgrid=True, gridcolor="#161d2e", range=[0, 100])
    st.plotly_chart(fig, use_container_width=True)


def _risk_donut_chart(risk: dict) -> None:
    """Donut chart of risk breakdown for email page."""
    import plotly.graph_objects as go

    components = risk.get("components", {})
    if not components:
        return

    names = [k.replace("_", " ").title() for k in components]
    weighted = [round(c.get("weighted", 0), 1) for c in components.values()]
    palette = ["#6366f1", "#3b82f6", "#10b981", "#f97316", "#ef4444", "#eab308", "#a855f7"]

    fig = go.Figure(go.Pie(
        labels=names, values=weighted, hole=0.58,
        marker={"colors": palette[:len(names)]},
        textinfo="none",
    ))
    fig.update_layout(
        title={"text": "Risk Score Breakdown", "font": {"color": "#e2e8f0", "size": 12}, "x": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 9},
        height=220, margin={"l": 10, "r": 10, "t": 35, "b": 10},
        legend={"font": {"color": "#8b949e", "size": 9}, "orientation": "v"},
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_auth_table(header_findings: list[dict]) -> None:
    """Render authentication table."""
    summary = auth_summary(header_findings)
    if not summary:
        st.info("No authentication data.")
        return

    sev_map = {"PASS": "LOW", "FAIL": "CRITICAL", "NONE": "MEDIUM", "WARN": "HIGH"}
    rows_html = ""
    for check, data in summary.items():
        result = data.get("result", "NONE")
        detail = data.get("detail", "")
        sev = sev_map.get(result, "INFO")
        color = severity_color(sev)
        rows_html += f"""
        <tr>
            <td style="padding:8px;font-weight:700;color:#94a3b8;">{check}</td>
            <td style="padding:8px;"><span class="badge badge-{sev}" style="color:{color};">{result}</span></td>
            <td style="padding:8px;font-size:0.72rem;color:#64748b;">{sev}</td>
            <td style="padding:8px;font-size:0.72rem;color:#94a3b8;">{detail[:60]}</td>
        </tr>
        """
    st.markdown(
        f"""
        <table style="width:100%;border-collapse:collapse;font-size:0.78rem;">
            <thead>
                <tr style="border-bottom:1px solid #1a2236;">
                    <th style="padding:8px;text-align:left;color:#475569;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;">Check</th>
                    <th style="padding:8px;text-align:left;color:#475569;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;">Status</th>
                    <th style="padding:8px;text-align:left;color:#475569;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;">Severity</th>
                    <th style="padding:8px;text-align:left;color:#475569;font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;">Details</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
