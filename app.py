"""AI Email Intelligence — SIH26106 main application.

Entry point for the Streamlit email threat detection and forensic
intelligence platform.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils.session import init_session, reset_session, has_investigation, get, set
from utils.helpers import (
    generate_investigation_id,
    risk_color,
    risk_level,
    severity_color,
    threat_label_color,
)
from analyzers.email_parser import parse_email
from analyzers.header_analyzer import analyze_headers, auth_summary
from analyzers.url_analyzer import analyze_urls
from analyzers.attachment_analyzer import analyze_attachments
from analyzers.ip_analyzer import analyze_ips, extract_public_ips
from analyzers.domain_analyzer import extract_domains, analyze_domains
from ai.classifier import classify_email
from ai.risk_score import calculate_risk
from intelligence.geolocation import geolocate_ips
from intelligence.threat_intel import (
    check_ip_reputation,
    check_hash_reputation,
    check_domain_reputation,
    check_url_reputation,
)
from forensics.evidence import build_evidence
from forensics.timeline import build_timeline

load_dotenv()

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_emails"


# ---------------------------------------------------------------------------
# CSS / styling
# ---------------------------------------------------------------------------
def inject_css() -> None:
    """Inject custom CSS matching the reference SOC dark-theme UI."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

        /* ---- Global Reset ---- */
        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        .stApp { background: #0a0e1a; color: #e2e8f0; }
        .main .block-container { padding-top: 1rem; padding-bottom: 2rem; max-width: 1400px; }
        [data-testid="stSidebarNav"] { display: none !important; }

        /* ---- Sidebar ---- */
        section[data-testid="stSidebar"] {
            background: #080c14;
            border-right: 1px solid #161d2e;
            min-width: 220px !important;
            max-width: 220px !important;
        }
        section[data-testid="stSidebar"] > div { padding: 0.8rem 0.8rem; }

        /* Brand */
        .sb-brand {
            display: flex; align-items: center; gap: 10px;
            padding: 8px 4px 16px 4px; margin-bottom: 4px;
            border-bottom: 1px solid #161d2e;
        }
        .sb-brand-icon {
            width: 34px; height: 34px;
            background: linear-gradient(135deg, #6366f1 0%, #3b82f6 100%);
            border-radius: 9px; display: flex; align-items: center;
            justify-content: center; font-size: 1rem; color: #fff;
            box-shadow: 0 0 16px rgba(99,102,241,0.5); flex-shrink: 0;
        }
        .sb-brand-text { font-size: 1.15rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.4px; }
        .sb-brand-sub { font-size: 0.62rem; color: #475569; font-weight: 500; margin-top: 1px; }

        /* Nav section headers */
        .sb-section {
            font-size: 0.62rem; font-weight: 700; color: #374151;
            text-transform: uppercase; letter-spacing: 1.4px;
            padding: 14px 4px 6px 4px;
        }

        /* Nav items */
        .sb-nav-item {
            display: flex; align-items: center; gap: 10px;
            padding: 9px 10px; border-radius: 8px; margin-bottom: 2px;
            cursor: pointer; transition: all 0.15s ease;
            font-size: 0.85rem; font-weight: 500; color: #94a3b8;
            text-decoration: none;
        }
        .sb-nav-item:hover { background: #111827; color: #e2e8f0; }
        .sb-nav-item.active {
            background: linear-gradient(90deg, rgba(99,102,241,0.2) 0%, rgba(59,130,246,0.1) 100%);
            color: #818cf8; border: 1px solid rgba(99,102,241,0.25);
        }
        .sb-nav-icon { font-size: 1rem; width: 20px; text-align: center; }

        /* Tools items */
        .sb-tool-item {
            display: flex; align-items: center; gap: 8px;
            padding: 7px 10px; border-radius: 7px; margin-bottom: 2px;
            font-size: 0.82rem; color: #64748b; cursor: pointer;
            transition: all 0.15s ease;
        }
        .sb-tool-item:hover { background: #0f172a; color: #94a3b8; }

        /* System Status */
        .sb-status {
            background: #0d1117; border: 1px solid #161d2e;
            border-radius: 10px; padding: 10px 12px; margin-top: 12px;
        }
        .sb-status-row { display: flex; align-items: center; gap: 8px; }
        .sb-status-dot {
            width: 8px; height: 8px; background: #10b981; border-radius: 50%;
            box-shadow: 0 0 8px rgba(16,185,129,0.7); flex-shrink: 0;
        }
        .sb-status-label { font-size: 0.78rem; font-weight: 700; color: #f0fdf4; }
        .sb-status-mode { font-size: 0.68rem; color: #475569; margin-top: 4px; }
        .sb-status-mode span { color: #10b981; font-weight: 600; }

        /* Investigation mini panel */
        .sb-inv {
            background: #0d1117; border: 1px solid #1e293b;
            border-radius: 10px; padding: 10px 12px; margin-top: 8px;
            font-size: 0.75rem;
        }
        .sb-inv-label { font-size: 0.6rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #475569; margin-bottom: 6px; }
        .sb-inv-row { margin-bottom: 3px; color: #94a3b8; }
        .sb-inv-row strong { color: #cbd5e1; }

        /* ---- Hero ---- */
        .hero {
            padding: 1.4rem 0 0.8rem 0;
        }
        .hero-eyebrow {
            display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
        }
        .hero-badge {
            font-size: 0.65rem; font-weight: 700; letter-spacing: 1px;
            text-transform: uppercase; color: #6366f1;
            background: rgba(99,102,241,0.12); border: 1px solid rgba(99,102,241,0.3);
            padding: 2px 8px; border-radius: 20px;
        }
        .hero-title {
            font-size: 1.9rem; font-weight: 900; color: #f8fafc;
            letter-spacing: -0.7px; line-height: 1.15; margin: 0 0 0.5rem 0;
        }
        .hero-title .cyan { color: #00d4ff; }
        .hero-title .purple { color: #a78bfa; }
        .hero-sub { color: #64748b; font-size: 0.88rem; margin: 0; max-width: 720px; line-height: 1.5; }

        /* ---- Upload Card ---- */
        .upload-card {
            background: #0d1117;
            border: 2px dashed #1e293b;
            border-radius: 14px;
            padding: 2.5rem 2rem;
            text-align: center;
            transition: border-color 0.2s ease;
            position: relative;
        }
        .upload-card:hover { border-color: #6366f1; }
        .upload-icon {
            font-size: 2.5rem; margin-bottom: 0.8rem;
            filter: drop-shadow(0 0 12px rgba(99,102,241,0.4));
        }
        .upload-title { font-size: 1rem; font-weight: 700; color: #f8fafc; margin-bottom: 4px; }
        .upload-sub { font-size: 0.8rem; color: #64748b; margin-bottom: 4px; }
        .upload-formats { font-size: 0.72rem; color: #475569; }

        /* ---- Metric Cards ---- */
        .metric-card {
            background: #0d1117;
            border: 1px solid #1a2236;
            border-radius: 12px;
            padding: 1rem 1.1rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .metric-card:hover { transform: translateY(-2px); border-color: #252f45; }
        .metric-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0;
            height: 2px; background: var(--accent, #6366f1);
        }
        .metric-label {
            font-size: 0.67rem; font-weight: 700; color: #475569;
            text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;
        }
        .metric-value {
            font-size: 1.7rem; font-weight: 900; line-height: 1;
            color: var(--accent, #f8fafc);
        }
        .metric-unit { font-size: 0.85rem; font-weight: 600; color: #64748b; }
        .metric-sub { font-size: 0.72rem; font-weight: 600; margin-top: 6px; color: #64748b; }

        /* ---- Badges ---- */
        .badge {
            display: inline-block; padding: 2px 8px; border-radius: 5px;
            font-size: 0.65rem; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase;
        }
        .badge-CRITICAL { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.35); }
        .badge-HIGH { background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.35); }
        .badge-MEDIUM { background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.35); }
        .badge-LOW { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.35); }
        .badge-INFO { background: rgba(59,130,246,0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.35); }
        .badge-PHISHING { background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid rgba(239,68,68,0.5); }
        .badge-SUSPICIOUS { background: rgba(249,115,22,0.2); color: #f97316; border: 1px solid rgba(249,115,22,0.4); }
        .badge-BENIGN { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.35); }

        /* ---- Progress Tracker ---- */
        .progress-track {
            display: flex; align-items: flex-start; justify-content: space-between;
            padding: 16px 0 8px 0; overflow-x: auto;
        }
        .progress-item {
            display: flex; flex-direction: column; align-items: center;
            flex: 1; min-width: 90px; position: relative;
        }
        .progress-item:not(:last-child)::after {
            content: ''; position: absolute;
            top: 15px; left: calc(50% + 16px);
            width: calc(100% - 32px); height: 2px;
            background: linear-gradient(90deg, #10b981, #10b981);
        }
        .progress-circle {
            width: 32px; height: 32px; border-radius: 50%;
            background: linear-gradient(135deg, #10b981, #059669);
            display: flex; align-items: center; justify-content: center;
            font-size: 0.85rem; color: #fff; font-weight: 800;
            box-shadow: 0 0 12px rgba(16,185,129,0.4);
            position: relative; z-index: 1;
        }
        .progress-circle.pending {
            background: #1e293b;
            box-shadow: none; color: #475569;
        }
        .progress-name {
            font-size: 0.65rem; font-weight: 600; color: #94a3b8;
            text-align: center; margin-top: 6px; line-height: 1.3;
        }
        .progress-status { font-size: 0.6rem; color: #10b981; font-weight: 700; margin-top: 2px; }

        /* ---- Section Header ---- */
        .section-hdr {
            display: flex; align-items: center; gap: 10px;
            font-size: 1.05rem; font-weight: 700; color: #e2e8f0;
            margin-bottom: 14px; padding-bottom: 10px;
            border-bottom: 1px solid #161d2e;
        }
        .section-hdr-icon {
            width: 28px; height: 28px; border-radius: 7px;
            background: rgba(99,102,241,0.15); border: 1px solid rgba(99,102,241,0.25);
            display: flex; align-items: center; justify-content: center; font-size: 0.85rem;
        }
        .section-title {
            font-size: 1.1rem; font-weight: 700; color: #38bdf8;
            margin-bottom: 14px; display: flex; align-items: center; gap: 8px;
        }

        /* ---- Tabs ---- */
        .stTabs [data-baseweb="tab-list"] {
            gap: 4px; background: #0d1117;
            padding: 4px; border-radius: 9px;
            border: 1px solid #1a2236;
        }
        .stTabs [data-baseweb="tab"] {
            border-radius: 6px; padding: 7px 14px;
            font-weight: 600; font-size: 0.82rem; color: #64748b; border: none;
            background: transparent;
        }
        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #6366f1, #4f46e5) !important;
            color: #ffffff !important;
        }

        /* ---- Data Tables ---- */
        .stDataFrame { border-radius: 10px; overflow: hidden; }
        .stDataFrame th { background: #111827 !important; color: #94a3b8 !important; }
        .stDataFrame td { background: #0d1117 !important; color: #e2e8f0 !important; }

        /* ---- Expanders ---- */
        .streamlit-expanderHeader {
            background: #0d1117 !important; border-radius: 8px !important;
            border: 1px solid #1a2236 !important;
        }

        /* ---- Buttons ---- */
        .stButton > button {
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            color: #fff; border: none; border-radius: 8px;
            font-weight: 600; font-size: 0.85rem;
            transition: all 0.2s ease;
        }
        .stButton > button:hover { transform: translateY(-1px); box-shadow: 0 4px 15px rgba(99,102,241,0.4); }
        .stButton > button[kind="secondary"] {
            background: #111827; color: #94a3b8; border: 1px solid #1f2937;
        }

        /* ---- Verdict Card ---- */
        .verdict-card {
            border-radius: 14px; padding: 1.8rem;
            text-align: center; position: relative; overflow: hidden;
        }
        .verdict-label { font-size: 2.4rem; font-weight: 900; letter-spacing: 1px; }
        .verdict-conf { font-size: 1rem; font-weight: 600; margin-top: 6px; }
        .verdict-badge { margin-top: 10px; }

        /* ---- Info / Warning ---- */
        .stAlert { border-radius: 10px !important; }

        /* ---- Footer ---- */
        .footer {
            text-align: center; color: #334155; font-size: 0.72rem;
            margin-top: 1.5rem; padding-top: 0.8rem; border-top: 1px solid #161d2e;
        }

        /* ---- Demo label pill ---- */
        .demo-pill {
            display: inline-flex; align-items: center; gap: 6px;
            background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.25);
            border-radius: 20px; padding: 3px 10px;
            font-size: 0.7rem; font-weight: 600; color: #818cf8;
        }

        /* Metric-box for backward compat with pages */
        .metric-box {
            background: #0d1117; border-radius: 12px; padding: 1rem 1.1rem;
            border: 1px solid #1a2236; transition: all 0.2s ease;
        }
        .metric-box:hover { border-color: #252f45; transform: translateY(-1px); }
        .metric-box-title { font-size: 0.67rem; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
        .metric-box-val { font-size: 1.6rem; font-weight: 900; color: #f8fafc; line-height: 1.1; }
        .metric-box-sub { font-size: 0.72rem; font-weight: 600; margin-top: 6px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def run_analysis_pipeline(raw_email: bytes | str, investigation_id: str) -> None:
    """Run the full analysis pipeline and store results in session state."""
    steps = [
        "Email Parsed", "Headers Analyzed", "URLs Extracted", "Attachments Analyzed",
        "IP Infrastructure", "Threat Intel", "Geolocation", "AI Classification",
        "Risk Scored", "Timeline Generated",
    ]

    progress = st.progress(0, text="Starting analysis…")
    status = st.empty()

    for i, label in enumerate(steps):
        pct = int((i / len(steps)) * 100)
        progress.progress(pct, text=f"Analyzing: {label}…")
        status.markdown(
            f"<span style='font-size:0.82rem;color:#6366f1;font-weight:600;'>⚡ {label}…</span>",
            unsafe_allow_html=True,
        )

        if i == 0:
            parsed = parse_email(raw_email)
            set("parsed_email", parsed.to_dict())
        elif i == 1:
            set("header_findings", analyze_headers(parse_email(raw_email)))
        elif i == 2:
            set("url_results", analyze_urls(parse_email(raw_email).urls))
        elif i == 3:
            set("attachment_results", analyze_attachments(parse_email(raw_email).attachments))
        elif i == 4:
            p = parse_email(raw_email)
            set("ip_results", analyze_ips(p.all_ips))
            domains = extract_domains(p.body_text or "") + extract_domains(p.body_html or "")
            set("domain_results", analyze_domains(list(set(domains))))
        elif i == 5:
            _run_threat_intel()
        elif i == 6:
            _run_geolocation()
        elif i == 7:
            _run_ai_classification()
        elif i == 8:
            _run_risk_score()
        elif i == 9:
            _run_forensics()

    progress.progress(100, text="Analysis complete ✓")
    status.empty()
    set("analysis_complete", True)


def _run_threat_intel() -> None:
    ip_results = get("ip_results", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    domain_results = get("domain_results", [])
    ti: list[dict[str, Any]] = []
    for ip in [r["ip"] for r in ip_results if r.get("is_public")][:5]:
        ti.append(check_ip_reputation(ip))
    for u in url_results[:5]:
        ti.append(check_url_reputation(u.get("url", "")))
    for a in attachment_results[:3]:
        ti.append(check_hash_reputation(a.get("sha256", "")))
    for d in domain_results[:3]:
        ti.append(check_domain_reputation(d.get("domain", "")))
    set("threat_intel", ti)


def _run_geolocation() -> None:
    ip_results = get("ip_results", [])
    public_ips = [r["ip"] for r in ip_results if r.get("is_public")]
    set("geo_results", geolocate_ips(public_ips[:10]))


def _run_ai_classification() -> None:
    raw = st.session_state.get("_raw_email", b"")
    if not raw:
        return
    parsed_obj = parse_email(raw)
    ai_result = classify_email(
        parsed_obj,
        get("header_findings", []),
        get("url_results", []),
        get("attachment_results", []),
        get("threat_intel", []),
    )
    set("ai_result", ai_result)


def _run_risk_score() -> None:
    risk = calculate_risk(
        get("ai_result", {}),
        get("header_findings", []),
        get("url_results", []),
        get("attachment_results", []),
        get("threat_intel", []),
    )
    set("risk_result", risk)


def _run_forensics() -> None:
    parsed = get("parsed_email", {})
    header_findings = get("header_findings", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    ip_results = get("ip_results", [])
    threat_intel = get("threat_intel", [])
    ai_result = get("ai_result", {})
    risk_result = get("risk_result", {})

    set("evidence", build_evidence(header_findings, url_results, attachment_results, ip_results, threat_intel, ai_result))
    set("timeline", build_timeline(
        parsed=parsed, ip_results=ip_results, url_results=url_results,
        attachment_results=attachment_results, threat_intel=threat_intel,
        ai_result=ai_result, risk_result=risk_result,
    ))


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar() -> None:
    """Render the sidebar with brand, navigation, tools, and status."""
    vt = bool(os.environ.get("VIRUSTOTAL_API_KEY") or _st_secret("VIRUSTOTAL_API_KEY"))
    abuse = bool(os.environ.get("ABUSEIPDB_API_KEY") or _st_secret("ABUSEIPDB_API_KEY"))
    ipinfo = bool(os.environ.get("IPINFO_TOKEN") or _st_secret("IPINFO_TOKEN"))
    mode = "FULL INTELLIGENCE" if any([vt, abuse, ipinfo]) else "LOCAL ANALYSIS"

    with st.sidebar:
        # Brand
        st.markdown(
            """
            <div class="sb-brand">
                <div class="sb-brand-icon">🛡️</div>
                <div>
                    <div class="sb-brand-text">SIH26106</div>
                    <div class="sb-brand-sub">Threat Intelligence Platform</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Main nav
        st.markdown('<div class="sb-section">MAIN MENU</div>', unsafe_allow_html=True)
        st.page_link("app.py", label="Dashboard", icon="🏠")
        st.page_link("pages/2_📧_Email_Analysis.py", label="Email Analysis", icon="📧")
        st.page_link("pages/3_🌐_Threat_Intelligence.py", label="Threat Intelligence", icon="🌐")
        st.page_link("pages/4_🔬_Digital_Forensics.py", label="Digital Forensics", icon="🔬")
        st.page_link("pages/5_📄_Reports.py", label="Reports", icon="📄")
        # Live Monitor with connection status indicator
        lm_connected = st.session_state.get("_lm_connected", False)
        lm_label = "📡 Live Monitor 🟢" if lm_connected else "📡 Live Monitor"
        st.page_link("pages/6_📡_Live_Monitor.py", label=lm_label, icon="📡")

        # Tools
        st.markdown('<div class="sb-section">TOOLS</div>', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="sb-tool-item">🔍 Indicator Lookup</div>
            <div class="sb-tool-item">🔑 Hash Lookup</div>
            <div class="sb-tool-item">⚙️ Settings</div>
            """,
            unsafe_allow_html=True,
        )

        # System status
        st.markdown(
            f"""
            <div class="sb-status">
                <div class="sb-status-row">
                    <div class="sb-status-dot"></div>
                    <div class="sb-status-label">System Status</div>
                </div>
                <div class="sb-status-mode">All Systems Operational<br>
                    Mode: <span>{mode}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Active investigation
        if has_investigation():
            inv_id = get("investigation_id", "N/A")
            risk = get("risk_result", {})
            ai = get("ai_result", {})
            score = risk.get("score", 0)
            level = risk.get("level", "N/A")
            label = ai.get("label", "N/A")
            st.markdown(
                f"""
                <div class="sb-inv">
                    <div class="sb-inv-label">Active Investigation</div>
                    <div class="sb-inv-row"><strong>ID:</strong> {inv_id[:18]}…</div>
                    <div class="sb-inv-row"><strong>Risk:</strong>
                        <span style="color:{risk_color(level)};font-weight:700;">{score}/100 ({level})</span>
                    </div>
                    <div class="sb-inv-row"><strong>Verdict:</strong>
                        <span style="color:{threat_label_color(label)};font-weight:700;">{label}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown('<p class="footer">AI Email Threat Intelligence<br>SIH26106 Prototype</p>', unsafe_allow_html=True)


def _st_secret(key: str) -> str:
    try:
        return st.secrets.get(key, "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------
def main() -> None:
    """Main entry: render sidebar, hero, upload, and dashboard."""
    init_session()
    inject_css()
    render_sidebar()

    # Hero
    st.markdown(
        """
        <div class="hero">
            <div class="hero-eyebrow">
                <span class="hero-badge">⚡ AI-Powered SOC Platform</span>
            </div>
            <h1 class="hero-title">AI-Powered Email Threat <span class="cyan">Detection</span> &amp; <span class="purple">Forensic Intelligence</span></h1>
            <p class="hero-sub">Analyze suspicious emails, identify malicious infrastructure, investigate evidence, and generate explainable intelligence.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Top-right demo button
    _, btn_col = st.columns([4, 1])
    with btn_col:
        if st.button("🧪 Load Demo Email", use_container_width=True):
            _load_demo("phishing.eml")

    st.write("")

    # Upload + Demo section
    col_up, col_demo = st.columns([1.6, 1])

    with col_up:
        st.markdown(
            """
            <div class="upload-card">
                <div class="upload-icon">📂</div>
                <div class="upload-title">Upload Suspicious Email</div>
                <div class="upload-sub">Drag &amp; drop your .eml file here or click to browse</div>
                <div class="upload-formats">Supports: .eml and .txt files</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write("")
        uploaded = st.file_uploader(
            "Upload .eml or .txt file",
            type=["eml", "txt"],
            label_visibility="collapsed",
        )
        if uploaded is not None:
            raw = uploaded.read()
            if len(raw) > 10 * 1024 * 1024:
                st.error("File exceeds 10 MB limit.")
            else:
                _handle_upload(raw)

    with col_demo:
        st.markdown(
            """
            <div class="section-hdr">
                <div class="section-hdr-icon">🧪</div>
                Demo Investigations
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption("Load a synthetic sample email to test the platform instantly.")
        bc1, bc2 = st.columns(2)
        with bc1:
            if st.button("📧 Phishing", use_container_width=True):
                _load_demo("phishing.eml")
            if st.button("📋 Suspicious", use_container_width=True):
                _load_demo("suspicious.eml")
        with bc2:
            if st.button("✅ Benign", use_container_width=True):
                _load_demo("benign.eml")
            if st.button("🗑️ Clear", use_container_width=True):
                reset_session()
                st.rerun()

    # Dashboard or feature cards
    if has_investigation():
        st.divider()
        _render_dashboard()
    else:
        st.divider()
        _render_feature_cards()


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def _handle_upload(raw: bytes | str) -> None:
    inv_id = generate_investigation_id()
    set("investigation_id", inv_id)
    st.session_state["_raw_email"] = raw
    set("demo_loaded", False)
    run_analysis_pipeline(raw, inv_id)
    st.rerun()


def _load_demo(filename: str) -> None:
    path = SAMPLE_DIR / filename
    if not path.exists():
        st.error(f"Sample file not found: {filename}")
        return
    raw = path.read_bytes()
    inv_id = generate_investigation_id()
    set("investigation_id", inv_id)
    set("demo_loaded", True)
    set("current_demo", filename)
    st.session_state["_raw_email"] = raw
    run_analysis_pipeline(raw, inv_id)
    st.rerun()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
def _render_dashboard() -> None:
    """Render the investigation dashboard: metrics, progress, verdict, charts."""
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
    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">📊</div>Investigation Overview</div>',
        unsafe_allow_html=True,
    )

    susp_urls = sum(1 for u in urls if u.get("severity") in ("HIGH", "CRITICAL"))
    pub_ips = sum(1 for ip in ips if ip.get("is_public"))
    susp_att = sum(1 for a in attachments if a.get("is_dangerous") or a.get("is_macro"))

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    _metric_card(c1, "Risk Score", f"{score}", "/100", risk_color(level),
                 f'<span class="badge badge-{level}">{level}</span>')
    _metric_card(c2, "Threat Verdict", label, "", threat_label_color(label),
                 f"{confidence:.0%} Confidence")
    _metric_card(c3, "URLs Detected", str(len(urls)), "", "#38bdf8",
                 f'<span style="color:#f97316;">{susp_urls} Suspicious</span>' if susp_urls else "All Clear")
    _metric_card(c4, "Public IPs", str(pub_ips), "", "#ef4444",
                 f'<span style="color:#ef4444;">{min(pub_ips,2)} High-Risk</span>' if pub_ips else "None")
    _metric_card(c5, "Attachments", str(len(attachments)), "", "#eab308",
                 f'<span style="color:#eab308;">{susp_att} Suspicious</span>' if susp_att else "Clean")
    _metric_card(c6, "Evidence Items", str(len(evidence)), "", "#a855f7",
                 "High Severity" if score > 50 else "Recorded")

    # Progress tracker
    st.write("")
    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">⚡</div>Analysis Progress</div>',
        unsafe_allow_html=True,
    )
    steps = [
        "Email\nUploaded", "Email\nParsed", "Headers\nAnalyzed", "URLs\nExtracted",
        "Threat\nIntel", "AI\nAnalysis", "Risk\nScored", "Timeline\nGenerated",
    ]
    items_html = ""
    for s in steps:
        items_html += f"""
        <div class="progress-item">
            <div class="progress-circle">✓</div>
            <div class="progress-name">{s.replace(chr(10),'<br>')}</div>
            <div class="progress-status">Completed</div>
        </div>
        """
    st.markdown(f'<div class="progress-track">{items_html}</div>', unsafe_allow_html=True)

    st.divider()

    # Verdict + Risk gauge
    vcol, gcol = st.columns([1, 1])
    with vcol:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">🎯</div>Threat Verdict</div>',
            unsafe_allow_html=True,
        )
        border = risk_color(level)
        txt = threat_label_color(label)
        st.markdown(
            f"""
            <div class="verdict-card" style="background:#0d1117;border:2px solid {border}20;
                 box-shadow:0 0 30px {border}15;">
                <div class="verdict-label" style="color:{txt};">{label}</div>
                <div class="verdict-conf" style="color:{risk_color(level)};">{confidence:.0%} Confidence</div>
                <div class="verdict-badge"><span class="badge badge-{level}">{level} RISK</span></div>
                <div style="font-size:0.78rem;color:#475569;margin-top:8px;">{ai.get('model_mode','')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with gcol:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📈</div>Risk Score Gauge</div>',
            unsafe_allow_html=True,
        )
        _risk_gauge(score, level)

    st.divider()

    # Charts
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


def _render_feature_cards() -> None:
    """Render platform capability cards when no investigation is loaded."""
    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">🚀</div>Platform Capabilities</div>',
        unsafe_allow_html=True,
    )
    features = [
        ("📧", "#3b82f6", "Email Parsing", "Robust .eml parser with header, body, URL, and attachment extraction."),
        ("🔍", "#6366f1", "Header Forensics", "SPF, DKIM, DMARC validation plus spoofing and routing anomaly detection."),
        ("🌐", "#06b6d4", "URL Analysis", "Detects phishing keywords, IP URLs, shorteners, and suspicious TLDs."),
        ("🔬", "#a855f7", "Attachment Forensics", "SHA-256/MD5 hashing, dangerous extension and double-extension detection."),
        ("📍", "#f97316", "Geolocation", "IP geolocation with API support and offline fallback."),
        ("🛡️", "#10b981", "Threat Intelligence", "VirusTotal, AbuseIPDB integration with local heuristic fallback."),
        ("🤖", "#ef4444", "AI Threat Detection", "Hybrid TF-IDF + heuristic classifier with explainable predictions."),
        ("📊", "#eab308", "Risk Scoring", "Weighted 0-100 risk score with transparent component breakdown."),
        ("📋", "#64748b", "Forensic Reports", "JSON, CSV, and HTML investigation reports with evidence and timeline."),
    ]
    cols = st.columns(3)
    for i, (icon, color, title, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(
                f"""
                <div class="metric-card" style="--accent:{color}; margin-bottom: 12px;">
                    <div style="font-size:1.6rem;margin-bottom:8px;">{icon}</div>
                    <div style="font-size:0.95rem;font-weight:700;color:{color};margin-bottom:4px;">{title}</div>
                    <div style="font-size:0.8rem;color:#64748b;line-height:1.45;">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def _metric_card(container, label: str, value: str, unit: str, color: str, sub: str = "") -> None:
    """Render a styled metric card in the given column."""
    sub_html = f'<div class="metric-sub">{sub}</div>' if sub else ""
    with container:
        st.markdown(
            f"""
            <div class="metric-card" style="--accent:{color};">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color:{color};">{value}
                    <span class="metric-unit">{unit}</span>
                </div>
                {sub_html}
            </div>
            """,
            unsafe_allow_html=True,
        )


def _risk_gauge(score: int, level: str) -> None:
    """Render a Plotly risk gauge."""
    import plotly.graph_objects as go

    color = risk_color(level)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        number={"suffix": "/100", "font": {"color": "#e6edf3", "size": 30, "family": "Inter"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#334155", "tickfont": {"size": 10}},
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 25], "color": "rgba(16,185,129,0.08)"},
                {"range": [25, 50], "color": "rgba(234,179,8,0.08)"},
                {"range": [50, 75], "color": "rgba(249,115,22,0.08)"},
                {"range": [75, 100], "color": "rgba(239,68,68,0.08)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.85, "value": score,
            },
        },
    ))
    fig.update_layout(
        height=230,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "family": "Inter"},
        margin={"l": 20, "r": 20, "t": 10, "b": 10},
    )
    st.plotly_chart(fig, use_container_width=True)


def _risk_component_chart(risk: dict) -> None:
    """Donut chart of risk component breakdown."""
    import plotly.graph_objects as go

    components = risk.get("components", {})
    if not components:
        st.info("No risk component data.")
        return

    names = [k.replace("_", " ").title() for k in components]
    weighted = [round(c.get("weighted", 0), 1) for c in components.values()]
    palette = ["#6366f1", "#3b82f6", "#10b981", "#f97316", "#ef4444", "#eab308", "#a855f7", "#06b6d4"]

    fig = go.Figure(go.Pie(
        labels=names, values=weighted,
        hole=0.55,
        marker={"colors": palette[:len(names)]},
        textinfo="label+percent",
        textfont={"size": 10, "color": "#e2e8f0"},
    ))
    fig.update_layout(
        title={"text": "Risk Score Breakdown", "font": {"color": "#e2e8f0", "size": 13}, "x": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 10, "family": "Inter"},
        height=290, margin={"l": 10, "r": 10, "t": 40, "b": 10},
        legend={"font": {"color": "#8b949e", "size": 10}},
        showlegend=True,
    )
    st.plotly_chart(fig, use_container_width=True)


def _evidence_severity_chart(evidence: list[dict]) -> None:
    """Bar chart of evidence severity."""
    import plotly.graph_objects as go

    if not evidence:
        st.info("No evidence collected.")
        return

    counts: dict[str, int] = {}
    for e in evidence:
        sev = e.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    labels = list(counts.keys())
    values = list(counts.values())
    colors = [severity_color(l) for l in labels]

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color=colors, marker_line_width=0))
    fig.update_layout(
        title={"text": "Evidence Severity Distribution", "font": {"color": "#e2e8f0", "size": 13}, "x": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 10, "family": "Inter"},
        height=290, margin={"l": 20, "r": 10, "t": 40, "b": 20},
        bargap=0.35,
    )
    fig.update_xaxes(showgrid=False, color="#64748b")
    fig.update_yaxes(showgrid=True, gridcolor="#1a2236", color="#64748b")
    st.plotly_chart(fig, use_container_width=True)


def _url_severity_chart(urls: list[dict]) -> None:
    """Bar chart of URL severity distribution."""
    import plotly.graph_objects as go

    if not urls:
        st.info("No URLs detected.")
        return

    counts: dict[str, int] = {}
    for u in urls:
        sev = u.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    labels = list(counts.keys())
    values = list(counts.values())
    colors = [severity_color(l) for l in labels]

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color=colors, marker_line_width=0))
    fig.update_layout(
        title={"text": "URL Severity Distribution", "font": {"color": "#e2e8f0", "size": 13}, "x": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 10, "family": "Inter"},
        height=290, margin={"l": 20, "r": 10, "t": 40, "b": 20},
        bargap=0.35,
    )
    fig.update_xaxes(showgrid=False, color="#64748b")
    fig.update_yaxes(showgrid=True, gridcolor="#1a2236", color="#64748b")
    st.plotly_chart(fig, use_container_width=True)


def _auth_chart(header_findings: list[dict]) -> None:
    """Authentication check results bar chart."""
    import plotly.graph_objects as go

    summary = auth_summary(header_findings)
    if not summary:
        st.info("No authentication data.")
        return

    labels = list(summary.keys())
    results = [summary[l]["result"] for l in labels]
    color_map = {"PASS": "#10b981", "FAIL": "#ef4444", "NONE": "#64748b", "WARN": "#eab308"}
    colors = [color_map.get(r, "#64748b") for r in results]

    fig = go.Figure(go.Bar(
        x=labels, y=[1] * len(labels),
        marker_color=colors, marker_line_width=0,
        text=results, textposition="auto",
        textfont={"color": "#fff", "size": 12, "family": "Inter"},
    ))
    fig.update_layout(
        title={"text": "Authentication Results (SPF · DKIM · DMARC)", "font": {"color": "#e2e8f0", "size": 13}, "x": 0},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 10, "family": "Inter"},
        height=290, margin={"l": 20, "r": 10, "t": 40, "b": 20},
        showlegend=False, yaxis={"visible": False}, bargap=0.3,
    )
    fig.update_xaxes(showgrid=False, color="#94a3b8")
    st.plotly_chart(fig, use_container_width=True)


if __name__ == "__main__":
    main()
