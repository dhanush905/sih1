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
    """Inject custom CSS for a polished SOC-style dark theme."""
    st.markdown(
        """
        <style>
        /* ---- Global ---- */
        .stApp { background: linear-gradient(135deg, #0a0e1a 0%, #0d1421 100%); }
        .main .block-container { padding-top: 1.5rem; max-width: 1200px; }

        /* ---- Sidebar ---- */
        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0d1421 0%, #0a0e1a 100%);
            border-right: 1px solid #1c2535;
        }
        .sidebar-title {
            font-size: 1.4rem; font-weight: 800; color: #00d4ff;
            letter-spacing: 0.5px; margin-bottom: 0;
        }
        .sidebar-subtitle {
            font-size: 0.78rem; color: #8b949e; margin-top: 2px;
        }

        /* ---- Hero ---- */
        .hero {
            background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 50%, #0d1b2a 100%);
            border-radius: 16px; padding: 2.5rem 2rem; margin-bottom: 1.5rem;
            border: 1px solid #1c2535; position: relative; overflow: hidden;
        }
        .hero::before {
            content: ''; position: absolute; top: -50%; right: -10%;
            width: 400px; height: 400px;
            background: radial-gradient(circle, rgba(0,212,255,0.08) 0%, transparent 70%);
            border-radius: 50%;
        }
        .hero h1 {
            font-size: 2.1rem; font-weight: 800; color: #e6edf3;
            margin: 0 0 0.5rem 0; letter-spacing: -0.5px;
        }
        .hero h1 span { color: #00d4ff; }
        .hero p { color: #8b949e; font-size: 0.95rem; margin: 0; }

        /* ---- Metric cards ---- */
        .metric-card {
            background: #121826; border-radius: 12px; padding: 1.2rem 1.4rem;
            border: 1px solid #1c2535; transition: transform 0.2s, box-shadow 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,212,255,0.1);
            border-color: #2a3548;
        }
        .metric-label { font-size: 0.72rem; color: #8b949e; text-transform: uppercase;
            letter-spacing: 1px; margin-bottom: 6px; }
        .metric-value { font-size: 1.6rem; font-weight: 700; color: #e6edf3; }
        .metric-value.small { font-size: 1.1rem; }

        /* ---- Verdict card ---- */
        .verdict-card {
            border-radius: 14px; padding: 2rem; text-align: center;
            border: 2px solid; transition: all 0.3s;
        }
        .verdict-label { font-size: 2rem; font-weight: 800; letter-spacing: 1px; }
        .verdict-sub { font-size: 1rem; margin-top: 8px; }

        /* ---- Badges ---- */
        .badge {
            display: inline-block; padding: 3px 12px; border-radius: 20px;
            font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px;
        }
        .badge-CRITICAL { background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid #f85149; }
        .badge-HIGH { background: rgba(219,109,40,0.15); color: #db6d28; border: 1px solid #db6d28; }
        .badge-MEDIUM { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid #d29922; }
        .badge-LOW { background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid #3fb950; }
        .badge-INFO { background: rgba(0,212,255,0.15); color: #00d4ff; border: 1px solid #00d4ff; }

        /* ---- Section headers ---- */
        .section-header {
            font-size: 1.15rem; font-weight: 700; color: #58a6ff;
            border-bottom: 1px solid #1c2535; padding-bottom: 8px; margin-bottom: 12px;
        }

        /* ---- Upload zone ---- */
        .upload-zone {
            border: 2px dashed #2a3548; border-radius: 12px; padding: 2rem;
            text-align: center; transition: border-color 0.3s;
        }
        .upload-zone:hover { border-color: #00d4ff; }

        /* ---- Progress steps ---- */
        .step-done { color: #3fb950; }
        .step-pending { color: #6e7681; }
        .step-current { color: #00d4ff; font-weight: 600; }

        /* ---- Tables ---- */
        .stDataFrame { border-radius: 8px; overflow: hidden; }

        /* ---- Footer ---- */
        .footer { text-align: center; color: #484f58; font-size: 0.75rem;
            margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1c2535; }

        /* ---- Animations ---- */
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .fade-in { animation: fadeIn 0.4s ease-out; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
        .pulse { animation: pulse 2s infinite; }
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
        "Email parsed",
        "Headers analyzed",
        "URLs extracted",
        "Attachments analyzed",
        "IP infrastructure extracted",
        "Threat intelligence checked",
        "Geolocation completed",
        "AI classification completed",
        "Risk score calculated",
        "Forensic timeline generated",
    ]

    progress = st.progress(0, text="Starting analysis...")
    status_text = st.empty()

    for i, label in enumerate(steps):
        pct = int((i / len(steps)) * 100)
        progress.progress(pct, text=f"Analyzing: {label}...")
        status_text.markdown(
            f"<span class='step-current'>Processing: {label}</span>",
            unsafe_allow_html=True,
        )

        if i == 0:
            parsed = parse_email(raw_email)
            set("parsed_email", parsed.to_dict())
        elif i == 1:
            parsed_obj = parse_email(raw_email)
            set("header_findings", analyze_headers(parsed_obj))
        elif i == 2:
            parsed_obj = parse_email(raw_email)
            set("url_results", analyze_urls(parsed_obj.urls))
        elif i == 3:
            parsed_obj = parse_email(raw_email)
            set("attachment_results", analyze_attachments(parsed_obj.attachments))
        elif i == 4:
            parsed_obj = parse_email(raw_email)
            set("ip_results", analyze_ips(parsed_obj.all_ips))
            domains = extract_domains(parsed_obj.body_text or "") + extract_domains(parsed_obj.body_html or "")
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

    progress.progress(100, text="Analysis complete!")
    status_text.empty()
    set("analysis_complete", True)

    # Show completion checklist
    st.markdown("### Analysis Complete")
    for label in steps:
        st.markdown(f":white_check_mark: {label}")


def _run_threat_intel() -> None:
    """Query threat intelligence for all indicators."""
    parsed = get("parsed_email", {})
    ip_results = get("ip_results", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    domain_results = get("domain_results", [])

    ti: list[dict[str, Any]] = []
    public_ips = [r["ip"] for r in ip_results if r.get("is_public")]
    for ip in public_ips[:5]:  # limit to avoid rate limits
        ti.append(check_ip_reputation(ip))
    for u in url_results[:5]:
        ti.append(check_url_reputation(u.get("url", "")))
    for a in attachment_results[:3]:
        ti.append(check_hash_reputation(a.get("sha256", "")))
    for d in domain_results[:3]:
        ti.append(check_domain_reputation(d.get("domain", "")))
    set("threat_intel", ti)


def _run_geolocation() -> None:
    """Geolocate all public IPs."""
    ip_results = get("ip_results", [])
    public_ips = [r["ip"] for r in ip_results if r.get("is_public")]
    geo = geolocate_ips(public_ips[:10])
    set("geo_results", geo)


def _run_ai_classification() -> None:
    """Run the AI classifier."""
    from analyzers.email_parser import parse_email
    raw = st.session_state.get("_raw_email", b"")
    if not raw:
        return
    parsed_obj = parse_email(raw)
    header_findings = get("header_findings", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    threat_intel = get("threat_intel", [])
    ai_result = classify_email(parsed_obj, header_findings, url_results, attachment_results, threat_intel)
    set("ai_result", ai_result)


def _run_risk_score() -> None:
    """Calculate the risk score."""
    ai_result = get("ai_result", {})
    header_findings = get("header_findings", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    threat_intel = get("threat_intel", [])
    risk = calculate_risk(ai_result, header_findings, url_results, attachment_results, threat_intel)
    set("risk_result", risk)


def _run_forensics() -> None:
    """Build evidence and timeline."""
    header_findings = get("header_findings", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])
    ip_results = get("ip_results", [])
    threat_intel = get("threat_intel", [])
    ai_result = get("ai_result", {})
    risk_result = get("risk_result", {})
    parsed = get("parsed_email", {})

    evidence = build_evidence(header_findings, url_results, attachment_results, ip_results, threat_intel, ai_result)
    set("evidence", evidence)

    timeline = build_timeline(
        parsed=parsed,
        ip_results=ip_results,
        url_results=url_results,
        attachment_results=attachment_results,
        threat_intel=threat_intel,
        ai_result=ai_result,
        risk_result=risk_result,
    )
    set("timeline", timeline)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar() -> None:
    """Render the sidebar with branding and investigation status."""
    with st.sidebar:
        st.markdown('<p class="sidebar-title">SIH26106</p>', unsafe_allow_html=True)
        st.markdown('<p class="sidebar-subtitle">Email Threat Detection &amp; Forensic Intelligence</p>', unsafe_allow_html=True)
        st.divider()

        st.markdown("### Navigation")
        st.page_link("app.py", label="Dashboard", icon="🏠")
        st.page_link("pages/1_📊_Dashboard.py", label="Investigation Dashboard", icon="📊")
        st.page_link("pages/2_📧_Email_Analysis.py", label="Email Analysis", icon="📧")
        st.page_link("pages/3_🌐_Threat_Intelligence.py", label="Threat Intelligence", icon="🌐")
        st.page_link("pages/4_🔬_Digital_Forensics.py", label="Digital Forensics", icon="🔬")
        st.page_link("pages/5_📄_Reports.py", label="Reports", icon="📄")

        st.divider()
        st.markdown("### System Status")

        # API status
        vt = bool(os.environ.get("VIRUSTOTAL_API_KEY") or _st_secret("VIRUSTOTAL_API_KEY"))
        abuse = bool(os.environ.get("ABUSEIPDB_API_KEY") or _st_secret("ABUSEIPDB_API_KEY"))
        ipinfo = bool(os.environ.get("IPINFO_TOKEN") or _st_secret("IPINFO_TOKEN"))

        mode = "FULL INTELLIGENCE" if any([vt, abuse, ipinfo]) else "LOCAL ANALYSIS"
        mode_color = "#3fb950" if mode == "FULL INTELLIGENCE" else "#d29922"
        st.markdown(f"**Mode:** <span style='color:{mode_color}'>{mode}</span>", unsafe_allow_html=True)
        st.markdown(f"- VirusTotal: {'✅' if vt else '❌'}")
        st.markdown(f"- AbuseIPDB: {'✅' if abuse else '❌'}")
        st.markdown(f"- IPInfo: {'✅' if ipinfo else '❌'}")

        st.divider()

        if has_investigation():
            st.markdown("### Current Investigation")
            inv_id = get("investigation_id", "N/A")
            st.markdown(f"**ID:** `{inv_id}`")

            risk = get("risk_result", {})
            ai = get("ai_result", {})
            score = risk.get("score", 0)
            level = risk.get("level", "N/A")
            label = ai.get("label", "N/A")

            st.markdown(f"**Risk Score:** <span style='color:{risk_color(level)}'>{score}/100</span>", unsafe_allow_html=True)
            st.markdown(f"**Threat:** <span style='color:{threat_label_color(label)}'>{label}</span>", unsafe_allow_html=True)

            urls = get("url_results", [])
            ips = get("ip_results", [])
            st.markdown(f"**URLs:** {len(urls)}")
            st.markdown(f"**IPs:** {len(ips)}")
        else:
            st.markdown("### No active investigation")
            st.caption("Upload or load a demo email to begin.")

        st.divider()
        st.markdown('<p class="footer">AI Email Intelligence<br>SIH26106 Prototype</p>', unsafe_allow_html=True)


def _st_secret(key: str) -> str:
    """Safely read a Streamlit secret."""
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
        <div class="hero fade-in">
            <h1>AI Email <span>Intelligence</span></h1>
            <p>Analyze suspicious emails, identify malicious infrastructure,
               investigate evidence, and generate explainable forensic intelligence.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Upload + demo section
    col_up, col_demo = st.columns([3, 2])

    with col_up:
        st.markdown('<div class="section-header">Upload Suspicious Email</div>', unsafe_allow_html=True)
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
        st.markdown('<div class="section-header">Demo Investigation</div>', unsafe_allow_html=True)
        st.caption("Load a synthetic sample email to test the platform instantly.")
        dcol1, dcol2, dcol3 = st.columns(3)
        with dcol1:
            if st.button("Benign", use_container_width=True):
                _load_demo("benign.eml")
        with dcol2:
            if st.button("Phishing", use_container_width=True):
                _load_demo("phishing.eml")
        with dcol3:
            if st.button("Suspicious", use_container_width=True):
                _load_demo("suspicious.eml")

        if st.button("Clear Investigation", use_container_width=True):
            reset_session()
            st.rerun()

    # Dashboard content
    if has_investigation():
        st.divider()
        _render_dashboard()
    else:
        st.divider()
        _render_feature_cards()


def _handle_upload(raw: bytes | str) -> None:
    """Handle an uploaded email file."""
    inv_id = generate_investigation_id()
    set("investigation_id", inv_id)
    st.session_state["_raw_email"] = raw
    set("demo_loaded", False)
    run_analysis_pipeline(raw, inv_id)
    st.rerun()


def _load_demo(filename: str) -> None:
    """Load a sample .eml file from the sample_emails directory."""
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


def _render_dashboard() -> None:
    """Render the main dashboard with metrics, verdict, and charts."""
    st.markdown('<div class="section-header fade-in">Investigation Dashboard</div>', unsafe_allow_html=True)

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

    # Metric cards row
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

    # Verdict + Risk gauge
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

    # Charts row
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
    """Render feature overview cards when no investigation is loaded."""
    st.markdown('<div class="section-header">Platform Capabilities</div>', unsafe_allow_html=True)
    features = [
        ("📧", "Email Parsing", "Robust .eml parser with header, body, URL, and attachment extraction."),
        ("🔍", "Header Forensics", "SPF, DKIM, DMARC validation plus spoofing and routing anomaly detection."),
        ("🌐", "URL Analysis", "Passive URL analysis — detects phishing keywords, IP URLs, shorteners, suspicious TLDs."),
        ("🔬", "Attachment Forensics", "SHA-256/MD5 hashing, dangerous extension and double-extension detection."),
        ("📍", "Geolocation", "IP geolocation with API support and offline fallback."),
        ("🛡️", "Threat Intelligence", "VirusTotal, AbuseIPDB integration with local heuristic fallback."),
        ("🤖", "AI Threat Detection", "Hybrid TF-IDF + heuristic classifier with explainable predictions."),
        ("📊", "Risk Scoring", "Weighted 0-100 risk score with transparent component breakdown."),
        ("📋", "Forensic Reports", "JSON, CSV, and HTML investigation reports with evidence and timeline."),
    ]
    cols = st.columns(3)
    for i, (icon, title, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(
                f"""
                <div class="metric-card fade-in" style="margin-bottom:12px;">
                    <div style="font-size:1.8rem;">{icon}</div>
                    <div style="font-size:1rem;font-weight:700;color:#58a6ff;margin:6px 0;">{title}</div>
                    <div style="font-size:0.82rem;color:#8b949e;">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def _metric_card(label: str, value: str, color: str = "#e6edf3") -> None:
    """Render a metric card."""
    st.markdown(
        f"""
        <div class="metric-card fade-in">
            <div class="metric-label">{label}</div>
            <div class="metric-value" style="color:{color};">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _risk_gauge(score: int, level: str) -> None:
    """Render a Plotly risk gauge."""
    import plotly.graph_objects as go

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        number={"suffix": "/100", "font": {"color": "#e6edf3", "size": 28}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#484f58", "tickfont": {"size": 10}},
            "bar": {"color": risk_color(level)},
            "steps": [
                {"range": [0, 25], "color": "rgba(63,185,80,0.15)"},
                {"range": [26, 50], "color": "rgba(210,153,34,0.15)"},
                {"range": [51, 75], "color": "rgba(219,109,40,0.15)"},
                {"range": [76, 100], "color": "rgba(248,81,73,0.15)"},
            ],
            "threshold": {
                "line": {"color": "#e6edf3", "width": 2},
                "thickness": 0.8,
                "value": score,
            },
        },
    ))
    fig.update_layout(
        height=220,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e"},
        margin={"l": 20, "r": 20, "t": 10, "b": 10},
    )
    st.plotly_chart(fig, use_container_width=True)


def _risk_component_chart(risk: dict) -> None:
    """Bar chart of risk component scores."""
    import plotly.graph_objects as go

    components = risk.get("components", {})
    if not components:
        st.info("No risk component data.")
        return

    names = [k.replace("_", " ").title() for k in components]
    raw_scores = [c.get("raw", 0) for c in components.values()]
    weighted = [round(c.get("weighted", 0), 1) for c in components.values()]

    fig = go.Figure()
    fig.add_trace(go.Bar(name="Raw Score", x=names, y=raw_scores, marker_color="#58a6ff"))
    fig.add_trace(go.Bar(name="Weighted", x=names, y=weighted, marker_color="#00d4ff"))
    fig.update_layout(
        barmode="group",
        title="Risk Component Breakdown",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 11},
        height=280,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
    )
    st.plotly_chart(fig, use_container_width=True)


def _evidence_severity_chart(evidence: list[dict]) -> None:
    """Pie chart of evidence by severity."""
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

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        marker={"colors": colors},
        hole=0.4,
    ))
    fig.update_layout(
        title="Evidence Severity Distribution",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 11},
        height=280,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
    )
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

    fig = go.Figure(go.Bar(x=labels, y=values, marker_color=colors))
    fig.update_layout(
        title="URL Severity Distribution",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 11},
        height=280,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
    )
    st.plotly_chart(fig, use_container_width=True)


def _auth_chart(header_findings: list[dict]) -> None:
    """Bar chart of authentication results."""
    import plotly.graph_objects as go

    summary = auth_summary(header_findings)
    if not summary:
        st.info("No authentication data.")
        return

    labels = list(summary.keys())
    results = [summary[l]["result"] for l in labels]
    colors = ["#f85149" if r == "FAIL" else "#3fb950" if r == "PASS" else "#d29922" for r in results]

    fig = go.Figure(go.Bar(x=labels, y=[1] * len(labels), marker_color=colors, text=results, textposition="auto"))
    fig.update_layout(
        title="Authentication Results",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 11},
        height=280,
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        showlegend=False,
        yaxis={"visible": False},
    )
    st.plotly_chart(fig, use_container_width=True)


def _hex_rgb(hex_color: str) -> str:
    """Convert hex color to 'r,g,b' string for rgba."""
    hex_color = hex_color.lstrip("#")
    r, g, b = int(hex_color[:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    return f"{r},{g},{b}"


if __name__ == "__main__":
    main()
