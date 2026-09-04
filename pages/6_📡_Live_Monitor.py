"""Live Email Monitor — Real-time inbox connection and threat analysis."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, get, set
from utils.helpers import generate_investigation_id, risk_color, threat_label_color
from utils.email_connector import (
    PROVIDER_PRESETS,
    IMAPConnector,
    build_connector,
    EmailSummary,
)
from analyzers.email_parser import parse_email
from analyzers.header_analyzer import analyze_headers
from analyzers.url_analyzer import analyze_urls
from analyzers.attachment_analyzer import analyze_attachments
from analyzers.ip_analyzer import analyze_ips
from analyzers.domain_analyzer import extract_domains, analyze_domains
from ai.classifier import classify_email
from ai.risk_score import calculate_risk
from intelligence.threat_intel import (
    check_ip_reputation, check_hash_reputation,
    check_domain_reputation, check_url_reputation,
)
from intelligence.geolocation import geolocate_ips
from forensics.evidence import build_evidence
from forensics.timeline import build_timeline
from app import inject_css, render_sidebar


# ---------------------------------------------------------------------------
# Session keys for live monitor
# ---------------------------------------------------------------------------
_KEY_CONNECTOR   = "_lm_connector"
_KEY_CONNECTED   = "_lm_connected"
_KEY_PROVIDER    = "_lm_provider"
_KEY_USERNAME    = "_lm_username"
_KEY_MAILBOX     = "_lm_mailbox_info"
_KEY_EMAILS      = "_lm_emails"
_KEY_RESULTS     = "_lm_results"          # list of analysis result dicts
_KEY_AUTO        = "_lm_auto_refresh"
_KEY_LAST_FETCH  = "_lm_last_fetch"
_KEY_FOLDER      = "_lm_folder"


def _conn() -> IMAPConnector | None:
    return st.session_state.get(_KEY_CONNECTOR)


def _is_connected() -> bool:
    return bool(st.session_state.get(_KEY_CONNECTED, False))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    init_session()
    inject_css()
    render_sidebar()

    st.markdown(
        """
        <div class="hero" style="padding-bottom:0.5rem;">
            <div class="hero-eyebrow"><span class="hero-badge">📡 Live Monitor</span></div>
            <h1 class="hero-title" style="font-size:1.5rem;">
                Live Email <span class="cyan">Threat</span> Monitor
            </h1>
            <p class="hero-sub">
                Connect your email account directly for real-time inbox scanning and instant threat analysis.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Top status bar
    _render_status_bar()

    st.write("")

    if not _is_connected():
        _render_connect_panel()
    else:
        _render_monitor_dashboard()


# ---------------------------------------------------------------------------
# Status bar
# ---------------------------------------------------------------------------
def _render_status_bar() -> None:
    if _is_connected():
        info = st.session_state.get(_KEY_MAILBOX, {})
        prov = st.session_state.get(_KEY_PROVIDER, "Unknown")
        user = st.session_state.get(_KEY_USERNAME, "")
        unread = info.get("unread_count", 0)
        total  = info.get("inbox_count", 0)

        col_s, col_u, col_t, col_disc = st.columns([2.5, 1, 1, 0.8])
        with col_s:
            st.markdown(
                f"""
                <div class="metric-card" style="--accent:#10b981;padding:0.8rem 1rem;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <div style="width:10px;height:10px;background:#10b981;border-radius:50%;
                             box-shadow:0 0 8px #10b981;"></div>
                        <div>
                            <div style="font-size:0.75rem;font-weight:700;color:#10b981;">CONNECTED — {prov}</div>
                            <div style="font-size:0.68rem;color:#64748b;">{user}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_u:
            st.markdown(
                f"""
                <div class="metric-card" style="--accent:#f97316;padding:0.8rem 1rem;">
                    <div class="metric-label">Unread</div>
                    <div class="metric-value" style="color:#f97316;font-size:1.4rem;">{unread}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_t:
            results = st.session_state.get(_KEY_RESULTS, [])
            threats = sum(1 for r in results if r.get("label") in ("PHISHING", "SUSPICIOUS"))
            st.markdown(
                f"""
                <div class="metric-card" style="--accent:#ef4444;padding:0.8rem 1rem;">
                    <div class="metric-label">Threats Found</div>
                    <div class="metric-value" style="color:#ef4444;font-size:1.4rem;">{threats}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_disc:
            st.write("")
            if st.button("🔌 Disconnect", use_container_width=True):
                _disconnect()
                st.rerun()
    else:
        st.markdown(
            """
            <div class="metric-card" style="--accent:#64748b;padding:0.8rem 1rem;display:flex;align-items:center;gap:8px;">
                <div style="width:10px;height:10px;background:#475569;border-radius:50%;"></div>
                <div style="font-size:0.78rem;color:#64748b;font-weight:600;">NOT CONNECTED — Configure your email account below</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Connect Panel
# ---------------------------------------------------------------------------
def _render_connect_panel() -> None:
    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">🔌</div>Connect Email Account</div>',
        unsafe_allow_html=True,
    )

    # Provider tiles
    st.caption("Choose your email provider:")
    providers = list(PROVIDER_PRESETS.keys())
    provider_icons = {"Gmail": "🔴", "Outlook / Hotmail": "🔵", "Yahoo Mail": "🟣", "Custom IMAP": "⚙️"}

    pcols = st.columns(len(providers))
    selected = st.session_state.get("_lm_sel_provider", "Gmail")

    for i, prov in enumerate(providers):
        with pcols[i]:
            active = selected == prov
            border = "#6366f1" if active else "#1a2236"
            bg = "rgba(99,102,241,0.08)" if active else "#0d1117"
            icon = provider_icons.get(prov, "📧")
            st.markdown(
                f"""
                <div style="background:{bg};border:2px solid {border};border-radius:12px;
                     padding:16px;text-align:center;cursor:pointer;transition:all 0.2s;">
                    <div style="font-size:1.8rem;">{icon}</div>
                    <div style="font-size:0.78rem;font-weight:700;color:{'#818cf8' if active else '#94a3b8'};
                         margin-top:6px;">{prov}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button(f"Select", key=f"sel_{prov}", use_container_width=True):
                st.session_state["_lm_sel_provider"] = prov
                st.rerun()

    st.write("")
    provider = st.session_state.get("_lm_sel_provider", "Gmail")
    preset = PROVIDER_PRESETS[provider]

    # Help text
    st.markdown(
        f"""
        <div style="background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.2);
             border-radius:10px;padding:12px 16px;margin-bottom:16px;">
            <div style="font-size:0.72rem;font-weight:700;color:#818cf8;margin-bottom:6px;">
                ℹ️ {provider} — Setup Instructions
            </div>
            <div style="font-size:0.78rem;color:#94a3b8;line-height:1.6;">
                {preset['help'].replace(chr(10), '<br>')}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Credentials form
    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">🔑</div>Credentials</div>',
        unsafe_allow_html=True,
    )

    with st.form("connect_form", clear_on_submit=False):
        fc1, fc2 = st.columns(2)
        with fc1:
            username = st.text_input(
                "Email Address",
                placeholder="you@gmail.com",
                help="Your full email address",
            )
        with fc2:
            password = st.text_input(
                "App Password / Password",
                type="password",
                placeholder="••••••••••••••••",
                help="Use an App Password for Gmail/Yahoo/Outlook with MFA enabled",
            )

        if provider == "Custom IMAP":
            hc1, hc2 = st.columns([2, 1])
            with hc1:
                custom_host = st.text_input("IMAP Server", placeholder="imap.yourmail.com")
            with hc2:
                custom_port = st.number_input("Port", value=993, min_value=1, max_value=65535)
        else:
            custom_host = ""
            custom_port = preset["port"]

        folder = st.selectbox("Folder to Monitor", ["INBOX", "Spam", "Junk", "Trash"], index=0)
        limit = st.slider("Emails to fetch", min_value=5, max_value=50, value=20, step=5)

        # Security notice
        st.markdown(
            """
            <div style="background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);
                 border-radius:8px;padding:10px 14px;margin-top:8px;">
                <div style="font-size:0.72rem;color:#10b981;font-weight:600;">🔒 Security Note</div>
                <div style="font-size:0.72rem;color:#64748b;margin-top:3px;">
                    Credentials are stored only in your browser session memory and never written to disk.
                    All connections use SSL/TLS encryption. This app runs locally on your machine.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        submitted = st.form_submit_button("🔌 Connect & Scan Inbox", type="primary", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("Please enter your email address and password.")
            else:
                with st.spinner(f"Connecting to {provider}…"):
                    connector = build_connector(
                        provider=provider,
                        username=username,
                        password=password,
                        custom_host=custom_host,
                        custom_port=int(custom_port),
                    )
                    result = connector.connect()

                if result.success:
                    st.session_state[_KEY_CONNECTOR] = connector
                    st.session_state[_KEY_CONNECTED] = True
                    st.session_state[_KEY_PROVIDER] = provider
                    st.session_state[_KEY_USERNAME] = username
                    st.session_state[_KEY_MAILBOX] = result.mailbox_info
                    st.session_state[_KEY_FOLDER] = folder
                    st.session_state["_lm_fetch_limit"] = limit
                    st.session_state[_KEY_RESULTS] = []
                    st.success(f"✅ Connected! Fetching emails from {folder}…")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error(f"❌ Connection failed: {result.message}")
                    if "Gmail" in provider:
                        st.info("💡 Tip: Make sure you're using an **App Password**, not your Gmail password. "
                                "Go to myaccount.google.com/apppasswords to generate one.")


# ---------------------------------------------------------------------------
# Monitor Dashboard (when connected)
# ---------------------------------------------------------------------------
def _render_monitor_dashboard() -> None:
    connector = _conn()
    if not connector:
        return

    folder = st.session_state.get(_KEY_FOLDER, "INBOX")
    limit  = st.session_state.get("_lm_fetch_limit", 20)

    # Controls bar
    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">🎛️</div>Monitor Controls</div>',
        unsafe_allow_html=True,
    )
    ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([1, 1, 1, 1])
    with ctrl1:
        if st.button("🔄 Refresh Inbox", use_container_width=True):
            _fetch_emails(connector, folder, limit)
            st.rerun()
    with ctrl2:
        emails: list[EmailSummary] = st.session_state.get(_KEY_EMAILS, [])
        unread = [e for e in emails if not e.is_read]
        if st.button(f"⚡ Analyze All Unread ({len(unread)})", use_container_width=True):
            _analyze_multiple(unread, connector)
            st.rerun()
    with ctrl3:
        if st.button("🔍 Analyze All Fetched", use_container_width=True):
            _analyze_multiple(emails, connector)
            st.rerun()
    with ctrl4:
        auto = st.toggle("⏱ Auto-Refresh (60s)", value=st.session_state.get(_KEY_AUTO, False))
        st.session_state[_KEY_AUTO] = auto

    st.write("")

    # Fetch on first load
    if _KEY_EMAILS not in st.session_state or not st.session_state[_KEY_EMAILS]:
        with st.spinner("Fetching emails from inbox…"):
            _fetch_emails(connector, folder, limit)

    emails = st.session_state.get(_KEY_EMAILS, [])
    results: list[dict] = st.session_state.get(_KEY_RESULTS, [])

    # Tabs
    tab_inbox, tab_threats, tab_stats = st.tabs([
        f"📥 Inbox ({len(emails)})",
        f"🚨 Threat Feed ({len(results)})",
        "📊 Live Statistics",
    ])

    with tab_inbox:
        _render_inbox_table(emails, connector)

    with tab_threats:
        _render_threat_feed(results)

    with tab_stats:
        _render_live_stats(results, emails)

    # Auto-refresh
    if st.session_state.get(_KEY_AUTO):
        last = st.session_state.get(_KEY_LAST_FETCH, 0)
        if time.time() - last >= 60:
            _fetch_emails(connector, folder, limit)
            st.rerun()
        remaining = max(0, 60 - int(time.time() - last))
        st.markdown(
            f'<div style="font-size:0.72rem;color:#475569;margin-top:8px;">⏱ Auto-refresh in {remaining}s</div>',
            unsafe_allow_html=True,
        )
        time.sleep(1)
        st.rerun()


# ---------------------------------------------------------------------------
# Inbox Table
# ---------------------------------------------------------------------------
def _render_inbox_table(emails: list[EmailSummary], connector: IMAPConnector) -> None:
    if not emails:
        st.markdown(
            """
            <div class="metric-box" style="padding:2rem;text-align:center;">
                <div style="font-size:2rem;">📭</div>
                <div style="color:#64748b;margin-top:8px;">No emails found. Click Refresh Inbox.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    results_map = {r["uid"]: r for r in st.session_state.get(_KEY_RESULTS, [])}

    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">📥</div>Inbox Emails</div>',
        unsafe_allow_html=True,
    )

    for email_item in emails:
        uid = email_item.uid
        analyzed = results_map.get(uid)

        if analyzed:
            label = analyzed.get("label", "UNKNOWN")
            score = analyzed.get("score", 0)
            level = analyzed.get("level", "INFO")
            lcolor = threat_label_color(label)
            rcolor = risk_color(level)
            verdict_html = f"""
                <span class="badge badge-{'PHISHING' if label=='PHISHING' else 'HIGH' if label=='SUSPICIOUS' else 'LOW'}">{label}</span>
                <span style="font-size:0.72rem;color:{rcolor};font-weight:700;margin-left:6px;">{score}/100</span>
            """
        else:
            verdict_html = '<span style="font-size:0.72rem;color:#475569;">Not analyzed</span>'

        read_indicator = "" if email_item.is_read else "●"
        size_kb = round(email_item.size_bytes / 1024, 1) if email_item.size_bytes else "?"

        # Row container
        row_bg = "rgba(239,68,68,0.04)" if (analyzed and analyzed.get("label") == "PHISHING") else \
                 "rgba(249,115,22,0.04)" if (analyzed and analyzed.get("label") == "SUSPICIOUS") else "#0d1117"
        row_border = ("#ef444430" if (analyzed and analyzed.get("label") == "PHISHING") else
                      "#f9731630" if (analyzed and analyzed.get("label") == "SUSPICIOUS") else "#1a2236")

        with st.container():
            st.markdown(
                f"""
                <div style="background:{row_bg};border:1px solid {row_border};border-radius:10px;
                     padding:10px 14px;margin-bottom:6px;display:flex;align-items:center;gap:12px;">
                    <div style="color:#6366f1;font-size:0.65rem;width:10px;">{read_indicator}</div>
                    <div style="flex:2;min-width:0;">
                        <div style="font-size:0.82rem;font-weight:{'700' if not email_item.is_read else '500'};
                             color:#f8fafc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                            {email_item.subject[:60]}
                        </div>
                        <div style="font-size:0.72rem;color:#64748b;margin-top:2px;">
                            {email_item.sender[:50]} · {email_item.date[:16]}
                        </div>
                    </div>
                    <div style="flex-shrink:0;">{verdict_html}</div>
                    <div style="font-size:0.68rem;color:#475569;flex-shrink:0;">{size_kb} KB</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Analyze button inline
            btn_key = f"analyze_{uid}"
            if st.button(
                "🔍 Analyze" if not analyzed else "✅ Re-Analyze",
                key=btn_key,
                help=f"Analyze email UID {uid}",
            ):
                with st.spinner(f"Fetching & analyzing: {email_item.subject[:40]}…"):
                    raw = connector.fetch_email_raw(uid)
                    if raw:
                        result = _run_quick_analysis(uid, email_item.subject, email_item.sender, raw)
                        results: list = st.session_state.get(_KEY_RESULTS, [])
                        # Replace or append
                        results = [r for r in results if r["uid"] != uid]
                        results.insert(0, result)
                        st.session_state[_KEY_RESULTS] = results
                        st.rerun()
                    else:
                        st.error("Failed to fetch email content.")


# ---------------------------------------------------------------------------
# Threat Feed
# ---------------------------------------------------------------------------
def _render_threat_feed(results: list[dict]) -> None:
    if not results:
        st.markdown(
            """
            <div class="metric-box" style="padding:2rem;text-align:center;">
                <div style="font-size:2rem;">🔍</div>
                <div style="color:#64748b;margin-top:8px;">No emails analyzed yet. Select emails from the Inbox tab.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">🚨</div>Live Threat Feed</div>',
        unsafe_allow_html=True,
    )

    # Alert for critical threats
    critical = [r for r in results if r.get("label") == "PHISHING"]
    if critical:
        st.markdown(
            f"""
            <div style="background:rgba(239,68,68,0.1);border:2px solid rgba(239,68,68,0.4);
                 border-radius:12px;padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;">
                <div style="font-size:1.5rem;">🚨</div>
                <div>
                    <div style="font-size:0.88rem;font-weight:700;color:#ef4444;">
                        {len(critical)} PHISHING EMAIL{'S' if len(critical)>1 else ''} DETECTED
                    </div>
                    <div style="font-size:0.75rem;color:#f87171;margin-top:2px;">
                        Immediate action recommended — do not click links or open attachments.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    for r in results:
        label = r.get("label", "UNKNOWN")
        score = r.get("score", 0)
        level = r.get("level", "INFO")
        lcolor = threat_label_color(label)
        rcolor = risk_color(level)
        confidence = r.get("confidence", 0)

        border = {"PHISHING": "#ef4444", "SUSPICIOUS": "#f97316", "BENIGN": "#10b981"}.get(label, "#475569")
        bg     = {"PHISHING": "rgba(239,68,68,0.06)", "SUSPICIOUS": "rgba(249,115,22,0.04)", "BENIGN": "rgba(16,185,129,0.04)"}.get(label, "transparent")

        with st.expander(f"[{label}] {r.get('subject','(No Subject)')[:70]} — Score: {score}/100"):
            st.markdown(
                f"""
                <div style="background:{bg};border-left:3px solid {border};border-radius:8px;padding:12px 16px;margin-bottom:12px;">
                    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:10px;">
                        <span style="font-size:1.4rem;font-weight:900;color:{lcolor};">{label}</span>
                        <span class="badge badge-{level}">{level} RISK</span>
                        <span style="font-size:0.82rem;color:{rcolor};font-weight:700;">{score}/100</span>
                        <span style="font-size:0.75rem;color:#64748b;">{confidence:.0%} confidence</span>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:0.78rem;">
                        <div><span style="color:#475569;">From:</span> <strong style="color:#e2e8f0;">{r.get('sender','N/A')}</strong></div>
                        <div><span style="color:#475569;">Date:</span> <strong style="color:#e2e8f0;">{r.get('date','N/A')[:16]}</strong></div>
                        <div><span style="color:#475569;">URLs:</span> <strong style="color:#f97316;">{r.get('url_count',0)} detected</strong></div>
                        <div><span style="color:#475569;">Attachments:</span> <strong style="color:#eab308;">{r.get('attachment_count',0)}</strong></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Explanation bullets
            explanation = r.get("explanation", [])
            if explanation:
                st.markdown("**🤖 AI Reasoning:**")
                for exp in explanation[:6]:
                    st.markdown(f"- {exp}")

            # Load into main investigation
            if st.button(f"📊 Load into Full Investigation", key=f"load_{r['uid']}"):
                raw = r.get("raw_bytes", b"")
                if raw:
                    inv_id = generate_investigation_id()
                    set("investigation_id", inv_id)
                    set("demo_loaded", False)
                    st.session_state["_raw_email"] = raw
                    # Store pre-computed results
                    set("parsed_email", r.get("parsed_dict", {}))
                    set("ai_result", {"label": label, "confidence": confidence, "explanation": explanation, "model_mode": "Live IMAP"})
                    set("risk_result", {"score": score, "level": level, "components": {}})
                    set("analysis_complete", True)
                    st.success("✅ Loaded! Navigate to Dashboard to see full investigation.")


# ---------------------------------------------------------------------------
# Live Statistics
# ---------------------------------------------------------------------------
def _render_live_stats(results: list[dict], emails: list[EmailSummary]) -> None:
    import plotly.graph_objects as go

    analyzed = len(results)
    total = len(emails)

    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">📊</div>Live Analysis Statistics</div>',
        unsafe_allow_html=True,
    )

    sc1, sc2, sc3, sc4 = st.columns(4)
    phishing   = sum(1 for r in results if r.get("label") == "PHISHING")
    suspicious = sum(1 for r in results if r.get("label") == "SUSPICIOUS")
    benign     = sum(1 for r in results if r.get("label") == "BENIGN")
    avg_score  = round(sum(r.get("score", 0) for r in results) / max(analyzed, 1))

    with sc1:
        st.markdown(
            f"""<div class="metric-card" style="--accent:#6366f1;">
                <div class="metric-label">Analyzed</div>
                <div class="metric-value" style="color:#6366f1;">{analyzed}<span class="metric-unit">/{total}</span></div>
                <div class="metric-sub">emails scanned</div>
            </div>""", unsafe_allow_html=True,
        )
    with sc2:
        st.markdown(
            f"""<div class="metric-card" style="--accent:#ef4444;">
                <div class="metric-label">Phishing</div>
                <div class="metric-value" style="color:#ef4444;">{phishing}</div>
                <div class="metric-sub">threats detected</div>
            </div>""", unsafe_allow_html=True,
        )
    with sc3:
        st.markdown(
            f"""<div class="metric-card" style="--accent:#f97316;">
                <div class="metric-label">Suspicious</div>
                <div class="metric-value" style="color:#f97316;">{suspicious}</div>
                <div class="metric-sub">flagged emails</div>
            </div>""", unsafe_allow_html=True,
        )
    with sc4:
        st.markdown(
            f"""<div class="metric-card" style="--accent:#10b981;">
                <div class="metric-label">Avg Risk Score</div>
                <div class="metric-value" style="color:#10b981;">{avg_score}<span class="metric-unit">/100</span></div>
            </div>""", unsafe_allow_html=True,
        )

    st.write("")

    if results:
        ch1, ch2 = st.columns(2)
        with ch1:
            counts = {"PHISHING": phishing, "SUSPICIOUS": suspicious, "BENIGN": benign}
            labels = list(counts.keys())
            values = list(counts.values())
            colors = ["#ef4444", "#f97316", "#10b981"]
            fig = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.55,
                marker={"colors": colors}, textinfo="label+value",
                textfont={"color": "#e2e8f0", "size": 11},
            ))
            fig.update_layout(
                title={"text": "Threat Classification", "font": {"color": "#e2e8f0", "size": 13}, "x": 0},
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#8b949e"}, height=280,
                margin={"l": 10, "r": 10, "t": 40, "b": 10},
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)

        with ch2:
            scores = [r.get("score", 0) for r in results]
            subj   = [r.get("subject", "?")[:25] + "…" for r in results]
            bar_colors = [
                "#ef4444" if s >= 75 else "#f97316" if s >= 50 else "#eab308" if s >= 25 else "#10b981"
                for s in scores
            ]
            fig2 = go.Figure(go.Bar(
                x=subj, y=scores, marker_color=bar_colors, marker_line_width=0,
            ))
            fig2.update_layout(
                title={"text": "Risk Scores per Email", "font": {"color": "#e2e8f0", "size": 13}, "x": 0},
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#8b949e", "size": 9}, height=280,
                margin={"l": 20, "r": 10, "t": 40, "b": 60},
                yaxis={"range": [0, 100], "showgrid": True, "gridcolor": "#161d2e", "color": "#64748b"},
                xaxis={"color": "#64748b", "tickangle": -35},
            )
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("Analyze some emails from the Inbox tab to see statistics here.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _fetch_emails(connector: IMAPConnector, folder: str, limit: int) -> None:
    """Fetch email summaries and store in session."""
    emails = connector.fetch_emails(folder=folder, limit=limit, unread_only=False, fetch_raw=False)
    st.session_state[_KEY_EMAILS] = emails
    st.session_state[_KEY_LAST_FETCH] = time.time()
    # Update unread count
    info = st.session_state.get(_KEY_MAILBOX, {})
    info["unread_count"] = sum(1 for e in emails if not e.is_read)
    st.session_state[_KEY_MAILBOX] = info


def _analyze_multiple(emails: list[EmailSummary], connector: IMAPConnector) -> None:
    """Analyze multiple emails with a progress bar."""
    if not emails:
        return
    prog = st.progress(0, text="Analyzing emails…")
    results: list = st.session_state.get(_KEY_RESULTS, [])
    results_map = {r["uid"]: r for r in results}

    for i, em in enumerate(emails):
        prog.progress(int((i / len(emails)) * 100), text=f"Analyzing: {em.subject[:40]}…")
        raw = connector.fetch_email_raw(em.uid)
        if raw:
            result = _run_quick_analysis(em.uid, em.subject, em.sender, raw)
            results_map[em.uid] = result

    prog.progress(100, text="Analysis complete ✓")
    # Sort: threats first
    sorted_results = sorted(
        results_map.values(),
        key=lambda r: (0 if r.get("label") == "PHISHING" else 1 if r.get("label") == "SUSPICIOUS" else 2),
    )
    st.session_state[_KEY_RESULTS] = sorted_results


def _run_quick_analysis(uid: str, subject: str, sender: str, raw: bytes) -> dict:
    """Run the full analysis pipeline on a raw email and return a compact result dict."""
    try:
        parsed_obj = parse_email(raw)
        parsed_dict = parsed_obj.to_dict()

        header_findings = analyze_headers(parsed_obj)
        url_results     = analyze_urls(parsed_obj.urls)
        att_results     = analyze_attachments(parsed_obj.attachments)
        ip_results      = analyze_ips(parsed_obj.all_ips)
        domains         = extract_domains(parsed_obj.body_text or "") + extract_domains(parsed_obj.body_html or "")
        domain_results  = analyze_domains(list(set(domains)))

        # Threat intel (limit to avoid rate limits)
        ti = []
        for ip in [r["ip"] for r in ip_results if r.get("is_public")][:3]:
            ti.append(check_ip_reputation(ip))
        for u in url_results[:3]:
            ti.append(check_url_reputation(u.get("url", "")))

        # Geolocation (fast)
        public_ips = [r["ip"] for r in ip_results if r.get("is_public")]
        geolocate_ips(public_ips[:5])

        ai_result  = classify_email(parsed_obj, header_findings, url_results, att_results, ti)
        risk       = calculate_risk(ai_result, header_findings, url_results, att_results, ti)

        return {
            "uid":              uid,
            "subject":          subject,
            "sender":           sender,
            "date":             parsed_dict.get("date", ""),
            "label":            ai_result.get("label", "UNKNOWN"),
            "score":            risk.get("score", 0),
            "level":            risk.get("level", "INFO"),
            "confidence":       ai_result.get("confidence", 0),
            "explanation":      ai_result.get("explanation", []),
            "url_count":        len(url_results),
            "attachment_count": len(att_results),
            "parsed_dict":      parsed_dict,
            "raw_bytes":        raw,
        }
    except Exception as e:
        return {
            "uid":      uid,
            "subject":  subject,
            "sender":   sender,
            "date":     "",
            "label":    "ERROR",
            "score":    0,
            "level":    "INFO",
            "confidence": 0,
            "explanation": [f"Analysis error: {e}"],
            "url_count": 0,
            "attachment_count": 0,
            "parsed_dict": {},
            "raw_bytes": raw,
        }


def _disconnect() -> None:
    """Safely disconnect and clear all live monitor state."""
    connector = st.session_state.pop(_KEY_CONNECTOR, None)
    if connector:
        try:
            connector.disconnect()
        except Exception:
            pass
    for key in [_KEY_CONNECTED, _KEY_PROVIDER, _KEY_USERNAME, _KEY_MAILBOX,
                _KEY_EMAILS, _KEY_RESULTS, _KEY_AUTO, _KEY_LAST_FETCH, _KEY_FOLDER,
                "_lm_sel_provider", "_lm_fetch_limit"]:
        st.session_state.pop(key, None)


if __name__ == "__main__":
    main()
