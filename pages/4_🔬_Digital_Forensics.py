"""Digital Forensics page — evidence, timeline, attack chain, infrastructure map."""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from utils.helpers import severity_color
from app import inject_css, render_sidebar


def main() -> None:
    init_session()
    inject_css()
    render_sidebar()

    st.markdown(
        """
        <div class="hero" style="padding-bottom:0.5rem;">
            <div class="hero-eyebrow"><span class="hero-badge">🔬 Forensics</span></div>
            <h1 class="hero-title" style="font-size:1.5rem;">Digital Forensics</h1>
            <p class="hero-sub">Digital forensics analysis and incident reconstruction.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not has_investigation():
        st.warning("No active investigation. Please upload or load a demo email from the main page.")
        st.page_link("app.py", label="Go to Dashboard", icon="🏠")
        return

    parsed = get("parsed_email", {})
    evidence = get("evidence", [])
    timeline = get("timeline", [])
    ip_results = get("ip_results", [])
    geo = get("geo_results", [])
    url_results = get("url_results", [])
    attachment_results = get("attachment_results", [])

    tab_chain, tab_map, tab_timeline, tab_graph = st.tabs([
        "⛓️ Attack Chain", "🗺️ Infrastructure Map", "🕐 Timeline", "🔗 Evidence Graph"
    ])

    # ---- ATTACK CHAIN ----
    with tab_chain:
        col_c1, col_c2 = st.columns([1.05, 1])
        with col_c1:
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">⛓️</div>Attack Chain Reconstruction</div>',
                unsafe_allow_html=True,
            )
            _render_attack_chain(parsed, ip_results, url_results, attachment_results)

        with col_c2:
            st.markdown(
                '<div class="section-hdr"><div class="section-hdr-icon">🔗</div>Evidence Network Graph</div>',
                unsafe_allow_html=True,
            )
            _render_evidence_graph()

    # ---- INFRA MAP ----
    with tab_map:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">🗺️</div>Infrastructure Geolocation Map</div>',
            unsafe_allow_html=True,
        )
        _render_infra_map(geo)

    # ---- TIMELINE ----
    with tab_timeline:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">🕐</div>Chronological Forensic Timeline</div>',
            unsafe_allow_html=True,
        )
        if timeline:
            _render_timeline(timeline)
        else:
            st.info("No timeline data available.")

    # ---- EVIDENCE ----
    with tab_graph:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📋</div>Evidence List &amp; Graph</div>',
            unsafe_allow_html=True,
        )
        _render_evidence_cards(evidence)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _render_attack_chain(parsed: dict, ip_results: list, url_results: list, attachments: list) -> None:
    """Render the attack chain node list matching the reference UI."""
    from_addr = parsed.get("from", "security@secure-login.verify")
    public_ips = [r["ip"] for r in ip_results if r.get("is_public")]
    ip_str = public_ips[0] if public_ips else "192.0.2.1"
    url_str = url_results[0].get("url", "https://secure-login.verify/login") if url_results else "https://secure-login.verify/login"
    att_str = attachments[0].get("filename", "invoice.pdf.exe") if attachments else "No attachment"

    nodes = [
        ("📤", "Sender", from_addr, "Normal", "#3b82f6", False),
        ("🖥️", "Mail Server", parsed.get("return_path", f"mail.{ip_str}"), "Normal", "#6366f1", False),
        ("🌍", "Source IP", ip_str, "High Risk", "#ef4444", True),
        ("🔗", "Domain", "secure-login.verify", "High Risk", "#ef4444", True),
        ("🌐", "URL", url_str[:60] + ("…" if len(url_str) > 60 else ""), "High Risk", "#ef4444", True),
        ("📎", "Attachment", att_str, "Suspicious", "#eab308", False),
        ("🛡️", "Threat Intelligence", "Multiple sources flagged", "High Risk", "#ef4444", True),
    ]

    for icon, label, val, risk_tag, col, is_high in nodes:
        badge = f'<span class="badge badge-{"CRITICAL" if is_high else "MEDIUM"}">{risk_tag}</span>' if risk_tag != "Normal" else ""
        connector = '<div style="width:2px;height:12px;background:linear-gradient(#253347,#253347);margin:0 auto;"></div>'
        st.markdown(
            f"""
            <div class="metric-box" style="margin-bottom:4px;padding:10px 14px;display:flex;
                 justify-content:space-between;align-items:center;border-left:3px solid {col};">
                <div style="display:flex;align-items:center;gap:10px;">
                    <div style="font-size:1.1rem;">{icon}</div>
                    <div>
                        <div style="font-size:0.68rem;color:#475569;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;">{label}</div>
                        <div style="font-size:0.8rem;color:#e2e8f0;font-weight:500;margin-top:1px;word-break:break-all;">{val}</div>
                    </div>
                </div>
                <div>{badge}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_evidence_graph() -> None:
    """Render an interactive evidence network diagram."""
    import numpy as np
    import plotly.graph_objects as go

    angles = np.linspace(0, 2 * np.pi, 7, endpoint=False)
    x_outer = list(np.cos(angles))
    y_outer = list(np.sin(angles))
    x_all = x_outer + [0]
    y_all = y_outer + [0]

    labels = ["Sender", "Mail Server", "Source IP", "Domain", "URL", "Attachment", "Threat Intel", "Email"]
    sizes = [20, 20, 28, 24, 24, 22, 26, 32]
    colors = ["#6366f1", "#3b82f6", "#ef4444", "#f97316", "#ef4444", "#eab308", "#ef4444", "#10b981"]

    edge_x, edge_y = [], []
    for i in range(7):
        edge_x.extend([x_outer[i], 0, None])
        edge_y.extend([y_outer[i], 0, None])

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line={"color": "#1e293b", "width": 1.5}, hoverinfo="none",
    ))
    fig.add_trace(go.Scatter(
        x=x_all, y=y_all, mode="markers+text",
        text=labels, textposition="bottom center",
        textfont={"color": "#94a3b8", "size": 10},
        marker={
            "size": sizes, "color": colors,
            "line": {"width": 2, "color": "#0d1117"},
            "opacity": 0.9,
        },
        hoverinfo="text",
    ))
    fig.update_layout(
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"visible": False, "range": [-1.5, 1.5]},
        yaxis={"visible": False, "range": [-1.5, 1.5]},
        height=400, margin={"l": 10, "r": 10, "t": 10, "b": 30},
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_timeline(timeline: list[dict]) -> None:
    """Render a vertical forensic timeline."""
    import plotly.graph_objects as go

    events = [t.get("event", "") for t in timeline]
    details = [t.get("detail", "") for t in timeline]
    steps = list(range(1, len(timeline) + 1))

    fig = go.Figure(go.Scatter(
        x=[1] * len(steps), y=steps,
        mode="markers+text",
        text=events, textposition="middle right",
        textfont={"color": "#e2e8f0", "size": 12},
        marker={"size": 14, "color": "#6366f1", "line": {"width": 2, "color": "#0d1117"}},
        hovertext=details, hoverinfo="text",
    ))
    fig.update_layout(
        xaxis={"visible": False, "range": [0.5, 2]},
        yaxis={"autorange": "reversed", "showgrid": False, "zeroline": False, "tickfont": {"color": "#64748b"}},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e"},
        height=max(350, len(timeline) * 50),
        margin={"l": 20, "r": 220, "t": 10, "b": 20},
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_evidence_cards(evidence: list[dict]) -> None:
    """Render evidence card list."""
    if evidence:
        for ev in evidence:
            sev = ev.get("severity", "INFO")
            col = severity_color(sev)
            with st.expander(f"[{sev}] {ev.get('id','')} — {ev.get('finding','')}"):
                st.markdown(
                    f"""
                    <div style="display:flex;gap:8px;margin-bottom:8px;">
                        <span class="badge badge-{sev}">{sev}</span>
                        <span style="font-size:0.75rem;color:#64748b;">Type: <strong style="color:#94a3b8;">{ev.get('type','')}</strong></span>
                    </div>
                    <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:6px;">{ev.get('description','')}</div>
                    <code style="font-size:0.75rem;color:#38bdf8;">{ev.get('evidence','')}</code>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        st.info("No evidence collected.")


def _render_infra_map(geo: list[dict]) -> None:
    """Render a world map of infrastructure."""
    import plotly.graph_objects as go

    valid = [g for g in geo if g.get("lat") is not None and g.get("lon") is not None]
    if not valid:
        st.markdown(
            """
            <div class="metric-box" style="padding:1.5rem;text-align:center;">
                <div style="font-size:2rem;margin-bottom:8px;">🗺️</div>
                <div style="color:#64748b;font-size:0.85rem;">No mappable coordinates available.<br>
                Geolocation API may be unavailable. Add IPINFO_TOKEN to .env for live data.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    lats = [g["lat"] for g in valid]
    lons = [g["lon"] for g in valid]
    labels = [f"{g.get('ip','?')} — {g.get('city','?')}, {g.get('country','?')}" for g in valid]

    fig = go.Figure(go.Scattergeo(
        lat=lats, lon=lons, mode="markers",
        marker={"size": 16, "color": "#ef4444", "line": {"width": 2, "color": "#fff"}, "opacity": 0.9},
        text=labels, hoverinfo="text",
    ))
    fig.update_layout(
        geo={
            "projection_type": "equirectangular",
            "showland": True, "landcolor": "#1a2236",
            "showocean": True, "oceancolor": "#0d1117",
            "showframe": False, "showcountries": True, "countrycolor": "#253347",
            "bgcolor": "rgba(0,0,0,0)",
        },
        paper_bgcolor="rgba(0,0,0,0)",
        margin={"l": 0, "r": 0, "t": 0, "b": 0},
        height=420,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Detail cards
    gcols = st.columns(min(len(valid), 3))
    for i, g in enumerate(valid[:3]):
        with gcols[i]:
            st.markdown(
                f"""
                <div class="metric-card" style="--accent:#ef4444;">
                    <div class="metric-label">IP Infrastructure</div>
                    <div class="metric-value" style="color:#ef4444;font-size:1rem;">{g.get('ip','N/A')}</div>
                    <div class="metric-sub">{g.get('city','?')}, {g.get('country','?')}</div>
                    <div style="font-size:0.72rem;color:#475569;margin-top:4px;">{g.get('org','N/A')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


if __name__ == "__main__":
    main()
