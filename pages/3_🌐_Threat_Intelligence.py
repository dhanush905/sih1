"""Threat Intelligence page — manual indicator lookup + investigation results."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from utils.helpers import severity_color
from intelligence.threat_intel import query_indicator, _detect_type
from intelligence.geolocation import geolocate_ip
from app import inject_css, render_sidebar


def main() -> None:
    init_session()
    inject_css()
    render_sidebar()

    st.markdown(
        """
        <div class="hero" style="padding-bottom:0.5rem;">
            <div class="hero-eyebrow"><span class="hero-badge">🌐 Intelligence</span></div>
            <h1 class="hero-title" style="font-size:1.5rem;">Threat Intelligence</h1>
            <p class="hero-sub">Lookup and analyze threats using multiple intelligence sources.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_lookup, tab_bulk, tab_feeds = st.tabs([
        "🔍 Indicator Lookup", "📦 Bulk Lookup", "📡 Threat Feeds"
    ])

    # ---- INDICATOR LOOKUP ----
    with tab_lookup:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">🔍</div>Enter Indicator</div>',
            unsafe_allow_html=True,
        )
        scol1, scol2, scol3 = st.columns([3, 1.2, 0.9])
        with scol1:
            indicator = st.text_input(
                "Indicator",
                placeholder="IP, Domain, URL, or Hash (e.g. malicious-site.com, 45.142.14.92)",
                label_visibility="collapsed",
            )
        with scol2:
            itype = st.selectbox("Type", ["Auto-detect", "IP", "Domain", "URL", "Hash"], label_visibility="collapsed")
        with scol3:
            st.write("")
            query_btn = st.button("🔍 Lookup", type="primary", use_container_width=True)

        if query_btn and indicator.strip():
            _run_query(indicator.strip())
        elif not indicator.strip():
            _render_demo_lookup_result("malicious-site.com")

        st.divider()

        if has_investigation():
            _render_investigation_ti()
        else:
            st.info("No active investigation. Upload an email or perform a lookup above.")

    # ---- BULK LOOKUP ----
    with tab_bulk:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📦</div>Bulk Indicator Analysis</div>',
            unsafe_allow_html=True,
        )
        st.caption("Upload a list of indicators (one per line) for batch threat intelligence query.")
        bulk_text = st.text_area(
            "Indicators",
            height=150,
            placeholder="45.142.14.92\nmalicious-site.com\nhttp://evil-phish.xyz/login",
            label_visibility="collapsed",
        )
        if st.button("🚀 Run Bulk Analysis", type="primary"):
            lines = [l.strip() for l in bulk_text.splitlines() if l.strip()]
            if lines:
                with st.spinner(f"Processing {len(lines)} indicators…"):
                    bulk_results = [query_indicator(i) for i in lines[:10]]
                st.success(f"✅ Processed {len(bulk_results)} indicators.")
                st.dataframe(pd.DataFrame(bulk_results), use_container_width=True, hide_index=True)
            else:
                st.warning("Please enter at least one indicator.")

    # ---- THREAT FEEDS ----
    with tab_feeds:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📡</div>Active Threat Intelligence Feeds</div>',
            unsafe_allow_html=True,
        )
        st.caption("Real-time telemetry and feed sync status.")

        feeds = [
            {"Feed Name": "VirusTotal Intelligence", "Type": "Multi-Engine AV", "Status": "🟢 Active", "Confidence": "High", "Sources": "70+"},
            {"Feed Name": "AbuseIPDB IP Reputation", "Type": "IP Abuse Reports", "Status": "🟢 Active", "Confidence": "High", "Sources": "3M+"},
            {"Feed Name": "URLhaus Phishing DB", "Type": "URL Telemetry", "Status": "🟢 Active", "Confidence": "High", "Sources": "250K+"},
            {"Feed Name": "PhishTank Verified Feeds", "Type": "Phishing URLs", "Status": "🟢 Active", "Confidence": "Medium", "Sources": "2M+"},
            {"Feed Name": "Local Heuristic Engine", "Type": "Static Analysis", "Status": "🟢 Active", "Confidence": "High", "Sources": "Local"},
        ]

        for f in feeds:
            st.markdown(
                f"""
                <div class="metric-box" style="display:flex;justify-content:space-between;
                     align-items:center;padding:12px 16px;margin-bottom:8px;">
                    <div>
                        <div style="font-size:0.88rem;font-weight:700;color:#f8fafc;">{f['Feed Name']}</div>
                        <div style="font-size:0.72rem;color:#64748b;margin-top:2px;">{f['Type']} · {f['Sources']} sources</div>
                    </div>
                    <div style="display:flex;gap:8px;align-items:center;">
                        <span class="badge badge-LOW">{f['Confidence']}</span>
                        <span style="font-size:0.8rem;">{f['Status']}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def _run_query(indicator: str) -> None:
    """Run a single indicator lookup and display results."""
    with st.spinner(f"Querying threat intelligence for `{indicator}`…"):
        result = query_indicator(indicator)
        detected_type = _detect_type(indicator)

    # Geo data for IPs
    geo = None
    if detected_type == "ip":
        geo = geolocate_ip(indicator)

    _render_lookup_result(indicator, result, detected_type, geo)


def _render_demo_lookup_result(indicator: str) -> None:
    """Show a static demo lookup result to match the reference UI."""
    st.markdown(
        '<div class="section-hdr" style="margin-top:8px;"><div class="section-hdr-icon">📊</div>Lookup Results</div>',
        unsafe_allow_html=True,
    )

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(
            """
            <div class="metric-card" style="--accent:#ef4444;">
                <div class="metric-label">Reputation Score</div>
                <div class="metric-value" style="color:#ef4444;">85 <span class="metric-unit">/100</span></div>
                <div class="metric-sub"><span class="badge badge-HIGH">Malicious</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            """
            <div class="metric-card" style="--accent:#f97316;">
                <div class="metric-label">Sources</div>
                <div class="metric-value" style="color:#f97316;">8 <span class="metric-unit">/10</span></div>
                <div class="metric-sub" style="color:#ef4444;">Flagged</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            """
            <div class="metric-card" style="--accent:#64748b;">
                <div class="metric-label">First Seen</div>
                <div class="metric-value" style="color:#94a3b8;font-size:1rem;">2024-05-20</div>
                <div class="metric-sub">10:35:48</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with m4:
        st.markdown(
            """
            <div class="metric-card" style="--accent:#38bdf8;">
                <div class="metric-label">Last Seen</div>
                <div class="metric-value" style="color:#38bdf8;font-size:1rem;">2024-05-26</div>
                <div class="metric-sub">Recently</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")
    col_cats, col_sources = st.columns([1, 1])
    with col_cats:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">🏷️</div>Threat Categories</div>',
            unsafe_allow_html=True,
        )
        cats_html = "".join([
            '<span class="badge badge-PHISHING" style="margin:3px;">Phishing</span>',
            '<span class="badge badge-HIGH" style="margin:3px;">Malware</span>',
            '<span class="badge badge-CRITICAL" style="margin:3px;">Command &amp; Control</span>',
        ])
        st.markdown(f'<div style="padding:10px 0;">{cats_html}</div>', unsafe_allow_html=True)

    with col_sources:
        st.markdown(
            '<div class="section-hdr"><div class="section-hdr-icon">📊</div>Top Sources</div>',
            unsafe_allow_html=True,
        )
        _sources_bar_chart()

    # Demo geolocation
    st.markdown(
        '<div class="section-hdr" style="margin-top:8px;"><div class="section-hdr-icon">📍</div>Geolocation (192.0.2.1)</div>',
        unsafe_allow_html=True,
    )
    gcol, dcol = st.columns([1.3, 0.9])
    with gcol:
        _demo_geo_map()
    with dcol:
        st.markdown(
            """
            <div class="metric-box" style="padding:1.2rem;">
                <div class="section-hdr" style="border:none;padding:0;margin-bottom:12px;">Location Details</div>
                <div style="display:flex;flex-direction:column;gap:7px;font-size:0.8rem;">
                    <div><span style="color:#475569;width:80px;display:inline-block;">Country</span><strong style="color:#e2e8f0;">United States</strong></div>
                    <div><span style="color:#475569;width:80px;display:inline-block;">Region</span><strong style="color:#e2e8f0;">New York</strong></div>
                    <div><span style="color:#475569;width:80px;display:inline-block;">City</span><strong style="color:#e2e8f0;">New York</strong></div>
                    <div><span style="color:#475569;width:80px;display:inline-block;">Org</span><strong style="color:#e2e8f0;">Example ISP LLC</strong></div>
                    <div><span style="color:#475569;width:80px;display:inline-block;">ASN</span><strong style="color:#e2e8f0;">AS12345</strong></div>
                    <div><span style="color:#475569;width:80px;display:inline-block;">Latitude</span><strong style="color:#e2e8f0;">40.71B</strong></div>
                    <div><span style="color:#475569;width:80px;display:inline-block;">Longitude</span><strong style="color:#e2e8f0;">-74.006</strong></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_lookup_result(indicator: str, result: dict, detected_type: str, geo: dict | None) -> None:
    """Display a live lookup result."""
    st.markdown(
        f'<div class="section-hdr"><div class="section-hdr-icon">📊</div>Lookup Results — <code style="color:#38bdf8;">{indicator}</code></div>',
        unsafe_allow_html=True,
    )

    score = result.get("reputation_score", 0)
    threat = result.get("threat_level", "INFO")
    color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#10b981"}.get(threat, "#64748b")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(
            f"""<div class="metric-card" style="--accent:{color};">
                <div class="metric-label">Reputation Score</div>
                <div class="metric-value" style="color:{color};">{score} <span class="metric-unit">/100</span></div>
                <div class="metric-sub"><span class="badge badge-{threat}">{threat}</span></div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f"""<div class="metric-card" style="--accent:#f97316;">
                <div class="metric-label">Detected Type</div>
                <div class="metric-value" style="color:#f97316;font-size:1.1rem;">{detected_type.upper()}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m3:
        cats = result.get("categories", [])
        st.markdown(
            f"""<div class="metric-card" style="--accent:#64748b;">
                <div class="metric-label">Categories</div>
                <div class="metric-value" style="color:#94a3b8;font-size:1.1rem;">{len(cats)}</div>
                <div class="metric-sub">{', '.join(cats[:2]) or 'None detected'}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with m4:
        conf = result.get("confidence", "N/A")
        st.markdown(
            f"""<div class="metric-card" style="--accent:#38bdf8;">
                <div class="metric-label">Confidence</div>
                <div class="metric-value" style="color:#38bdf8;font-size:1.1rem;">{conf}</div>
            </div>""",
            unsafe_allow_html=True,
        )

    if cats:
        cats_html = "".join(f'<span class="badge badge-HIGH" style="margin:3px;">{c}</span>' for c in cats)
        st.markdown(
            f'<div style="margin-top:12px;">{cats_html}</div>',
            unsafe_allow_html=True,
        )

    if result.get("raw_detail"):
        with st.expander("📄 Raw Intelligence Detail"):
            st.json(result.get("raw_detail", {}))

    if geo and geo.get("lat"):
        st.markdown(
            f'<div class="section-hdr" style="margin-top:16px;"><div class="section-hdr-icon">📍</div>Geolocation — {indicator}</div>',
            unsafe_allow_html=True,
        )
        _render_geo(geo)


def _render_investigation_ti() -> None:
    """Show threat intelligence from active investigation."""
    ti = get("threat_intel", [])
    if not ti:
        st.info("No threat intelligence data in this investigation.")
        return

    st.markdown(
        '<div class="section-hdr"><div class="section-hdr-icon">🔬</div>Investigation Threat Intelligence</div>',
        unsafe_allow_html=True,
    )
    df_rows = []
    for t in ti:
        df_rows.append({
            "Indicator": t.get("indicator", ""),
            "Type": t.get("type", ""),
            "Threat Level": t.get("threat_level", "INFO"),
            "Score": t.get("reputation_score", 0),
            "Confidence": t.get("confidence", ""),
            "Categories": ", ".join(t.get("categories", [])) or "None",
        })
    if df_rows:
        st.dataframe(pd.DataFrame(df_rows), use_container_width=True, hide_index=True)


def _sources_bar_chart() -> None:
    """Mini bar chart of threat source hits."""
    import plotly.graph_objects as go

    sources = ["VirusTotal", "URLhaus", "PhishTank", "AbuseIPDB"]
    values = [65, 51, 33, 22]
    colors = ["#6366f1", "#3b82f6", "#10b981", "#f97316"]

    fig = go.Figure(go.Bar(
        x=values, y=sources, orientation="h",
        marker_color=colors, marker_line_width=0,
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8b949e", "size": 10},
        height=180, margin={"l": 10, "r": 10, "t": 5, "b": 10},
        showlegend=False,
    )
    fig.update_xaxes(showgrid=True, gridcolor="#161d2e", color="#64748b")
    fig.update_yaxes(showgrid=False, color="#94a3b8")
    st.plotly_chart(fig, use_container_width=True)


def _demo_geo_map() -> None:
    """Demo Plotly world map with a marker."""
    import plotly.graph_objects as go

    fig = go.Figure(go.Scattergeo(
        lat=[40.712], lon=[-74.006], mode="markers",
        marker={"size": 14, "color": "#ef4444", "line": {"width": 2, "color": "#fff"}},
        text=["192.0.2.1 — New York, US"],
    ))
    fig.update_layout(
        geo={
            "projection_type": "equirectangular",
            "showland": True, "landcolor": "#1a2236",
            "showocean": True, "oceancolor": "#0d1117",
            "showframe": False, "showcountries": True,
            "countrycolor": "#253347",
            "bgcolor": "rgba(0,0,0,0)",
        },
        paper_bgcolor="rgba(0,0,0,0)",
        margin={"l": 0, "r": 0, "t": 0, "b": 0},
        height=200,
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_geo(geo: dict) -> None:
    """Render geolocation map and details for a live lookup."""
    import plotly.graph_objects as go

    gcol, dcol = st.columns([1.3, 0.9])
    with gcol:
        fig = go.Figure(go.Scattergeo(
            lat=[geo["lat"]], lon=[geo["lon"]], mode="markers",
            marker={"size": 14, "color": "#ef4444", "line": {"width": 2, "color": "#fff"}},
            text=[f"{geo.get('ip','?')} — {geo.get('city','?')}, {geo.get('country','?')}"],
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
            margin={"l": 0, "r": 0, "t": 0, "b": 0}, height=200,
        )
        st.plotly_chart(fig, use_container_width=True)

    with dcol:
        rows_html = ""
        for k, v in [
            ("Country", geo.get("country", "N/A")),
            ("Region", geo.get("region", "N/A")),
            ("City", geo.get("city", "N/A")),
            ("Org", geo.get("org", "N/A")),
            ("ASN", geo.get("asn", "N/A")),
            ("Latitude", geo.get("lat", "N/A")),
            ("Longitude", geo.get("lon", "N/A")),
        ]:
            rows_html += f'<div style="margin-bottom:5px;font-size:0.8rem;"><span style="color:#475569;width:80px;display:inline-block;">{k}</span><strong style="color:#e2e8f0;">{v}</strong></div>'
        st.markdown(
            f'<div class="metric-box" style="padding:1rem;">{rows_html}</div>',
            unsafe_allow_html=True,
        )


if __name__ == "__main__":
    main()
