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
from app import inject_css


def main() -> None:
    init_session()
    inject_css()

    st.markdown(
        '<div class="section-header fade-in">Threat Intelligence</div>',
        unsafe_allow_html=True,
    )

    # Manual lookup section
    st.markdown("### Manual Indicator Lookup")
    st.caption("Enter an IP, domain, URL, or file hash to query available intelligence providers.")

    indicator = st.text_input("Indicator", placeholder="e.g. 45.142.14.92, example.com, https://suspicious.xyz/login")

    qcol1, qcol2 = st.columns([3, 1])
    with qcol1:
        if st.button("Query Indicator", type="primary", use_container_width=True):
            if indicator.strip():
                _run_query(indicator.strip())
            else:
                st.warning("Please enter an indicator.")
    with qcol2:
        detected = _detect_type(indicator) if indicator.strip() else ""
        st.metric("Detected Type", detected)

    st.divider()

    # Investigation results
    if has_investigation():
        _render_investigation_ti()
    else:
        st.info("No active investigation. Upload an email or use manual lookup above.")


def _run_query(indicator: str) -> None:
    """Query a single indicator and display results."""
    with st.spinner("Querying threat intelligence..."):
        result = query_indicator(indicator)

    rep = (result.get("reputation") or "").upper()
    rep_color = {
        "MALICIOUS": "#f85149",
        "SUSPICIOUS": "#db6d28",
        "CLEAN": "#3fb950",
        "UNKNOWN": "#8b949e",
    }.get(rep, "#8b949e")

    st.markdown("### Result")
    r1, r2, r3 = st.columns(3)
    with r1:
        st.metric("Indicator", result.get("indicator", ""))
    with r2:
        st.metric("Type", result.get("type", ""))
    with r3:
        st.markdown(
            f"<div style='text-align:center;padding-top:20px;'><span style='color:{rep_color};font-weight:700;font-size:1.2rem;'>{rep}</span></div>",
            unsafe_allow_html=True,
        )

    st.markdown(f"**Source:** {result.get('source', '')}")
    st.markdown(f"**Confidence:** {result.get('confidence', 0):.0%}")
    st.markdown(f"**Evidence:** {result.get('evidence', '')}")
    st.markdown(f"**Last Checked:** {result.get('last_checked', '')}")

    # Geolocation for IPs
    if result.get("type") == "IP":
        st.markdown("### Geolocation")
        geo = geolocate_ip(indicator)
        g1, g2, g3, g4 = st.columns(4)
        with g1:
            st.metric("Country", geo.get("country", "N/A"))
        with g2:
            st.metric("Region", geo.get("region", "N/A"))
        with g3:
            st.metric("City", geo.get("city", "N/A"))
        with g4:
            st.metric("ASN/Org", f"{geo.get('asn', 'N/A')} / {geo.get('org', 'N/A')}")
        st.caption(f"Source: {geo.get('source', '')}")
        st.caption("Geolocation represents observed network infrastructure, not necessarily the attacker's physical location.")

    if result.get("raw"):
        with st.expander("Raw API Response"):
            st.json(result["raw"])


def _render_investigation_ti() -> None:
    """Display threat intel results from the current investigation."""
    ti = get("threat_intel", [])
    geo = get("geo_results", [])

    st.markdown("### Investigation Threat Intelligence")
    if ti:
        ti_rows = []
        for t in ti:
            ti_rows.append({
                "Indicator": t.get("indicator", "")[:60],
                "Type": t.get("type", ""),
                "Source": t.get("source", ""),
                "Reputation": t.get("reputation", ""),
                "Confidence": f"{t.get('confidence', 0):.0%}",
                "Evidence": t.get("evidence", "")[:80],
            })
        st.dataframe(pd.DataFrame(ti_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No threat intelligence results from investigation.")

    st.divider()
    st.markdown("### Geolocation Results")
    if geo:
        geo_rows = []
        for g in geo:
            geo_rows.append({
                "IP": g.get("ip", ""),
                "Country": g.get("country", "N/A"),
                "Region": g.get("region", "N/A"),
                "City": g.get("city", "N/A"),
                "ASN": g.get("asn", "N/A"),
                "Org": g.get("org", "N/A"),
                "Source": g.get("source", ""),
            })
        st.dataframe(pd.DataFrame(geo_rows), use_container_width=True, hide_index=True)
        st.caption("Geolocation represents observed network infrastructure and not necessarily the attacker's physical location.")
    else:
        st.info("No geolocation data available.")

    # Map
    if geo:
        _render_geo_map(geo)


def _render_geo_map(geo: list[dict]) -> None:
    """Render a Plotly scatter map of geolocated IPs."""
    import plotly.graph_objects as go

    valid = [g for g in geo if g.get("lat") is not None and g.get("lon") is not None]
    if not valid:
        st.info("No mappable geolocation coordinates available (API may be unavailable).")
        return

    lats = [g["lat"] for g in valid]
    lons = [g["lon"] for g in valid]
    labels = [f"{g.get('ip','')} — {g.get('city','')}, {g.get('country','')}" for g in valid]

    fig = go.Figure(go.Scattermapbox(
        lat=lats, lon=lons,
        mode="markers",
        marker={"size": 14, "color": "#f85149"},
        text=labels,
        hoverinfo="text",
    ))
    fig.update_layout(
        mapbox={"style": "carto-darkmatter", "center": {"lat": lats[0], "lon": lons[0]}, "zoom": 2},
        margin={"l": 0, "r": 0, "t": 0, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        height=350,
    )
    st.plotly_chart(fig, use_container_width=True)


if __name__ == "__main__":
    main()
