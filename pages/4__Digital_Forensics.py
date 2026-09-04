"""Digital Forensics page — evidence, timeline, attack chain, infrastructure map."""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from utils.helpers import severity_color
from app import inject_css


def main() -> None:
    init_session()
    inject_css()

    st.markdown(
        '<div class="section-header fade-in">Digital Forensics</div>',
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

    # Evidence cards
    st.markdown("### Evidence")
    if evidence:
        for ev in evidence:
            sev = ev.get("severity", "INFO")
            color = severity_color(sev)
            with st.expander(f"{ev.get('id', '')} — {ev.get('finding', '')} [{sev}]"):
                st.markdown(f"**Type:** {ev.get('type', '')}")
                st.markdown(f"**Severity:** <span class='badge badge-{sev}'>{sev}</span>", unsafe_allow_html=True)
                st.markdown(f"**Description:** {ev.get('description', '')}")
                st.markdown(f"**Evidence:** `{ev.get('evidence', '')}`")
                st.caption(f"Timestamp: {ev.get('timestamp', '')}")
    else:
        st.info("No evidence collected.")

    st.divider()

    # Forensic timeline
    st.markdown("### Forensic Timeline")
    if timeline:
        _render_timeline(timeline)
    else:
        st.info("No timeline data.")

    st.divider()

    # Attack chain
    st.markdown("### Attack Chain")
    _render_attack_chain(parsed, ip_results, url_results, attachment_results)

    st.divider()

    # Infrastructure map
    st.markdown("### Infrastructure Map")
    _render_infra_map(geo)


def _render_timeline(timeline: list[dict]) -> None:
    """Render a vertical timeline visualization."""
    import plotly.graph_objects as go

    events = [t.get("event", "") for t in timeline]
    details = [t.get("detail", "") for t in timeline]
    steps = list(range(1, len(timeline) + 1))

    fig = go.Figure(go.Scatter(
        x=[1] * len(steps), y=steps,
        mode="markers+text",
        text=events,
        textposition="middle right",
        textfont={"color": "#e6edf3", "size": 12},
        marker={"size": 16, "color": "#00d4ff", "line": {"width": 2, "color": "#0a0e1a"}},
        hovertext=details,
        hoverinfo="text",
    ))
    fig.update_layout(
        xaxis={"visible": False, "range": [0.5, 1.5]},
        yaxis={"autorange": "reversed", "showgrid": False, "zeroline": False,
               "tickfont": {"color": "#8b949e"}},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=max(300, len(timeline) * 45),
        margin={"l": 20, "r": 200, "t": 10, "b": 10},
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Also show as table
    with st.expander("Timeline Details"):
        for t in timeline:
            st.markdown(f"**Step {t.get('step', '')}:** {t.get('event', '')} — {t.get('detail', '')}")


def _render_attack_chain(parsed: dict, ip_results: list, url_results: list, attachments: list) -> None:
    """Render the attack chain as a visual flow."""
    from_addr = parsed.get("from", "Unknown")
    public_ips = [r["ip"] for r in ip_results if r.get("is_public")]
    ip_str = ", ".join(public_ips[:3]) if public_ips else "None"
    url_str = ", ".join(u.get("domain", "") for u in url_results[:3]) if url_results else "None"
    att_str = ", ".join(a.get("filename", "") for a in attachments[:3]) if attachments else "None"

    chain = [
        ("Sender", from_addr),
        ("Mail Server", parsed.get("return_path", "N/A")),
        ("Source IP", ip_str),
        ("Domains", url_str),
        ("URLs", url_str),
        ("Attachments", att_str),
        ("Threat Intelligence", "See TI page"),
    ]

    chain_html = '<div style="display:flex;flex-direction:column;gap:8px;">'
    for i, (label, value) in enumerate(chain):
        chain_html += f"""
        <div class="metric-card" style="padding:10px 16px;">
            <span style="color:#00d4ff;font-weight:700;">{label}</span>
            <span style="color:#8b949e;margin:0 8px;">→</span>
            <span style="color:#e6edf3;">{value}</span>
        </div>
        """
        if i < len(chain) - 1:
            chain_html += '<div style="text-align:center;color:#484f58;font-size:1.2rem;">↓</div>'
    chain_html += "</div>"
    st.markdown(chain_html, unsafe_allow_html=True)


def _render_infra_map(geo: list[dict]) -> None:
    """Render infrastructure map of public IPs."""
    import plotly.graph_objects as go

    valid = [g for g in geo if g.get("lat") is not None and g.get("lon") is not None]
    if not valid:
        st.info("No mappable infrastructure coordinates available (geolocation API may be unavailable).")
        st.caption("In LOCAL ANALYSIS mode, geolocation coordinates are not available without an API key.")
        return

    lats = [g["lat"] for g in valid]
    lons = [g["lon"] for g in valid]
    labels = [f"{g.get('ip','')} — {g.get('city','')}, {g.get('country','')}" for g in valid]

    fig = go.Figure(go.Scattermapbox(
        lat=lats, lon=lons,
        mode="markers",
        marker={"size": 16, "color": "#f85149", "line": {"width": 2, "color": "#fff"}},
        text=labels,
        hoverinfo="text",
    ))
    fig.update_layout(
        mapbox={"style": "carto-darkmatter", "center": {"lat": lats[0], "lon": lons[0]}, "zoom": 2},
        margin={"l": 0, "r": 0, "t": 0, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        height=400,
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption("Observed infrastructure geolocation — not necessarily the attacker's physical location.")


if __name__ == "__main__":
    main()
