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
from app import inject_css


def main() -> None:
    init_session()
    inject_css()

    st.markdown(
        '<div class="section-header fade-in">Forensic Reports</div>',
        unsafe_allow_html=True,
    )

    if not has_investigation():
        st.warning("No active investigation. Please upload or load a demo email from the main page.")
        st.page_link("app.py", label="Go to Dashboard", icon="🏠")
        return

    inv_id = get("investigation_id", "N/A")
    st.markdown(f"**Investigation ID:** `{inv_id}`")

    # Build the full state dict for report generation
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

    # Report preview
    st.markdown("### Report Summary")

    risk = state["risk_result"]
    ai = state["ai_result"]
    score = risk.get("score", 0)
    level = risk.get("level", "N/A")
    label = ai.get("label", "N/A")

    scol1, scol2, scol3 = st.columns(3)
    with scol1:
        st.metric("Threat Classification", label)
    with scol2:
        st.metric("Risk Score", f"{score}/100 ({level})")
    with scol3:
        st.metric("Evidence Items", str(len(state["evidence"])))

    st.divider()

    # Download buttons
    st.markdown("### Download Reports")

    json_report = generate_json_report(state)
    html_report = generate_html_report(state)
    csv_reports = generate_csv_reports(state)

    dcol1, dcol2, dcol3 = st.columns(3)
    with dcol1:
        st.download_button(
            label="Download JSON Report",
            data=json_report,
            file_name=f"forensic_report_{inv_id}.json",
            mime="application/json",
            use_container_width=True,
        )
    with dcol2:
        st.download_button(
            label="Download HTML Report",
            data=html_report.encode("utf-8"),
            file_name=f"forensic_report_{inv_id}.html",
            mime="text/html",
            use_container_width=True,
        )
    with dcol3:
        # Combine CSVs into one file
        combined_csv = "\n\n".join(f"# {name}\n{content}" for name, content in csv_reports.items())
        st.download_button(
            label="Download CSV Reports",
            data=combined_csv,
            file_name=f"forensic_report_{inv_id}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.divider()

    # Individual CSV downloads
    st.markdown("### Individual CSV Exports")
    csv_cols = st.columns(len(csv_reports))
    for i, (name, content) in enumerate(csv_reports.items()):
        with csv_cols[i]:
            st.download_button(
                label=f"Download {name}",
                data=content,
                file_name=name,
                mime="text/csv",
                use_container_width=True,
            )

    st.divider()

    # HTML preview
    st.markdown("### HTML Report Preview")
    with st.expander("View HTML Report"):
        st.components.v1.html(html_report, height=600, scrolling=True)

    # JSON preview
    with st.expander("View JSON Report"):
        st.code(json_report, language="json")

    # Disclaimer
    st.divider()
    st.warning(
        "This report represents automated forensic analysis and should be validated "
        "by a qualified security analyst before being used as definitive attribution."
    )


if __name__ == "__main__":
    main()
