"""Email Analysis page — summary, authentication, URLs, attachments, IPs."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.session import init_session, has_investigation, get
from utils.helpers import severity_color, truncate
from analyzers.header_analyzer import auth_summary
from app import inject_css


def main() -> None:
    init_session()
    inject_css()

    st.markdown(
        '<div class="section-header fade-in">Email Analysis</div>',
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

    # Email Summary
    st.markdown("### Email Summary")
    scol1, scol2 = st.columns(2)
    with scol1:
        st.markdown(f"**From:** {parsed.get('from', 'N/A')}")
        st.markdown(f"**To:** {parsed.get('to', 'N/A')}")
        st.markdown(f"**CC:** {parsed.get('cc', 'N/A')}")
        st.markdown(f"**Subject:** {parsed.get('subject', 'N/A')}")
    with scol2:
        st.markdown(f"**Date:** {parsed.get('date', 'N/A')}")
        st.markdown(f"**Message-ID:** `{parsed.get('message_id', 'N/A')}`")
        st.markdown(f"**Reply-To:** {parsed.get('reply_to', 'N/A')}")
        st.markdown(f"**Return-Path:** {parsed.get('return_path', 'N/A')}")

    st.divider()

    # Authentication table
    st.markdown("### Authentication Results")
    summary = auth_summary(header_findings)
    if summary:
        auth_rows = []
        for check, data in summary.items():
            auth_rows.append({
                "Check": check,
                "Result": data["result"],
                "Severity": data["severity"],
            })
        df_auth = pd.DataFrame(auth_rows)
        st.dataframe(df_auth, use_container_width=True, hide_index=True)
    else:
        st.info("No authentication headers found.")

    st.divider()

    # Header findings
    st.markdown("### Header Forensic Findings")
    if header_findings:
        for f in header_findings:
            sev = f.get("severity", "INFO")
            color = severity_color(sev)
            with st.expander(f"{f.get('finding', 'Unknown')} — {sev}"):
                st.markdown(f"**Severity:** <span class='badge badge-{sev}'>{sev}</span>", unsafe_allow_html=True)
                st.markdown(f"**Explanation:** {f.get('explanation', '')}")
                st.markdown(f"**Evidence:** `{truncate(f.get('evidence', ''), 300)}`")
    else:
        st.info("No header findings.")

    st.divider()

    # URLs
    st.markdown("### URLs Detected")
    if url_results:
        url_rows = []
        for u in url_results:
            url_rows.append({
                "URL": truncate(u.get("url", ""), 80),
                "Domain": u.get("domain", ""),
                "HTTPS": "Yes" if u.get("is_https") else "No",
                "IP URL": "Yes" if u.get("is_ip") else "No",
                "Length": u.get("length", 0),
                "Suspicious TLD": "Yes" if u.get("suspicious_tld") else "No",
                "Shortener": "Yes" if u.get("is_shortener") else "No",
                "Keywords": ", ".join(u.get("suspicious_keywords", [])),
                "Severity": u.get("severity", "INFO"),
            })
        df_urls = pd.DataFrame(url_rows)
        st.dataframe(df_urls, use_container_width=True, hide_index=True)
    else:
        st.info("No URLs detected in this email.")

    st.divider()

    # Attachments
    st.markdown("### Attachments")
    if attachment_results:
        att_rows = []
        for a in attachment_results:
            att_rows.append({
                "Filename": a.get("filename", ""),
                "Extension": a.get("extension", ""),
                "MIME": a.get("mime_type", ""),
                "Size": a.get("size_human", ""),
                "SHA-256": a.get("sha256", "")[:32] + "...",
                "Dangerous": "Yes" if a.get("is_dangerous") else "No",
                "Macro": "Yes" if a.get("is_macro") else "No",
                "Double Ext": "Yes" if a.get("double_extension") else "No",
                "Severity": a.get("severity", "INFO"),
            })
        df_att = pd.DataFrame(att_rows)
        st.dataframe(df_att, use_container_width=True, hide_index=True)
    else:
        st.info("No attachments in this email.")

    st.divider()

    # IP Infrastructure
    st.markdown("### IP Infrastructure")
    if ip_results:
        ip_rows = []
        for ip in ip_results:
            ip_rows.append({
                "IP": ip.get("ip", ""),
                "Classification": ip.get("classification", ""),
                "Public": "Yes" if ip.get("is_public") else "No",
                "Version": ip.get("version", ""),
            })
        df_ips = pd.DataFrame(ip_rows)
        st.dataframe(df_ips, use_container_width=True, hide_index=True)
    else:
        st.info("No IPs detected.")

    # Body preview
    st.divider()
    st.markdown("### Email Body Preview")
    body_text = parsed.get("body_text", "")
    if body_text:
        st.text(truncate(body_text, 2000))
    else:
        st.caption("No plain-text body.")
    if parsed.get("body_html"):
        with st.expander("View HTML body"):
            st.code(truncate(parsed["body_html"], 3000), language="html")


if __name__ == "__main__":
    main()
