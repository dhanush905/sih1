"""Forensic report generation: JSON, CSV, HTML."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any


def generate_json_report(state: dict[str, Any]) -> str:
    """Generate a complete JSON investigation report."""
    report = _build_report_dict(state)
    return json.dumps(report, indent=2, default=str)


def generate_csv_reports(state: dict[str, Any]) -> dict[str, str]:
    """Generate CSV exports for URLs, IPs, evidence, and attachments."""
    return {
        "urls.csv": _list_to_csv(state.get("url_results", [])),
        "ips.csv": _list_to_csv(state.get("ip_results", [])),
        "evidence.csv": _list_to_csv(state.get("evidence", [])),
        "attachments.csv": _list_to_csv(state.get("attachment_results", [])),
    }


def generate_html_report(state: dict[str, Any]) -> str:
    """Generate a professional HTML forensic report."""
    report = _build_report_dict(state)
    return _render_html(report)


def _build_report_dict(state: dict[str, Any]) -> dict[str, Any]:
    """Assemble the full report dictionary."""
    parsed = state.get("parsed_email") or {}
    ai = state.get("ai_result") or {}
    risk = state.get("risk_result") or {}
    return {
        "investigation_id": state.get("investigation_id", "N/A"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "email_summary": {
            "from": parsed.get("from", ""),
            "to": parsed.get("to", ""),
            "subject": parsed.get("subject", ""),
            "date": parsed.get("date", ""),
            "message_id": parsed.get("message_id", ""),
        },
        "threat_classification": {
            "label": ai.get("label", "N/A"),
            "confidence": ai.get("confidence", 0),
            "model_mode": ai.get("model_mode", "N/A"),
            "explanation": ai.get("explanation", []),
        },
        "risk_score": {
            "score": risk.get("score", 0),
            "level": risk.get("level", "N/A"),
            "components": {k: v.get("raw", 0) for k, v in (risk.get("components") or {}).items()},
            "increasing": risk.get("increasing", []),
            "decreasing": risk.get("decreasing", []),
        },
        "header_analysis": state.get("header_findings", []),
        "url_analysis": state.get("url_results", []),
        "ip_analysis": state.get("ip_results", []),
        "geolocation": state.get("geo_results", []),
        "threat_intelligence": state.get("threat_intel", []),
        "attachments": state.get("attachment_results", []),
        "evidence": state.get("evidence", []),
        "forensic_timeline": state.get("timeline", []),
        "recommendations": _recommendations(risk, ai),
        "disclaimer": (
            "This report represents automated forensic analysis and should be validated "
            "by a qualified security analyst before being used as definitive attribution."
        ),
    }


def _recommendations(risk: dict, ai: dict) -> list[str]:
    """Generate recommendations based on the analysis."""
    recs: list[str] = []
    level = (risk.get("level") or "").upper()
    label = (ai.get("label") or "").upper()
    if level in ("HIGH", "CRITICAL"):
        recs.append("Do not interact with any links or attachments in this email.")
        recs.append("Block the sender domain and source IPs at the mail gateway.")
        recs.append("Report this email to your security team or incident response team.")
    if label in ("PHISHING", "MALWARE"):
        recs.append("If any user clicked a link, initiate credential reset and session revocation.")
    if label == "MALWARE":
        recs.append("If any attachment was opened, isolate the affected endpoint and run a full AV scan.")
    if level == "MEDIUM":
        recs.append("Quarantine the email and monitor for similar messages.")
    if level == "LOW":
        recs.append("No immediate action required; monitor for escalation.")
    if not recs:
        recs.append("Email appears benign; no action required.")
    recs.append("Validate findings with a qualified security analyst before attribution.")
    return recs


def _list_to_csv(items: list[dict]) -> str:
    """Convert a list of dicts to CSV string."""
    if not items:
        return ""
    fieldnames = list(dict.fromkeys(k for item in items for k in item.keys()))
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in items:
        writer.writerow(row)
    return buf.getvalue()


def _render_html(report: dict[str, Any]) -> str:
    """Render an HTML forensic report."""
    css = """
    <style>
      body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e1a; color: #e6edf3; margin: 40px; }
      h1 { color: #00d4ff; border-bottom: 2px solid #121826; padding-bottom: 10px; }
      h2 { color: #58a6ff; margin-top: 30px; }
      .card { background: #121826; border-radius: 8px; padding: 16px 24px; margin: 12px 0; }
      .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
      .CRITICAL { background: #f85149; color: #fff; }
      .HIGH { background: #db6d28; color: #fff; }
      .MEDIUM { background: #d29922; color: #000; }
      .LOW { background: #3fb950; color: #000; }
      .INFO { background: #00d4ff; color: #000; }
      table { width: 100%; border-collapse: collapse; margin: 12px 0; }
      th { background: #161b22; color: #58a6ff; padding: 8px; text-align: left; }
      td { padding: 8px; border-bottom: 1px solid #21262d; }
      .disclaimer { background: #1c1c1c; border-left: 4px solid #f85149; padding: 12px 16px; margin-top: 30px; font-style: italic; }
    </style>
    """
    parts = [f"<html><head><meta charset='utf-8'>{css}</head><body>"]
    parts.append(f"<h1>Forensic Investigation Report</h1>")
    parts.append(f"<p><strong>Investigation ID:</strong> {report['investigation_id']}<br>")
    parts.append(f"<strong>Generated:</strong> {report['generated_at']}</p>")

    # Email summary
    es = report["email_summary"]
    parts.append("<div class='card'>")
    parts.append("<h2>Email Summary</h2>")
    parts.append(f"<p><strong>From:</strong> {es['from']}<br><strong>To:</strong> {es['to']}<br>")
    parts.append(f"<strong>Subject:</strong> {es['subject']}<br><strong>Date:</strong> {es['date']}<br>")
    parts.append(f"<strong>Message-ID:</strong> {es['message_id']}</p>")
    parts.append("</div>")

    # Threat verdict
    tc = report["threat_classification"]
    risk = report["risk_score"]
    parts.append("<div class='card'>")
    parts.append("<h2>Threat Verdict</h2>")
    parts.append(f"<p><span class='badge {risk['level']}'>{tc['label']}</span> ")
    parts.append(f"<span class='badge {risk['level']}'>Risk: {risk['score']}/100 ({risk['level']})</span></p>")
    parts.append(f"<p><strong>Confidence:</strong> {tc['confidence']:.0%} | <strong>Model:</strong> {tc['model_mode']}</p>")
    parts.append("</div>")

    # Header analysis
    parts.append("<h2>Header Analysis</h2>")
    parts.append(_table_html(report["header_analysis"], ["finding", "severity", "explanation", "evidence"]))

    # URLs
    parts.append("<h2>URL Analysis</h2>")
    parts.append(_table_html(report["url_analysis"], ["url", "domain", "severity", "is_https", "suspicious_keywords"]))

    # IPs
    parts.append("<h2>IP Analysis</h2>")
    parts.append(_table_html(report["ip_analysis"], ["ip", "classification", "is_public"]))

    # Geolocation
    parts.append("<h2>Geolocation</h2>")
    parts.append(_table_html(report["geolocation"], ["ip", "country", "region", "city", "asn", "org", "source"]))

    # Threat intel
    parts.append("<h2>Threat Intelligence</h2>")
    parts.append(_table_html(report["threat_intelligence"], ["indicator", "type", "source", "reputation", "confidence", "evidence"]))

    # Attachments
    parts.append("<h2>Attachments</h2>")
    parts.append(_table_html(report["attachments"], ["filename", "extension", "mime_type", "size_human", "sha256", "severity"]))

    # Evidence
    parts.append("<h2>Evidence</h2>")
    parts.append(_table_html(report["evidence"], ["id", "type", "finding", "severity", "description"]))

    # Timeline
    parts.append("<h2>Forensic Timeline</h2>")
    parts.append(_table_html(report["forensic_timeline"], ["step", "event", "detail", "timestamp"]))

    # Recommendations
    parts.append("<h2>Recommendations</h2><ul>")
    for r in report["recommendations"]:
        parts.append(f"<li>{r}</li>")
    parts.append("</ul>")

    # Disclaimer
    parts.append(f"<div class='disclaimer'>{report['disclaimer']}</div>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _table_html(items: list[dict], cols: list[str]) -> str:
    """Render a list of dicts as an HTML table."""
    if not items:
        return "<p>No data.</p>"
    parts = ["<table><tr>"]
    for c in cols:
        parts.append(f"<th>{c.replace('_', ' ').title()}</th>")
    parts.append("</tr>")
    for row in items:
        parts.append("<tr>")
        for c in cols:
            val = str(row.get(c, ""))
            if len(val) > 60:
                val = val[:57] + "..."
            sev = str(row.get("severity", "")).upper()
            if c == "severity" and sev:
                parts.append(f"<td><span class='badge {sev}'>{sev}</span></td>")
            else:
                parts.append(f"<td>{val}</td>")
        parts.append("</tr>")
    parts.append("</table>")
    return "".join(parts)
