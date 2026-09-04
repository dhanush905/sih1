"""Session-state helpers for persisting investigation data across pages."""
from __future__ import annotations

from typing import Any

import streamlit as st


def init_session() -> None:
    """Initialise default session keys if absent."""
    defaults: dict[str, Any] = {
        "investigation_id": None,
        "parsed_email": None,
        "header_findings": [],
        "url_results": [],
        "attachment_results": [],
        "ip_results": [],
        "domain_results": [],
        "threat_intel": [],
        "geo_results": [],
        "ai_result": {},
        "risk_result": {},
        "evidence": [],
        "timeline": [],
        "analysis_complete": False,
        "demo_loaded": False,
        "current_demo": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def reset_session() -> None:
    """Clear all investigation data."""
    for key in list(st.session_state.keys()):
        if key in ("__page__",):
            continue
        # keep streamlit-internal keys
        if key.startswith("_"):
            continue
        del st.session_state[key]
    init_session()


def get(key: str, default: Any = None) -> Any:
    """Return a session value or default."""
    return st.session_state.get(key, default)


def set(key: str, value: Any) -> None:
    """Set a session value."""
    st.session_state[key] = value


def has_investigation() -> bool:
    """Return True if an investigation is loaded."""
    return bool(st.session_state.get("analysis_complete"))
