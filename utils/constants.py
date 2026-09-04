"""Application-wide constants."""
from __future__ import annotations

SEVERITY_ORDER: list[str] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}

THREAT_LABELS: dict[str, str] = {
    "BENIGN": "#3fb950",
    "SPAM": "#d29922",
    "PHISHING": "#db6d28",
    "MALWARE": "#f85149",
    "SUSPICIOUS": "#a371f7",
}

SUSPICIOUS_TLDS: set[str] = {
    "xyz", "top", "click", "country", "stream", "gq", "tk", "ml",
    "cf", "ga", "work", "date", "racing", "review", "party", "loan",
    "download", "kim", "win", "men", "biz", "info", "zip", "mov",
}

URL_KEYWORDS: set[str] = {
    "login", "verify", "password", "account", "security", "update",
    "payment", "invoice", "authentication", "wallet", "confirm",
    "signin", "unlock", "suspend", "alert", "validate", "reactivate",
    "webscr", "appleid", "paypal", "bank", "secure", "reset",
}

DANGEROUS_EXTENSIONS: set[str] = {
    "exe", "dll", "js", "vbs", "ps1", "bat", "cmd", "scr", "iso",
    "img", "jar", "apk", "com", "pif", "reg", "hta", "cpl", "wsf",
    "msi", "lnk",
}

MACRO_EXTENSIONS: set[str] = {
    "docm", "xlsm", "pptm", "xlsb", "slk",
}

FREE_MAIL_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com", "zoho.com",
    "gmx.com", "yandex.com",
}

SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorte.st", "cutt.ly", "t.ly",
    "rb.gy", "shorturl.at", "tiny.cc",
}

URGENCY_KEYWORDS: set[str] = {
    "urgent", "immediate", "action required", "verify now", "account suspended",
    "confirm immediately", "warning", "alert", "limited time", "expire",
    "suspended", "deactivate", "unusual activity", "security alert",
    "password expired", "account locked", "final notice", "important",
    "critical", "verify your account", "update required",
}

# Risk component weights (must sum to 1.0)
RISK_WEIGHTS: dict[str, float] = {
    "ai_detection": 0.40,
    "header_forensics": 0.20,
    "url_analysis": 0.15,
    "threat_intelligence": 0.15,
    "attachment_analysis": 0.10,
}

# Risk level boundaries
RISK_BOUNDARIES: dict[str, tuple[int, int]] = {
    "LOW": (0, 25),
    "MEDIUM": (26, 50),
    "HIGH": (51, 75),
    "CRITICAL": (76, 100),
}

MAX_UPLOAD_BYTES: int = 10 * 1024 * 1024  # 10 MB
