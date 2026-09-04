"""Hybrid AI threat classifier: TF-IDF + Logistic Regression with heuristic fallback."""
from __future__ import annotations

import os
from typing import Any

import numpy as np

from .features import extract_features
from .model_manager import load_model, model_exists
from analyzers.email_parser import ParsedEmail
from utils.constants import URGENCY_KEYWORDS


def classify_email(
    parsed: ParsedEmail,
    header_findings: list[dict],
    url_results: list[dict],
    attachment_results: list[dict],
    threat_intel: list[dict],
) -> dict[str, Any]:
    """Classify an email and return label, confidence, probabilities, explanation."""
    features = extract_features(parsed, header_findings, url_results, attachment_results, threat_intel)

    if model_exists():
        try:
            return _classify_with_model(parsed, features)
        except Exception:
            pass

    return _heuristic_classify(parsed, features)


def _classify_with_model(parsed: ParsedEmail, features: dict) -> dict[str, Any]:
    """Use a trained scikit-learn model if available."""
    model = load_model()
    if model is None:
        return _heuristic_classify(parsed, features)

    # Build text feature
    text = f"{parsed.subject or ''} {parsed.body_text or ''}"
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba([text])[0]
            classes = list(model.classes_)
            label = classes[int(np.argmax(probs))]
            confidence = float(max(probs))
            prob_dict = {classes[i]: float(probs[i]) for i in range(len(classes))}
        else:
            label = model.predict([text])[0]
            confidence = 0.80
            prob_dict = {str(label): confidence}
    except Exception:
        return _heuristic_classify(parsed, features)

    return {
        "label": str(label).upper(),
        "confidence": round(confidence, 4),
        "probabilities": {k: round(v, 4) for k, v in prob_dict.items()},
        "explanation": _model_explanation(features),
        "model_mode": "Trained ML model (TF-IDF + classifier)",
    }


def _heuristic_classify(parsed: ParsedEmail, features: dict) -> dict[str, Any]:
    """Deterministic rule-based fallback classifier."""
    score = 0
    reasons: list[str] = []

    # Authentication failures
    if features.get("spf_fail"):
        score += 15
        reasons.append("SPF failure")
    if features.get("dmarc_fail"):
        score += 15
        reasons.append("DMARC failure")
    if features.get("dkim_fail"):
        score += 10
        reasons.append("DKIM failure")
    if features.get("missing_auth"):
        score += 15
        reasons.append("No authentication headers")

    # Spoofing
    if features.get("reply_to_mismatch"):
        score += 15
        reasons.append("Reply-To mismatch")
    if features.get("return_path_mismatch"):
        score += 5
        reasons.append("Return-Path mismatch")

    # URLs
    if features.get("has_ip_url"):
        score += 15
        reasons.append("IP-based URL")
    if features.get("num_suspicious_urls", 0) >= 2:
        score += 20
        reasons.append("Multiple suspicious URLs")
    elif features.get("num_suspicious_urls", 0) == 1:
        score += 10
        reasons.append("Suspicious URL detected")
    if features.get("has_suspicious_tld"):
        score += 10
        reasons.append("Suspicious TLD")
    if features.get("has_shortener"):
        score += 5
        reasons.append("URL shortener")

    # Attachments
    if features.get("dangerous_attachment"):
        score += 25
        reasons.append("Dangerous attachment extension")
    if features.get("macro_attachment"):
        score += 15
        reasons.append("Macro-enabled attachment")
    if features.get("double_extension"):
        score += 20
        reasons.append("Double extension")

    # Body / subject
    if features.get("subject_urgency"):
        score += 10
        reasons.append("Urgency in subject")
    if features.get("urgency_in_body"):
        score += 10
        reasons.append("Urgency language in body")
    if features.get("suspicious_keyword_count", 0) >= 4:
        score += 15
        reasons.append("High count of phishing keywords")
    elif features.get("suspicious_keyword_count", 0) >= 2:
        score += 8
        reasons.append("Phishing keywords present")

    # Threat intel
    if features.get("threat_intel_malicious", 0) > 0:
        score += 20
        reasons.append("Threat intelligence: malicious indicator")
    elif features.get("threat_intel_hits", 0) > 0:
        score += 10
        reasons.append("Threat intelligence: suspicious indicator")

    score = min(score, 100)

    # Label mapping
    if score >= 70:
        label = "PHISHING" if not features.get("dangerous_attachment") else "MALWARE"
    elif score >= 45:
        label = "SUSPICIOUS"
    elif score >= 25:
        label = "SPAM"
    else:
        label = "BENIGN"

    confidence = min(0.98, 0.50 + score / 200.0)

    # rough probability distribution
    probs = {
        "BENIGN": 0.0,
        "SPAM": 0.0,
        "PHISHING": 0.0,
        "MALWARE": 0.0,
        "SUSPICIOUS": 0.0,
    }
    probs[label] = confidence
    remainder = 1.0 - confidence
    for other in probs:
        if other != label:
            probs[other] = round(remainder / 4, 4)
    probs[label] = round(confidence, 4)

    return {
        "label": label,
        "confidence": round(confidence, 4),
        "probabilities": probs,
        "explanation": reasons,
        "model_mode": "Heuristic fallback (no trained model)",
    }


def _model_explanation(features: dict) -> list[str]:
    """Return top contributing features for model mode."""
    reasons = []
    if features.get("spf_fail"):
        reasons.append("SPF failure")
    if features.get("dmarc_fail"):
        reasons.append("DMARC failure")
    if features.get("reply_to_mismatch"):
        reasons.append("Reply-To mismatch")
    if features.get("has_ip_url"):
        reasons.append("IP-based URL")
    if features.get("num_suspicious_urls", 0) > 0:
        reasons.append(f"{features['num_suspicious_urls']} suspicious URL(s)")
    if features.get("dangerous_attachment"):
        reasons.append("Dangerous attachment")
    if features.get("urgency_in_body"):
        reasons.append("Urgency language in body")
    if features.get("threat_intel_malicious", 0) > 0:
        reasons.append("Threat intel: malicious")
    return reasons or ["No strong indicators"]
