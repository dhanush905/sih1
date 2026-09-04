"""Model manager — loads a trained model if present, else heuristic fallback."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

MODEL_DIR = Path(__file__).resolve().parent.parent / "ml" / "models"


def model_path() -> Path:
    """Return the path to the trained model file."""
    return MODEL_DIR / "email_classifier.joblib"


def model_exists() -> bool:
    """Return True if a trained model is available on disk."""
    return model_path().exists()


def load_model() -> Any:
    """Load the joblib model, or None if unavailable."""
    if not model_exists():
        return None
    try:
        import joblib
        return joblib.load(model_path())
    except Exception:
        return None


def save_model(model: Any) -> None:
    """Persist a model to disk."""
    try:
        import joblib
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, model_path())
    except Exception:
        pass
