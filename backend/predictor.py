"""
PhishGuard AI — Prediction Service
=====================================
Provides:
  • load_model()         — loads the trained joblib pipeline
  • predict_url(url)     — classifies a URL
  • explain_prediction() — returns human-readable risk indicators
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from backend.config import METADATA_PATH, METRICS_PATH, MODEL_PATH
from backend.features import (
    FEATURE_NAMES,
    extract_url_features,
    features_to_vector,
    get_risk_indicators,
)

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# Module-level singletons (loaded once, reused per request)
# ──────────────────────────────────────────────────────────────────────────
_model = None
_metadata: dict | None = None
_metrics: dict | None = None

DISCLAIMER = (
    "This is a machine-learning estimate based on URL structure only. "
    "It is not a guarantee of safety. New or targeted phishing attacks may "
    "evade the model. Always verify important sites through official channels."
)


# ──────────────────────────────────────────────────────────────────────────
# Model loading
# ──────────────────────────────────────────────────────────────────────────

class ModelNotFoundError(FileNotFoundError):
    pass


class PredictionError(RuntimeError):
    pass


def load_model(force_reload: bool = False) -> Any:
    """
    Load (or reload) the trained sklearn pipeline from disk.
    Returns the pipeline object.  Raises ModelNotFoundError if absent.
    """
    global _model, _metadata, _metrics

    if _model is not None and not force_reload:
        return _model

    if not MODEL_PATH.exists():
        raise ModelNotFoundError(
            f"Model file not found at '{MODEL_PATH}'. "
            "Please run 'python -m backend.train_model' first."
        )

    log.info("Loading model from %s …", MODEL_PATH)
    _model = joblib.load(MODEL_PATH)

    if METADATA_PATH.exists():
        with open(METADATA_PATH) as f:
            _metadata = json.load(f)
        # Validate feature alignment
        saved_features = _metadata.get("feature_names", [])
        if saved_features and saved_features != FEATURE_NAMES:
            log.warning(
                "Feature name mismatch between model metadata and current "
                "features.py. Re-training is recommended. "
                "Saved: %s | Current: %s",
                saved_features, FEATURE_NAMES,
            )

    if METRICS_PATH.exists():
        with open(METRICS_PATH) as f:
            _metrics = json.load(f)

    log.info("Model loaded: %s", _metadata.get("model_name") if _metadata else "unknown")
    return _model


def get_metadata() -> dict:
    """Return model metadata dict; load if needed."""
    if _metadata is None:
        load_model()
    return _metadata or {}


def get_saved_metrics() -> dict:
    """Return saved evaluation metrics; load if needed."""
    if _metrics is None:
        load_model()
    return _metrics or {}


def model_is_available() -> bool:
    """True if the model file exists and can be loaded."""
    try:
        load_model()
        return True
    except (ModelNotFoundError, Exception):
        return False


# ──────────────────────────────────────────────────────────────────────────
# Input validation
# ──────────────────────────────────────────────────────────────────────────

import urllib.parse as _urlparse
import re as _re

_ALLOWED_SCHEMES = {"http", "https", "ftp", "ftps"}
_MAX_URL_LEN = 2048


def validate_url(url: str) -> tuple[bool, str]:
    """
    Lightweight URL validation.
    Returns (is_valid, error_message).
    Does NOT visit the URL.
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string."

    url = url.strip()
    if len(url) > _MAX_URL_LEN:
        return False, f"URL exceeds maximum allowed length ({_MAX_URL_LEN} chars)."

    # Reject dangerous schemes early — before adding http:// prefix.
    # URLs like `javascript:alert(1)` or `data:text/html,...` contain ":" but
    # not "://" and would otherwise get "http://" prepended, becoming a
    # seemingly-valid URL that then crashes during port parsing.
    _colon_pos = url.find(":")
    if _colon_pos > 0 and "://" not in url:
        _candidate_scheme = url[:_colon_pos].lower()
        if _candidate_scheme not in _ALLOWED_SCHEMES:
            return False, f"URL scheme '{_candidate_scheme}' is not supported. Use http or https."

    # Add scheme if missing for parsing
    test_url = url if "://" in url else "http://" + url

    try:
        parsed = _urlparse.urlparse(test_url)
    except Exception:
        return False, "URL could not be parsed."

    if not parsed.netloc:
        return False, "URL does not contain a valid hostname."

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, f"URL scheme '{scheme}' is not supported. Use http or https."

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "URL has an empty hostname."

    # Reject obviously invalid hostnames
    if hostname.startswith(".") or hostname.endswith("."):
        return False, "Hostname starts or ends with a dot."

    return True, ""


# ──────────────────────────────────────────────────────────────────────────
# Risk scoring
# ──────────────────────────────────────────────────────────────────────────

def _map_risk_level(score: float, prediction_label: int) -> str:
    """
    Derive a qualitative risk level from model probability and prediction.
    Thresholds chosen conservatively (prefer catching phishing).
    """
    if prediction_label == 0:          # model says phishing
        if score >= 0.80:
            return "CRITICAL"
        elif score >= 0.60:
            return "HIGH"
        else:
            return "MEDIUM"
    else:                               # model says legitimate
        if score <= 0.30:
            return "LOW"
        elif score <= 0.50:
            return "LOW"
        else:
            return "LOW"


# ──────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Validate → extract features → classify URL.

    Returns a dict with fields:
      url, prediction, risk_level, score, score_type,
      indicators, features, disclaimer, error (on failure)
    """
    # ── 1. Validate ─────────────────────────────────────────────────────
    is_valid, err_msg = validate_url(url)
    if not is_valid:
        return {
            "url": url,
            "error": err_msg,
            "prediction": None,
        }

    # ── 2. Load model ───────────────────────────────────────────────────
    try:
        pipe = load_model()
    except ModelNotFoundError as exc:
        return {
            "url": url,
            "error": str(exc),
            "prediction": None,
        }

    # ── 3. Feature extraction ────────────────────────────────────────────
    feat_dict = extract_url_features(url)
    feature_vector = np.array(features_to_vector(feat_dict)).reshape(1, -1)

    # ── 4. Prediction ────────────────────────────────────────────────────
    try:
        pred_label = int(pipe.predict(feature_vector)[0])
    except Exception as exc:
        log.error("Prediction failed: %s", exc)
        raise PredictionError(f"Model prediction failed: {exc}") from exc

    prediction_str = "PHISHING" if pred_label == 0 else "LIKELY LEGITIMATE"

    # ── 5. Score / probability ───────────────────────────────────────────
    score: float | None = None
    score_type: str = "unavailable"

    try:
        probas = pipe.predict_proba(feature_vector)[0]
        # probas[0] = P(phishing), probas[1] = P(legitimate)
        if pred_label == 0:
            score = float(probas[0])        # confidence in phishing
        else:
            score = float(probas[1])        # confidence in legitimate
        score_type = "model_probability"
    except Exception:
        # Some models (e.g. SVM without probability=True) don't have predict_proba
        score = None
        score_type = "unavailable"

    # ── 6. Risk level ────────────────────────────────────────────────────
    effective_score = score if score is not None else (0.7 if pred_label == 0 else 0.3)
    risk_level = _map_risk_level(effective_score, pred_label)

    # ── 7. Indicators ────────────────────────────────────────────────────
    indicators = get_risk_indicators(feat_dict)

    # ── 8. Return structured result ──────────────────────────────────────
    return {
        "url": url,
        "prediction": prediction_str,
        "risk_level": risk_level,
        "score": round(score, 4) if score is not None else None,
        "score_type": score_type,
        "indicators": indicators,
        "features": {name: round(float(val), 6) for name, val in feat_dict.items()},
        "disclaimer": DISCLAIMER,
    }


def explain_prediction(url: str) -> dict:
    """
    Return the same result as predict_url() — included as a named alias
    for API clarity.  Indicators are derived from actual extracted features.
    """
    return predict_url(url)
