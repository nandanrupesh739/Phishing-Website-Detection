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

from backend.config import METADATA_PATH, METRICS_PATH, MODEL_PATH, MODELS_DIR
from backend.features import (
    FEATURE_NAMES,
    canonical_url_string,
    extract_url_features,
    features_to_vector,
    get_risk_indicators,
    normalise_url,
)

log = logging.getLogger(__name__)

MODEL_PKL_PATH = MODELS_DIR / "model.pkl"

# ──────────────────────────────────────────────────────────────────────────
# Module-level singletons (loaded once, reused per request)
# ──────────────────────────────────────────────────────────────────────────
_model = None
_scaler = None
_vectorizer = None
_bundle: dict | None = None
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
    Load (or reload) the trained model/bundle from disk.
    Checks models/model.pkl first, falling back to phishguard_model.joblib.
    Returns the model or pipeline object. Raises ModelNotFoundError if absent.
    """
    global _model, _scaler, _vectorizer, _bundle, _metadata, _metrics

    if _model is not None and not force_reload:
        return _model

    target_path = MODEL_PKL_PATH if MODEL_PKL_PATH.exists() else MODEL_PATH
    if not target_path.exists():
        raise ModelNotFoundError(
            f"Model file not found at '{MODEL_PKL_PATH}' or '{MODEL_PATH}'. "
            "Please run 'python train.py' first."
        )

    # Ensure target_path is restricted exclusively to project models directory
    try:
        target_path.resolve().relative_to(MODELS_DIR.resolve())
    except ValueError:
        raise PermissionError(
            f"Security violation: Model file '{target_path}' is outside approved '{MODELS_DIR}' directory."
        )

    log.info("Loading model from %s …", target_path)
    loaded = joblib.load(target_path)

    if isinstance(loaded, dict) and "model" in loaded:
        _bundle = loaded
        _model = loaded["model"]
        _scaler = loaded.get("scaler")
        _vectorizer = loaded.get("vectorizer")
    else:
        _bundle = None
        _model = loaded
        _scaler = getattr(loaded, "named_steps", {}).get("scaler") if hasattr(loaded, "named_steps") else None
        _vectorizer = getattr(loaded, "named_steps", {}).get("tfidf") if hasattr(loaded, "named_steps") else None

    if METADATA_PATH.exists():
        with open(METADATA_PATH, encoding="utf-8") as f:
            _metadata = json.load(f)
        # Validate feature alignment
        saved_features = _metadata.get("feature_names", [])
        if saved_features and saved_features != FEATURE_NAMES and _vectorizer is None:
            log.warning(
                "Feature name mismatch between model metadata and current "
                "features.py. Re-training is recommended. "
                "Saved: %s | Current: %s",
                saved_features, FEATURE_NAMES,
            )

    if METRICS_PATH.exists():
        with open(METRICS_PATH, encoding="utf-8") as f:
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
    except ModelNotFoundError as exc:
        log.info("Model not available: %s", exc)
        return False
    except (AttributeError, KeyError, ValueError, EOFError, ImportError, OSError, PermissionError) as exc:
        log.error("Failed to load model file due to corrupted format: %s", exc)
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

    # Reject invalid port numbers (e.g. host:abc or host:99999)
    try:
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            return False, "URL contains an invalid port number (must be between 1 and 65535)."
    except (ValueError, OverflowError):
        return False, "URL contains an invalid port number."

    return True, ""


# ──────────────────────────────────────────────────────────────────────────
# Risk scoring
# ──────────────────────────────────────────────────────────────────────────

def _map_risk_level(score: float, prediction_label: int | str) -> str:
    """
    Derive a qualitative risk level from model probability and prediction.
    Prediction label: 1 / 'PHISHING' = threat, 0 / 'SAFE' = safe.
    Thresholds chosen conservatively (prefer catching phishing).
    """
    if prediction_label in (1, "PHISHING", "phishing"):
        if score >= 0.80:
            return "CRITICAL"
        elif score >= 0.60:
            return "HIGH"
        else:
            return "MEDIUM"
    else:  # SAFE
        return "LOW"


def _extract_top_contributions(model, scaler, vectorizer, X_input, top_k: int = 8) -> list[dict]:
    """
    Extract top contributing features using Tree SHAP values (for LightGBM/XGBoost/tree models)
    or coefficient x value (for linear models).
    Returns list of dicts: [{"feature": str, "contribution": float, "direction": "PHISHING"|"SAFE"}].
    """
    if model is None:
        return []

    try:
        estimators = []
        if hasattr(model, "calibrated_classifiers_"):
            for clf in model.calibrated_classifiers_:
                base = getattr(clf, "estimator", getattr(clf, "base_estimator", None))
                if base is not None:
                    estimators.append(base)
        else:
            estimators.append(model)

        if not estimators:
            return []

        contrib_list = []
        for est in estimators:
            if hasattr(est, "booster_") and hasattr(est.booster_, "predict"):
                c = est.booster_.predict(X_input, pred_contrib=True)
                if hasattr(c, "toarray"):
                    c = c.toarray()
                contrib_list.append(np.asarray(c)[0])
            elif hasattr(est, "coef_"):
                coef = np.asarray(est.coef_)
                if hasattr(X_input, "toarray"):
                    x_arr = X_input.toarray()[0]
                else:
                    x_arr = np.asarray(X_input)[0]
                c = coef[0] * x_arr
                contrib_list.append(c)

        if not contrib_list:
            return []

        mean_contrib = np.mean(contrib_list, axis=0)
        # Tree SHAP appends expected value (bias) at the end; linear models don't
        expected_len = len(FEATURE_NAMES) + (len(vectorizer.get_feature_names_out()) if vectorizer is not None and hasattr(vectorizer, "get_feature_names_out") else 0)
        if len(mean_contrib) > expected_len:
            mean_contrib = mean_contrib[:-1]

        fnames = list(FEATURE_NAMES)
        if vectorizer is not None and hasattr(vectorizer, "get_feature_names_out"):
            fnames += [f"n-gram '{w}'" for w in vectorizer.get_feature_names_out()]

        if len(mean_contrib) != len(fnames):
            limit = min(len(mean_contrib), len(fnames))
            mean_contrib = mean_contrib[:limit]
            fnames = fnames[:limit]

        top_idx = np.argsort(np.abs(mean_contrib))[::-1][:top_k]
        results = []
        for idx in top_idx:
            val = float(mean_contrib[idx])
            if abs(val) < 0.001:
                continue
            results.append({
                "feature": fnames[idx],
                "contribution": round(val, 4),
                "direction": "PHISHING" if val > 0 else "SAFE",
            })
        return results
    except Exception as exc:
        log.warning("Feature contribution calculation failed: %s", exc)
        return []


# ──────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Validate → extract features → classify URL as 'SAFE' or 'PHISHING'.

    Returns a dict with fields:
      url, prediction ("SAFE" or "PHISHING"), confidence (float percentage),
      confidence_str (e.g. "98.5%"), risk_level, score, score_type,
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
        load_model()
    except ModelNotFoundError as exc:
        return {
            "url": url,
            "error": str(exc),
            "prediction": None,
        }

    # ── 3. Feature extraction & input prep ──────────────────────────────
    feat_dict = extract_url_features(url)
    norm_url = canonical_url_string(url)
    raw_vec = np.array(features_to_vector(feat_dict), dtype=np.float32).reshape(1, -1)

    if _scaler is not None and _vectorizer is not None:
        import scipy.sparse
        X_tab = _scaler.transform(raw_vec)
        X_tfidf = _vectorizer.transform([norm_url])
        X_input = scipy.sparse.hstack([X_tab, X_tfidf])
    elif _vectorizer is not None:
        X_input = _vectorizer.transform([norm_url])
    elif _scaler is not None:
        X_input = _scaler.transform(raw_vec)
    else:
        X_input = raw_vec

    # ── 4. Decision Threshold & Prediction ──────────────────────────────
    threshold = 0.50
    if _metadata and "decision_threshold" in _metadata:
        try:
            threshold = float(_metadata["decision_threshold"])
        except (ValueError, TypeError):
            threshold = 0.50
    elif _bundle and "threshold" in _bundle:
        try:
            threshold = float(_bundle["threshold"])
        except (ValueError, TypeError):
            threshold = 0.50

    score: float | None = None
    confidence_pct: float | None = None
    score_type: str = "unavailable"

    # Probabilistic prediction using threshold
    try:
        probas = _model.predict_proba(X_input)[0]
        # probas[0] = P(SAFE), probas[1] = P(PHISHING)
        prob_safe = float(probas[0])
        prob_phish = float(probas[1])

        # Apply calibrated threshold to phishing probability
        pred_label = 1 if prob_phish >= threshold else 0
        if pred_label == 1:
            score = prob_phish
            confidence_pct = prob_phish * 100.0
        else:
            score = prob_safe
            confidence_pct = prob_safe * 100.0
        score_type = "calibrated_probability"
    except Exception:
        try:
            pred_label = int(_model.predict(X_input)[0])
        except Exception as exc:
            log.error("Prediction failed: %s", exc)
            raise PredictionError(f"Model prediction failed: {exc}") from exc
        score = None
        confidence_pct = None
        score_type = "unavailable"

    # Target: 1 = PHISHING, 0 = SAFE
    prediction_str = "PHISHING" if pred_label == 1 else "SAFE"

    # ── 5. Risk level ────────────────────────────────────────────────────
    effective_score = score if score is not None else (0.8 if pred_label == 1 else 0.2)
    risk_level = _map_risk_level(effective_score, pred_label)

    # ── 6. Indicators & Feature Contributions ────────────────────────────
    indicators = get_risk_indicators(feat_dict)
    feature_contributions = _extract_top_contributions(_model, _scaler, _vectorizer, X_input)

    # ── 7. Return structured result ──────────────────────────────────────
    confidence_str = f"{confidence_pct:.1f}%" if confidence_pct is not None else "N/A"
    return {
        "url": url,
        "prediction": prediction_str,
        "confidence": round(confidence_pct, 2) if confidence_pct is not None else None,
        "confidence_str": confidence_str,
        "threshold": round(threshold, 4),
        "risk_level": risk_level,
        "score": round(score, 4) if score is not None else None,
        "score_type": score_type,
        "indicators": indicators,
        "feature_contributions": feature_contributions,
        "features": {name: round(float(val), 6) for name, val in feat_dict.items()},
        "disclaimer": DISCLAIMER,
    }


def explain_prediction(url: str) -> dict:
    """
    Return the same result as predict_url() — included as a named alias
    for API clarity.  Indicators are derived from actual extracted features.
    """
    return predict_url(url)
