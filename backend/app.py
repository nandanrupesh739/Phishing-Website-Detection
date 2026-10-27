"""
PhishGuard AI — Flask REST API
===============================
Endpoints
---------
GET  /api/health          — service status & model availability
POST /api/predict         — classify a single URL (rate-limited)
POST /api/predict-batch   — classify up to 100 URLs in batch (rate-limited)
GET  /api/history         — paginated scan history
DELETE /api/history       — clear scan history (protected by optional API key)
GET  /api/model-metrics   — saved test evaluation metrics
GET  /api/model-info      — model metadata

Security notes
--------------
- No stack traces or file paths are exposed to callers.
- Rate limiting enforced via Flask-Limiter (60 req/min).
- Optional API key protection on history deletion.
- Optional URL anonymisation (stores only host + SHA-256 hash).
- Input is length-limited and scheme-validated.
- SECRET_KEY fails loudly when FLASK_DEBUG is False and still default.
- The app never visits submitted URLs.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Ensure project root is on the path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config
from backend.database import (
    clear_history,
    get_history,
    get_history_stats,
    get_total_count,
    init_db,
    insert_scan,
)
from backend.predictor import (
    ModelNotFoundError,
    PredictionError,
    get_metadata,
    get_saved_metrics,
    model_is_available,
    predict_url,
)

# ──────────────────────────────────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.json.sort_keys = False

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

CORS(app, origins=config.CORS_ALLOWED_ORIGINS, methods=["GET", "POST", "DELETE"])


def enforce_production_secret_key(app_instance: Flask, force_check: bool = False) -> None:
    """Ensure SECRET_KEY is not default in non-debug production deployment."""
    is_testing = not force_check and ("pytest" in sys.modules or app_instance.config.get("TESTING", False))
    if not is_testing and not config.FLASK_DEBUG:
        insecure_keys = (
            "change-me-in-production",
            "default-insecure-key",
            "change-this-to-a-long-random-string",
            "",
        )
        if config.SECRET_KEY in insecure_keys:
            raise RuntimeError(
                "FATAL SECURITY CONFIGURATION: SECRET_KEY must be configured with a "
                "strong secret in production when FLASK_DEBUG is false. "
                "Set SECRET_KEY in your .env file."
            )


enforce_production_secret_key(app)

# Initialise DB on startup
with app.app_context():
    init_db()


# ──────────────────────────────────────────────────────────────────────────
# Helpers & Error Handlers
# ──────────────────────────────────────────────────────────────────────────

def _error(message: str, code: int) -> tuple:
    return jsonify({"error": message}), code


def _ok(data: dict) -> tuple:
    return jsonify(data), 200


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded (maximum 60 requests per minute). Please slow down."
    }), 429


# ──────────────────────────────────────────────────────────────────────────
# GET /api/health
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Return service status and model availability."""
    model_ready = model_is_available()
    meta = get_metadata() if model_ready else {}
    return jsonify({
        "status": "ok",
        "model_available": model_ready,
        "model_name": meta.get("model_name"),
        "model_version": meta.get("model_version"),
        "feature_count": meta.get("feature_count"),
        "decision_threshold": meta.get("decision_threshold"),
    }), 200


# ──────────────────────────────────────────────────────────────────────────
# POST /api/predict
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/predict", methods=["POST"])
@limiter.limit(config.RATE_LIMIT_PREDICT)
def predict():
    """
    Body: { "url": "<string>", "anonymize": <bool, optional> }
    Returns prediction result or error.
    """
    if not request.is_json:
        return _error("Request body must be JSON.", 400)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("Request body must be a JSON object.", 400)

    url = data.get("url", "")

    if not url or not isinstance(url, str):
        return _error("'url' field is required and must be a string.", 400)

    url = url.strip()
    if len(url) > config.MAX_URL_LENGTH:
        return _error(
            f"URL exceeds maximum allowed length ({config.MAX_URL_LENGTH} characters).", 400
        )
    if len(url) == 0:
        return _error("URL must not be empty.", 400)

    anonymize = data.get("anonymize", None)

    # Run prediction
    try:
        result = predict_url(url)
    except ModelNotFoundError:
        return _error(
            "The prediction model is not available. Please train the model first.", 503
        )
    except PredictionError:
        return _error("An internal error occurred during prediction.", 500)
    except Exception:
        log.exception("Unexpected error during prediction for url=%r", url[:80])
        return _error("An unexpected error occurred.", 500)

    # If validation failed inside predict_url, return 400
    if result.get("prediction") is None:
        return jsonify(result), 400

    # Persist to history
    try:
        meta = get_metadata()
        insert_scan(
            submitted_url=url,
            prediction=result.get("prediction"),
            risk_level=result.get("risk_level"),
            model_score=result.get("score"),
            score_type=result.get("score_type"),
            model_version=meta.get("model_version"),
            anonymize=anonymize,
        )
    except Exception:
        log.warning("Failed to save scan to history (non-fatal).")

    return jsonify(result), 200


# ──────────────────────────────────────────────────────────────────────────
# POST /api/predict-batch
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/predict-batch", methods=["POST"])
@limiter.limit(config.RATE_LIMIT_PREDICT)
def predict_batch():
    """
    Body: { "urls": ["<string>", ...], "anonymize": <bool, optional> }
    Accepts up to config.MAX_BATCH_SIZE (100) URLs.
    """
    if not request.is_json:
        return _error("Request body must be JSON.", 400)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("Request body must be a JSON object.", 400)

    urls = data.get("urls")
    if not isinstance(urls, list) or len(urls) == 0:
        return _error("'urls' field must be a non-empty list of URL strings.", 400)

    if len(urls) > config.MAX_BATCH_SIZE:
        return _error(
            f"Batch size exceeds maximum of {config.MAX_BATCH_SIZE} URLs.", 400
        )

    anonymize = data.get("anonymize", None)

    if not model_is_available():
        return _error(
            "The prediction model is not available. Please train the model first.", 503
        )

    meta = get_metadata()
    results = []
    safe_count = 0
    phish_count = 0
    error_count = 0

    for raw_u in urls:
        if not isinstance(raw_u, str) or not raw_u.strip():
            results.append({
                "url": raw_u,
                "error": "URL must be a non-empty string.",
                "prediction": None,
            })
            error_count += 1
            continue

        clean_u = raw_u.strip()
        if len(clean_u) > config.MAX_URL_LENGTH:
            results.append({
                "url": clean_u,
                "error": f"URL exceeds maximum allowed length ({config.MAX_URL_LENGTH} characters).",
                "prediction": None,
            })
            error_count += 1
            continue

        res = predict_url(clean_u)
        results.append(res)
        pred = res.get("prediction")

        if pred == "PHISHING":
            phish_count += 1
        elif pred == "SAFE":
            safe_count += 1
        else:
            error_count += 1

        if pred in ("SAFE", "PHISHING"):
            try:
                insert_scan(
                    submitted_url=clean_u,
                    prediction=pred,
                    risk_level=res.get("risk_level"),
                    model_score=res.get("score"),
                    score_type=res.get("score_type"),
                    model_version=meta.get("model_version"),
                    anonymize=anonymize,
                )
            except Exception:
                log.warning("Failed to save batch item to history (non-fatal).")

    threshold = meta.get("decision_threshold", 0.50)
    return jsonify({
        "results": results,
        "total": len(results),
        "threshold": threshold,
        "summary": {
            "safe_count": safe_count,
            "phishing_count": phish_count,
            "error_count": error_count,
        },
    }), 200


# ──────────────────────────────────────────────────────────────────────────
# GET /api/history
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/history", methods=["GET"])
def history():
    """
    Query params: ?limit=<int>&offset=<int>
    Returns paginated scan history, newest first.
    """
    try:
        limit = min(int(request.args.get("limit", config.HISTORY_PAGE_SIZE)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (ValueError, TypeError):
        return _error("'limit' and 'offset' must be integers.", 400)

    records = get_history(limit=limit, offset=offset)
    total = get_total_count()
    stats = get_history_stats()

    return jsonify({
        "records": records,
        "total": total,
        "limit": limit,
        "offset": offset,
        "stats": stats,
    }), 200


# ──────────────────────────────────────────────────────────────────────────
# DELETE /api/history
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/history", methods=["DELETE"])
def delete_history():
    """
    Permanently deletes all scan history from the local database.
    Protected by optional HISTORY_API_KEY from environment.
    """
    if config.HISTORY_API_KEY:
        provided_key = request.headers.get("x-api-key") or ""
        if not provided_key and request.headers.get("Authorization"):
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                provided_key = auth[7:].strip()
        if provided_key != config.HISTORY_API_KEY:
            return _error(
                "Unauthorized: Invalid or missing API key for history deletion.", 401
            )

    try:
        deleted = clear_history()
        return jsonify({
            "message": f"Scan history cleared. {deleted} record(s) deleted.",
            "deleted_count": deleted,
        }), 200
    except Exception:
        log.exception("Failed to clear scan history.")
        return _error("Failed to clear scan history.", 500)


# ──────────────────────────────────────────────────────────────────────────
# GET /api/model-metrics
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/model-metrics", methods=["GET"])
def model_metrics():
    """Return saved evaluation metrics from the most recent training run."""
    if not model_is_available():
        return _error(
            "No trained model found. Run 'python train.py' first.", 503
        )
    try:
        metrics = get_saved_metrics()
        return jsonify(metrics), 200
    except Exception:
        log.exception("Failed to load model metrics.")
        return _error("Failed to load model metrics.", 500)


# ──────────────────────────────────────────────────────────────────────────
# GET /api/model-info
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/model-info", methods=["GET"])
def model_info():
    """Return model metadata: type, version, dataset source, feature count, timestamp."""
    if not model_is_available():
        return jsonify({
            "model_available": False,
            "message": "No trained model found. Run the training pipeline first.",
        }), 200

    meta = get_metadata()
    safe_fields = [
        "model_name", "model_version", "feature_count",
        "feature_names", "dataset_source", "dataset_size",
        "label_distribution", "trained_at", "class_mapping",
        "decision_threshold", "target_phishing_recall",
        "split_description", "library_versions",
    ]
    return jsonify({k: meta[k] for k in safe_fields if k in meta}), 200


# ──────────────────────────────────────────────────────────────────────────
# GET /api/external-eval
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/external-eval", methods=["GET"])
def external_eval():
    """Return saved external benchmark evaluation metrics if available."""
    eval_file = config.REPORTS_DIR / "external_eval.json"
    if not eval_file.exists():
        return jsonify({
            "available": False,
            "message": "External benchmark evaluation not yet run. Run 'python scripts/external_eval.py'.",
        }), 200
    try:
        with open(eval_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["available"] = True
        return jsonify(data), 200
    except Exception:
        log.exception("Failed to load external evaluation results.")
        return _error("Failed to load external evaluation results.", 500)


# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Starting PhishGuard AI backend on %s:%s", config.FLASK_HOST, config.FLASK_PORT)
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
    )
