"""
PhishGuard AI — Flask REST API
===============================
Endpoints
---------
GET  /api/health          — service status & model availability
POST /api/predict         — classify a URL
GET  /api/history         — paginated scan history
DELETE /api/history       — clear all scan history
GET  /api/model-metrics   — saved test evaluation metrics
GET  /api/model-info      — model metadata

Security notes
--------------
- No stack traces or file paths are exposed to callers.
- Input is length-limited and scheme-validated.
- CORS origins are controlled via environment variables.
- The app never visits submitted URLs.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

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
app.config["JSON_SORT_KEYS"] = False

CORS(app, origins=config.CORS_ALLOWED_ORIGINS, methods=["GET", "POST", "DELETE"])

# Initialise DB on startup
with app.app_context():
    init_db()


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _error(message: str, code: int) -> tuple:
    return jsonify({"error": message}), code


def _ok(data: dict) -> tuple:
    return jsonify(data), 200


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
    }), 200


# ──────────────────────────────────────────────────────────────────────────
# POST /api/predict
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/predict", methods=["POST"])
def predict():
    """
    Body: { "url": "<string>" }
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

    # Run prediction
    try:
        result = predict_url(url)
    except ModelNotFoundError as exc:
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
        )
    except Exception:
        log.warning("Failed to save scan to history (non-fatal).")

    return jsonify(result), 200


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
    This action is irreversible.
    """
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
    # Only expose safe fields — no internal file paths
    safe_fields = [
        "model_name", "model_version", "feature_count",
        "feature_names", "dataset_source", "dataset_size",
        "label_distribution", "trained_at", "class_mapping",
    ]
    return jsonify({k: meta[k] for k in safe_fields if k in meta}), 200


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
