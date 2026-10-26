"""
Tests for backend/app.py — Flask REST API

Uses Flask test client. Model is mocked so tests run without a trained model file.
Database is isolated using an in-memory SQLite via monkeypatching.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


@pytest.fixture(scope="module")
def mock_model():
    """Create a mock sklearn pipeline."""
    pipe = MagicMock()
    pipe.predict.return_value = np.array([1])
    pipe.predict_proba.return_value = np.array([[0.18, 0.82]])
    return pipe


@pytest.fixture()
def app(mock_model, tmp_path):
    """Create a Flask test app with mocked model and temp DB."""
    import backend.predictor as pred_module
    import backend.config as cfg_module

    # Patch DB path to a temp file
    test_db = tmp_path / "test_phishguard.db"
    cfg_module.DB_PATH = test_db

    # Reset and inject mock model
    pred_module._model = mock_model
    pred_module._metadata = {
        "model_name": "MockModel",
        "model_version": "test-0.1",
        "feature_names": [],
        "feature_count": 25,
        "dataset_source": "test",
        "dataset_size": 1000,
        "label_distribution": {"0": 500, "1": 500},
        "trained_at": "2025-01-01T00:00:00+00:00",
        "class_mapping": {"0": "SAFE", "1": "PHISHING"},
    }
    pred_module._metrics = {
        "test_metrics": {"test_accuracy": 0.95},
        "validation_comparison": {},
        "feature_importances": [],
    }

    # Import app after patching to pick up new DB path
    import importlib
    import backend.app as app_module
    importlib.reload(app_module)

    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

    # Cleanup
    pred_module._model = None
    pred_module._metadata = None
    pred_module._metrics = None


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self, app):
        resp = app.get("/api/health")
        assert resp.status_code == 200

    def test_health_has_status_ok(self, app):
        data = resp_json(app.get("/api/health"))
        assert data["status"] == "ok"

    def test_health_reports_model_available(self, app):
        data = resp_json(app.get("/api/health"))
        assert "model_available" in data


# ---------------------------------------------------------------------------
# POST /api/predict
# ---------------------------------------------------------------------------

class TestPredictEndpoint:
    def test_valid_url_returns_200(self, app):
        resp = app.post(
            "/api/predict",
            data=json.dumps({"url": "http://192.168.1.1/login"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_prediction_field_present(self, app):
        data = post_predict(app, "http://evil.com/verify")
        assert "prediction" in data

    def test_prediction_is_phishing(self, app):
        data = post_predict(app, "http://192.168.1.1/login")
        assert data["prediction"] == "PHISHING"

    def test_response_has_required_fields(self, app):
        data = post_predict(app, "http://example.com")
        for field in ("url", "prediction", "risk_level", "score", "indicators", "disclaimer"):
            assert field in data, f"Missing field: {field}"

    def test_empty_url_returns_400(self, app):
        resp = app.post(
            "/api/predict",
            data=json.dumps({"url": ""}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_url_field_returns_400(self, app):
        resp = app.post(
            "/api/predict",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_non_json_body_returns_400(self, app):
        resp = app.post(
            "/api/predict",
            data="not-json",
            content_type="text/plain",
        )
        assert resp.status_code == 400

    def test_non_dict_json_body_returns_400(self, app):
        # JSON arrays, numbers, strings must return 400, not 500
        for bad_body in ["[1, 2, 3]", '"just-a-string"', "123", "true"]:
            resp = app.post(
                "/api/predict",
                data=bad_body,
                content_type="application/json",
            )
            assert resp.status_code == 400, f"Expected 400 for {bad_body}, got {resp.status_code}"

    def test_invalid_port_returns_400(self, app):
        for bad_url in ["http://example.com:abc/login", "http://example.com:99999/login"]:
            resp = app.post(
                "/api/predict",
                data=json.dumps({"url": bad_url}),
                content_type="application/json",
            )
            assert resp.status_code == 400
            assert "port" in resp_json(resp).get("error", "").lower()

    def test_javascript_scheme_rejected(self, app):
        resp = app.post(
            "/api/predict",
            data=json.dumps({"url": "javascript:alert(1)"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_very_long_url_rejected(self, app):
        long_url = "http://example.com/" + "a" * 3000
        resp = app.post(
            "/api/predict",
            data=json.dumps({"url": long_url}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_url_with_ip_address(self, app):
        data = post_predict(app, "http://10.0.0.1/phish")
        assert data["prediction"] is not None


# ---------------------------------------------------------------------------
# GET /api/history
# ---------------------------------------------------------------------------

class TestHistoryEndpoint:
    def test_history_returns_200(self, app):
        resp = app.get("/api/history")
        assert resp.status_code == 200

    def test_history_has_records_and_total(self, app):
        data = resp_json(app.get("/api/history"))
        assert "records" in data
        assert "total" in data

    def test_history_populated_after_scan(self, app):
        post_predict(app, "http://192.168.1.1/login")
        data = resp_json(app.get("/api/history"))
        assert data["total"] >= 1

    def test_invalid_limit_returns_400(self, app):
        resp = app.get("/api/history?limit=notanumber")
        assert resp.status_code == 400

    def test_history_stats_counts_safe_and_likely_legitimate(self, app):
        from backend.database import insert_scan, clear_history
        clear_history()

        insert_scan("http://safe1.com", "SAFE", "LOW", 0.1, "model_probability", "1.0.0")
        insert_scan("http://safe2.com", "LIKELY LEGITIMATE", "LOW", 0.15, "model_probability", "1.0.0")
        insert_scan("http://phish1.com", "PHISHING", "CRITICAL", 0.99, "model_probability", "1.0.0")
        insert_scan("http://err1.com", None, None, None, "unavailable", "1.0.0")

        data = resp_json(app.get("/api/history"))
        stats = data["stats"]
        assert stats["total"] == 4
        assert stats["legitimate_count"] == 2  # counts both SAFE and LIKELY LEGITIMATE
        assert stats["phishing_count"] == 1
        assert stats["error_count"] == 1


# ---------------------------------------------------------------------------
# DELETE /api/history
# ---------------------------------------------------------------------------

class TestDeleteHistoryEndpoint:
    def test_delete_returns_200(self, app):
        resp = app.delete("/api/history")
        assert resp.status_code == 200

    def test_delete_clears_records(self, app):
        post_predict(app, "http://evil.com/verify")
        app.delete("/api/history")
        data = resp_json(app.get("/api/history"))
        assert data["total"] == 0


# ---------------------------------------------------------------------------
# GET /api/model-metrics
# ---------------------------------------------------------------------------

class TestModelMetricsEndpoint:
    def test_metrics_returns_200(self, app):
        resp = app.get("/api/model-metrics")
        assert resp.status_code == 200

    def test_metrics_contains_test_metrics(self, app):
        data = resp_json(app.get("/api/model-metrics"))
        assert "test_metrics" in data


# ---------------------------------------------------------------------------
# GET /api/model-info
# ---------------------------------------------------------------------------

class TestModelInfoEndpoint:
    def test_model_info_returns_200(self, app):
        resp = app.get("/api/model-info")
        assert resp.status_code == 200

    def test_model_info_has_name(self, app):
        data = resp_json(app.get("/api/model-info"))
        assert "model_name" in data

    def test_model_info_no_file_paths(self, app):
        data = resp_json(app.get("/api/model-info"))
        # No file paths should be returned
        assert "model_path" not in data
        assert "db_path" not in data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resp_json(response) -> dict:
    return json.loads(response.data)


def post_predict(client, url: str) -> dict:
    resp = client.post(
        "/api/predict",
        data=json.dumps({"url": url}),
        content_type="application/json",
    )
    return resp_json(resp)
