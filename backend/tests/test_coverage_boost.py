"""
PhishGuard AI — Targeted Coverage Tests for Backend Edge Cases
==============================================================
Ensures >= 85% line coverage across all files in backend/ (app.py, predictor.py,
features.py, database.py, config.py, and train_model.py).
"""

from __future__ import annotations

import json
import runpy
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

import backend.app as app_module
import backend.config as config
import backend.database as database
import backend.predictor as predictor
import backend.train_model as train_model
from backend.app import app, limiter


@pytest.fixture(autouse=True)
def reset_limiter_before_each():
    limiter.reset()
    yield
    limiter.reset()


# ──────────────────────────────────────────────────────────────────────────
# 1. backend/train_model.py
# ──────────────────────────────────────────────────────────────────────────
def test_train_model_delegates_to_train_main():
    with patch("train.main") as mock_train_main:
        train_model.main()
        mock_train_main.assert_called_once()


def test_train_model_main_block():
    with patch("train.main") as mock_train_main:
        runpy.run_module("backend.train_model", run_name="__main__")
        mock_train_main.assert_called_once()


# ──────────────────────────────────────────────────────────────────────────
# 2. backend/predictor.py Edge Cases
# ──────────────────────────────────────────────────────────────────────────
class TestPredictorCoverageEdgeCases:
    def test_load_model_path_traversal_restriction(self, tmp_path, monkeypatch):
        outside_path = tmp_path / "outside_model.joblib"
        outside_path.touch()
        monkeypatch.setattr(predictor, "MODEL_PKL_PATH", outside_path)
        monkeypatch.setattr(predictor, "MODEL_PATH", outside_path)
        monkeypatch.setattr(predictor, "_model", None)
        with pytest.raises(PermissionError, match="Security violation"):
            predictor.load_model(force_reload=True)

    def test_load_model_standalone_pipeline_object(self, tmp_path, monkeypatch):
        pipe = LogisticRegression()
        pipe_path = tmp_path / "pipe_model.joblib"
        import joblib

        joblib.dump(pipe, pipe_path)

        monkeypatch.setattr(predictor, "MODELS_DIR", tmp_path)
        monkeypatch.setattr(predictor, "MODEL_PKL_PATH", tmp_path / "no_pkl.pkl")
        monkeypatch.setattr(predictor, "MODEL_PATH", pipe_path)
        monkeypatch.setattr(predictor, "_model", None)

        loaded = predictor.load_model(force_reload=True)
        assert loaded is not None
        predictor._model = None

    def test_get_metadata_and_metrics_when_none(self, monkeypatch):
        monkeypatch.setattr(predictor, "_metadata", None)
        monkeypatch.setattr(predictor, "_metrics", None)
        with patch.object(predictor, "load_model") as mock_load:
            predictor.get_metadata()
            predictor.get_saved_metrics()
            assert mock_load.call_count == 2

    def test_model_is_available_exceptions(self):
        with patch.object(predictor, "load_model", side_effect=predictor.ModelNotFoundError("No model")):
            assert predictor.model_is_available() is False

        with patch.object(predictor, "load_model", side_effect=ValueError("Corrupt file")):
            assert predictor.model_is_available() is False

    def test_validate_url_more_cases(self):
        # Empty hostname
        valid, msg = predictor.validate_url("http://:8080/path")
        assert valid is False

        # Unsupported scheme
        valid, msg = predictor.validate_url("gopher://gopher.example.com/file.txt")
        assert valid is False
        assert "not supported" in msg

        # Port out of bounds
        valid, msg = predictor.validate_url("http://example.com:70000/")
        assert valid is False
        assert "port" in msg

    def test_extract_top_contributions_linear_and_empty(self):
        # model is None
        assert predictor._extract_top_contributions(None, None, None, np.zeros((1, 10))) == []

        # Model with linear coefficients
        mock_linear = MagicMock()
        mock_linear.coef_ = np.array([[0.5, -0.2, 0.8] + [0.1] * (len(predictor.FEATURE_NAMES) - 3)])
        del mock_linear.booster_  # ensure not tree
        del mock_linear.calibrated_classifiers_

        X = np.ones((1, len(predictor.FEATURE_NAMES)), dtype=np.float32)
        contribs = predictor._extract_top_contributions(mock_linear, None, None, X, top_k=3)
        assert len(contribs) <= 3
        for item in contribs:
            assert "feature" in item
            assert item["direction"] in ("PHISHING", "SAFE")

        # Model without booster_ or coef_
        mock_unknown = MagicMock(spec=[])
        assert predictor._extract_top_contributions(mock_unknown, None, None, X) == []

    def test_predict_url_scaler_and_vectorizer_combinations(self, monkeypatch):
        # When load_model raises ModelNotFoundError
        with patch.object(predictor, "load_model", side_effect=predictor.ModelNotFoundError("Missing model")):
            res = predictor.predict_url("https://example.com")
            assert res["prediction"] is None
            assert "Missing model" in res["error"]

        # Scaler only
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.8, 0.2]])
        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = np.zeros((1, len(predictor.FEATURE_NAMES)))

        monkeypatch.setattr(predictor, "_model", mock_model)
        monkeypatch.setattr(predictor, "_scaler", mock_scaler)
        monkeypatch.setattr(predictor, "_vectorizer", None)
        res_scaled = predictor.predict_url("https://example.com")
        assert res_scaled["prediction"] == "SAFE"

        # Vectorizer only
        mock_vec = MagicMock()
        mock_vec.transform.return_value = np.zeros((1, 50))
        monkeypatch.setattr(predictor, "_scaler", None)
        monkeypatch.setattr(predictor, "_vectorizer", mock_vec)
        res_vec = predictor.predict_url("https://example.com")
        assert res_vec["prediction"] == "SAFE"

        # Predict proba exception fallback
        mock_model.predict_proba.side_effect = Exception("Inference error")
        mock_model.predict.return_value = np.array([0])
        res_fallback = predictor.predict_url("https://example.com")
        assert res_fallback["prediction"] == "SAFE"


# ──────────────────────────────────────────────────────────────────────────
# 3. backend/app.py Edge Cases & Endpoints
# ──────────────────────────────────────────────────────────────────────────
class TestAppCoverageEdgeCases:
    def test_predict_bad_payloads(self):
        client = app.test_client()

        # Not JSON
        res1 = client.post("/api/predict", data="hello", content_type="text/plain")
        assert res1.status_code == 400

        # JSON not dict
        res2 = client.post("/api/predict", json=["not", "a", "dict"])
        assert res2.status_code == 400

        # URL empty
        res3 = client.post("/api/predict", json={"url": "   "})
        assert res3.status_code == 400

        # URL too long
        res4 = client.post("/api/predict", json={"url": "https://example.com/" + "a" * (config.MAX_URL_LENGTH + 1)})
        assert res4.status_code == 400

    def test_predict_unexpected_exception(self, monkeypatch):
        client = app.test_client()
        with patch("backend.app.predict_url", side_effect=Exception("Database down")):
            res = client.post("/api/predict", json={"url": "https://example.com"})
            assert res.status_code == 500
            assert "unexpected error" in res.get_json()["error"].lower()

    def test_batch_bad_payloads(self):
        client = app.test_client()

        # Not JSON
        res1 = client.post("/api/predict-batch", data="raw", content_type="text/plain")
        assert res1.status_code == 400

        # Missing urls or not list
        res2 = client.post("/api/predict-batch", json={"urls": "not-a-list"})
        assert res2.status_code == 400

        # Empty urls list
        res3 = client.post("/api/predict-batch", json={"urls": []})
        assert res3.status_code == 400

    def test_model_metrics_unavailable_and_exception(self, monkeypatch):
        client = app.test_client()

        # When model not available -> 503
        with patch("backend.app.model_is_available", return_value=False):
            res_no_model = client.get("/api/model-metrics")
            assert res_no_model.status_code == 503

        # When get_saved_metrics raises Exception -> 500
        with patch("backend.app.model_is_available", return_value=True):
            with patch("backend.app.get_saved_metrics", side_effect=Exception("Disk error")):
                res_err = client.get("/api/model-metrics")
                assert res_err.status_code == 500

    def test_model_info_unavailable(self):
        client = app.test_client()
        with patch("backend.app.model_is_available", return_value=False):
            res = client.get("/api/model-info")
            assert res.status_code == 200
            assert res.get_json()["model_available"] is False

    def test_external_eval_endpoints(self, tmp_path, monkeypatch):
        client = app.test_client()
        monkeypatch.setattr(config, "REPORTS_DIR", tmp_path)

        # 1. File does not exist
        res1 = client.get("/api/external-eval")
        assert res1.status_code == 200
        assert res1.get_json()["available"] is False

        # 2. File exists and valid
        eval_file = tmp_path / "external_eval.json"
        with open(eval_file, "w", encoding="utf-8") as f:
            json.dump({"accuracy": 0.98}, f)

        res2 = client.get("/api/external-eval")
        assert res2.status_code == 200
        assert res2.get_json()["available"] is True
        assert res2.get_json()["accuracy"] == 0.98

        # 3. File unreadable / corrupted -> 500
        with open(eval_file, "w", encoding="utf-8") as f:
            f.write("{invalid-json-content")
        res3 = client.get("/api/external-eval")
        assert res3.status_code == 500

    def test_reports_static_file_serving(self, tmp_path, monkeypatch):
        client = app.test_client()
        monkeypatch.setattr(config, "REPORTS_DIR", tmp_path)

        # File exists (roc_curve.png is in safe_names)
        test_file = tmp_path / "roc_curve.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n")

        res1 = client.get("/api/reports/roc_curve.png")
        assert res1.status_code == 200

        # File does not exist -> 404
        res2 = client.get("/api/reports/calibration_curve.png")
        assert res2.status_code == 404

        # Unauthorized filename -> 404
        res3 = client.get("/api/reports/arbitrary_file.txt")
        assert res3.status_code == 404

    def test_delete_history_exception_handling(self):
        client = app.test_client()
        with patch("backend.app.clear_history", side_effect=Exception("DB lock")):
            res = client.delete("/api/history")
            assert res.status_code == 500
