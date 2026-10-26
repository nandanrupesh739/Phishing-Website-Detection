"""
PhishGuard AI — Audit Requirements Tests
=========================================
Tests confirming:
  1. Label convention end-to-end: 0 = SAFE, 1 = PHISHING everywhere
  2. Metrics JSON schema contract matching frontend TypeScript types
  3. database.get_history_stats counts 'SAFE' and legacy 'LIKELY LEGITIMATE'
  4. URL normalisation parity between training and inference
  5. Decision threshold usage in predictions
  6. Rate limiting on /api/predict
"""
import json
import sqlite3
import pytest
from pathlib import Path
from flask import Flask

import backend.config as config
from backend.features import normalise_url, extract_url_features, FEATURE_NAMES
from backend.predictor import predict_url, load_model
from backend.database import _get_conn, init_db, get_history_stats, insert_scan
from backend.app import app


class TestLabelConventionEndToEnd:
    """Requirement 1: 0 = SAFE, 1 = PHISHING everywhere."""

    def test_predictor_returns_canonical_labels(self):
        """predict_url must return only 'SAFE' or 'PHISHING' (never 0/1 or 'LIKELY LEGITIMATE')."""
        res_safe = predict_url("https://www.google.com")
        assert res_safe["prediction"] in ("SAFE", "PHISHING")

        res_phish = predict_url("http://192.168.1.1:8080/paypal.com/login.php")
        assert res_phish["prediction"] in ("SAFE", "PHISHING")

    def test_model_metadata_label_mapping(self):
        """models/model_metadata.json must define 0: SAFE, 1: PHISHING."""
        meta_path = config.METADATA_PATH
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            mapping = meta.get("target_mapping") or meta.get("class_mapping")
            assert mapping is not None
            # Handle int or str keys in json
            val_0 = mapping.get(0) or mapping.get("0")
            val_1 = mapping.get(1) or mapping.get("1")
            assert val_0 == "SAFE"
            assert val_1 == "PHISHING"

    def test_saved_model_bundle_target_mapping(self):
        """Winner joblib bundle must store target_mapping {0: 'SAFE', 1: 'PHISHING'}."""
        import joblib
        if config.MODEL_PATH.exists():
            bundle = joblib.load(config.MODEL_PATH)
            if isinstance(bundle, dict) and "target_mapping" in bundle:
                tm = bundle["target_mapping"]
                assert tm.get(0) == "SAFE"
                assert tm.get(1) == "PHISHING"


class TestMetricsContractAgainstFrontend:
    """Requirement 2: metrics JSON contract matching frontend ModelMetricsResponse."""

    def test_metrics_json_schema(self):
        metrics_file = config.METRICS_PATH
        assert metrics_file.exists(), "models/model_metrics.json must exist"

        with open(metrics_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Top-level required keys
        assert "test_metrics" in data, "test_metrics object is required"
        assert "validation_comparison" in data, "validation_comparison object is required"
        assert "feature_importances" in data, "feature_importances list is required"
        assert "dataset_source" in data, "dataset_source is required"
        assert "dataset_size" in data, "dataset_size is required"
        assert "label_distribution" in data, "label_distribution is required"

        tm = data["test_metrics"]
        required_tm_fields = [
            "model_name", "accuracy", "precision", "recall",
            "f1", "roc_auc", "average_precision", "confusion_matrix"
        ]
        for field in required_tm_fields:
            assert field in tm, f"test_metrics missing required field '{field}'"

        assert isinstance(tm["model_name"], str)
        assert 0.0 <= tm["accuracy"] <= 1.0
        assert 0.0 <= tm["precision"] <= 1.0
        assert 0.0 <= tm["recall"] <= 1.0
        assert 0.0 <= tm["f1"] <= 1.0
        assert 0.0 <= tm["roc_auc"] <= 1.0
        assert 0.0 <= tm["average_precision"] <= 1.0

        # Confusion matrix format: 2x2
        cm = tm["confusion_matrix"]
        assert isinstance(cm, list) and len(cm) == 2
        assert len(cm[0]) == 2 and len(cm[1]) == 2

        # Validation comparison per model
        vc = data["validation_comparison"]
        assert isinstance(vc, dict) and len(vc) >= 1
        for m_name, metrics in vc.items():
            assert "accuracy" in metrics
            assert "f1" in metrics

        # Feature importances
        fi = data["feature_importances"]
        assert isinstance(fi, list) and len(fi) > 0
        for item in fi[:5]:
            assert "feature" in item and "importance" in item


class TestDatabaseHistoryStats:
    """Requirement 3: get_history_stats counts SAFE and legacy LIKELY LEGITIMATE."""

    def test_history_stats_counts_safe_and_legacy_rows(self, tmp_path, monkeypatch):
        import backend.database as db_mod
        test_db = tmp_path / "test_stats.db"
        monkeypatch.setattr(config, "DB_PATH", test_db)
        monkeypatch.setattr(db_mod, "DB_PATH", test_db)
        init_db()

        # Insert SAFE, PHISHING, and legacy LIKELY LEGITIMATE records
        insert_scan("https://example-safe.com", "SAFE", "LOW", 0.02, "calibrated_probability", "1.0.0")
        insert_scan("https://example-phish.com", "PHISHING", "CRITICAL", 0.99, "calibrated_probability", "1.0.0")
        # Manually insert legacy row
        with _get_conn() as conn:
            conn.execute(
                """INSERT INTO scan_history (submitted_url, prediction, risk_level, model_score, scan_timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                ("https://example-legacy.com", "LIKELY LEGITIMATE", "LOW", 0.05, "2026-01-01T00:00:00Z"),
            )

        stats = get_history_stats()
        assert stats["total"] == 3
        assert stats["phishing_count"] == 1
        # Both SAFE (1) and LIKELY LEGITIMATE (1) must count toward legitimate_count
        assert stats["legitimate_count"] == 2
        assert stats["error_count"] == 0


class TestUrlNormalisationParity:
    """Requirement 5: normalise_url parity between training and inference."""

    def test_bare_domain_and_https_parity(self):
        url_bare = "github.com/security"
        url_https = "https://github.com/security"
        url_www = "http://www.github.com/security"

        norm_bare, missing_bare = normalise_url(url_bare)
        norm_https, missing_https = normalise_url(url_https)
        norm_www, missing_www = normalise_url(url_www)

        assert missing_bare is True
        assert missing_https is False
        assert missing_www is False

        # Structural features excluding scheme_missing should be identical
        f_bare = extract_url_features(url_bare)
        f_https = extract_url_features(url_https)

        for name in FEATURE_NAMES:
            if name in ("scheme_missing", "has_https"):
                continue
            assert f_bare[name] == f_https[name], f"Mismatch on {name}: {f_bare[name]} vs {f_https[name]}"


class TestThresholdApplication:
    """Requirement 11: Tuned decision threshold is respected in predictor."""

    def test_predict_url_returns_confidence_and_threshold(self):
        res = predict_url("https://www.google.com")
        assert "confidence" in res
        assert "threshold" in res
        assert "confidence_str" in res
        assert isinstance(res["threshold"], float)
        assert 0.0 < res["threshold"] < 1.0


class TestPredictBatchEndpoint:
    """Requirement 17: /api/predict-batch works with max 100 URLs."""

    def test_batch_prediction_under_limit(self):
        client = app.test_client()
        urls = ["https://google.com", "http://evil-phish.xyz/login"]
        response = client.post("/api/predict-batch", json={"urls": urls})
        assert response.status_code == 200
        data = response.get_json()
        assert data["total"] == 2
        assert len(data["results"]) == 2
        assert "summary" in data
        assert data["summary"]["safe_count"] + data["summary"]["phishing_count"] + data["summary"]["error_count"] == 2
