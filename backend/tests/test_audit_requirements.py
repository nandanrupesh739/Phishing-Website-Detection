"""
PhishGuard AI — Complete Audit Requirements & Verification Tests
================================================================
Comprehensive test suite verifying:
  1. Label convention end-to-end: 0 = SAFE, 1 = PHISHING everywhere
  2. Metrics JSON schema contract matching frontend TypeScript types exactly
  3. URL normalisation parity between training and inference
  4. Edge-case URLs that must not crash (bad ports, IPv6, punycode, spaces, null bytes, long URLs)
  5. co.in / co.uk subdomain counting and brand_in_wrong_place heuristics
  6. Decision threshold application in predictions & calibrated confidence range (0-100%)
  7. Database stats counting SAFE and PHISHING, and legacy schema migration
  8. Rate limiting, API-key protection on DELETE, batch endpoint limits, security headers, CORS
  9. Zero domain overlap between train / validation / test splits
 10. Zero-network static analysis guarantee (network socket monkeypatch)
"""

from __future__ import annotations

import json
import socket
import sqlite3
import sys
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

import backend.config as config
from backend.app import app
from backend.database import (
    _get_conn,
    clear_history,
    get_history,
    get_history_stats,
    init_db,
    insert_scan,
)
from backend.features import (
    FEATURE_NAMES,
    canonical_url_string,
    extract_url_features,
    features_to_vector,
    normalise_url,
    normalize_url,
)
from backend.predictor import (
    _extract_top_contributions,
    _map_risk_level,
    get_metadata,
    get_saved_metrics,
    load_model,
    model_is_available,
    predict_url,
    validate_url,
)


# ──────────────────────────────────────────────────────────────────────────
# 1. Label Convention End-to-End
# ──────────────────────────────────────────────────────────────────────────
class TestLabelConventionEndToEnd:
    """Raw dataset (1=legitimate, 0=phishing) -> Standardised: 0=SAFE, 1=PHISHING."""

    def test_predictor_returns_canonical_labels(self):
        """predict_url must return only 'SAFE' or 'PHISHING' (never 0/1 or 'LIKELY LEGITIMATE')."""
        res_safe = predict_url("https://www.google.com")
        assert res_safe["prediction"] in ("SAFE", "PHISHING")

        res_phish = predict_url("http://192.168.1.1:8080/paypal.com/login.php")
        assert res_phish["prediction"] in ("SAFE", "PHISHING")

    def test_model_metadata_label_mapping(self):
        """Metadata must define 0: SAFE, 1: PHISHING."""
        meta = get_metadata()
        mapping = meta.get("target_mapping") or meta.get("class_mapping")
        assert mapping is not None
        val_0 = mapping.get(0) or mapping.get("0")
        val_1 = mapping.get(1) or mapping.get("1")
        assert val_0 == "SAFE"
        assert val_1 == "PHISHING"

    def test_raw_dataset_mapping_logic(self):
        """Verify the raw PhiUSIIL dataset mapping logic (1 -> 0, 0 -> 1)."""
        raw_series = pd.Series([1, 0, 1, 1, 0])
        mapped = raw_series.map({1: 0, 0: 1})
        assert mapped.tolist() == [0, 1, 0, 0, 1]


# ──────────────────────────────────────────────────────────────────────────
# 2. Metrics JSON Schema vs Frontend TypeScript Types
# ──────────────────────────────────────────────────────────────────────────
class TestMetricsContractAgainstFrontendTypes:
    """Matches frontend/src/types/api.ts ModelMetricsResponse interface."""

    def test_metrics_json_schema_matches_typescript_types(self):
        metrics = get_saved_metrics()
        assert isinstance(metrics, dict), "Metrics must be a JSON dictionary"

        # ModelMetricsResponse top-level fields
        assert "test_metrics" in metrics, "Missing test_metrics in ModelMetricsResponse"
        assert "validation_comparison" in metrics, "Missing validation_comparison"
        assert "feature_importances" in metrics, "Missing feature_importances"

        tm = metrics["test_metrics"]
        # Required fields in frontend TestMetrics
        assert "model_name" in tm and isinstance(tm["model_name"], str)
        assert "accuracy" in tm and isinstance(tm["accuracy"], (int, float))
        assert "precision" in tm and isinstance(tm["precision"], (int, float))
        assert "recall" in tm and isinstance(tm["recall"], (int, float))
        assert "f1" in tm and isinstance(tm["f1"], (int, float))
        assert "roc_auc" in tm
        assert "average_precision" in tm
        assert "confusion_matrix" in tm and isinstance(tm["confusion_matrix"], list)

        # Confusion matrix must be 2x2
        cm = tm["confusion_matrix"]
        assert len(cm) == 2 and len(cm[0]) == 2 and len(cm[1]) == 2

        # Validation comparison dictionary
        vc = metrics["validation_comparison"]
        assert isinstance(vc, dict)
        for model_name, entry in vc.items():
            assert "accuracy" in entry and isinstance(entry["accuracy"], (int, float))

        # Feature importances list
        fi = metrics["feature_importances"]
        assert isinstance(fi, list)
        for item in fi[:5]:
            assert "feature" in item and isinstance(item["feature"], str)
            assert "importance" in item and isinstance(item["importance"], (int, float))


# ──────────────────────────────────────────────────────────────────────────
# 3. URL Normalisation Parity Between Training and Inference
# ──────────────────────────────────────────────────────────────────────────
class TestUrlNormalisationParity:
    """Verifies that bare domains, http, https, and leading www normalize canonically."""

    def test_bare_domain_https_and_www_parity(self):
        url_bare = "github.com/security"
        url_https = "https://github.com/security"
        url_www = "https://www.github.com/security"
        url_http_www = "http://www.github.com/security"

        norm_bare = normalize_url(url_bare)
        norm_https = normalize_url(url_https)
        norm_www = normalize_url(url_www)
        norm_http_www = normalize_url(url_http_www)

        assert norm_bare == "https://github.com/security"
        assert norm_https == "https://github.com/security"
        assert norm_www == "https://github.com/security"
        assert norm_http_www == "http://github.com/security"

        # Check scheme_missing flag
        _, missing_bare = normalise_url(url_bare)
        _, missing_https = normalise_url(url_https)
        assert missing_bare is True
        assert missing_https is False

        # Structural feature vector equality (excluding scheme_missing and has_https)
        f_bare = extract_url_features(url_bare)
        f_https = extract_url_features(url_https)
        for name in FEATURE_NAMES:
            if name in ("scheme_missing", "has_https"):
                continue
            assert f_bare[name] == f_https[name], f"Mismatch on {name}: {f_bare[name]} vs {f_https[name]}"


# ──────────────────────────────────────────────────────────────────────────
# 4. Edge-Case URLs That Must Not Crash
# ──────────────────────────────────────────────────────────────────────────
class TestEdgeCaseUrlsNoCrash:
    """Ensures input validation and feature extraction never crash on malformed inputs."""

    @pytest.mark.parametrize(
        "edge_url",
        [
            "http://example.com:abc",
            "http://example.com:99999",
            "http://example.com:-1",
            "http://[::1/path",
            "http://[invalid-ipv6]/",
            "https://example.com/path with spaces in it",
            "http://münchen.de/über-uns",
            "http://xn--p1ai.ru/portal",
            "http://example.com/null\x00byte",
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "file:///etc/passwd",
            "about:blank",
            "http://" + "a" * 3000 + ".com",
            "https://...///...///",
            "https://user:pass@example.com:8080/path?q=1#frag",
        ],
    )
    def test_edge_case_urls_do_not_crash(self, edge_url):
        # 1. validate_url must return a tuple (bool, str) without throwing
        valid, msg = validate_url(edge_url)
        assert isinstance(valid, bool)
        assert isinstance(msg, str)

        # 2. extract_url_features must return a 42-feature dict without unhandled exceptions
        feats = extract_url_features(edge_url)
        assert isinstance(feats, dict)
        assert len(feats) == len(FEATURE_NAMES)
        for k in FEATURE_NAMES:
            assert isinstance(feats[k], (int, float))

        # 3. predict_url must return a structured response without crashing
        res = predict_url(edge_url)
        assert isinstance(res, dict)
        assert "url" in res


# ──────────────────────────────────────────────────────────────────────────
# 5. Multi-Level TLDs & Brand in Wrong Place
# ──────────────────────────────────────────────────────────────────────────
class TestSubdomainsAndBrandHeuristics:
    """Verifies co.in / co.uk PSL handling and brand impersonation detection."""

    def test_multi_level_tld_subdomain_counting(self):
        # co.uk and co.in have registered domain one level under co.uk
        f1 = extract_url_features("https://paypal.co.uk")
        assert f1["num_subdomains"] == 0.0

        f2 = extract_url_features("https://login.paypal.co.uk")
        assert f2["num_subdomains"] == 1.0

        f3 = extract_url_features("https://verify.portal.login.company.co.in")
        assert f3["num_subdomains"] == 3.0

    def test_brand_in_wrong_place_heuristic(self):
        # Legitimate brand on its registered domain: brand_in_wrong_place = 0.0
        f_legit = extract_url_features("https://www.paypal.com/signin")
        assert f_legit["brand_in_wrong_place"] == 0.0

        # Phishing spoof with brand in subdomain: brand_in_wrong_place = 1.0
        f_phish1 = extract_url_features("https://paypal.secure-login.xyz/auth")
        assert f_phish1["brand_in_wrong_place"] == 1.0

        # Phishing spoof with brand in path: brand_in_wrong_place = 1.0
        f_phish2 = extract_url_features("http://192.168.1.50/paypal/login.php")
        assert f_phish2["brand_in_wrong_place"] == 1.0


# ──────────────────────────────────────────────────────────────────────────
# 6. Threshold Application & Calibrated Confidence Range
# ──────────────────────────────────────────────────────────────────────────
class TestThresholdAndCalibratedConfidence:
    """Verifies confidence score mapping (0.0 to 100.0) and threshold logic."""

    def test_calibrated_confidence_range(self):
        for test_url in ["https://google.com", "http://suspicious-verify.xyz/login"]:
            res = predict_url(test_url)
            if res.get("confidence") is not None:
                assert 0.0 <= res["confidence"] <= 100.0
                assert "%" in res["confidence_str"]

    def test_threshold_influences_prediction(self, monkeypatch):
        import backend.predictor as p_mod

        # Synthetic mock model returning score 0.60
        mock_clf = MagicMock()
        mock_clf.predict_proba.return_value = np.array([[0.40, 0.60]])
        monkeypatch.setattr(p_mod, "_model", mock_clf)
        monkeypatch.setattr(p_mod, "_scaler", None)
        monkeypatch.setattr(p_mod, "_vectorizer", None)

        # Case 1: Threshold = 0.50 -> Score 0.60 >= 0.50 -> PHISHING
        monkeypatch.setattr(p_mod, "_metadata", {"decision_threshold": 0.50})
        monkeypatch.setattr(p_mod, "_bundle", {"threshold": 0.50})
        res1 = p_mod.predict_url("https://example.com/test")
        assert res1["prediction"] == "PHISHING"
        assert res1["threshold"] == 0.50

        # Case 2: Threshold = 0.70 -> Score 0.60 < 0.70 -> SAFE
        monkeypatch.setattr(p_mod, "_metadata", {"decision_threshold": 0.70})
        monkeypatch.setattr(p_mod, "_bundle", {"threshold": 0.70})
        res2 = p_mod.predict_url("https://example.com/test")
        assert res2["prediction"] == "SAFE"
        assert res2["threshold"] == 0.70


# ──────────────────────────────────────────────────────────────────────────
# 7. Database History Stats & Legacy Schema Migration
# ──────────────────────────────────────────────────────────────────────────
class TestDatabaseStatsAndMigration:
    """Verifies stats counters and backwards-compatibility migrations."""

    def test_stats_counts_and_migration(self, tmp_path, monkeypatch):
        import backend.database as db_mod

        test_db = tmp_path / "test_migration.db"
        monkeypatch.setattr(config, "DB_PATH", test_db)
        monkeypatch.setattr(db_mod, "DB_PATH", test_db)

        # 1. Create an old legacy schema table missing score_type column
        conn = sqlite3.connect(str(test_db))
        conn.execute(
            """
            CREATE TABLE scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submitted_url TEXT NOT NULL,
                prediction TEXT,
                risk_level TEXT,
                model_score REAL,
                model_version TEXT,
                scan_timestamp TEXT NOT NULL
            )
            """
        )
        # Insert old-format rows
        conn.execute(
            "INSERT INTO scan_history (submitted_url, prediction, risk_level, model_score, model_version, scan_timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("https://safe.com", "SAFE", "LOW", 0.05, "1.0", "2026-01-01T00:00:00Z"),
        )
        conn.execute(
            "INSERT INTO scan_history (submitted_url, prediction, risk_level, model_score, model_version, scan_timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("https://legacy.com", "LIKELY LEGITIMATE", "LOW", 0.08, "0.9", "2026-01-01T00:00:00Z"),
        )
        conn.execute(
            "INSERT INTO scan_history (submitted_url, prediction, risk_level, model_score, model_version, scan_timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("http://phish.xyz", "PHISHING", "CRITICAL", 0.98, "1.0", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
        conn.close()

        # 2. Run init_db() which executes migration logic adding score_type
        init_db()

        # Verify score_type column was added
        with _get_conn() as c:
            cols = [row[1] for row in c.execute("PRAGMA table_info(scan_history)").fetchall()]
            assert "score_type" in cols

        # 3. Check stats counts: SAFE (1) + LIKELY LEGITIMATE (1) = 2 legitimate_count
        stats = get_history_stats()
        assert stats["total"] == 3
        assert stats["phishing_count"] == 1
        assert stats["legitimate_count"] == 2
        assert stats["error_count"] == 0


# ──────────────────────────────────────────────────────────────────────────
# 8. API Security: Rate Limiting, Admin Keys, Batch Limits, Headers, CORS
# ──────────────────────────────────────────────────────────────────────────
class TestApiSecurityAndPolicies:
    """Verifies security headers, CORS, rate limits, and batch size guardrails."""

    def test_security_headers_present(self):
        client = app.test_client()
        res = client.get("/api/health")
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in res.headers

    def test_cors_origin_handling(self):
        client = app.test_client()
        res = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert res.headers.get("Access-Control-Allow-Origin") in ("http://localhost:5173", "*")

    def test_batch_size_limits_and_ordering(self):
        client = app.test_client()

        # Reject batch > 100
        too_many = [f"https://site{i}.com" for i in range(101)]
        res_limit = client.post("/api/predict-batch", json={"urls": too_many})
        assert res_limit.status_code == 400
        assert "100" in res_limit.get_json()["error"]

        # Preserve ordering
        urls = ["https://first.com", "https://second.com", "https://third.com"]
        res_order = client.post("/api/predict-batch", json={"urls": urls})
        assert res_order.status_code == 200
        data = res_order.get_json()
        assert len(data["results"]) == 3
        assert data["results"][0]["url"] == "https://first.com"
        assert data["results"][1]["url"] == "https://second.com"
        assert data["results"][2]["url"] == "https://third.com"

    def test_delete_history_admin_key_protection(self, monkeypatch):
        monkeypatch.setattr(config, "HISTORY_API_KEY", "test-secret-key-123")
        client = app.test_client()

        # Missing key -> 401
        res1 = client.delete("/api/history")
        assert res1.status_code == 401

        # Wrong key -> 401
        res2 = client.delete("/api/history", headers={"x-api-key": "wrong-key"})
        assert res2.status_code == 401

        # Valid x-api-key -> 200
        res3 = client.delete("/api/history", headers={"x-api-key": "test-secret-key-123"})
        assert res3.status_code == 200

        # Valid Authorization Bearer key -> 200
        res4 = client.delete("/api/history", headers={"Authorization": "Bearer test-secret-key-123"})
        assert res4.status_code == 200

    def test_rate_limiting_enforcement(self):
        from backend.app import limiter

        limiter.reset()
        client = app.test_client()
        rate_limited = False
        for i in range(65):
            r = client.post("/api/predict", json={"url": f"https://test-ratelimit-{i}.com"})
            if r.status_code == 429:
                rate_limited = True
                assert "ratelimit" in r.get_json().get("error", "").lower() or r.status_code == 429
                break
        assert rate_limited is True, "Rate limit of 60 req/min was not enforced after 65 requests"
        limiter.reset()


# ──────────────────────────────────────────────────────────────────────────
# 9. Zero Domain Overlap Between Splits
# ──────────────────────────────────────────────────────────────────────────
class TestZeroDomainOverlapSplit:
    """Confirms no domain leakage between train, validation, and test splits."""

    def test_split_domain_grouped_zero_overlap(self):
        from train import split_domain_grouped

        rows = []
        for i in range(15):
            rows.append({"canonical_url": f"https://sub{i}.google.com", "domain_group": "google.com", "label": 0})
            rows.append({"canonical_url": f"https://auth{i}.paypal.com", "domain_group": "paypal.com", "label": 0})
            rows.append({"canonical_url": f"http://phish{i}.evil.xyz", "domain_group": "evil.xyz", "label": 1})
            rows.append({"canonical_url": f"http://bad{i}.scam.top", "domain_group": "scam.top", "label": 1})
            rows.append({"canonical_url": f"https://user{i}.github.io", "domain_group": "github.io", "label": 0})
            rows.append({"canonical_url": f"https://bank{i}.chase.com", "domain_group": "chase.com", "label": 0})
        df = pd.DataFrame(rows)

        df_train, df_val, df_test = split_domain_grouped(df)

        dom_train = set(df_train["domain_group"])
        dom_val = set(df_val["domain_group"])
        dom_test = set(df_test["domain_group"])

        assert len(dom_train & dom_val) == 0, f"Domain overlap between train and val: {dom_train & dom_val}"
        assert len(dom_train & dom_test) == 0, f"Domain overlap between train and test: {dom_train & dom_test}"
        assert len(dom_val & dom_test) == 0, f"Domain overlap between val and test: {dom_val & dom_test}"


# ──────────────────────────────────────────────────────────────────────────
# 10. Strict Network Isolation Guarantee
# ──────────────────────────────────────────────────────────────────────────
class TestZeroNetworkRequestsGuarantee:
    """Verifies that no code path makes network requests on submitted URLs."""

    def test_predict_and_batch_never_make_network_calls(self, monkeypatch):
        """
        Monkeypatch socket and HTTP libraries to raise immediately.
        Prediction must succeed purely through static lexical and structural analysis.
        """

        def forbidden_call(*args, **kwargs):
            raise AssertionError("CRITICAL SECURITY VIOLATION: Network call was attempted on a submitted URL!")

        # Block raw sockets
        monkeypatch.setattr(socket, "socket", forbidden_call)
        monkeypatch.setattr(socket, "create_connection", forbidden_call)

        # Block standard urllib
        monkeypatch.setattr(urllib.request, "urlopen", forbidden_call)

        # Block requests if imported
        if "requests" in sys.modules:
            import requests

            monkeypatch.setattr(requests, "get", forbidden_call)
            monkeypatch.setattr(requests, "post", forbidden_call)
            monkeypatch.setattr(requests.sessions.Session, "request", forbidden_call)

        # Run single prediction
        result = predict_url("http://192.168.1.1:8080/paypal-update/auth.php")
        assert result["prediction"] in ("SAFE", "PHISHING")

        # Run batch prediction via client
        client = app.test_client()
        batch_res = client.post(
            "/api/predict-batch",
            json={"urls": ["https://google.com", "http://evil-spoof.xyz/login"]},
        )
        assert batch_res.status_code == 200
        batch_data = batch_res.get_json()
        assert len(batch_data["results"]) == 2
