"""
PhishGuard AI — End-to-End Live HTTP Smoke Test
===============================================
Starts the Flask server on a dynamic free ephemeral port in-process, runs real HTTP
requests against all key endpoints using urllib, asserts status codes, schema fields,
and detection results, then cleanly shuts down the server.

Exits with code 0 on success, and non-zero on any failure.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import backend.config as config
from backend.features import FEATURE_NAMES, normalize_url, extract_url_features, features_to_vector


def get_free_port() -> int:
    """Find a free ephemeral port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ensure_model_available(tmp_dir: Path):
    """If real trained model does not exist, build a synthetic model bundle in tmp_dir."""
    if not config.MODEL_PATH.exists():
        print("[*] No pre-trained model on disk. Generating synthetic model for smoke test…")
        import joblib
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.preprocessing import StandardScaler
        import scipy.sparse

        model_file = tmp_dir / "phishguard_model.joblib"
        metadata_file = tmp_dir / "model_metadata.json"
        metrics_file = tmp_dir / "model_metrics.json"

        urls = [
            "https://google.com", "https://github.com", "https://wikipedia.org", "https://python.org",
            "http://paypal-verification-update.xyz/login", "http://apple-id-verify.account-security.top/auth",
            "http://192.168.1.1:8080/bank/login", "http://secure-login-account-update.net/signin",
        ]
        y = np.array([0, 0, 0, 0, 1, 1, 1, 1], dtype=int)

        tld_freq = {".com": 0.5, ".org": 0.25, ".xyz": 0.1, ".top": 0.1, ".net": 0.05}
        X_feats = [features_to_vector(extract_url_features(u, tld_freq_map=tld_freq)) for u in urls]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(np.array(X_feats, dtype=np.float32))

        norm_urls = [normalize_url(u) for u in urls]
        tfidf = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=50)
        X_tfidf = tfidf.fit_transform(norm_urls)
        X_comb = scipy.sparse.hstack([X_scaled, X_tfidf])

        clf = LogisticRegression(random_state=42)
        clf.fit(X_comb, y)

        bundle = {
            "model": clf,
            "scaler": scaler,
            "vectorizer": tfidf,
            "feature_names": FEATURE_NAMES,
            "threshold": 0.50,
            "tld_freq_map": tld_freq,
            "target_mapping": {0: "SAFE", 1: "PHISHING"},
            "model_name": "SyntheticSmokeModel",
            "model_version": "1.0.0-smoke",
            "trained_at": "2026-01-01T00:00:00Z",
        }
        joblib.dump(bundle, model_file)

        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump({
                "model_name": "SyntheticSmokeModel",
                "model_version": "1.0.0-smoke",
                "feature_count": len(FEATURE_NAMES),
                "feature_names": FEATURE_NAMES,
                "dataset_source": "Smoke Test Synthetic",
                "dataset_size": len(urls),
                "decision_threshold": 0.50,
                "target_phishing_recall": 0.98,
            }, f)

        with open(metrics_file, "w", encoding="utf-8") as f:
            json.dump({
                "test_metrics": {
                    "model_name": "SyntheticSmokeModel",
                    "accuracy": 1.0,
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "roc_auc": 1.0,
                    "average_precision": 1.0,
                    "confusion_matrix": [[4, 0], [0, 4]],
                },
                "validation_comparison": {"SyntheticSmokeModel": {"accuracy": 1.0, "f1": 1.0}},
                "feature_importances": [{"feature": "url_length", "importance": 0.5}],
            }, f)

        config.MODELS_DIR = tmp_dir
        config.MODEL_PATH = model_file
        config.METADATA_PATH = metadata_file
        config.METRICS_PATH = metrics_file

        import backend.predictor as p_mod
        p_mod.MODELS_DIR = tmp_dir
        p_mod.MODEL_PATH = model_file
        p_mod.METADATA_PATH = metadata_file
        p_mod.METRICS_PATH = metrics_file
        p_mod._model = None


def http_request(base_url: str, method: str, path: str, data: dict | None = None) -> tuple[int, dict]:
    """Execute HTTP request using urllib and return (status_code, json_dict)."""
    url = f"{base_url}{path}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8")
        try:
            return err.code, json.loads(raw)
        except Exception:
            return err.code, {"error": raw}


def main():
    print("=" * 70)
    print("PHISHGUARD AI — END-TO-END LIVE HTTP SMOKE TEST")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = Path(tmp_str)

        # Isolate database
        smoke_db = tmp_dir / "smoke_test.db"
        config.DB_PATH = smoke_db
        import backend.database as db_mod
        db_mod.DB_PATH = smoke_db
        db_mod.init_db()

        # Ensure model exists
        ensure_model_available(tmp_dir)

        # Import Flask app and clean rate limiters
        from backend.app import app, limiter
        limiter.reset()

        port = get_free_port()
        base_url = f"http://127.0.0.1:{port}"
        print(f"[*] Starting live Flask HTTP server on ephemeral port {port}…")

        from werkzeug.serving import make_server
        server = make_server("127.0.0.1", port, app)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        # Poll until online
        server_ready = False
        for attempt in range(30):
            try:
                status, res = http_request(base_url, "GET", "/api/health")
                if status == 200 and res.get("status") == "ok":
                    server_ready = True
                    break
            except Exception:
                time.sleep(0.1)

        if not server_ready:
            print("[FAIL] Flask test server failed to start within timeout.")
            server.shutdown()
            sys.exit(1)

        try:
            print("[*] Server is healthy and responding. Beginning test suite…\n")

            # 1. GET /api/health
            status, res = http_request(base_url, "GET", "/api/health")
            assert status == 200, f"Expected 200, got {status}: {res}"
            assert res.get("status") == "ok"
            assert res.get("model_available") is True
            print(f"[PASS] 1. GET  /api/health -> model={res.get('model_name')}, features={res.get('feature_count')}")

            # 2. POST /api/predict (Safe-looking URL)
            safe_url = "https://internal-docs.my-clean-domain.org/security/guide"
            status, res = http_request(base_url, "POST", "/api/predict", {"url": safe_url})
            assert status == 200, f"Expected 200, got {status}: {res}"
            assert res.get("prediction") in ("SAFE", "PHISHING")
            assert "score" in res
            assert "confidence" in res
            assert "threshold" in res
            print(f"[PASS] 2. POST /api/predict (Safe-looking) -> Prediction: {res.get('prediction')} ({res.get('confidence_str')})")

            # 3. POST /api/predict (Phishing-looking URL)
            phish_url = "http://192.168.1.105:8080/paypal-security-update/login.php"
            status, res = http_request(base_url, "POST", "/api/predict", {"url": phish_url})
            assert status == 200, f"Expected 200, got {status}: {res}"
            assert res.get("prediction") == "PHISHING"
            assert "explanation" in res
            assert isinstance(res["explanation"], list)
            print(f"[PASS] 3. POST /api/predict (Phishing-looking) -> Prediction: {res.get('prediction')} | SHAP Contribs: {len(res['explanation'])}")

            # 4. POST /api/predict-batch
            batch_urls = [
                "https://trusted-portal.service.com/account",
                "http://fake-appleid-confirm.xyz/auth",
            ]
            status, res = http_request(base_url, "POST", "/api/predict-batch", {"urls": batch_urls})
            assert status == 200, f"Expected 200, got {status}: {res}"
            assert res.get("total") == 2
            assert len(res.get("results", [])) == 2
            assert "summary" in res
            assert res["summary"]["safe_count"] + res["summary"]["phishing_count"] == 2
            print(f"[PASS] 4. POST /api/predict-batch -> Total: {res.get('total')}, Summary: {res.get('summary')}")

            # 5. GET /api/history
            status, res = http_request(base_url, "GET", "/api/history?limit=10&offset=0")
            assert status == 200, f"Expected 200, got {status}: {res}"
            assert res.get("total", 0) >= 3
            assert len(res.get("records", [])) >= 3
            assert "stats" in res
            print(f"[PASS] 5. GET  /api/history -> Total logged: {res.get('total')}, Records returned: {len(res.get('records', []))}")

            # 6. GET /api/model-metrics
            status, res = http_request(base_url, "GET", "/api/model-metrics")
            assert status == 200, f"Expected 200, got {status}: {res}"
            assert "test_metrics" in res
            assert "accuracy" in res["test_metrics"]
            assert "confusion_matrix" in res["test_metrics"]
            print(f"[PASS] 6. GET  /api/model-metrics -> Model: {res['test_metrics'].get('model_name')}, Test Acc: {res['test_metrics'].get('accuracy')}")

            # 7. Security Header Verification
            req = urllib.request.Request(f"{base_url}/api/health")
            with urllib.request.urlopen(req) as resp:
                headers = dict(resp.headers)
                assert headers.get("X-Content-Type-Options") == "nosniff"
                assert headers.get("X-Frame-Options") == "DENY"
                assert "Content-Security-Policy" in headers
            print("[PASS] 7. Security Headers -> X-Content-Type-Options, X-Frame-Options, CSP verified.")

            print("\n" + "=" * 70)
            print("ALL END-TO-END HTTP REST ENDPOINTS VERIFIED & WORKING PERFECTLY!")
            print("=" * 70)

        finally:
            print("[*] Gracefully shutting down live Flask server…")
            server.shutdown()
            server_thread.join(timeout=3.0)
            print("[*] Server shutdown complete.")


if __name__ == "__main__":
    main()
