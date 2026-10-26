"""
End-to-end System Verification Test
===================================
Tests all backend REST endpoints and prediction logic:
1.  GET  /api/health
2.  GET  /api/model-info
3.  GET  /api/model-metrics
4.  POST /api/predict (Safe URL)
5.  POST /api/predict (Phishing URL with IP)
6.  POST /api/predict (Phishing URL with suspicious domain)
7.  POST /api/predict (Validation error: Missing URL)
8.  POST /api/predict (Validation error: Unsupported scheme)
9.  POST /api/predict (Validation error: Non-JSON body)
10. GET  /api/history
11. DELETE /api/history
12. GET  /api/history (after delete)
"""
import urllib.request
import urllib.error
import json
import sys

BASE = "http://127.0.0.1:5000"

def req(method: str, path: str, body=None, headers=None):
    if headers is None:
        headers = {}
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            data = body.encode("utf-8")
    request_obj = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request_obj) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def main():
    print("=" * 65)
    print("PHISHGUARD AI — FULL SYSTEM FUNCTIONALITY AUDIT")
    print("=" * 65)

    # 1. Health
    s, r = req("GET", "/api/health")
    assert s == 200 and r["status"] == "ok" and r["model_available"] is True
    print(f"[PASS] 1. GET /api/health -> status={r['status']}, model_name={r['model_name']}, features={r['feature_count']}")

    # 2. Model info
    s, r = req("GET", "/api/model-info")
    assert s == 200 and r["model_name"] == "XGBoost" and r["feature_count"] == 25
    print(f"[PASS] 2. GET /api/model-info -> model={r['model_name']}, v{r['model_version']}, dataset={r['dataset_size']:,}")

    # 3. Model metrics
    s, r = req("GET", "/api/model-metrics")
    assert s == 200 and "test_metrics" in r and "validation_comparison" in r and "feature_importances" in r
    print(f"[PASS] 3. GET /api/model-metrics -> accuracy={r['test_metrics']['test_accuracy']}, F1={r['test_metrics']['phishing_f1']}, models={list(r['validation_comparison'].keys())}")

    # 4. Predict Safe URL
    s, r = req("POST", "/api/predict", {"url": "https://www.github.com"})
    assert s == 200 and r["prediction"] == "SAFE" and r["risk_level"] == "LOW"
    print(f"[PASS] 4. POST /api/predict (Safe) -> {r['prediction']} | Confidence: {r['confidence']}% | Risk: {r['risk_level']}")

    # 5. Predict Phishing URL with IP
    s, r = req("POST", "/api/predict", {"url": "http://192.168.1.1/paypal/login.php?cmd=_login"})
    assert s == 200 and r["prediction"] == "PHISHING"
    print(f"[PASS] 5. POST /api/predict (Phish IP) -> {r['prediction']} | Confidence: {r['confidence']}% | Risk: {r['risk_level']} | Indicators: {len(r['indicators'])}")

    # 6. Predict Phishing URL with domain spoofing
    s, r = req("POST", "/api/predict", {"url": "http://signin-security-update-appleid.com/confirm.html"})
    assert s == 200 and r["prediction"] == "PHISHING"
    print(f"[PASS] 6. POST /api/predict (Phish Spoof) -> {r['prediction']} | Confidence: {r['confidence']}% | Risk: {r['risk_level']} | Indicators: {len(r['indicators'])}")

    # 7. Predict Validation: Missing URL
    s, r = req("POST", "/api/predict", {})
    assert s == 400
    print(f"[PASS] 7. POST /api/predict (Missing URL) -> Code: {s}, error: {r.get('error')}")

    # 8. Predict Validation: Bad scheme
    s, r = req("POST", "/api/predict", {"url": "javascript:alert(1)"})
    assert s == 400
    print(f"[PASS] 8. POST /api/predict (Unsupported Scheme) -> Code: {s}, error: {r.get('error')}")

    # 9. Predict Validation: Non-JSON body
    s, r = req("POST", "/api/predict", "raw text body", headers={"Content-Type": "text/plain"})
    assert s == 400
    print(f"[PASS] 9. POST /api/predict (Non-JSON) -> Code: {s}, error: {r.get('error')}")

    # 10. Scan History
    s, r = req("GET", "/api/history")
    assert s == 200 and r["total"] >= 3
    print(f"[PASS] 10. GET /api/history -> total scans={r['total']}, stats={r['stats']}")

    # 11. Clear History
    s, r = req("DELETE", "/api/history")
    assert s == 200 and "deleted_count" in r
    print(f"[PASS] 11. DELETE /api/history -> {r['message']}")

    # 12. Verify History Cleared
    s, r = req("GET", "/api/history")
    assert s == 200 and r["total"] == 0 and len(r["records"]) == 0
    print(f"[PASS] 12. GET /api/history (after delete) -> total scans={r['total']}")

    print("=" * 65)
    print("ALL 12 BACKEND & API FUNCTIONS VERIFIED AND WORKING 100%!")
    print("=" * 65)


if __name__ == "__main__":
    main()
