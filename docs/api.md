# PhishGuard AI — REST API Documentation

Base URL: `http://localhost:5000/api` (or proxied via Vite/Nginx under `/api`)

All requests and responses use JSON. PhishGuard AI never connects to, fetches, or visits target URLs. URLs are parsed purely as offline text strings.

---

## Authentication & Headers

| Header | Description | Required |
| ------ | ----------- | -------- |
| `Content-Type: application/json` | Required on `POST` requests | Yes |
| `X-Admin-Key: <key>` | Required on `DELETE /api/history` | For deletion |

Security headers included automatically on all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## Rate Limiting

- **Predict Endpoints**: Limited to `60 requests per minute` per client IP.
- When exceeded, the API returns HTTP `429 Too Many Requests`.

---

## Endpoints

### 1. `GET /api/health`
Check server status, loaded model name, feature count, and database connectivity.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_name": "LightGBM (Tabular + TF-IDF)",
  "features_count": 42,
  "app_version": "1.1.0",
  "model_version": "1.1.0",
  "database_connected": true
}
```

---

### 2. `POST /api/predict`
Analyze a single URL and return classification, calibrated confidence, risk score, and SHAP explainability attributions.

**Request Body**:
```json
{
  "url": "https://secure-login.paypal.com.verify-account.info/login",
  "anonymize": false
}
```

**Response `200 OK`**:
```json
{
  "prediction": "PHISHING",
  "confidence": 98.4,
  "score": 0.984,
  "risk_level": "high",
  "indicators": [
    "Brand impersonation detected",
    "Suspicious security keyword detected",
    "High URL length"
  ],
  "explanations": [
    {
      "feature": "has_brand_impersonation",
      "value": 1.0,
      "shap_value": 0.42,
      "contribution": "increases risk"
    }
  ],
  "features": {
    "url_length": 65,
    "has_https": 1
  },
  "model_name": "LightGBM (Tabular + TF-IDF)",
  "calibrated": true,
  "decision_threshold": 0.95
}
```

---

### 3. `POST /api/predict-batch`
Analyze up to 100 URLs in a single request. Maintains input order.

**Request Body**:
```json
{
  "urls": [
    "https://github.com/security",
    "http://suspicious-billing.com/update"
  ],
  "anonymize": false
}
```

**Response `200 OK`**:
```json
{
  "results": [
    {
      "url": "https://github.com/security",
      "prediction": "SAFE",
      "confidence": 99.2,
      "risk_level": "low"
    },
    {
      "url": "http://suspicious-billing.com/update",
      "prediction": "PHISHING",
      "confidence": 96.5,
      "risk_level": "high"
    }
  ],
  "summary": {
    "total": 2,
    "safe_count": 1,
    "phishing_count": 1,
    "error_count": 0
  }
}
```

---

### 4. `GET /api/history`
Retrieve paginated scan history and summary statistics.

**Query Parameters**:
- `limit` (integer, default: 50, max: 200)
- `offset` (integer, default: 0)

**Response `200 OK`**:
```json
{
  "scans": [
    {
      "id": 1,
      "url": "https://github.com/security",
      "prediction": "SAFE",
      "confidence": 99.2,
      "risk_level": "low",
      "indicators": [],
      "timestamp": "2026-10-27T10:00:00Z"
    }
  ],
  "total": 1,
  "stats": {
    "total_scans": 1,
    "phishing_count": 0,
    "safe_count": 1,
    "phishing_percentage": 0.0
  }
}
```

---

### 5. `DELETE /api/history`
Clear scan history. Requires administrative authorization.

**Headers**:
- `X-Admin-Key: <ADMIN_API_KEY>`

**Response `200 OK`**:
```json
{
  "message": "Scan history cleared successfully",
  "deleted_count": 42
}
```

---

### 6. `GET /api/model-metrics`
Returns validation comparison, held-out test evaluation, calibration statistics, and feature importances.

**Response `200 OK`**:
Returns the full metrics payload matching `docs/metrics.json`.

---

### 7. `GET /api/features`
Returns the complete list of 42 lexical feature names extracted by the analyzer.
