# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

---

## Reporting a Vulnerability

We take the security of PhishGuard AI seriously. If you discover a security vulnerability or potential threat vector, please report it responsibly:

1. **Do not create public GitHub issues** for security vulnerabilities.
2. Submit a private report via **[GitHub Security Advisories](https://github.com/nandanrupesh739/Phishing-Website-Detection/security/advisories/new)** or contact the maintainers directly.
3. Include detailed steps to reproduce the vulnerability, including sample requests, environment details, and proof-of-concept scripts.
4. We acknowledge receipt within **48 hours** and aim to provide a remediation plan within **7 business days**.

---

## Scope & Security Architecture

### 1. Zero-Network URL Safety Guarantee
- PhishGuard AI is strictly an **offline, static lexical feature analyzer**.
- The backend **never makes network calls** (HTTP/HTTPS, socket connections, DNS resolutions, WHOIS queries) to any submitted URL.
- All URL inputs are treated as inert strings.
- Frontend links are rendered as plain text spans with copy buttons—never clickable `<a>` hyperlinks—preventing accidental navigation or drive-by downloads.

### 2. Model Deserialization & Pickle Trust Warning
> [!CAUTION]
> **Pickle and Joblib files can execute arbitrary code upon deserialization.**
- PhishGuard loads pre-trained machine learning weights via `joblib.load()` / `pickle.load()`.
- **Never load model files (`phishguard_model.joblib`, `model.pkl`) from untrusted, unknown, or public sources.**
- Model files must only be trained locally using `python train.py` or downloaded from verified, cryptographically signed release artifacts.
- In production containers, model volumes should be mounted read-only (`:ro`).

### 3. API Hardening & Access Control
- **Rate Limiting**: The public `/api/predict` and `/api/predict-batch` endpoints are protected by IP-based rate limits (default: 60 requests per minute).
- **Request Size & Batch Caps**: Payloads are restricted to `MAX_CONTENT_LENGTH = 1MB` and batch scanning is limited to 100 URLs per request.
- **Administrative Endpoints**: `DELETE /api/history` requires the `X-Admin-Key` header matching `ADMIN_API_KEY`.
- **Security Headers**: Standard OWASP-recommended security headers are enforced on all responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self'`
  - `Referrer-Policy: strict-origin-when-cross-origin`

### 4. Educational & Research Scope
PhishGuard AI is designed as an educational and research project demonstrating machine learning classification on lexical URL features. It is not an enterprise boundary firewall, web gateway, or antimalware solution. Deploying this system in mission-critical environments should only be done as a complementary layer alongside TLS inspection, dynamic sandbox execution, and domain reputation telemetry.
