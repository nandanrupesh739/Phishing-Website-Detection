# Changelog

All notable changes to the PhishGuard AI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-27

### Added
- **Phase 6: Tests, CI, Packaging & Documentation**
  - Comprehensive Pytest test suite with 168 tests achieving 96% line coverage on `backend/`.
  - Zero-network safety enforcement monkeypatch test preventing outbound requests on analyzed URLs.
  - Vitest + React Testing Library suite for frontend with 39 passing tests.
  - End-to-end smoke test script (`scripts/e2e_smoke.py`) testing live REST API on an ephemeral port.
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`) with Python 3.11/3.12 matrix, Node 20, and git leakage checks for datasets, models, databases, and secrets.
  - Containerization: `backend/Dockerfile` (`python:3.12-slim`, non-root user, no cache), `frontend/Dockerfile` (multi-stage Nginx), and `docker-compose.yml` with isolated internal backend network and healthchecks.
  - Documentation assets export script (`scripts/export_docs_assets.py`), MIT `LICENSE`, `SECURITY.md` (pickle trust advisory & threat model), `CONTRIBUTING.md`, and `Makefile`.
  - Complete, honest rewrite of `README.md` with verified metrics, architecture diagram, and limitations.
- **Phase 5: Frontend Quality & User Experience**
  - Robust states across all views: LoadingSkeleton, ErrorState with Retry, and EmptyState.
  - Persistent offline backend alert banner with automated health polling every 30 seconds.
  - TreeSHAP local feature attribution chart ("Why this result?") using Recharts.
  - Batch URL scanner with drag-and-drop file upload, live progress queue, and formula-injection-safe CSV export (CWE-1236).
  - Copy result summary and copy raw URL buttons with accessible tooltips.
  - Client-side URL character counter (up to 2,048 chars) with scheme validation.
  - Educational sample URLs for safe and phishing scenarios.
  - Accessibility enhancements: full keyboard navigation, `:focus-visible` outlines, ARIA live announcements, and WCAG AA dual-encoded visual cues.
- **Phase 4: Backend Hardening, Security & API Enhancements**
  - Rate limiting via `Flask-Limiter` enforcing 60 requests per minute per IP on prediction endpoints.
  - Protected `DELETE /api/history` requiring administrative secret header `X-Admin-Key`.
  - Batch prediction endpoint `POST /api/predict-batch` accepting up to 100 URLs while preserving order.
  - Privacy mode (`ANONYMIZE_URLS=true`) hashing URLs with SHA-256 before database persistence.
  - Security headers enforced via `after_request`: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP, and strict referrer policy.
  - Automatic SQLite schema migration adding missing columns without data loss.
  - Safe model loading preventing directory traversal attacks.
- **Phase 3: Honest Machine Learning Pipeline & Evaluation**
  - Strict 70/15/15 Domain-Grouped Split using `tldextract` ensuring 0 domain overlap between splits.
  - Character 3–5-gram TF-IDF subword vectorizer (20,000 features) combined with 42 tabular features.
  - 5-fold cross-validation comparing LightGBM, Random Forest, Logistic Regression, and Naive Bayes.
  - Probability calibration via `CalibratedClassifierCV(method="sigmoid", cv=3)` (Platt scaling).
  - Validation threshold tuning setting decision boundary to 0.9500 targeting >= 98% recall with 0 test false positives.
  - Real-time TreeSHAP contribution extraction (`booster_.predict(pred_contrib=True)`).
  - Diagnostic error analysis (`scripts/error_analysis.py`) and out-of-distribution evaluation harness (`scripts/external_eval.py`).
- **Phase 2: Lexical Feature Engineering & URL Normalization**
  - Canonical URL normalization function used identically in training and inference (stripping whitespace, removing `www.`, downcasing host, preserving paths/queries).
  - Bundled offline Public Suffix List integration via `tldextract` for domain, TLD, and subdomain parsing.
  - Brand impersonation detection flagging spoofed names in paths or subdomains of untrusted domains.
  - Scoped suspicious term matching to paths and subdomains.
  - 11 new structural features including `domain_num_digits`, `longest_token_length`, `domain_vowel_ratio`, `path_depth`, `has_double_extension`, `has_at_in_path`, `has_ip_in_path`.
- **Phase 1: Architecture & Critical Bug Fixes**
  - End-to-end unified label convention: `0 = SAFE` (legitimate) and `1 = PHISHING` across trainer, database, API, and UI.
  - Consolidated training pipeline into `train.py` with `backend/train_model.py` serving as a legacy compatibility adapter.
  - Hardened port parser handling invalid non-numeric or out-of-range ports without crashing (`http://host:abc`, `http://host:99999`).
  - Database scan history statistics counting `SAFE` and `PHISHING` records correctly.
  - JSON payload validation returning HTTP 400 Bad Request on malformed inputs.
