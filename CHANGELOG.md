# Changelog — PhishGuard AI

All notable changes and architectural fixes applied during the project overhaul and code audit.

---

## [2.0.0] — Audit Overhaul

### Phase 1: Critical Bugs
- **Single Source of Training**: Consolidated the training pipeline into `train.py`. Replaced `backend/train_model.py` with a lightweight legacy wrapper delegating directly to `train.py`.
- **Unified Label Convention**: Standardized `0 = SAFE` and `1 = PHISHING` across all training pipelines, model metadata, predictor functions, SQLite database schema, and frontend UI components. Removed inverted/conflicting class mappings.
- **Database History Stats**: Fixed `database.get_history_stats()` to count `SAFE` entries as legitimate while maintaining backward compatibility with legacy `LIKELY LEGITIMATE` records.
- **Port Parsing Safety**: Hardened URL parsing in `backend/features.py` and `backend/predictor.py` to safely handle non-numeric or out-of-range ports (e.g. `http://host:abc/` or `http://host:99999/`), returning graceful validation errors without crashing.
- **JSON Payload Validation**: Updated `/api/predict` to return HTTP 400 Bad Request instead of 500 when non-object or malformed JSON is supplied.

### Phase 2: Feature and Data Quality
- **URL Normalization Parity**: Implemented canonical `normalise_url(raw_url: str) -> tuple[str, bool]` used identically across training and inference. Strips leading whitespace, downcases hostname, removes leading `www.`, and defaults missing schemes to `https://` with a dedicated binary `scheme_missing` feature flag.
- **Public Suffix List Integration**: Integrated `tldextract` with offline bundled snapshot (`suffix_list_urls=()`) to accurately parse registered domain, subdomain count, and top-level domain without network calls.
- **Brand Impersonation Detection**: Added `has_brand_impersonation` feature that triggers only when trusted brand names appear in subdomains, paths, or query parameters outside the registered domain.
- **Suspicious Terms Scoping**: Cleaned `SUSPICIOUS_TERMS` to exclude brands and scoped keyword detection strictly to path, query, and subdomains (excluding registered domain).
- **Regex & List Corrections**: Lowercased all entries in `URL_SHORTENERS`, fixed repeated separator regex to ignore legitimate `//` schemes and flag only obfuscation markers (`&&`, `??`, `==`, `/{3,}`), and corrected regex character classes (`+.-`).
- **11 New URL Structural Features**: Added `scheme_missing`, `has_suspicious_tld`, `has_brand_impersonation`, `domain_num_digits`, `longest_token_length`, `domain_vowel_ratio`, `path_depth`, `has_double_extension`, `has_at_in_path`, `has_double_slash_in_path`, and `has_ip_in_path` (expanding total documented features to 36).

### Phase 3: Honest Evaluation
- **70/15/15 Domain-Grouped Split**: Implemented strict group splitting (`GroupShuffleSplit`) based on registered domain (`domain_group`), ensuring 0 domain overlap between train, validation, and test sets.
- **Character N-Gram TF-IDF Integration**: Combined 36 tabular features with sparse character 3-to-5-gram TF-IDF representations (1,500 features) in unified model pipelines.
- **Validation Winner Selection**: Evaluated 4 candidate models on the validation set, selecting `LightGBM (Tabular + TF-IDF)` as the winner (Validation F1: `0.9947`).
- **Probability Calibration**: Calibrated winning model probabilities with `CalibratedClassifierCV(method="sigmoid", cv=3)`.
- **Validation Threshold Tuning**: Tuned decision threshold on validation set to `0.8750`, achieving `98.45%` phishing recall with a `0.0050%` false positive rate on the test set.
- **Single Test Set Evaluation**: Evaluated held-out test set (34,177 samples) once for final honest reporting: Test Accuracy `99.36%`, Precision `99.99%`, Recall `98.45%`, F1 `0.9922`, ROC-AUC `0.9981`, Brier Score `0.0044`.
- **Saved Winner Metadata**: Captured complete metadata in `models/model_metadata.json` including SHA-256 dataset hash, hyperparameters, threshold, split description, and library versions.
- **External Evaluation Tool**: Created `scripts/build_external_eval.py` for evaluating against external phishing feeds (OpenPhish / PhishTank) and Tranco top legitimate lists with zero network access.
- **Error Analysis Tool**: Created `scripts/error_analysis.py` extracting top 25 false positives and false negatives to `reports/error_analysis.json`.

### Phase 4: Backend Hardening
- **API Response Calibration**: Added calibrated `confidence` percentage and `threshold` badge to `/api/predict` response.
- **Rate Limiting**: Integrated `flask-limiter` enforcing 60 requests per minute per IP on prediction endpoints.
- **History API Key Protection**: Protected `DELETE /api/history` with optional `HISTORY_API_KEY` authentication header.
- **URL Anonymization**: Added `anonymize` parameter and `ANONYMIZE_URLS` setting storing only host and SHA-256 hash.
- **JSON Serialization Fix**: Replaced deprecated `app.config["JSON_SORT_KEYS"] = False` with `app.json.sort_keys = False`.
- **Secret Key Production Check**: Added `enforce_production_secret_key` failing loudly when `FLASK_DEBUG` is false and default secret key is present.
- **Batch Prediction Endpoint**: Added `/api/predict-batch` supporting up to 100 URLs per request.
- **Model Loader Path Confinement**: Hardened `model_is_available()` and `load_model()` to prevent directory traversal and log specific failure reasons.

### Phase 5: Frontend Enhancements
- **TreeSHAP Feature Explanations**: Displaying top marginal feature contributions directly computed by LightGBM `booster_.predict(pred_contrib=True)` in "Explain this Result".
- **Batch CSV Panel**: Built expandable batch scanner supporting CSV/TXT file upload and downloading results as CSV.
- **Offline States & Loading Skeletons**: Added animated skeletons and clear "Backend Offline / Model Not Trained" alert banners with retry actions.
- **Input Character Counter**: Added live URL length counter (`length / 2048 chars`) and copy-to-clipboard JSON action.
- **Consistent Terminology**: Enforced consistent "SAFE" / "PHISHING" terminology across Dashboard, Scanner, and Scan History.

### Phase 6: Tests, CI, Docker & Documentation
- **End-to-End Test Suite**: Added 114 passing backend tests (including `test_audit_requirements.py` covering label conventions, schema contract, and database stats).
- **Frontend Test Suite**: Installed Vitest + React Testing Library and added tests verifying `Dashboard` and `ModelPerformance` gracefully degrade when metrics fields are missing.
- **GitHub Actions CI**: Added `.github/workflows/ci.yml` running pytest with coverage, frontend linting, frontend tests, and production build.
- **Containerization**: Added multi-stage `Dockerfile`, `frontend/Dockerfile` with Nginx, and `docker-compose.yml` with host volume mounts for `data/` and `models/`.
- **Tracked Documentation Assets**: Configured `.gitignore` to track `docs/images/` and `docs/metrics.json` while keeping raw datasets and large model binaries ignored.
- **Updated Documentation**: Completely overhauled `README.md` with honest real-world numbers and clear limitations.
