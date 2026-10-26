# PhishGuard AI — Phishing Website Detection System

<div align="center">

![PhishGuard AI](https://img.shields.io/badge/PhishGuard-AI-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**An educational machine learning system that detects phishing URLs using URL-structure features.**

[Quick Start](#quick-start) · [Architecture](#architecture) · [API Docs](#api-documentation) · [Testing](#testing)

</div>

> ⚠️ **Disclaimer**: This is an **educational project**. It is not a certified threat-intelligence product.
> Predictions are estimates based on URL structure only and must not be the sole basis for security decisions.
> New or targeted phishing attacks may evade the model.

---

## Problem Statement

Phishing attacks account for over 36% of all data breaches. Attackers create convincing fake websites that
mimic legitimate services to steal credentials and financial information. URL-structure analysis provides a
first line of defence — examining the URL before any network request is made, without loading the page or
executing JavaScript from potentially malicious sites.

## Objectives

- Demonstrate an end-to-end ML pipeline: dataset → features → model → REST API → dashboard
- Extract 25 interpretable URL-string features (no DNS / WHOIS / page content)
- Train and compare multiple classifiers; select by validation phishing F1-score
- Evaluate honestly on a held-out test set; never report training accuracy as test accuracy
- Prioritise phishing recall to minimise false negatives
- Build a professional, responsive cybersecurity dashboard

## Architecture

```mermaid
flowchart TD
    User["👤 User (Browser)"]
    Frontend["⚛️ React + Vite Frontend\nPort 5173"]
    Backend["🐍 Flask REST API\nPort 5000"]
    Features["🔬 Feature Extractor\nbackend/features.py\n25 URL-string features"]
    Model["🤖 ML Model\n(joblib Pipeline)\nmodels/"]
    DB["🗄️ SQLite\nScan History"]
    Reports["📊 Reports\nMetrics & Plots"]

    User -->|"Enter URL"| Frontend
    Frontend -->|"POST /api/predict"| Backend
    Backend --> Features
    Features --> Model
    Model -->|"Prediction + Score"| Backend
    Backend --> DB
    Backend -->|"JSON Result"| Frontend
    Frontend -->|"Show Result"| User
    Backend -->|"GET /api/model-metrics"| Reports
```

## Technology Stack

| Layer | Technology |
|-------|-----------|
| ML Framework | scikit-learn 1.4+, XGBoost 2.0+, LightGBM 4.0+, ucimlrepo |
| Data Processing | Pandas, NumPy |
| Model Persistence | Joblib |
| Visualisation | Matplotlib, Seaborn (training), Recharts (frontend) |
| Backend API | Flask 3, Flask-CORS |
| Database | SQLite (via stdlib sqlite3) |
| Frontend | React 18, Vite, TypeScript, Tailwind CSS 3 |
| Icons | Lucide React |
| Charts | Recharts |
| Testing | Pytest, Flask test client |

## Dataset

**PhiUSIIL Phishing URL Dataset** — UCI Machine Learning Repository

- **Records**: 235,795 URLs (235,370 after deduplication)
- **Source**: [https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
- **Label**: `1` = Legitimate, `0` = Phishing (Standardised to `0` = SAFE, `1` = PHISHING)
- **License**: CC BY 4.0

> **Citation**: Prasad, A., & Chandra, S. (2023). PhiUSIIL Phishing URL (Website) Dataset.
> UCI Machine Learning Repository. https://doi.org/10.24432/C59S6B

## URL Feature Engineering

25 features extracted from URL strings (no network requests):

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Total URL character length |
| 2 | `hostname_length` | Length of hostname component |
| 3 | `num_dots` | Number of dot characters |
| 4 | `num_hyphens` | Number of hyphen characters |
| 5 | `num_at_symbols` | Count of @ symbols |
| 6 | `num_digits` | Count of digit characters |
| 7 | `num_subdomains` | Number of subdomain levels above TLD |
| 8 | `path_length` | URL path length |
| 9 | `num_query_params` | Number of query parameters |
| 10 | `num_percent_encoded` | Number of `%XX` encoded sequences |
| 11 | `num_suspicious_chars` | Count of suspicious punctuation |
| 12 | `has_ip_hostname` | Hostname is an IP address (0/1) |
| 13 | `has_non_default_port` | Non-standard port specified (0/1) |
| 14 | `has_https` | HTTPS scheme used (0/1, not a safety indicator) |
| 15 | `is_url_shortener` | Known URL shortener service (0/1) |
| 16 | `has_suspicious_terms` | Keywords like `login`, `verify` present (0/1) |
| 17 | `has_repeated_separators` | Repeated `//`, `&&` etc. (0/1) |
| 18 | `has_long_hostname` | Hostname > 50 chars (0/1) |
| 19 | `hostname_entropy` | Shannon entropy of hostname (bits) |
| 20 | `digit_ratio` | Digit characters / total characters |
| 21 | `has_punycode` | `xn--` punycode in hostname (0/1) |
| 22 | `has_non_ascii_hostname` | Non-ASCII characters in hostname (0/1) |
| 23 | `has_at_before_host` | @ present in netloc (0/1) |
| 24 | `has_unusual_encoding` | High density of unusual encodings (0/1) |
| 25 | `num_special_chars` | Count of unusual special characters |

## Model Evaluation & Benchmark Results

### 1. 5-Fold Stratified Cross-Validation (Training Split)

Models were evaluated on the training split using 5-fold stratified cross-validation on the phishing class F1-score:

| Model | Mean F1 | Std F1 | Fit / CV Time |
| :--- | :---: | :---: | :---: |
| **XGBoost (Champion)** | **0.9948** | **±0.0003** | 10.6s |
| **Random Forest** | 0.9948 | ±0.0002 | 52.3s |
| **Naive Bayes (char TF-IDF)** | 0.9907 | ±0.0006 | 100.2s |
| **Logistic Regression** | 0.9871 | ±0.0007 | 7.2s |

### 2. Final Evaluation on Held-Out Test Set (20% Split, 47,074 URLs)

After tuning XGBoost with `RandomizedSearchCV` (25 iterations), the final production model was evaluated on the unseen held-out test set:

| Model | Accuracy | Precision (Phish) | Recall (Phish) | F1-Score | ROC-AUC | Fit Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost (Tuned)** | **99.58%** | **99.86%** | **99.16%** | **0.9951** | **0.9980** | 192.0s |
| **Random Forest** | 99.58% | 99.86% | 99.15% | 0.9950 | 0.9980 | 12.3s |
| **Naive Bayes (TF-IDF)** | 99.18% | 98.92% | 99.17% | 0.9905 | 0.9986 | 26.2s |
| **Logistic Regression** | 99.18% | 99.73% | 98.35% | 0.9904 | 0.9967 | 0.7s |

### 3. Held-Out Confusion Matrix (XGBoost)

$$\text{Total Test Samples} = 47,074$$

| Actual \ Predicted | Predicted Phishing (1) | Predicted Safe (0) | Total |
| :--- | :---: | :---: | :---: |
| **Actual Phishing (1)** | **19,938 (True Positive)** | 169 (False Negative) | 20,107 |
| **Actual Safe (0)** | 28 (False Positive) | **26,939 (True Negative)** | 26,967 |

- **Phishing Detection Rate (Recall)**: $99.16\%$ (19,938 of 20,107 phishing URLs caught)
- **False Positive Rate**: $0.10\%$ (only 28 false alarms out of 26,967 legitimate test URLs)

### 4. Feature Importance Analysis

Gradient-boosted decision tree feature importance breakdown:

| Rank | Feature | Importance | Interpretation |
| :---: | :--- | :---: | :--- |
| 1 | `has_https` | 50.94% | Strongest differentiator; plain HTTP is heavily associated with disposable phishing sites. |
| 2 | `path_length` | 39.03% | Long multi-directory paths typically host credential forms or deep redirect endpoints. |
| 3 | `num_digits` | 5.00% | Phishing URLs frequently contain IP octets or generated session tokens with numerical IDs. |
| 4 | `num_subdomains` | 1.31% | Deep subdomains (`login.account.verify...`) spoof trustworthy brand names. |
| 5 | `num_suspicious_chars` | 1.18% | Obfuscation markers and query delimiters (`@`, `%`, `=`, `&`). |

### 5. Live API Benchmark & Dataset Artifact Analysis

Testing 10 live URL variations against the active REST API:

| # | Type | URL | Prediction | Confidence | Risk Level |
| :-: | :--- | :--- | :---: | :---: | :---: |
| 1 | Legitimate | `https://www.google.com` | **SAFE** | 99.3% | LOW |
| 2 | Legitimate | `https://www.github.com` | **SAFE** | 99.7% | LOW |
| 3 | Legitimate | `https://en.wikipedia.org` | **SAFE** | 99.5% | LOW |
| 4 | Legitimate (College) | `https://www.stanford.edu` | **SAFE** | 99.5% | LOW |
| 5 | Variant Test | `https://github.com` (no `www`) | **PHISHING** | 99.2% | CRITICAL |
| 6 | Variant Test | `google.com` (bare domain) | **PHISHING** | 100.0% | CRITICAL |
| 7 | Malicious (IP host) | `http://192.168.1.100/secure/login.php` | **PHISHING** | 100.0% | CRITICAL |
| 8 | Malicious (Spoof) | `http://paypal-account-verification.security-update-2026.com/login/verify.php` | **PHISHING** | 100.0% | CRITICAL |
| 9 | Malicious (@ trick) | `http://user:password@malicious-bank-login.xyz/account/confirm` | **PHISHING** | 100.0% | CRITICAL |
| 10 | Malicious (Odd TLD) | `http://apple-id-suspended.support-center.top/recovery/auth.html` | **PHISHING** | 100.0% | CRITICAL |

> [!NOTE]
> **Why do bare domains like `github.com` or `google.com` trigger a false alarm?**  
> In the PhiUSIIL dataset, 100% of the legitimate training URLs were collected as canonical root homepages starting with `https://www.`. Conversely, bare URLs (`google.com`) or URLs without `www.` (`github.com`) match feature patterns that the tree models heavily associate with short-lived phishing sites (which rarely register and configure `www.` subdomains). Prepending `https://www.` immediately restores safe classification (>99.5%).

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- PowerShell (Windows)

### 1. Clone and Set Up

```powershell
# Navigate to project directory
cd "c:\Users\homeo\Desktop\Projects\Phishing-Website-Detection"

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# If you get a policy error, run first:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install Python dependencies
pip install -r requirements.txt

# Copy environment template
Copy-Item .env.example .env
```

### 2. Download the Dataset

**Option A (Automated via script):**
```powershell
python download_data.py
```

**Option B (Manual download):**
1. Visit: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. Click **Download** and extract the ZIP file
3. Place the CSV in the `data/` directory as `phishing_dataset.csv`:

```
data/
  phishing_dataset.csv  ← Place here
```

### 3. Train the Model

```powershell
# Ensure venv is active
.\.venv\Scripts\Activate.ps1

# Run 4-model training, 5-fold CV, and hyperparameter tuning pipeline
python train.py
```

This will:
- Load, deduplicate, and clean the dataset (235,370 URLs)
- Extract 25 URL features with progress indicators
- Run 5-fold stratified cross-validation on 4 candidate models
- Tune the best model (XGBoost) with `RandomizedSearchCV`
- Evaluate on the held-out test set
- Save artifacts to `models/model.pkl` and `models/phishguard_model.joblib`
- Save metrics to `models/model_metrics.json`
- Save plots and reports to `reports/`

### 4. Start the Backend

```powershell
# In a new PowerShell terminal (with venv active)
.\.venv\Scripts\Activate.ps1
python -m backend.app

# Backend runs at: http://127.0.0.1:5000
```

### 5. Start the Frontend

```powershell
# In another new PowerShell terminal
cd frontend
npm install
npm run dev

# Frontend runs at: http://localhost:5173
```

Open http://localhost:5173 in your browser.

## API Documentation

Base URL: `http://127.0.0.1:5000`

### GET /api/health

```json
{
  "status": "ok",
  "model_available": true,
  "model_name": "XGBoost",
  "model_version": "1.0.0",
  "feature_count": 25
}
```

### POST /api/predict

**Request:**
```json
{ "url": "http://192.168.1.1/login" }
```

**Response:**
```json
{
  "url": "http://192.168.1.1/login",
  "prediction": "PHISHING",
  "risk_level": "CRITICAL",
  "score": 0.9234,
  "score_type": "model_probability",
  "indicators": [
    "Hostname is an IP address (not a domain name)",
    "URL path or query contains suspicious keyword(s)"
  ],
  "features": { "url_length": 25.0, "has_ip_hostname": 1.0, ... },
  "disclaimer": "This is a machine-learning estimate..."
}
```

### GET /api/history

Query params: `?limit=50&offset=0`

### DELETE /api/history

Permanently clears all local scan history.

### GET /api/model-metrics

Returns saved training evaluation metrics.

### GET /api/model-info

Returns model metadata (name, version, feature count, training timestamp).

## Testing

```powershell
# Activate venv
.\.venv\Scripts\Activate.ps1

# Run all tests
python -m pytest

# With coverage report
python -m pytest --cov=backend --cov-report=term-missing
```

Test coverage:
- `test_features.py` — 20 test classes, all 25 features tested
- `test_predictor.py` — Validation, risk mapping, mock model response structure
- `test_api.py`       — All 6 endpoints, edge cases, error handling

## Project Structure

```
phishing-website-detection/
├── backend/
│   ├── __init__.py
│   ├── app.py           — Flask REST API (6 endpoints)
│   ├── config.py        — Centralised configuration
│   ├── database.py      — SQLite scan history
│   ├── features.py      — URL feature extraction (25 features)
│   ├── predictor.py     — Prediction service
│   ├── train_model.py   — Full training pipeline
│   └── tests/
│       ├── test_features.py
│       ├── test_predictor.py
│       └── test_api.py
├── frontend/
│   ├── src/
│   │   ├── pages/       — Dashboard, Scanner, History, Performance, About
│   │   ├── services/    — API client
│   │   ├── types/       — TypeScript interfaces
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── package.json
│   └── vite.config.ts
├── data/
│   └── README.md        — Dataset download instructions
├── models/              — Saved model and metadata (gitignored)
├── reports/             — Evaluation plots (gitignored)
├── .env.example
├── .gitignore
├── pytest.ini
├── requirements.txt
└── README.md
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| PowerShell execution policy error | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `Model file not found` error | Run `python -m backend.train_model` first |
| Dataset not found | Download CSV to `data/phishing_dataset.csv` |
| Port 5000 in use | Change `FLASK_PORT` in `.env` |
| Port 5173 in use | Change `server.port` in `frontend/vite.config.ts` |
| `npm install` fails | Check Node.js version ≥ 18; retry with `npm install --legacy-peer-deps` |
| Import errors during training | Ensure venv is activated and run from project root |

## Limitations

- **URL-structure only**: No DNS, WHOIS, page content, or screenshots are used
- **Model drift**: Trained on a static dataset; new attack patterns may evade the model
- **Not a security product**: Never use as the sole basis for security decisions
- **Adversarial URLs**: Attackers who know the features can craft evasive URLs

## Future Scope

- Optional DNS / WHOIS enrichment (configurable, with explicit user consent)
- Integration with VirusTotal or Google Safe Browsing API
- SHAP-based local explanation of individual predictions
- Model retraining pipeline with periodic phishing feed updates
- Browser extension for real-time URL checking
- User feedback loop for false positive / false negative correction

## License

**Code**: MIT License — see LICENSE file
**Dataset**: CC BY 4.0 — Attribution required (see Dataset section)

---
*Built as an educational demonstration of machine learning applied to cybersecurity.*
