"""
PhishGuard AI — Application Configuration
==========================================
Centralised settings loaded from environment variables.
All sensitive values must be set in the .env file (never committed to git).
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# ──────────────────────────────────────────────
# Root paths
# ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent  # project root
load_dotenv(BASE_DIR / ".env")

# ──────────────────────────────────────────────
# Data paths
# ──────────────────────────────────────────────
DATA_DIR = BASE_DIR / "data"
DATA_PATH = DATA_DIR / os.getenv("DATASET_FILENAME", "phishing_dataset.csv")

# ──────────────────────────────────────────────
# Model / artefact paths
# ──────────────────────────────────────────────
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "phishguard_model.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
METRICS_PATH = MODELS_DIR / "model_metrics.json"

# ──────────────────────────────────────────────
# Reports
# ──────────────────────────────────────────────
REPORTS_DIR = BASE_DIR / "reports"

# ──────────────────────────────────────────────
# SQLite database
# ──────────────────────────────────────────────
DB_PATH = BASE_DIR / os.getenv("DB_FILENAME", "phishguard.db")

# ──────────────────────────────────────────────
# Flask settings
# ──────────────────────────────────────────────
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")

# ──────────────────────────────────────────────
# CORS
# ──────────────────────────────────────────────
# Comma-separated list of allowed origins, e.g. "http://localhost:5173"
_raw_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
CORS_ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ──────────────────────────────────────────────
# API limits & Security
# ──────────────────────────────────────────────
MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
HISTORY_PAGE_SIZE = int(os.getenv("HISTORY_PAGE_SIZE", "50"))
RATE_LIMIT_PREDICT = os.getenv("RATE_LIMIT_PREDICT", "60 per minute")
MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "100"))
HISTORY_API_KEY = os.getenv("HISTORY_API_KEY", "")
ANONYMIZE_URLS = os.getenv("ANONYMIZE_URLS", "false").lower() == "true"

# ──────────────────────────────────────────────
# Training hyper-parameters (fixed seeds)
# ──────────────────────────────────────────────
RANDOM_SEED = 42
TRAIN_SIZE = 0.70
VAL_SIZE   = 0.15
TEST_SIZE  = 0.15

# ──────────────────────────────────────────────
# Feature extraction constants
# ──────────────────────────────────────────────
# Configurable list of known URL-shortening service hostnames (all lowercase)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "adf.ly", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im",
    "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com",
    "short.to", "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com",
    "snipr.com", "fic.kr", "loopt.us", "doiop.com", "twitthis.com",
    "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do",
    "lnkd.in", "db.tt", "qr.ae", "x.co", "prettylinkpro.com", "dlvr.it",
    "fur.ly", "ity.im", "q.gs", "po.st", "bc.vc", "twurl.cc",
    "n.pr", "abcurl.net", "p6l.org", "shorte.st", "mcaf.ee",
    "rb.gy", "cutt.ly", "shorturl.at", "clck.ru", "u.to",
}

# Suspicious terms that commonly appear in phishing URLs (excluding brand names)
SUSPICIOUS_TERMS = {
    "login", "verify", "update", "secure", "account", "password",
    "confirm", "banking", "signin", "sign-in", "webscr", "redirect",
    "validation", "wallet", "credential", "suspended", "unusual",
    "activity", "alert", "notification", "support", "helpdesk",
    "recover", "unlock", "authorize", "authenticate", "billing", "security",
}

# Known brand names monitored for brand impersonation outside registered domain
KNOWN_BRANDS = {
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "chase", "wellsfargo", "bankofamerica", "citibank",
    "ebay", "instagram", "whatsapp", "twitter", "linkedin", "dropbox",
    "yahoo", "outlook", "icloud", "binance", "coinbase", "steam",
    "walmart", "irs", "usps", "dhl", "fedex",
}

# TLDs disproportionately associated with phishing and malicious registrations
SUSPICIOUS_TLDS = {
    "xyz", "top", "gq", "tk", "ml", "cf", "ga", "buzz", "club",
    "work", "shop", "icu", "vip", "fit", "live", "link", "guru",
    "surf", "casa", "loan", "men", "country", "stream", "download",
    "racing", "win", "bid", "party", "date", "faith", "review",
    "trade", "cricket", "accountant", "science",
}

# Hostname length threshold for "unusually long hostname"
LONG_HOSTNAME_THRESHOLD = 50

# ──────────────────────────────────────────────
# Model version tag (updated each training run)
# ──────────────────────────────────────────────
MODEL_VERSION = "1.0.0"
