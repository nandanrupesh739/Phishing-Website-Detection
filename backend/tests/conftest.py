"""
PhishGuard AI — Global Pytest Fixtures
======================================
Provides lightweight synthetic models, datasets, and isolated configurations
so that the test suite runs completely independently of real dataset files
or pre-trained models.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import joblib
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import scipy.sparse

import backend.config as config
from backend.features import FEATURE_NAMES, normalize_url, extract_url_features, features_to_vector
import backend.predictor as predictor_module
import backend.database as database_module


@pytest.fixture(scope="session")
def synthetic_model_dir(tmp_path_factory) -> Path:
    """
    Train a tiny synthetic model bundle and save it to a temporary directory.
    Guarantees that test suites can run without real data/ or models/ on disk.
    """
    tmp_dir = tmp_path_factory.mktemp("synthetic_models")
    model_file = tmp_dir / "phishguard_model.joblib"
    metadata_file = tmp_dir / "model_metadata.json"
    metrics_file = tmp_dir / "model_metrics.json"

    # Synthetic training sample URLs (10 safe, 10 phishing)
    urls = [
        # Safe
        "https://google.com",
        "https://github.com",
        "https://wikipedia.org",
        "https://python.org",
        "https://microsoft.com",
        "https://apple.com",
        "https://amazon.com",
        "https://mozilla.org",
        "https://stackoverflow.com",
        "https://cloudflare.com",
        # Phishing
        "http://paypal-verification-update.com/login",
        "http://192.168.1.100:8080/secure/bank",
        "http://apple-id-verify.account-security.xyz",
        "http://wellsfargo-security-alert.net/auth",
        "http://amazon-account-suspended.top/signin",
        "http://chase-online-login.info/verify",
        "http://netflix-billing-update.club/pay",
        "http://microsoft-outlook-office365.biz/login",
        "http://secure-banking-portal.cc/credentials",
        "http://login-update-account.vip/portal",
    ]
    # 0 = SAFE, 1 = PHISHING
    y = np.array([0] * 10 + [1] * 10, dtype=int)

    # Extract 42 structural features
    tld_freq = {".com": 0.6, ".org": 0.2, ".xyz": 0.05, ".top": 0.05, ".net": 0.1}
    X_feats = [features_to_vector(extract_url_features(u, tld_freq_map=tld_freq)) for u in urls]
    X_mat = np.array(X_feats, dtype=np.float32)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_mat)

    norm_urls = [normalize_url(u) for u in urls]
    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=100)
    X_tfidf = tfidf.fit_transform(norm_urls)

    X_combined = scipy.sparse.hstack([X_scaled, X_tfidf])

    # Train tiny logistic regression model
    clf = LogisticRegression(random_state=42, max_iter=200)
    clf.fit(X_combined, y)

    # Save bundle
    bundle = {
        "model": clf,
        "scaler": scaler,
        "vectorizer": tfidf,
        "feature_names": FEATURE_NAMES,
        "threshold": 0.50,
        "tld_freq_map": tld_freq,
        "target_mapping": {0: "SAFE", 1: "PHISHING"},
        "model_name": "SyntheticTestModel",
        "model_version": "1.0.0-synthetic",
        "trained_at": "2026-01-01T00:00:00Z",
    }
    joblib.dump(bundle, model_file)

    metadata = {
        "model_name": "SyntheticTestModel",
        "model_version": "1.0.0-synthetic",
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "dataset_source": "Synthetic Testing Dataset",
        "dataset_size": len(urls),
        "label_distribution": {"0": 10, "1": 10},
        "target_mapping": {0: "SAFE", 1: "PHISHING"},
        "class_mapping": {"0": "SAFE", "1": "PHISHING"},
        "decision_threshold": 0.50,
        "target_phishing_recall": 0.98,
        "split_description": "Synthetic test fixture",
        "library_versions": {"scikit-learn": "1.4.0"},
        "trained_at": "2026-01-01T00:00:00Z",
    }
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    metrics = {
        "test_metrics": {
            "model_name": "SyntheticTestModel",
            "accuracy": 1.0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "roc_auc": 1.0,
            "average_precision": 1.0,
            "brier_score": 0.01,
            "false_positive_rate": 0.0,
            "confusion_matrix": [[10, 0], [0, 10]],
        },
        "validation_comparison": {
            "SyntheticTestModel": {
                "accuracy": 1.0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "roc_auc": 1.0,
            }
        },
        "feature_importances": [
            {"feature": name, "importance": float(abs(clf.coef_[0][i]))}
            for i, name in enumerate(FEATURE_NAMES[:10])
        ],
        "dataset_source": "Synthetic Testing Dataset",
        "dataset_size": len(urls),
        "label_distribution": {"0": 10, "1": 10},
        "decision_threshold": 0.50,
    }
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return tmp_dir


@pytest.fixture(autouse=True)
def setup_test_environment(synthetic_model_dir, monkeypatch, tmp_path):
    """
    Automatically activate synthetic models and temp database if real models/ or db are absent,
    ensuring isolated tests everywhere.
    """
    # If real model does not exist, point to synthetic model
    if not config.MODEL_PATH.exists():
        monkeypatch.setattr(config, "MODELS_DIR", synthetic_model_dir)
        monkeypatch.setattr(config, "MODEL_PATH", synthetic_model_dir / "phishguard_model.joblib")
        monkeypatch.setattr(config, "METADATA_PATH", synthetic_model_dir / "model_metadata.json")
        monkeypatch.setattr(config, "METRICS_PATH", synthetic_model_dir / "model_metrics.json")
        monkeypatch.setattr(predictor_module, "MODELS_DIR", synthetic_model_dir)
        monkeypatch.setattr(predictor_module, "MODEL_PATH", synthetic_model_dir / "phishguard_model.joblib")
        monkeypatch.setattr(predictor_module, "METADATA_PATH", synthetic_model_dir / "model_metadata.json")
        monkeypatch.setattr(predictor_module, "METRICS_PATH", synthetic_model_dir / "model_metrics.json")
        predictor_module._model = None
        predictor_module._bundle = None
        predictor_module._scaler = None
        predictor_module._vectorizer = None
        predictor_module._metadata = None
        predictor_module._metrics = None
