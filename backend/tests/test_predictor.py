"""
Tests for backend/predictor.py — Prediction Service

Tests validate:
  - URL validation logic
  - ModelNotFoundError when model is absent
  - Response structure when model is present (mocked)
  - Risk level mapping

No real URLs are visited. No real model file is required for validation tests.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.predictor import (
    ModelNotFoundError,
    _map_risk_level,
    validate_url,
)


# ---------------------------------------------------------------------------
# URL Validation
# ---------------------------------------------------------------------------

class TestValidateUrl:
    def test_valid_http_url(self):
        ok, err = validate_url("http://example.com")
        assert ok is True
        assert err == ""

    def test_valid_https_url(self):
        ok, err = validate_url("https://www.google.com/search?q=test")
        assert ok is True

    def test_url_without_scheme_accepted(self):
        # Predictor normalises missing scheme
        ok, err = validate_url("example.com/path")
        assert ok is True

    def test_empty_string_rejected(self):
        ok, err = validate_url("")
        assert ok is False
        assert err != ""

    def test_none_rejected(self):
        ok, err = validate_url(None)  # type: ignore[arg-type]
        assert ok is False

    def test_whitespace_only_rejected(self):
        ok, err = validate_url("   ")
        assert ok is False

    def test_too_long_url_rejected(self):
        url = "http://example.com/" + "a" * 3000
        ok, err = validate_url(url)
        assert ok is False
        assert "length" in err.lower() or "exceed" in err.lower()

    def test_javascript_scheme_rejected(self):
        ok, err = validate_url("javascript:alert(1)")
        assert ok is False

    def test_data_scheme_rejected(self):
        ok, err = validate_url("data:text/html,<h1>hi</h1>")
        assert ok is False

    def test_file_scheme_rejected(self):
        ok, err = validate_url("file:///etc/passwd")
        assert ok is False

    def test_url_with_ip_address_valid(self):
        ok, err = validate_url("http://192.168.1.1/phish")
        assert ok is True

    def test_ftp_url_valid(self):
        ok, err = validate_url("ftp://files.example.com/data.zip")
        assert ok is True

    def test_punycode_url_valid(self):
        ok, err = validate_url("http://xn--nxasmq6b.com")
        assert ok is True


# ---------------------------------------------------------------------------
# Risk Level Mapping
# ---------------------------------------------------------------------------

class TestRiskLevelMapping:
    def test_high_confidence_phishing(self):
        assert _map_risk_level(0.95, 1) == "CRITICAL"

    def test_medium_confidence_phishing(self):
        assert _map_risk_level(0.65, 1) == "HIGH"

    def test_low_confidence_phishing(self):
        assert _map_risk_level(0.45, 1) == "MEDIUM"

    def test_legitimate_always_low(self):
        assert _map_risk_level(0.9, 0) == "LOW"
        assert _map_risk_level(0.5, 0) == "LOW"
        assert _map_risk_level(0.1, 0) == "LOW"


# ---------------------------------------------------------------------------
# ModelNotFoundError when model is missing
# ---------------------------------------------------------------------------

class TestModelNotFound:
    def test_load_model_raises_when_absent(self):
        """Patching model paths to non-existent files should raise ModelNotFoundError."""
        import backend.predictor as pred_module

        # Reset cached model
        pred_module._model = None

        fake_path = Path("/nonexistent/path/model.pkl")
        fake_joblib = Path("/nonexistent/path/model.joblib")
        with patch.object(pred_module, "MODEL_PKL_PATH", fake_path), \
             patch.object(pred_module, "MODEL_PATH", fake_joblib):
            with pytest.raises(ModelNotFoundError):
                pred_module.load_model(force_reload=True)


# ---------------------------------------------------------------------------
# predict_url with mocked model
# ---------------------------------------------------------------------------

class TestPredictUrlWithMockedModel:
    """Use a mock pipeline to test predict_url response structure."""

    @pytest.fixture(autouse=True)
    def mock_pipeline(self):
        import backend.predictor as pred_module

        mock_pipe = MagicMock()
        mock_pipe.predict.return_value = np.array([1])           # phishing = 1
        mock_pipe.predict_proba.return_value = np.array([[0.13, 0.87]])  # P(SAFE)=0.13, P(PHISH)=0.87

        pred_module._model = mock_pipe
        pred_module._scaler = None
        pred_module._vectorizer = None
        pred_module._metadata = {
            "model_name": "TestModel",
            "model_version": "0.0.1",
            "feature_names": pred_module.FEATURE_NAMES if hasattr(pred_module, "FEATURE_NAMES") else [],
        }
        yield mock_pipe
        # Reset after test
        pred_module._model = None
        pred_module._scaler = None
        pred_module._vectorizer = None
        pred_module._metadata = None

    def test_phishing_prediction_structure(self):
        from backend.predictor import predict_url
        result = predict_url("http://192.168.1.1/login")

        assert "url" in result
        assert "prediction" in result
        assert "confidence" in result
        assert "risk_level" in result
        assert "score" in result
        assert "score_type" in result
        assert "indicators" in result
        assert "features" in result
        assert "disclaimer" in result

    def test_phishing_prediction_value(self):
        from backend.predictor import predict_url
        result = predict_url("http://192.168.1.1/login")
        assert result["prediction"] == "PHISHING"

    def test_score_is_float(self):
        from backend.predictor import predict_url
        result = predict_url("http://evil.example.com/verify")
        assert isinstance(result["score"], float)

    def test_indicators_is_list(self):
        from backend.predictor import predict_url
        result = predict_url("http://bit.ly/phish")
        assert isinstance(result["indicators"], list)

    def test_features_dict_has_correct_count(self):
        from backend.predictor import predict_url
        from backend.features import FEATURE_NAMES
        result = predict_url("http://example.com")
        assert len(result["features"]) == len(FEATURE_NAMES)

    def test_invalid_url_returns_error(self):
        from backend.predictor import predict_url
        result = predict_url("")
        assert result.get("prediction") is None
        assert "error" in result

    def test_javascript_scheme_rejected(self):
        from backend.predictor import predict_url
        result = predict_url("javascript:alert('xss')")
        assert result.get("prediction") is None

    def test_legitimate_prediction(self):
        import backend.predictor as pred_module
        pred_module._model.predict.return_value = np.array([0])  # safe = 0
        pred_module._model.predict_proba.return_value = np.array([[0.95, 0.05]])

        from backend.predictor import predict_url
        result = predict_url("https://www.google.com/search?q=test")
        assert result["prediction"] == "SAFE"
        assert result["risk_level"] == "LOW"
