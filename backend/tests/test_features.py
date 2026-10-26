"""
Tests for backend/features.py — URL Feature Extraction

All tests use controlled, synthetic URL strings.
No URLs are visited or fetched during tests.
"""
import math
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.features import (
    FEATURE_NAMES,
    extract_url_features,
    features_to_vector,
    get_risk_indicators,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def feats(url: str) -> dict:
    return extract_url_features(url)


# ---------------------------------------------------------------------------
# 1. Empty / None / whitespace input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_string_returns_all_zeros(self):
        result = feats("")
        assert all(v == 0.0 for v in result.values()), "Empty URL should return all zeros"

    def test_whitespace_returns_all_zeros(self):
        result = feats("   ")
        assert all(v == 0.0 for v in result.values())

    def test_none_returns_all_zeros(self):
        result = extract_url_features(None)  # type: ignore[arg-type]
        assert all(v == 0.0 for v in result.values())


# ---------------------------------------------------------------------------
# 2. Feature name ordering
# ---------------------------------------------------------------------------

class TestFeatureOrdering:
    def test_keys_match_feature_names(self):
        result = feats("http://example.com/path")
        assert list(result.keys()) == FEATURE_NAMES

    def test_feature_count(self):
        assert len(FEATURE_NAMES) == 25

    def test_vector_length_equals_feature_count(self):
        result = feats("http://example.com")
        vec = features_to_vector(result)
        assert len(vec) == len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# 3. URL length
# ---------------------------------------------------------------------------

class TestUrlLength:
    def test_short_url(self):
        url = "http://a.com"
        assert feats(url)["url_length"] == float(len(url))

    def test_long_url(self):
        url = "http://example.com/" + "a" * 200
        assert feats(url)["url_length"] == float(len(url))


# ---------------------------------------------------------------------------
# 4. HTTPS detection
# ---------------------------------------------------------------------------

class TestHttps:
    def test_https_scheme_flagged(self):
        assert feats("https://example.com")["has_https"] == 1.0

    def test_http_scheme_not_flagged(self):
        assert feats("http://example.com")["has_https"] == 0.0

    def test_no_scheme_normalised_to_http(self):
        # Missing scheme treated as http — should not be flagged as https
        assert feats("example.com")["has_https"] == 0.0


# ---------------------------------------------------------------------------
# 5. IP address hostname
# ---------------------------------------------------------------------------

class TestIPHostname:
    def test_ipv4_hostname(self):
        assert feats("http://192.168.1.1/path")["has_ip_hostname"] == 1.0

    def test_loopback(self):
        assert feats("http://127.0.0.1")["has_ip_hostname"] == 1.0

    def test_domain_not_flagged(self):
        assert feats("http://example.com")["has_ip_hostname"] == 0.0

    def test_ipv6_hostname(self):
        assert feats("http://[::1]/page")["has_ip_hostname"] == 1.0


# ---------------------------------------------------------------------------
# 6. @ symbol
# ---------------------------------------------------------------------------

class TestAtSymbol:
    def test_at_in_url_counted(self):
        result = feats("http://user@evil.com/phishing")
        assert result["num_at_symbols"] >= 1.0

    def test_at_before_host(self):
        result = feats("http://legitlooking@attacker.com/login")
        assert result["has_at_before_host"] == 1.0

    def test_no_at(self):
        result = feats("http://example.com/page")
        assert result["num_at_symbols"] == 0.0
        assert result["has_at_before_host"] == 0.0


# ---------------------------------------------------------------------------
# 7. URL shorteners
# ---------------------------------------------------------------------------

class TestUrlShortener:
    def test_bitly_flagged(self):
        assert feats("http://bit.ly/abc123")["is_url_shortener"] == 1.0

    def test_tinyurl_flagged(self):
        assert feats("https://tinyurl.com/some-path")["is_url_shortener"] == 1.0

    def test_normal_site_not_flagged(self):
        assert feats("https://www.google.com")["is_url_shortener"] == 0.0


# ---------------------------------------------------------------------------
# 8. Suspicious terms
# ---------------------------------------------------------------------------

class TestSuspiciousTerms:
    def test_login_flagged(self):
        assert feats("http://evil.com/login")["has_suspicious_terms"] == 1.0

    def test_verify_flagged(self):
        assert feats("http://bad.com/verify?token=abc")["has_suspicious_terms"] == 1.0

    def test_normal_page_not_flagged(self):
        assert feats("https://example.com/products")["has_suspicious_terms"] == 0.0


# ---------------------------------------------------------------------------
# 9. Percent-encoded sequences
# ---------------------------------------------------------------------------

class TestPercentEncoded:
    def test_encoded_chars_counted(self):
        result = feats("http://example.com/path%20with%20spaces")
        assert result["num_percent_encoded"] == 2.0

    def test_no_encoding(self):
        result = feats("http://example.com/normal-path")
        assert result["num_percent_encoded"] == 0.0


# ---------------------------------------------------------------------------
# 10. Dots and subdomains
# ---------------------------------------------------------------------------

class TestDots:
    def test_dot_count(self):
        result = feats("http://sub.example.co.uk/path")
        assert result["num_dots"] >= 3.0

    def test_subdomains(self):
        result = feats("http://a.b.c.example.com/page")
        assert result["num_subdomains"] >= 3.0

    def test_no_subdomain(self):
        result = feats("http://example.com/page")
        # host_parts = ["example", "com"] → 2 - 2 = 0
        assert result["num_subdomains"] == 0.0


# ---------------------------------------------------------------------------
# 11. Non-default port
# ---------------------------------------------------------------------------

class TestPort:
    def test_non_default_port_flagged(self):
        assert feats("http://example.com:8080/path")["has_non_default_port"] == 1.0

    def test_default_http_port_not_flagged(self):
        assert feats("http://example.com:80/path")["has_non_default_port"] == 0.0

    def test_default_https_port_not_flagged(self):
        assert feats("https://example.com:443/path")["has_non_default_port"] == 0.0

    def test_no_port_not_flagged(self):
        assert feats("https://example.com/path")["has_non_default_port"] == 0.0

    def test_invalid_string_port_does_not_crash(self):
        f = feats("http://example.com:abc/path")
        assert f["has_non_default_port"] == 0.0

    def test_invalid_out_of_range_port_does_not_crash(self):
        f = feats("http://example.com:99999/path")
        assert f["has_non_default_port"] == 0.0


# ---------------------------------------------------------------------------
# 12. Punycode / IDN
# ---------------------------------------------------------------------------

class TestPunycode:
    def test_punycode_flagged(self):
        assert feats("http://xn--nxasmq6b.com")["has_punycode"] == 1.0

    def test_normal_domain_not_flagged(self):
        assert feats("https://example.com")["has_punycode"] == 0.0


# ---------------------------------------------------------------------------
# 13. Query parameters
# ---------------------------------------------------------------------------

class TestQueryParams:
    def test_multiple_params(self):
        result = feats("http://example.com/page?a=1&b=2&c=3")
        assert result["num_query_params"] == 3.0

    def test_no_params(self):
        result = feats("http://example.com/page")
        assert result["num_query_params"] == 0.0


# ---------------------------------------------------------------------------
# 14. Entropy
# ---------------------------------------------------------------------------

class TestEntropy:
    def test_random_hostname_has_high_entropy(self):
        # Randomly-generated hostname should have higher entropy than a simple name
        result_random = feats("http://xq7k2mn8pzrv.com/")
        result_simple = feats("http://google.com/")
        assert result_random["hostname_entropy"] > result_simple["hostname_entropy"]

    def test_entropy_is_non_negative(self):
        result = feats("http://a.com")
        assert result["hostname_entropy"] >= 0.0


# ---------------------------------------------------------------------------
# 15. Digit ratio
# ---------------------------------------------------------------------------

class TestDigitRatio:
    def test_high_digit_ratio(self):
        result = feats("http://123456789.com/123456")
        assert result["digit_ratio"] > 0.2

    def test_zero_digit_ratio_for_alpha_url(self):
        result = feats("http://example.com/path")
        # Only digits in "example.com/path" are none
        assert result["digit_ratio"] == 0.0


# ---------------------------------------------------------------------------
# 16. Long hostname
# ---------------------------------------------------------------------------

class TestLongHostname:
    def test_long_hostname_flagged(self):
        long_host = "a" * 60
        result = feats(f"http://{long_host}.com/")
        assert result["has_long_hostname"] == 1.0

    def test_normal_hostname_not_flagged(self):
        result = feats("http://example.com/")
        assert result["has_long_hostname"] == 0.0


# ---------------------------------------------------------------------------
# 17. Hyphens
# ---------------------------------------------------------------------------

class TestHyphens:
    def test_hyphen_count(self):
        result = feats("http://my-long-url-name.com/a-b-c")
        assert result["num_hyphens"] == 5.0


# ---------------------------------------------------------------------------
# 18. features_to_vector alignment
# ---------------------------------------------------------------------------

class TestVectorAlignment:
    def test_vector_values_match_dict_order(self):
        url = "http://test.example.com/page?q=1"
        feat_dict = extract_url_features(url)
        vec = features_to_vector(feat_dict)
        for i, name in enumerate(FEATURE_NAMES):
            assert vec[i] == feat_dict[name], f"Mismatch at feature '{name}'"


# ---------------------------------------------------------------------------
# 19. Risk indicators
# ---------------------------------------------------------------------------

class TestRiskIndicators:
    def test_ip_hostname_adds_indicator(self):
        feat_dict = extract_url_features("http://192.168.1.1/phish")
        indicators = get_risk_indicators(feat_dict)
        assert any("IP address" in ind for ind in indicators)

    def test_shortener_adds_indicator(self):
        feat_dict = extract_url_features("http://bit.ly/xyz")
        indicators = get_risk_indicators(feat_dict)
        assert any("shortening" in ind.lower() for ind in indicators)

    def test_suspicious_term_indicator(self):
        feat_dict = extract_url_features("http://evil.com/login")
        indicators = get_risk_indicators(feat_dict)
        assert any("suspicious keyword" in ind.lower() or "login" in ind.lower() for ind in indicators)

    def test_clean_url_has_no_critical_indicators(self):
        feat_dict = extract_url_features("https://www.google.com/search")
        indicators = get_risk_indicators(feat_dict)
        # Should have zero or very few indicators for a clean URL
        critical = [i for i in indicators if "IP" in i or "shortening" in i or "punycode" in i]
        assert len(critical) == 0


# ---------------------------------------------------------------------------
# 20. Graceful handling of unusual URLs
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_url_without_scheme(self):
        # Should not crash; scheme-less URLs get normalised
        result = feats("example.com/path/to/page")
        assert result["url_length"] > 0

    def test_url_with_only_scheme(self):
        result = feats("http://")
        # Should return defaults without crashing
        assert isinstance(result, dict)

    def test_very_long_url(self):
        url = "http://example.com/" + "a" * 2000
        result = feats(url)
        assert result["url_length"] == float(len(url))

    def test_url_with_unicode(self):
        # Should not raise; non-ASCII hostname detected
        result = feats("http://пример.com/путь")
        assert isinstance(result, dict)

    def test_url_with_multiple_at(self):
        result = feats("http://a@b@evil.com/path")
        assert result["num_at_symbols"] >= 2.0

    def test_ftp_url(self):
        result = feats("ftp://files.example.com/pub/data.zip")
        assert result["url_length"] > 0
        assert result["has_https"] == 0.0
