"""
Tests for backend/features.py — URL Feature Extraction
======================================================
Tests verify that:
  • Feature extraction returns all 36 documented features in FEATURE_NAMES.
  • Missing schemes default to HTTPS with scheme_missing = 1.0.
  • URL normalisation ensures parity between "github.com" and "https://github.com".
  • tldextract accurately resolves registered domain, subdomain count, and TLD.
  • Brand impersonation flags brands outside the registered domain only.
  • Obfuscation repeated separators ignore scheme and normal '//' in paths.
  • Advanced URL-only features compute accurately without crashing.
  • No URLs are fetched or visited during tests.
"""
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.features import (
    FEATURE_NAMES,
    canonical_url_string,
    extract_url_features,
    features_to_vector,
    get_risk_indicators,
    normalise_url,
    normalize_url,
    set_tld_frequency_map,
)


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
# 2. Feature name ordering and count
# ---------------------------------------------------------------------------
class TestFeatureOrdering:
    def test_keys_match_feature_names(self):
        result = feats("http://example.com/path")
        assert list(result.keys()) == FEATURE_NAMES

    def test_feature_count(self):
        assert len(FEATURE_NAMES) == 42

    def test_vector_length_equals_feature_count(self):
        result = feats("http://example.com")
        vec = features_to_vector(result)
        assert len(vec) == len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# 3. URL normalisation parity
# ---------------------------------------------------------------------------
class TestNormalisationParity:
    def test_normalize_url_returns_identical_canonical_strings(self):
        u1 = normalize_url("github.com")
        u2 = normalize_url("https://github.com")
        u3 = normalize_url("https://www.github.com")
        assert u1 == "https://github.com"
        assert u2 == "https://github.com"
        assert u3 == "https://github.com"

    def test_missing_scheme_defaults_to_neutral_has_https_and_missing_flag(self):
        url = "github.com"
        f = feats(url)
        assert f["scheme_missing"] == 1.0
        assert f["has_https"] == 0.0  # Set neutrally for scheme-less input

    def test_explicit_https_has_zero_scheme_missing(self):
        url = "https://github.com"
        f = feats(url)
        assert f["has_https"] == 1.0
        assert f["scheme_missing"] == 0.0

    def test_explicit_http_has_zero_https(self):
        url = "http://github.com"
        f = feats(url)
        assert f["has_https"] == 0.0
        assert f["scheme_missing"] == 0.0

    def test_www_stripped_and_host_lowercased(self):
        c1 = normalize_url("WWW.GitHub.COM/path")
        c2 = normalize_url("https://www.github.com/path")
        c3 = normalize_url("https://github.com/path")
        assert c1 == "https://github.com/path"
        assert c2 == "https://github.com/path"
        assert c3 == "https://github.com/path"

    def test_structural_feature_parity_between_bare_and_https_url(self):
        f_bare = feats("github.com/repo/project")
        f_https = feats("https://github.com/repo/project")
        f_www = feats("https://www.github.com/repo/project")
        # All features apart from documented scheme handling (scheme_missing and has_https)
        # must be strictly identical across bare, https, and https://www URLs
        scheme_keys = {"scheme_missing", "has_https"}
        for k in FEATURE_NAMES:
            if k not in scheme_keys:
                assert f_bare[k] == f_https[k] == f_www[k], f"Mismatch for feature {k}"
        assert f_bare["scheme_missing"] == 1.0
        assert f_bare["has_https"] == 0.0
        assert f_https["scheme_missing"] == 0.0
        assert f_https["has_https"] == 1.0
        assert f_www["scheme_missing"] == 0.0
        assert f_www["has_https"] == 1.0


# ---------------------------------------------------------------------------
# 4. Public Suffix List & TLD features
# ---------------------------------------------------------------------------
class TestPublicSuffixAndTLD:
    def test_tldextract_multi_label_subdomain_counts(self):
        # Multi-label PSL suffixes: .co.in, .ac.in, .co.uk
        assert feats("https://abc.co.in")["num_subdomains"] == 0.0
        assert feats("https://abc.ac.in")["num_subdomains"] == 0.0
        assert feats("https://x.co.uk")["num_subdomains"] == 0.0
        assert feats("https://sub.abc.co.in")["num_subdomains"] == 1.0
        assert feats("https://a.b.x.co.uk")["num_subdomains"] == 2.0

    def test_tldextract_subdomain_count(self):
        # co.uk is recognized as public suffix by bundled PSL
        f1 = feats("https://sub.example.co.uk")
        assert f1["num_subdomains"] == 1.0

        f2 = feats("https://a.b.c.example.com")
        assert f2["num_subdomains"] == 3.0

        f3 = feats("https://example.com")
        assert f3["num_subdomains"] == 0.0

    def test_suspicious_tld_flagged(self):
        assert feats("https://bank-login.xyz")["has_suspicious_tld"] == 1.0
        assert feats("https://verify-account.top")["has_suspicious_tld"] == 1.0
        assert feats("https://update.buzz")["has_suspicious_tld"] == 1.0
        assert feats("https://update.click")["has_suspicious_tld"] == 1.0
        assert feats("https://update.icu")["has_suspicious_tld"] == 1.0

    def test_benign_tld_not_flagged(self):
        assert feats("https://google.com")["has_suspicious_tld"] == 0.0
        assert feats("https://mit.edu")["has_suspicious_tld"] == 0.0
        assert feats("https://gov.uk")["has_suspicious_tld"] == 0.0

    def test_tld_frequency_encoding(self):
        set_tld_frequency_map({"com": 0.60, "org": 0.15})
        f_com = feats("https://example.com")
        assert abs(f_com["tld_frequency"] - 0.60) < 1e-5
        f_org = feats("https://example.org")
        assert abs(f_org["tld_frequency"] - 0.15) < 1e-5
        f_net = feats("https://example.net")
        assert f_net["tld_frequency"] == 0.0


# ---------------------------------------------------------------------------
# 5. Brand Impersonation & Suspicious Terms
# ---------------------------------------------------------------------------
class TestBrandImpersonation:
    def test_paypal_subdomain_spoof_flagged(self):
        # paypal appears in subdomain while registered domain is evil.xyz
        f = feats("https://paypal.com.evil.xyz/login")
        assert f["brand_in_wrong_place"] == 1.0
        assert f["has_brand_impersonation"] == 1.0

    def test_paypal_path_spoof_flagged(self):
        # paypal appears in path on unrelated domain
        f = feats("https://evil.xyz/paypal/signin")
        assert f["brand_in_wrong_place"] == 1.0
        assert f["has_brand_impersonation"] == 1.0

    def test_legitimate_paypal_not_flagged(self):
        # registered domain is paypal.com; should NOT be flagged
        f = feats("https://paypal.com/signin")
        assert f["brand_in_wrong_place"] == 0.0
        assert f["has_brand_impersonation"] == 0.0

    def test_legitimate_subdomain_paypal_not_flagged(self):
        f = feats("https://checkout.paypal.com/pay")
        assert f["brand_in_wrong_place"] == 0.0
        assert f["has_brand_impersonation"] == 0.0

    def test_google_legitimate_not_flagged(self):
        # https://www.google.com and accounts.google.com must NOT be flagged
        f1 = feats("https://www.google.com")
        assert f1["brand_in_wrong_place"] == 0.0
        assert f1["has_brand_impersonation"] == 0.0

        f2 = feats("https://accounts.google.com")
        assert f2["brand_in_wrong_place"] == 0.0
        assert f2["has_brand_impersonation"] == 0.0

    def test_suspicious_terms_in_subdomain_or_path(self):
        # Term in path
        assert feats("https://example.com/account/login")["has_suspicious_terms"] == 1.0
        # Term in subdomain
        assert feats("https://verify.example.com")["has_suspicious_terms"] == 1.0
        # Term as the registered domain itself (e.g. login.com) is NOT in outside_text
        assert feats("https://login.com/about")["has_suspicious_terms"] == 0.0


# ---------------------------------------------------------------------------
# 6. Obfuscation Repeated Separators & Regex Range
# ---------------------------------------------------------------------------
class TestObfuscationSeparators:
    def test_legitimate_scheme_not_flagged(self):
        f = feats("https://example.com/page")
        assert f["has_repeated_separators"] == 0.0

    def test_normal_double_slash_in_path_not_flagged_as_obfuscation(self):
        # Legitimate path routing // is NOT an obfuscation separator
        f = feats("https://example.com/folder//index.html")
        assert f["has_repeated_separators"] == 0.0
        # But it IS recorded in has_double_slash_in_path
        assert f["has_double_slash_in_path"] == 1.0

    def test_normal_equals_in_query_not_flagged_as_obfuscation(self):
        # Normal '==' e.g. base64 padding or parameter value is NOT flagged
        f = feats("https://example.com/path?token=abc==")
        assert f["has_repeated_separators"] == 0.0

    def test_real_obfuscation_separators_flagged(self):
        assert feats("https://example.com/path?a=1&&b=2")["has_repeated_separators"] == 1.0
        assert feats("https://example.com/path??q=1")["has_repeated_separators"] == 1.0
        assert feats("https://example.com///evil.com")["has_repeated_separators"] == 1.0


# ---------------------------------------------------------------------------
# 7. Additional URL-Only Features
# ---------------------------------------------------------------------------
class TestNewFeatures:
    def test_domain_digit_count(self):
        assert feats("https://chase123.com")["domain_digit_count"] == 3.0
        assert feats("https://chase123.com")["domain_num_digits"] == 3.0
        assert feats("https://chase.com")["domain_digit_count"] == 0.0

    def test_domain_hyphen_count(self):
        assert feats("https://my-secure-bank.com")["domain_hyphen_count"] == 2.0
        assert feats("https://chase.com")["domain_hyphen_count"] == 0.0

    def test_vowel_consonant_ratio(self):
        # "google" -> 3 vowels (o,o,e), 3 consonants (g,g,l) -> ratio = 1.0
        f_google = feats("https://google.com")
        assert abs(f_google["vowel_consonant_ratio"] - 1.0) < 0.01

    def test_digit_to_letter_ratio(self):
        # "bank12" -> 2 digits, 4 letters -> 2/4 = 0.50
        f = feats("https://bank12.com")
        assert abs(f["digit_to_letter_ratio"] - 0.50) < 0.01

    def test_longest_token_length(self):
        f = feats("https://example.com/a/supercalifragilisticexpialidocious/b")
        assert f["longest_token_length"] >= 34.0

    def test_domain_vowel_ratio(self):
        # "google" -> 3 vowels (o,o,e) / 6 letters = 0.50
        f_google = feats("https://google.com")
        assert abs(f_google["domain_vowel_ratio"] - 0.5) < 0.01

        # DGA domain with no vowels
        f_dga = feats("https://bcdfgh.com")
        assert f_dga["domain_vowel_ratio"] == 0.0

    def test_path_depth(self):
        assert feats("https://example.com/a/b/c/d")["path_depth"] == 4.0
        assert feats("https://example.com/")["path_depth"] == 0.0

    def test_has_double_extension(self):
        assert feats("https://example.com/invoices/doc.pdf.exe")["has_double_extension"] == 1.0
        assert feats("https://example.com/index.php.html")["has_double_extension"] == 1.0
        assert feats("https://example.com/index.html")["has_double_extension"] == 0.0

    def test_has_at_in_path(self):
        assert feats("https://example.com/login?redirect=user@bank.com")["has_at_in_path"] == 1.0
        assert feats("https://example.com/login")["has_at_in_path"] == 0.0

    def test_has_ip_in_path(self):
        assert feats("https://evil.com/redirect?dest=192.168.1.1")["has_ip_in_path"] == 1.0
        assert feats("https://evil.com/redirect?dest=google.com")["has_ip_in_path"] == 0.0


# ---------------------------------------------------------------------------
# 8. IP Hostname & Ports
# ---------------------------------------------------------------------------
class TestIPHostnameAndPort:
    def test_ipv4_hostname(self):
        assert feats("http://192.168.1.1/path")["has_ip_hostname"] == 1.0

    def test_loopback(self):
        assert feats("http://127.0.0.1")["has_ip_hostname"] == 1.0

    def test_domain_not_flagged(self):
        assert feats("http://example.com")["has_ip_hostname"] == 0.0

    def test_non_default_port_flagged(self):
        assert feats("http://example.com:8080/path")["has_non_default_port"] == 1.0

    def test_default_http_port_not_flagged(self):
        assert feats("http://example.com:80/path")["has_non_default_port"] == 0.0

    def test_default_https_port_not_flagged(self):
        assert feats("https://example.com:443/path")["has_non_default_port"] == 0.0

    def test_invalid_string_port_does_not_crash(self):
        f = feats("http://example.com:abc/path")
        assert f["has_non_default_port"] == 0.0

    def test_invalid_out_of_range_port_does_not_crash(self):
        f = feats("http://example.com:99999/path")
        assert f["has_non_default_port"] == 0.0


# ---------------------------------------------------------------------------
# 9. Shorteners, Punycode, Indicators
# ---------------------------------------------------------------------------
class TestShortenersAndIndicators:
    def test_shortener_lowercased_lookup(self):
        # BudURL.com and just.as in lowercase list
        assert feats("https://budurl.com/xyz")["is_url_shortener"] == 1.0
        assert feats("https://bit.ly/123")["is_url_shortener"] == 1.0

    def test_punycode_flagged(self):
        assert feats("http://xn--nxasmq6b.com")["has_punycode"] == 1.0

    def test_risk_indicators_include_brand_spoof(self):
        f = feats("https://paypal.com.evil.xyz/login")
        indicators = get_risk_indicators(f)
        assert any("brand impersonation" in ind.lower() for ind in indicators)


# ---------------------------------------------------------------------------
# 10. Vector Alignment
# ---------------------------------------------------------------------------
class TestVectorAlignment:
    def test_vector_values_match_dict_order(self):
        url = "http://test.example.com/page?q=1"
        feat_dict = extract_url_features(url)
        vec = features_to_vector(feat_dict)
        assert len(vec) == len(FEATURE_NAMES)
        for i, name in enumerate(FEATURE_NAMES):
            assert vec[i] == feat_dict[name], f"Mismatch at feature '{name}'"
