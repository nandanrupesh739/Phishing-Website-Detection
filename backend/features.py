"""
PhishGuard AI — URL Feature Extraction
=======================================
Single authoritative feature-extraction module shared by:
  • backend/train_model.py  (training)
  • backend/predictor.py    (inference)

All 25 features are documented inline.  The returned dict always has the
same keys in the same order so that feature vectors are aligned between
training and prediction.

Rules
-----
- Features are derived *only* from the URL string — no DNS, no HTTP, no WHOIS.
- HTTPS is never treated as proof of legitimacy.
- Invalid / un-parseable URLs are handled gracefully; defaults are returned.
- All computations are deterministic and have no side-effects.
"""

from __future__ import annotations

import ipaddress
import math
import re
import urllib.parse
from collections import OrderedDict
from typing import Dict

from backend.config import (
    LONG_HOSTNAME_THRESHOLD,
    SUSPICIOUS_TERMS,
    URL_SHORTENERS,
)

# ---------------------------------------------------------------------------
# Ordered feature name list
# ---------------------------------------------------------------------------
FEATURE_NAMES: list[str] = [
    "url_length",                # 1
    "hostname_length",           # 2
    "num_dots",                  # 3
    "num_hyphens",               # 4
    "num_at_symbols",            # 5
    "num_digits",                # 6
    "num_subdomains",            # 7
    "path_length",               # 8
    "num_query_params",          # 9
    "num_percent_encoded",       # 10
    "num_suspicious_chars",      # 11
    "has_ip_hostname",           # 12
    "has_non_default_port",      # 13
    "has_https",                 # 14
    "is_url_shortener",          # 15
    "has_suspicious_terms",      # 16
    "has_repeated_separators",   # 17
    "has_long_hostname",         # 18
    "hostname_entropy",          # 19
    "digit_ratio",               # 20
    "has_punycode",              # 21
    "has_non_ascii_hostname",    # 22
    "has_at_before_host",        # 23
    "has_unusual_encoding",      # 24
    "num_special_chars",         # 25  (formerly "suspicious punctuation")
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RE_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_RE_DOUBLE_SEP = re.compile(r"(//|&&|\?\?|==){1}")
_RE_NON_ASCII = re.compile(r"[^\x00-\x7F]")
_RE_UNUSUAL_ENC = re.compile(r"%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")

# Characters that are rare in legitimate URLs but common in phishing
_SUSPICIOUS_PUNCTS = set("@!#$^&*(){}|[]\\\"'<>,")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_ip_address(hostname: str) -> bool:
    """Return True if *hostname* is a valid IPv4 or IPv6 address literal."""
    # Strip surrounding brackets for IPv6
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalise_url(url: str) -> str:
    """
    Add a scheme if missing so that urllib.parse can correctly identify
    the hostname component.  Uses 'http://' as a neutral placeholder —
    the feature extractor records scheme separately.
    """
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    return url


def _safe_parse(url: str) -> urllib.parse.ParseResult | None:
    """Parse a URL, returning None on failure."""
    try:
        result = urllib.parse.urlparse(_normalise_url(url))
        return result if result.netloc else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extract 25 URL-string features from *url*.

    Returns an OrderedDict whose keys match FEATURE_NAMES in order.
    For un-parseable URLs all numeric features default to 0 / -1 where
    appropriate and binary flags default to 0.

    Parameters
    ----------
    url : str
        Raw URL submitted by the user or read from the training dataset.

    Returns
    -------
    dict
        Feature name → numeric value.  Binary features are 0 or 1.
    """
    # ── Initialise defaults ────────────────────────────────────────────────
    feats: Dict[str, float] = OrderedDict((k, 0.0) for k in FEATURE_NAMES)

    if not isinstance(url, str) or not url.strip():
        return feats

    raw_url = url.strip()
    parsed = _safe_parse(raw_url)

    # ── Feature 1: Total URL length ────────────────────────────────────────
    feats["url_length"] = float(len(raw_url))

    # ── Feature 3: Number of dots (full URL) ──────────────────────────────
    feats["num_dots"] = float(raw_url.count("."))

    # ── Feature 4: Number of hyphens (full URL) ───────────────────────────
    feats["num_hyphens"] = float(raw_url.count("-"))

    # ── Feature 5: Number of @ symbols (full URL) ─────────────────────────
    feats["num_at_symbols"] = float(raw_url.count("@"))

    # ── Feature 6: Number of digit characters ─────────────────────────────
    feats["num_digits"] = float(sum(ch.isdigit() for ch in raw_url))

    # ── Feature 10: Percent-encoded sequences ─────────────────────────────
    feats["num_percent_encoded"] = float(len(_RE_PERCENT.findall(raw_url)))

    # ── Feature 11: Suspicious punctuation characters ─────────────────────
    feats["num_suspicious_chars"] = float(
        sum(ch in _SUSPICIOUS_PUNCTS for ch in raw_url)
    )

    # ── Feature 25: Special characters (broader set) ──────────────────────
    special = set(raw_url) - set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789-._~:/?#[]@!$&'()*+,;=%"
    )
    feats["num_special_chars"] = float(len(special))

    # ── Feature 17: Repeated separators ───────────────────────────────────
    # Strip protocol '://' so standard URLs are not falsely flagged
    url_body = _RE_DOUBLE_SEP.search(re.sub(r"^[a-zA-Z0-9+-.]+://", "", raw_url))
    feats["has_repeated_separators"] = float(bool(url_body))

    # ── Feature 24: Unusual encoding ──────────────────────────────────────
    unusual_count = len(_RE_UNUSUAL_ENC.findall(raw_url))
    feats["has_unusual_encoding"] = float(unusual_count > 3)

    # ── Features that need a valid parse ──────────────────────────────────
    if parsed is None:
        # Digit ratio still computable
        total = len(raw_url)
        feats["digit_ratio"] = (
            feats["num_digits"] / total if total else 0.0
        )
        return feats

    hostname = parsed.hostname or ""
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # ── Feature 2: Hostname length ─────────────────────────────────────────
    feats["hostname_length"] = float(len(hostname))

    # ── Feature 7: Number of subdomain components ─────────────────────────
    # We approximate: split hostname by dots; count everything above the
    # registered domain (last two labels: domain.tld).
    host_parts = [p for p in hostname.split(".") if p]
    feats["num_subdomains"] = float(max(0, len(host_parts) - 2))

    # ── Feature 8: Path length ────────────────────────────────────────────
    feats["path_length"] = float(len(path))

    # ── Feature 9: Number of query parameters ─────────────────────────────
    if query:
        feats["num_query_params"] = float(len(urllib.parse.parse_qs(query)))
    else:
        feats["num_query_params"] = 0.0

    # ── Feature 12: IP address as hostname ────────────────────────────────
    feats["has_ip_hostname"] = float(_is_ip_address(hostname))

    # ── Feature 13: Non-default port ──────────────────────────────────────
    default_ports = {"http": 80, "https": 443, "ftp": 21}
    port = parsed.port
    if port is not None:
        feats["has_non_default_port"] = float(
            port != default_ports.get(scheme, -1)
        )
    else:
        feats["has_non_default_port"] = 0.0

    # ── Feature 14: HTTPS scheme ──────────────────────────────────────────
    # NOTE: HTTPS ≠ safety; included only as a structural URL feature.
    feats["has_https"] = float(scheme == "https")

    # ── Feature 15: URL shortener ─────────────────────────────────────────
    registered_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else hostname
    feats["is_url_shortener"] = float(
        hostname.lower() in URL_SHORTENERS
        or registered_domain.lower() in URL_SHORTENERS
    )

    # ── Feature 16: Suspicious terms ──────────────────────────────────────
    url_lower = raw_url.lower()
    feats["has_suspicious_terms"] = float(
        any(term in url_lower for term in SUSPICIOUS_TERMS)
    )

    # ── Feature 18: Unusually long hostname ───────────────────────────────
    feats["has_long_hostname"] = float(
        len(hostname) > LONG_HOSTNAME_THRESHOLD
    )

    # ── Feature 19: Shannon entropy of hostname ───────────────────────────
    feats["hostname_entropy"] = _shannon_entropy(hostname)

    # ── Feature 20: Digit-to-character ratio (full URL) ───────────────────
    total = len(raw_url)
    feats["digit_ratio"] = (
        feats["num_digits"] / total if total > 0 else 0.0
    )

    # ── Feature 21: Punycode indicators ───────────────────────────────────
    feats["has_punycode"] = float("xn--" in hostname.lower())

    # ── Feature 22: Non-ASCII hostname ────────────────────────────────────
    feats["has_non_ascii_hostname"] = float(
        bool(_RE_NON_ASCII.search(hostname))
    )

    # ── Feature 23: @ symbol before hostname boundary ─────────────────────
    # urllib handles user-info; if netloc contains '@' the parsed hostname
    # is already after the '@', so we check the raw netloc.
    feats["has_at_before_host"] = float("@" in (parsed.netloc or ""))

    return feats


# ---------------------------------------------------------------------------
# Utility: build aligned feature vector (list) from a dict
# ---------------------------------------------------------------------------

def features_to_vector(feat_dict: Dict[str, float]) -> list[float]:
    """Return feature values in canonical FEATURE_NAMES order."""
    return [feat_dict.get(name, 0.0) for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Utility: human-readable indicator list from features
# ---------------------------------------------------------------------------

def get_risk_indicators(feat_dict: Dict[str, float]) -> list[str]:
    """
    Translate extracted feature values into human-readable risk indicators.
    Only indicators supported by actual computed features are returned.
    """
    indicators: list[str] = []

    if feat_dict.get("has_ip_hostname"):
        indicators.append("Hostname is an IP address (not a domain name)")
    if feat_dict.get("has_at_before_host"):
        indicators.append("URL contains '@' before the hostname — possible credential trick")
    if feat_dict.get("is_url_shortener"):
        indicators.append("URL uses a known URL-shortening service (destination hidden)")
    if feat_dict.get("has_suspicious_terms"):
        indicators.append("URL path or query contains suspicious keyword(s) (e.g. login, verify, account)")
    if feat_dict.get("has_punycode"):
        indicators.append("Hostname contains punycode (IDN) encoding — possible homograph attack")
    if feat_dict.get("has_non_ascii_hostname"):
        indicators.append("Hostname contains non-ASCII characters")
    if feat_dict.get("has_long_hostname"):
        indicators.append(f"Hostname is unusually long (> {LONG_HOSTNAME_THRESHOLD} characters)")
    if feat_dict.get("has_non_default_port"):
        indicators.append("URL specifies a non-standard port number")
    if feat_dict.get("has_unusual_encoding"):
        indicators.append("URL contains an unusually high number of encoded characters")
    if feat_dict.get("has_repeated_separators"):
        indicators.append("URL contains repeated separators (e.g. '//') suggesting obfuscation")

    url_len = feat_dict.get("url_length", 0)
    if url_len > 75:
        indicators.append(f"URL is very long ({int(url_len)} characters)")

    entropy = feat_dict.get("hostname_entropy", 0)
    if entropy > 3.8:
        indicators.append(f"Hostname has high character entropy ({entropy:.2f} bits) — may be randomly generated")

    digit_ratio = feat_dict.get("digit_ratio", 0)
    if digit_ratio > 0.20:
        indicators.append(f"High proportion of digits in URL ({digit_ratio:.0%})")

    num_subdomains = feat_dict.get("num_subdomains", 0)
    if num_subdomains >= 3:
        indicators.append(f"URL has {int(num_subdomains)} subdomain levels — uncommon in legitimate sites")

    return indicators
