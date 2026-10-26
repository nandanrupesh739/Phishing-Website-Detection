"""
PhishGuard AI — URL Feature Extraction
=======================================
Single authoritative feature-extraction module shared by:
  • train.py             (training)
  • backend/predictor.py (inference)

All 36 features are documented inline. The returned dict always has the
same keys in the same order so that feature vectors are aligned between
training and prediction.

Rules
-----
- Features are derived *only* from the URL string — no DNS, no HTTP, no WHOIS.
- HTTPS is never treated as proof of legitimacy.
- Missing schemes default to HTTPS (modern browser convention) with a binary
  `scheme_missing` flag, ensuring "github.com" and "https://github.com" produce
  consistent structural features.
- Public suffix parsing uses `tldextract` in offline mode (bundled PSL snapshot).
- Invalid / un-parseable URLs are handled gracefully; defaults are returned.
- All computations are deterministic and have no side-effects.
"""

from __future__ import annotations

import ipaddress
import math
import re
import urllib.parse
from collections import OrderedDict
from typing import Dict, Tuple

import tldextract

from backend.config import (
    KNOWN_BRANDS,
    LONG_HOSTNAME_THRESHOLD,
    SUSPICIOUS_TERMS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

# ---------------------------------------------------------------------------
# Offline TLDExtract instance (no network calls; uses bundled snapshot)
# ---------------------------------------------------------------------------
_TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

# ---------------------------------------------------------------------------
# Ordered feature name list (36 features)
# ---------------------------------------------------------------------------
FEATURE_NAMES: list[str] = [
    "url_length",                # 1:  Total character length of normalized URL
    "hostname_length",           # 2:  Length of hostname component
    "num_dots",                  # 3:  Number of dots in URL
    "num_hyphens",               # 4:  Number of hyphens in URL
    "num_at_symbols",            # 5:  Number of @ characters in URL
    "num_digits",                # 6:  Total digit characters in URL
    "num_subdomains",            # 7:  Subdomain count via PSL (excluding 'www')
    "path_length",               # 8:  Character length of path
    "num_query_params",          # 9:  Count of query parameters
    "num_percent_encoded",       # 10: Count of %XX hex escapes
    "num_suspicious_chars",      # 11: Suspicious punctuation count
    "has_ip_hostname",           # 12: Binary flag: hostname is IPv4/IPv6 literal
    "has_non_default_port",      # 13: Binary flag: explicit non-standard port
    "has_https",                 # 14: Binary flag: HTTPS protocol used
    "is_url_shortener",          # 15: Binary flag: hostname/domain is known shortener
    "has_suspicious_terms",      # 16: Binary flag: keyword in path/query/subdomain (not domain)
    "has_repeated_separators",   # 17: Binary flag: obfuscation repeated delimiters (&&, ??, ==, 3+ slashes)
    "has_long_hostname",         # 18: Binary flag: hostname exceeds length threshold
    "hostname_entropy",          # 19: Shannon entropy of hostname (bits/char)
    "digit_ratio",               # 20: Ratio of digits to total characters
    "has_punycode",              # 21: Binary flag: punycode (xn--) in hostname
    "has_non_ascii_hostname",    # 22: Binary flag: non-ASCII characters in host
    "has_at_before_host",        # 23: Binary flag: @ appears in netloc / before host
    "has_unusual_encoding",      # 24: Binary flag: high count of encoded bytes
    "num_special_chars",         # 25: Special character count outside standard RFC sets
    "scheme_missing",            # 26: Binary flag: original input had no protocol scheme
    "has_suspicious_tld",        # 27: Binary flag: TLD is in high-risk phishing TLD set
    "has_brand_impersonation",   # 28: Binary flag: brand appears outside registered domain
    "domain_num_digits",         # 29: Count of digits within the registered domain
    "longest_token_length",      # 30: Length of the longest alphanumeric token
    "domain_vowel_ratio",        # 31: Vowel / letter ratio of domain name
    "path_depth",                # 32: Number of directory segments in path
    "has_double_extension",      # 33: Binary flag: double file extension (e.g. .php.html)
    "has_at_in_path",            # 34: Binary flag: @ appears in URL path or query
    "has_double_slash_in_path",  # 35: Binary flag: // appears in path
    "has_ip_in_path",            # 36: Binary flag: IPv4 address pattern in path or query
]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
_RE_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_RE_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_RE_OBFUSCATION_SEP = re.compile(r"(&&|\?\?|==|/{3,})")
_RE_NON_ASCII = re.compile(r"[^\x00-\x7F]")
_RE_UNUSUAL_ENC = re.compile(r"%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")
_RE_DOUBLE_EXT = re.compile(r"\.[a-zA-Z0-9]{2,4}\.[a-zA-Z0-9]{2,4}($|\?|/)")
_RE_IPV4_IN_PATH = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_TOKEN_DELIMS = re.compile(r"[\./\-_?&=:@+]")

_SUSPICIOUS_PUNCTS = set("@!#$^&*(){}|[]\\\"'<>,")


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def normalise_url(raw_url: str) -> Tuple[str, bool]:
    """
    Canonical URL normalisation used identically in training and inference.

    Steps:
      1. Strip whitespace.
      2. Detect whether a scheme exists. If missing, assume HTTPS (modern
         browser default) and mark `scheme_missing = True`.
      3. Lowercase the hostname.
      4. Remove leading 'www.' from hostname.
      5. Safely handle non-standard / invalid ports.
      6. Reconstruct canonical URL preserving path, query, and fragment.

    Decision on missing scheme:
      Modern browsers default to HTTPS when a user inputs a domain without
      a scheme. We normalize missing schemes to "https://" so that structural
      features (hostname length, path, entropy, etc.) match "https://domain.com",
      and record an explicit binary feature `scheme_missing = 1.0`.
      If HTTP is explicitly given, `has_https = 0.0` and `scheme_missing = 0.0`.
    """
    if not isinstance(raw_url, str):
        return "", False

    url = raw_url.strip()
    if not url:
        return "", False

    scheme_match = _RE_SCHEME.match(url)
    if scheme_match:
        scheme_missing = False
        url_with_scheme = url
    else:
        scheme_missing = True
        url_with_scheme = "https://" + url

    try:
        parsed = urllib.parse.urlsplit(url_with_scheme)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]

        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"

        port_part = ""
        try:
            if parsed.port:
                if (scheme == "https" and parsed.port != 443) or (scheme == "http" and parsed.port != 80):
                    port_part = f":{parsed.port}"
        except (ValueError, OverflowError):
            pass

        netloc = f"{userinfo}{host}{port_part}"
        canonical = urllib.parse.urlunsplit((
            scheme,
            netloc,
            parsed.path or "",
            parsed.query or "",
            parsed.fragment or "",
        ))
        return canonical, scheme_missing
    except Exception:
        return url, scheme_missing


def canonical_url_string(raw_url: str) -> str:
    """Return the normalized canonical URL string (without the boolean flag)."""
    return normalise_url(raw_url)[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is a valid IPv4 or IPv6 address literal."""
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _safe_parse(url: str) -> urllib.parse.ParseResult | None:
    """Parse a URL with error safety against port exceptions and malformed netloc."""
    try:
        result = urllib.parse.urlparse(url)
        if not result.netloc:
            return None
        try:
            _ = result.port
        except (ValueError, OverflowError):
            return None
        return result
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public Feature Extraction API
# ---------------------------------------------------------------------------
def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extract 36 structural URL features from *url*.

    Returns an OrderedDict whose keys match FEATURE_NAMES in exact order.
    For un-parseable URLs all numeric features default to 0 / -1 where
    appropriate and binary flags default to 0.

    Parameters
    ----------
    url : str
        Raw URL submitted by user or loaded from dataset.

    Returns
    -------
    OrderedDict[str, float]
        Feature name → float value. Binary features are 0.0 or 1.0.
    """
    feats: Dict[str, float] = OrderedDict((k, 0.0) for k in FEATURE_NAMES)

    if not isinstance(url, str) or not url.strip():
        return feats

    norm_url, scheme_missing = normalise_url(url)
    feats["scheme_missing"] = 1.0 if scheme_missing else 0.0

    parsed = _safe_parse(norm_url)

    # ── Feature 1: Total URL length ────────────────────────────────────────
    feats["url_length"] = float(len(norm_url))

    # ── Feature 3: Number of dots (full URL) ──────────────────────────────
    feats["num_dots"] = float(norm_url.count("."))

    # ── Feature 4: Number of hyphens (full URL) ───────────────────────────
    feats["num_hyphens"] = float(norm_url.count("-"))

    # ── Feature 5: Number of @ symbols (full URL) ─────────────────────────
    feats["num_at_symbols"] = float(norm_url.count("@"))

    # ── Feature 6: Number of digit characters ─────────────────────────────
    feats["num_digits"] = float(sum(ch.isdigit() for ch in norm_url))

    # ── Feature 10: Percent-encoded sequences ─────────────────────────────
    feats["num_percent_encoded"] = float(len(_RE_PERCENT.findall(norm_url)))

    # ── Feature 11: Suspicious punctuation characters ─────────────────────
    feats["num_suspicious_chars"] = float(
        sum(ch in _SUSPICIOUS_PUNCTS for ch in norm_url)
    )

    # ── Feature 25: Special characters ────────────────────────────────────
    special = set(norm_url) - set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789-._~:/?#[]@!$&'()*+,;=%"
    )
    feats["num_special_chars"] = float(len(special))

    # ── Feature 17: Obfuscation repeated separators ───────────────────────
    # Ignore protocol prefix; flag repeated delimiters (&&, ??, ==, 3+ slashes)
    url_body = _RE_SCHEME.sub("", norm_url)
    feats["has_repeated_separators"] = float(bool(_RE_OBFUSCATION_SEP.search(url_body)))

    # ── Feature 24: Unusual encoding ──────────────────────────────────────
    unusual_count = len(_RE_UNUSUAL_ENC.findall(norm_url))
    feats["has_unusual_encoding"] = float(unusual_count > 3)

    # ── Feature 30: Longest token length ──────────────────────────────────
    tokens = [t for t in _RE_TOKEN_DELIMS.split(norm_url) if t]
    feats["longest_token_length"] = float(max((len(t) for t in tokens), default=0))

    if parsed is None:
        total = len(norm_url)
        feats["digit_ratio"] = feats["num_digits"] / total if total else 0.0
        return feats

    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # ── Feature 2: Hostname length ─────────────────────────────────────────
    feats["hostname_length"] = float(len(hostname))

    # ── Public Suffix List Extraction ─────────────────────────────────────
    tld_res = _TLD_EXTRACTOR(norm_url)
    subdomain = tld_res.subdomain.lower()
    tld_suffix = tld_res.suffix.lower()
    reg_domain = (getattr(tld_res, "top_domain_under_public_suffix", None) or tld_res.domain).lower()
    domain_label = tld_res.domain.lower()

    # ── Feature 7: Subdomain count via PSL ────────────────────────────────
    sub_parts = [p for p in subdomain.split(".") if p and p != "www"]
    feats["num_subdomains"] = float(len(sub_parts))

    # ── Feature 8: Path length ────────────────────────────────────────────
    feats["path_length"] = float(len(path))

    # ── Feature 9: Number of query parameters ─────────────────────────────
    feats["num_query_params"] = float(len(urllib.parse.parse_qs(query))) if query else 0.0

    # ── Feature 12: IP address as hostname ────────────────────────────────
    feats["has_ip_hostname"] = float(_is_ip_address(hostname))

    # ── Feature 13: Non-default port ──────────────────────────────────────
    default_ports = {"http": 80, "https": 443, "ftp": 21}
    try:
        port = parsed.port
    except (ValueError, OverflowError):
        port = None

    if port is not None:
        feats["has_non_default_port"] = float(port != default_ports.get(scheme, -1))
    else:
        feats["has_non_default_port"] = 0.0

    # ── Feature 14: HTTPS scheme ──────────────────────────────────────────
    feats["has_https"] = float(scheme == "https")

    # ── Feature 15: URL shortener ─────────────────────────────────────────
    feats["is_url_shortener"] = float(
        hostname in URL_SHORTENERS or reg_domain in URL_SHORTENERS
    )

    # ── Outside registered domain text (subdomain, path, query) ───────────
    outside_text = f"{subdomain} {path} {query}".lower()

    # ── Feature 16: Suspicious terms in path/query/subdomain ──────────────
    feats["has_suspicious_terms"] = float(
        any(term in outside_text for term in SUSPICIOUS_TERMS)
    )

    # ── Feature 18: Unusually long hostname ───────────────────────────────
    feats["has_long_hostname"] = float(len(hostname) > LONG_HOSTNAME_THRESHOLD)

    # ── Feature 19: Shannon entropy of hostname ───────────────────────────
    feats["hostname_entropy"] = _shannon_entropy(hostname)

    # ── Feature 20: Digit-to-character ratio ──────────────────────────────
    total = len(norm_url)
    feats["digit_ratio"] = feats["num_digits"] / total if total > 0 else 0.0

    # ── Feature 21: Punycode indicators ───────────────────────────────────
    feats["has_punycode"] = float("xn--" in hostname)

    # ── Feature 22: Non-ASCII hostname ────────────────────────────────────
    feats["has_non_ascii_hostname"] = float(bool(_RE_NON_ASCII.search(hostname)))

    # ── Feature 23: @ symbol before hostname boundary ─────────────────────
    feats["has_at_before_host"] = float("@" in (parsed.netloc or ""))

    # ── Feature 27: Suspicious TLD ────────────────────────────────────────
    tld_parts = set(tld_suffix.split("."))
    feats["has_suspicious_tld"] = float(
        bool(tld_suffix in SUSPICIOUS_TLDS or (tld_parts & SUSPICIOUS_TLDS))
    )

    # ── Feature 28: Brand impersonation outside registered domain ─────────
    # Fires ONLY when a known brand name appears outside the registered domain
    is_brand_spoof = False
    for brand in KNOWN_BRANDS:
        if brand in outside_text and domain_label != brand and brand not in reg_domain:
            is_brand_spoof = True
            break
    feats["has_brand_impersonation"] = float(is_brand_spoof)

    # ── Feature 29: Count of digits in registered domain ──────────────────
    feats["domain_num_digits"] = float(sum(ch.isdigit() for ch in reg_domain))

    # ── Feature 31: Domain vowel/letter ratio ─────────────────────────────
    letters = [ch for ch in domain_label if ch.isalpha()]
    vowels = [ch for ch in letters if ch in "aeiou"]
    feats["domain_vowel_ratio"] = float(len(vowels) / len(letters)) if letters else 0.0

    # ── Feature 32: Path depth ────────────────────────────────────────────
    path_segments = [s for s in path.strip("/").split("/") if s]
    feats["path_depth"] = float(len(path_segments))

    # ── Feature 33: Double file extension ─────────────────────────────────
    feats["has_double_extension"] = float(bool(_RE_DOUBLE_EXT.search(path)))

    # ── Feature 34: @ in path or query ────────────────────────────────────
    feats["has_at_in_path"] = float("@" in path or "@" in query)

    # ── Feature 35: // in path ────────────────────────────────────────────
    feats["has_double_slash_in_path"] = float("//" in path)

    # ── Feature 36: IP address in path or query ───────────────────────────
    combined_path_query = f"{path}?{query}"
    feats["has_ip_in_path"] = float(bool(_RE_IPV4_IN_PATH.search(combined_path_query)))

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

    if feat_dict.get("has_brand_impersonation"):
        indicators.append("Target brand name appears outside the registered domain (brand impersonation attempt)")
    if feat_dict.get("has_ip_hostname"):
        indicators.append("Hostname is an IP address literal rather than a registered domain")
    if feat_dict.get("has_at_before_host") or feat_dict.get("has_at_in_path"):
        indicators.append("URL contains '@' symbol — potential credential deception trick")
    if feat_dict.get("is_url_shortener"):
        indicators.append("URL uses a known URL-shortening service (destination hidden)")
    if feat_dict.get("has_suspicious_tld"):
        indicators.append("Domain uses a top-level domain (TLD) frequently associated with malicious campaigns")
    if feat_dict.get("has_suspicious_terms"):
        indicators.append("URL path or query contains sensitive security keywords (e.g. login, verify, account)")
    if feat_dict.get("has_punycode"):
        indicators.append("Hostname contains punycode (IDN) encoding — possible homograph attack")
    if feat_dict.get("has_non_ascii_hostname"):
        indicators.append("Hostname contains non-ASCII characters")
    if feat_dict.get("has_double_extension"):
        indicators.append("URL path contains double file extensions (e.g. .php.html or .pdf.exe)")
    if feat_dict.get("has_ip_in_path"):
        indicators.append("URL path or query embeds an explicit IPv4 address")
    if feat_dict.get("has_double_slash_in_path"):
        indicators.append("URL path contains double slashes ('//') indicating possible path redirection")
    if feat_dict.get("has_long_hostname"):
        indicators.append(f"Hostname is unusually long (> {LONG_HOSTNAME_THRESHOLD} characters)")
    if feat_dict.get("has_non_default_port"):
        indicators.append("URL specifies a non-standard port number")
    if feat_dict.get("has_unusual_encoding"):
        indicators.append("URL contains an unusually high number of encoded characters")
    if feat_dict.get("has_repeated_separators"):
        indicators.append("URL contains repeated obfuscation separators (e.g. '&&', '??', '==')")

    url_len = feat_dict.get("url_length", 0)
    if url_len > 75:
        indicators.append(f"URL is unusually long ({int(url_len)} characters)")

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
