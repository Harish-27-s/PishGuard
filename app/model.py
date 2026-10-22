"""
app/model.py – Lexical URL feature extraction and Random Forest model inference.

Features extracted:
  1. url_length: total length of normalized URL
  2. dot_count: total number of dots in hostname
  3. hyphen_count: total number of hyphens in hostname
  4. digit_ratio: fraction of numeric digits in hostname
  5. subdomain_depth: count of subdomain segments
  6. entropy: Shannon entropy of hostname
  7. has_at: presence of '@' in URL (0 or 1)
  8. is_ip: whether host is an IPv4 or IPv6 address (0 or 1)
  9. suspicious_tld: whether TLD is in high-abuse TLD list (0 or 1)
 10. brand_keyword_present: presence of Indian brand keyword on non-official domain (0 or 1)
 11. path_length: character length of URL path
 12. special_char_count: frequency of punctuation characters (?, =, &, %, _, /)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np

from app.config import ROOT, get_official_allowlist, load_brands
from app.normalize import NormalizedURL, normalize
from app.rules import SUSPICIOUS_TLDS, calculate_entropy

MODEL_PATH = ROOT / "model.joblib"

FEATURE_NAMES = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "digit_ratio",
    "subdomain_depth",
    "entropy",
    "has_at",
    "is_ip",
    "suspicious_tld",
    "brand_keyword_present",
    "path_length",
    "special_char_count",
]

_CACHED_MODEL: Any = None


def extract_features(url: str, brands: Optional[list[dict[str, Any]]] = None) -> list[float]:
    """
    Extract 12 lexical features from *url*.
    Returns a float vector corresponding to FEATURE_NAMES.
    """
    norm = normalize(url)
    if norm is None:
        # Fallback for unparseable strings
        return [0.0] * len(FEATURE_NAMES)

    host = norm.host.lower()
    path = norm.path
    orig = norm.original
    suffix = norm.suffix.lower()

    # 1. URL Length
    url_length = float(len(orig))

    # 2. Dot Count in host
    dot_count = float(host.count("."))

    # 3. Hyphen Count in host
    hyphen_count = float(host.count("-"))

    # 4. Digit Ratio in host
    digits = sum(c.isdigit() for c in host)
    digit_ratio = float(digits / len(host)) if host else 0.0

    # 5. Subdomain Depth
    subparts = [p for p in norm.subdomain.split(".") if p]
    subdomain_depth = float(len(subparts))

    # 6. Shannon Entropy of host
    ent = float(calculate_entropy(host))

    # 7. Has '@'
    has_at = 1.0 if "@" in orig else 0.0

    # 8. Host is IP
    is_ip = 1.0 if norm.is_ip else 0.0

    # 9. Suspicious TLD
    suspicious_tld = 1.0 if suffix in SUSPICIOUS_TLDS else 0.0

    # 10. Brand keyword present on non-official domain
    brand_kw = 0.0
    allowlist = get_official_allowlist()
    if norm.registered_domain not in allowlist:
        if brands is None:
            brands = load_brands()
        for b in brands:
            official_doms = {d.lower() for d in b.get("official_domains", [])}
            if norm.registered_domain in official_doms:
                continue
            for kw in b.get("keywords", []):
                kw_clean = kw.lower().strip()
                if len(kw_clean) >= 3 and (kw_clean in host or kw_clean in path.lower()):
                    brand_kw = 1.0
                    break
            if brand_kw > 0.0:
                break

    # 11. Path Length
    path_length = float(len(path))

    # 12. Special Character Count in full URL (?, =, &, %, _, /)
    specials = set("?=&%_/")
    special_char_count = float(sum(1 for c in orig if c in specials))

    return [
        url_length,
        dot_count,
        hyphen_count,
        digit_ratio,
        subdomain_depth,
        ent,
        has_at,
        is_ip,
        suspicious_tld,
        brand_kw,
        path_length,
        special_char_count,
    ]


def load_model(path: Path = MODEL_PATH) -> Any:
    """Load the trained Random Forest model from disk (cached)."""
    global _CACHED_MODEL
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL

    if not path.exists():
        return None

    _CACHED_MODEL = joblib.load(path)
    return _CACHED_MODEL


def predict_proba(url: str, model_path: Path = MODEL_PATH) -> float:
    """
    Return the predicted probability (0.0 to 1.0) that *url* is phishing.
    If the model is not trained yet or domain is in allowlist, returns safe probability.
    """
    norm = normalize(url)
    if norm is None:
        return 0.0

    # Genuine allowlisted sites return 0.0 probability
    allowlist = get_official_allowlist()
    if norm.registered_domain in allowlist:
        return 0.0

    model = load_model(model_path)
    if model is None:
        # Fallback if model has not been trained yet
        return 0.0

    features = extract_features(url)
    features_2d = np.array([features], dtype=np.float64)

    try:
        # Index 1 is probability of class 1 (phishing)
        proba = float(model.predict_proba(features_2d)[0][1])
        return proba
    except Exception:
        return 0.0
