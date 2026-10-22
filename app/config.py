"""
app/config.py – Global configuration, paths, weights, and thresholds for PhishGuard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
PROCESSED_DIR = DATA_DIR / "processed"
DB_PATH = ROOT / "phishguard.db"

BRANDS_PATH = DATA_DIR / "indian_brands.json"
PATTERNS_PATH = DATA_DIR / "message_patterns.json"

# Scoring thresholds
THRESHOLD_SAFE_MAX = 35       # score < 35  -> Safe
THRESHOLD_SUSP_MAX = 65       # 35 <= score <= 65 -> Suspicious; score > 65 -> Dangerous

# Weights for combining rules and ML probability in scoring.py
WEIGHT_RULES = 0.50
WEIGHT_ML = 0.50

# Rule point assignments
POINTS_LOOKALIKE_BRAND = 45
POINTS_FAKE_GOV = 55
POINTS_BRAND_IN_SUBDOMAIN_OR_PATH = 40
POINTS_IP_HOST = 45
POINTS_PUNYCODE = 35
POINTS_UNUSUAL_TLD = 25
POINTS_HIGH_ENTROPY = 20
POINTS_EXCESSIVE_DOTS = 15
POINTS_EXCESSIVE_HYPHENS = 15
POINTS_HIGH_DIGIT_RATIO = 15
POINTS_AT_SYMBOL = 35
POINTS_LONG_URL = 15
POINTS_SUBDOMAIN_DEPTH = 15
POINTS_APK_LINK = 60
POINTS_RECENT_DOMAIN = 35

POINTS_MESSAGE_URGENCY = 25
POINTS_MESSAGE_KYC = 30
POINTS_MESSAGE_CHALLAN = 35
POINTS_MESSAGE_ACCOUNT = 30
POINTS_MESSAGE_PRIZE = 25
POINTS_MESSAGE_APK = 50


def load_brands() -> list[dict[str, Any]]:
    """Load Indian brand profiles from data/indian_brands.json."""
    if not BRANDS_PATH.exists():
        return []
    with open(BRANDS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_official_allowlist() -> set[str]:
    """
    Build an allow-list of official registered domains and hosts from indian_brands.json,
    plus foundational trusted domains (e.g. google.com).
    """
    allowlist = {
        "google.com",
        "google.co.in",
        "gstatic.com",
        "microsoft.com",
        "apple.com",
        "gov.in",
        "nic.in",
    }
    brands = load_brands()
    for b in brands:
        for domain in b.get("official_domains", []):
            d = domain.strip().lower()
            if d:
                allowlist.add(d)
    return allowlist


def is_official_host(host: str, allowlist: set[str] | None = None) -> bool:
    """Return whether *host* is an allowlisted domain or a real subdomain of one."""
    normalized_host = host.strip().lower().rstrip(".")
    if not normalized_host:
        return False

    trusted_domains = allowlist if allowlist is not None else get_official_allowlist()
    return any(
        normalized_host == domain or normalized_host.endswith(f".{domain}")
        for domain in trusted_domains
    )


def load_message_patterns() -> dict[str, Any]:
    """Load multilingual urgency and scam patterns from message_patterns.json."""
    if not PATTERNS_PATH.exists():
        return {"languages": {}}
    with open(PATTERNS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)
