"""
app/rules.py – Rule-based explainable phishing & domain spoofing detection engine.

Implements:
  a. Lookalike domain (rapidfuzz edit distance, homoglyph detection, brand keyword in
     subdomain/path of non-official domain, fake government patterns).
  b. URL structure checks (length, subdomain depth, hyphens, digit ratio, '@' symbol,
     IP host, punycode, unusual TLD, number of dots, Shannon entropy).
  c. APK detection (.apk URL extension, or message urging APK/app installation).
  d. Domain age via RDAP/WHOIS with a strict 3-second timeout and safe SQLite cache fallback.
  e. Multilingual message rules (urgency/threats in English, Hindi, Hinglish, Tamil),
     extracting URLs to run full checks.
"""

from __future__ import annotations

import math
import re
import socket
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import tldextract
from rapidfuzz import fuzz, distance

from app.config import (
    DB_PATH,
    get_official_allowlist,
    is_official_host,
    load_brands,
    load_message_patterns,
    POINTS_LOOKALIKE_BRAND,
    POINTS_FAKE_GOV,
    POINTS_BRAND_IN_SUBDOMAIN_OR_PATH,
    POINTS_IP_HOST,
    POINTS_PUNYCODE,
    POINTS_UNUSUAL_TLD,
    POINTS_HIGH_ENTROPY,
    POINTS_EXCESSIVE_DOTS,
    POINTS_EXCESSIVE_HYPHENS,
    POINTS_HIGH_DIGIT_RATIO,
    POINTS_AT_SYMBOL,
    POINTS_LONG_URL,
    POINTS_SUBDOMAIN_DEPTH,
    POINTS_APK_LINK,
    POINTS_RECENT_DOMAIN,
    POINTS_MESSAGE_URGENCY,
    POINTS_MESSAGE_KYC,
    POINTS_MESSAGE_CHALLAN,
    POINTS_MESSAGE_ACCOUNT,
    POINTS_MESSAGE_PRIZE,
    POINTS_MESSAGE_APK,
)
from app.database import cache_domain_age, get_cached_domain_age
from app.normalize import NormalizedURL, normalize


# ── Suspicious TLD list ────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = frozenset(
    [
        "top", "xyz", "club", "work", "site", "buzz", "online", "rest",
        "icu", "tk", "ml", "ga", "cf", "gq", "click", "fit", "link",
        "monster", "cfd", "cam", "sbs", "beauty", "hair", "quest",
        "skin", "fun", "uno", "casa", "surf", "stream", "download",
    ]
)

# Common homoglyph character substitutions (Cyrillic/Greek/Leetspeak -> Latin)
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ո": "n", "һ": "h",
    "0": "o", "1": "l", "3": "e", "5": "s", "8": "b",
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def replace_homoglyphs(text: str) -> str:
    """Replace visually confusable characters with canonical Latin equivalents."""
    out = []
    i = 0
    while i < len(text):
        if text[i : i + 2] == "vv":
            out.append("w")
            i += 2
            continue
        ch = text[i]
        out.append(HOMOGLYPH_MAP.get(ch, ch))
        i += 1
    return "".join(out)


# ── Rule A: Lookalike domain check ────────────────────────────────────────────

def check_lookalike(
    norm: NormalizedURL,
    brands: Optional[list[dict[str, Any]]] = None,
    allowlist: Optional[set[str]] = None,
) -> list[tuple[int, str]]:
    """
    Check for brand lookalikes, homoglyphs, brand keywords in subdomains/paths,
    and fake government portal patterns.
    """
    if allowlist is None:
        allowlist = get_official_allowlist()
    if brands is None:
        brands = load_brands()

    signals: list[tuple[int, str]] = []
    reg_domain = norm.registered_domain.lower()
    host = norm.host.lower()
    path = norm.path.lower()
    suffix = norm.suffix.lower()

    # 1. Allow-list check: if domain is legitimately registered to an official entity, skip
    if is_official_host(host, allowlist):
        return []

    # 2. Fake government portal check:
    # Real Indian gov sites must have suffix 'gov.in' or 'nic.in'.
    # If the domain/host uses 'gov', 'nic', 'parivahan', 'echallan', 'incometax', 'uidai'
    # but does NOT end with .gov.in or .nic.in, flag as high-confidence fake government portal.
    gov_patterns = ["gov", "nic", "echallan", "parivahan", "incometax", "uidai", "morth", "digilocker"]
    has_gov_pattern = any(
        re.search(rf"(?:^|[.\-_]){re.escape(pat)}(?:$|[.\-_])", host)
        for pat in gov_patterns
    )
    if has_gov_pattern:
        if suffix not in ("gov.in", "nic.in"):
            signals.append(
                (
                    POINTS_FAKE_GOV,
                    f"Fake government portal lookalike: Host '{host}' mimics official government identity but does not use .gov.in or .nic.in",
                )
            )

    # 3. Homoglyph and punycode check
    decoded_host = host
    if host.startswith("xn--"):
        try:
            decoded_host = host.encode("ascii").decode("idna")
        except Exception:
            decoded_host = host

    dehomoglyphed_host = replace_homoglyphs(decoded_host)
    if dehomoglyphed_host != decoded_host:
        # Check if the de-homoglyphed string targets an official allowlist domain
        for official in allowlist:
            if official and (official in dehomoglyphed_host or dehomoglyphed_host in official):
                signals.append(
                    (
                        POINTS_LOOKALIKE_BRAND,
                        f"Homoglyph spoofing detected: Domain uses visual lookalike characters targeting '{official}'",
                    )
                )
                break

    # 4. Brand keyword in subdomain or path of a non-official domain
    # Extract the main label of the registered domain (e.g. 'evil' from 'evil.com')
    reg_main = reg_domain.split(".")[0] if "." in reg_domain else reg_domain

    for b in brands:
        b_name = b.get("brand_name", "")
        keywords = b.get("keywords", [])
        official_domains = {d.lower() for d in b.get("official_domains", [])}

        # If this is already an official domain for this brand, ignore
        if is_official_host(host, official_domains):
            continue

        # Check if brand keyword is in subdomain
        for kw in keywords:
            kw_clean = kw.lower().strip()
            if len(kw_clean) < 3:
                continue

            # Brand keyword in subdomain
            if norm.subdomain and re.search(rf"(?:^|[.\-_]){re.escape(kw_clean)}(?:$|[.\-_])", norm.subdomain):
                signals.append(
                    (
                        POINTS_BRAND_IN_SUBDOMAIN_OR_PATH,
                        f"Brand keyword '{kw_clean}' found in subdomain of non-official domain '{reg_domain}' ({b_name})",
                    )
                )
                break

            # Brand keyword in path
            if path and re.search(rf"/(?:[^/]*[.\-_])?{re.escape(kw_clean)}(?:[.\-_][^/]*)?(?:/|$)", path):
                signals.append(
                    (
                        POINTS_BRAND_IN_SUBDOMAIN_OR_PATH,
                        f"Brand keyword '{kw_clean}' in URL path of non-official domain '{reg_domain}' ({b_name})",
                    )
                )
                break

    # 5. Rapidfuzz edit distance against official domains / brand names
    for b in brands:
        b_name = b.get("brand_name", "")
        official_domains = [d.lower() for d in b.get("official_domains", [])]
        if is_official_host(host, set(official_domains)):
            continue

        for off_dom in official_domains:
            off_main = off_dom.split(".")[0]
            if len(off_main) < 3:
                continue

            # Check Levenshtein distance on main registered domain label
            lev = distance.Levenshtein.distance(reg_main, off_main)
            if 0 < lev <= 2 and len(reg_main) >= 4 and len(off_main) >= 4:
                signals.append(
                    (
                        POINTS_LOOKALIKE_BRAND,
                        f"Lookalike domain: '{reg_domain}' is an edit distance of {lev} from official brand domain '{off_dom}' ({b_name})",
                    )
                )
                break

            # Ratio score for longer names
            sim = fuzz.ratio(reg_main, off_main)
            if sim >= 82 and reg_main != off_main:
                signals.append(
                    (
                        POINTS_LOOKALIKE_BRAND,
                        f"Lookalike domain: '{reg_domain}' has high similarity ({sim:.0f}%) to official domain '{off_dom}' ({b_name})",
                    )
                )
                break

    # Deduplicate signals by reason
    unique_signals: list[tuple[int, str]] = []
    seen_reasons = set()
    for pts, rsn in signals:
        if rsn not in seen_reasons:
            seen_reasons.add(rsn)
            unique_signals.append((pts, rsn))

    return unique_signals


# ── Rule B: URL structure checks ──────────────────────────────────────────────

def check_url_structure(norm: NormalizedURL) -> list[tuple[int, str]]:
    """
    Evaluate structural lexical properties of the URL:
    length, subdomain depth, hyphens, digit ratio, '@' symbol, IP host,
    punycode, unusual TLD, dot count, entropy.
    """
    signals: list[tuple[int, str]] = []
    url_str = norm.original
    host = norm.host
    path = norm.path
    suffix = norm.suffix

    # Allowlist bypass check
    allowlist = get_official_allowlist()
    if is_official_host(norm.host, allowlist):
        return []

    # 1. IP address host
    if norm.is_ip:
        signals.append((POINTS_IP_HOST, f"Host '{host}' is a raw IP address instead of a domain name"))

    # 2. Punycode
    if host.startswith("xn--") or ".xn--" in host:
        signals.append((POINTS_PUNYCODE, "Host uses Punycode (internationalized domain name often used in spoofing)"))

    # 3. '@' symbol in URL
    if "@" in url_str:
        signals.append((POINTS_AT_SYMBOL, "URL contains '@' symbol (often used to obscure destination)"))

    # 4. Length
    if len(url_str) > 75:
        signals.append((POINTS_LONG_URL, f"Unusually long URL ({len(url_str)} characters)"))

    # 5. Subdomain depth
    subparts = [p for p in norm.subdomain.split(".") if p]
    if len(subparts) >= 3:
        signals.append((POINTS_SUBDOMAIN_DEPTH, f"Excessive subdomain depth ({len(subparts)} levels: '{norm.subdomain}')"))

    # 6. Hyphens in host
    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        signals.append((POINTS_EXCESSIVE_HYPHENS, f"Multiple hyphens in hostname ({hyphen_count} hyphens)"))

    # 7. Digit ratio in hostname
    digits = sum(c.isdigit() for c in host)
    digit_ratio = digits / len(host) if host else 0.0
    if digit_ratio > 0.22 and not norm.is_ip:
        signals.append((POINTS_HIGH_DIGIT_RATIO, f"High digit density in domain name ({digit_ratio:.0%})"))

    # 8. Excessive dots
    dot_count = host.count(".")
    if dot_count >= 4 and not norm.is_ip:
        signals.append((POINTS_EXCESSIVE_DOTS, f"Excessive dots in hostname ({dot_count} dots)"))

    # 9. Unusual / high-risk TLD
    if suffix in SUSPICIOUS_TLDS:
        signals.append((POINTS_UNUSUAL_TLD, f"Unusual or high-risk top-level domain (.{suffix})"))

    # 10. Shannon Entropy of hostname
    ent = calculate_entropy(host)
    if ent > 4.1:
        signals.append((POINTS_HIGH_ENTROPY, f"High entropy domain name ({ent:.2f} bits, appears randomly generated)"))

    return signals


# ── Rule C: APK check ─────────────────────────────────────────────────────────

def check_apk(norm: Optional[NormalizedURL] = None, text: str = "") -> list[tuple[int, str]]:
    """
    Check if URL links directly to an Android APK or text instructs user to install APK/app.
    """
    signals: list[tuple[int, str]] = []

    if norm:
        # Check path or query string for .apk
        parsed = urlparse(norm.normalised)
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()
        if path_lower.endswith(".apk") or ".apk?" in norm.normalised.lower() or query_lower.endswith(".apk"):
            signals.append((POINTS_APK_LINK, "Direct link to Android application package (.apk file)"))

    # Message text asking to download / install APK or app
    if text:
        text_lower = text.lower()
        apk_text_patterns = [
            r"\.apk\b",
            r"(?:install|download)\s+(?:the\s+)?(?:app|apk|application)",
            r"(?:apk|app)\s+(?:download|install)",
            r"ऐप\s+(?:डाउनलोड|इंस्टॉल)",
            r"செயலியை\s+(?:பதிவிறக்கம்|நிறுவ)",
        ]
        if any(re.search(pat, text_lower) for pat in apk_text_patterns):
            signals.append((POINTS_MESSAGE_APK, "Message directs user to install an external APK or mobile application"))

    return signals


# ── Rule D: Domain age via RDAP/WHOIS ──────────────────────────────────────────

def check_domain_age(
    norm: NormalizedURL,
    db_path: Path = DB_PATH,
    timeout: float = 3.0,
) -> tuple[int, Optional[str]]:
    """
    Check domain creation date via RDAP / WHOIS with a strict timeout and SQLite caching.
    A domain registered under 30 days ago adds points.
    Never crashes; returns (0, None) on timeout or error.
    """
    allowlist = get_official_allowlist()
    if is_official_host(norm.host, allowlist) or norm.is_ip:
        return 0, None

    domain = norm.registered_domain
    if not domain:
        return 0, None

    # 1. Check local cache first
    cached = get_cached_domain_age(domain, db_path=db_path)
    created_iso: Optional[str] = None

    if cached is not None:
        if cached != "unknown":
            created_iso = cached
    else:
        # 2. Query RDAP (fast, REST-based, no subprocess)
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            resp = requests.get(
                rdap_url,
                timeout=timeout,
                headers={"Accept": "application/json", "User-Agent": "phishguard/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for event in data.get("events", []):
                    if event.get("eventAction") in ("registration", "created"):
                        raw_date = event.get("eventDate", "")
                        if raw_date:
                            created_iso = raw_date[:10]
                            break
            # Cache the result (or None if not found)
            cache_domain_age(domain, created_iso, db_path=db_path)
        except Exception:
            # Fallback: record as unknown so we don't block subsequent requests
            cache_domain_age(domain, None, db_path=db_path)

    # 3. Evaluate age if created date found
    if created_iso:
        try:
            created_dt = datetime.fromisoformat(created_iso)
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_old = (now - created_dt).days
            if days_old < 30:
                return (
                    POINTS_RECENT_DOMAIN,
                    f"Newly registered domain ({days_old} days old, registered {created_iso})",
                )
        except Exception:
            pass

    return 0, None


# ── Rule E: Multilingual message rules & URL extraction ────────────────────────

def extract_urls(text: str) -> list[str]:
    """Extract all URLs from message text."""
    url_pattern = re.compile(
        r"(?:https?://|www\.)[^\s<>\"]+|[a-zA-Z0-9.\-]+\.(?:com|in|org|net|co\.in|gov\.in|site|xyz|online|top|info|live)(?:/[^\s<>\"]*)?",
        re.IGNORECASE,
    )
    matches = url_pattern.findall(text)
    clean_urls = []
    for m in matches:
        u = m.rstrip(".,;!?:)'\"]}")
        if u and ("." in u or "://" in u):
            clean_urls.append(u)
    return clean_urls


def check_message_text(text: str) -> list[tuple[int, str]]:
    """
    Check message text for urgency, threats, and scam patterns
    in English, Hindi, Hinglish, and Tamil.
    """
    patterns_data = load_message_patterns()
    languages = patterns_data.get("languages", {})
    signals: list[tuple[int, str]] = []
    seen = set()

    for lang, categories in languages.items():
        # Challan pending
        for pat in categories.get("challan_pending", []):
            if re.search(pat, text, re.IGNORECASE):
                reason = f"Threat/urgency pattern detected: Pending traffic/e-challan notice ({lang})"
                if reason not in seen:
                    seen.add(reason)
                    signals.append((POINTS_MESSAGE_CHALLAN, reason))
                break

        # KYC expiry
        for pat in categories.get("kyc_expiry", []):
            if re.search(pat, text, re.IGNORECASE):
                reason = f"Threat/urgency pattern detected: KYC suspension or update lure ({lang})"
                if reason not in seen:
                    seen.add(reason)
                    signals.append((POINTS_MESSAGE_KYC, reason))
                break

        # Account blocked / disconnection
        for pat in categories.get("account_blocked", []):
            if re.search(pat, text, re.IGNORECASE):
                reason = f"Threat/urgency pattern detected: Account deactivation or service disconnection warning ({lang})"
                if reason not in seen:
                    seen.add(reason)
                    signals.append((POINTS_MESSAGE_ACCOUNT, reason))
                break

        # Prize / lottery / refund
        for pat in categories.get("prize_refund", []):
            if re.search(pat, text, re.IGNORECASE):
                reason = f"Lure pattern detected: Unsolicited prize, lottery, or tax refund ({lang})"
                if reason not in seen:
                    seen.add(reason)
                    signals.append((POINTS_MESSAGE_PRIZE, reason))
                break

        # Action urgency (click now)
        for pat in categories.get("action_urgency", []):
            if re.search(pat, text, re.IGNORECASE):
                reason = f"Urgency indicator detected: Coercive demand for immediate action ({lang})"
                if reason not in seen:
                    seen.add(reason)
                    signals.append((POINTS_MESSAGE_URGENCY, reason))
                break

    return signals


# ── Public Master Check ────────────────────────────────────────────────────────

def evaluate_rules(
    input_text: str,
    db_path: Path = DB_PATH,
    skip_network: bool = False,
) -> tuple[int, list[str]]:
    """
    Main rule engine entry point.
    Accepts a URL or message text.
    Returns:
        total_points (int, capped at 100),
        reasons (list[str])
    """
    raw = input_text.strip()
    if not raw:
        return 0, ["Empty input provided."]

    points = 0
    reasons: list[str] = []

    # Check if input is a direct single URL
    direct_norm = normalize(raw)
    is_direct_url = (
        direct_norm is not None
        and (" " not in raw or raw.startswith("http"))
        and len(raw.split()) <= 1
    )

    allowlist = get_official_allowlist()

    if is_direct_url and direct_norm:
        # Check allowlist for direct URL
        if is_official_host(direct_norm.host, allowlist):
            # Verified official domain: genuine site, never flag!
            return 0, [f"Verified official domain: '{direct_norm.registered_domain}' belongs to a legitimate entity."]

        # Run URL checks
        # 1. Lookalike
        for pts, rsn in check_lookalike(direct_norm, allowlist=allowlist):
            points += pts
            reasons.append(rsn)

        # 2. URL structure
        for pts, rsn in check_url_structure(direct_norm):
            points += pts
            reasons.append(rsn)

        # 3. APK check
        for pts, rsn in check_apk(direct_norm):
            points += pts
            reasons.append(rsn)

        # 4. Domain age check
        if not skip_network:
            age_pts, age_rsn = check_domain_age(direct_norm, db_path=db_path)
            if age_pts > 0 and age_rsn:
                points += age_pts
                reasons.append(age_rsn)

    else:
        # It is a text message (or message containing URLs)
        # 1. Check message threat patterns
        for pts, rsn in check_message_text(raw):
            points += pts
            reasons.append(rsn)

        # 2. Check APK in message
        for pts, rsn in check_apk(text=raw):
            points += pts
            reasons.append(rsn)

        # 3. Extract embedded URLs and run checks on each
        urls = extract_urls(raw)
        for u in urls:
            u_norm = normalize(u)
            if u_norm:
                if is_official_host(u_norm.host, allowlist):
                    continue  # official link in message

                for pts, rsn in check_lookalike(u_norm, allowlist=allowlist):
                    points += pts
                    reasons.append(f"Embedded URL ({u_norm.registered_domain}): {rsn}")

                for pts, rsn in check_url_structure(u_norm):
                    points += pts
                    reasons.append(f"Embedded URL ({u_norm.registered_domain}): {rsn}")

                for pts, rsn in check_apk(u_norm):
                    points += pts
                    reasons.append(f"Embedded URL ({u_norm.registered_domain}): {rsn}")

                if not skip_network:
                    age_pts, age_rsn = check_domain_age(u_norm, db_path=db_path)
                    if age_pts > 0 and age_rsn:
                        points += age_pts
                        reasons.append(f"Embedded URL ({u_norm.registered_domain}): {age_rsn}")

    # Remove duplicate reasons while preserving order
    seen_reasons = set()
    deduped_reasons = []
    for r in reasons:
        if r not in seen_reasons:
            seen_reasons.add(r)
            deduped_reasons.append(r)

    capped_points = min(100, points)
    if not deduped_reasons:
        deduped_reasons = ["No suspicious signals found."]

    return capped_points, deduped_reasons
