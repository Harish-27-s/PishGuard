"""
normalize.py – URL normalisation utilities for PhishGuard.

Steps applied (in order):
1. Strip leading/trailing whitespace.
2. Add 'http://' scheme if missing (so tldextract can parse the host).
3. Parse with urllib.parse.urlparse.
4. Lowercase the host and scheme.
5. Remove tracking query parameters (utm_*, fbclid, gclid, ref, …).
6. Remove URL fragments (#…).
7. Percent-decode the path once (idempotent).
8. Use tldextract to extract subdomain, registered_domain, suffix.

Returns a NormalizedURL dataclass so callers get structured fields
without re-parsing.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import tldextract

# ── Tracking parameters to strip ──────────────────────────────────────────────
_TRACKING_PARAMS: frozenset[str] = frozenset(
    [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "fbclid",
        "gclid",
        "msclkid",
        "dclid",
        "zanpid",
        "igshid",
        "ref",
        "referrer",
        "mc_eid",
        "mc_cid",
    ]
)

# Regex that matches any param whose *name* starts with utm_
_UTM_RE = re.compile(r"^utm_", re.IGNORECASE)


@dataclass
class NormalizedURL:
    """Structured representation of a normalised URL."""

    original: str
    normalised: str          # canonical URL string (no tracking, no fragment)
    scheme: str              # 'http' or 'https'
    host: str                # full host (may include subdomains), lowercase
    registered_domain: str   # e.g. 'sbi.co.in'
    subdomain: str           # e.g. 'www'
    suffix: str              # TLD, e.g. 'co.in'
    path: str                # URL path
    is_ip: bool              # True if host is an IPv4/IPv6 address


# IPv4 detection (simple but sufficient for scoring)
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def _strip_tracking(query_string: str) -> str:
    """Remove known tracking parameters from a query string."""
    if not query_string:
        return ""
    params = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
    kept = [
        (k, v)
        for k, v in params
        if k.lower() not in _TRACKING_PARAMS and not _UTM_RE.match(k)
    ]
    return urllib.parse.urlencode(kept)


def normalize(url: str) -> Optional[NormalizedURL]:
    """
    Normalise *url* and return a NormalizedURL, or None if unparseable.

    Handles:
    - Missing scheme (prepends 'http://')
    - Uppercase hosts
    - Tracking parameters
    - URL fragments
    - Punycode hosts (kept as-is so downstream can detect them)
    """
    raw = url.strip()
    if not raw:
        return None

    # Add scheme if missing so urlparse can split host vs path correctly
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        raw_with_scheme = "http://" + raw
    else:
        raw_with_scheme = raw

    try:
        parsed = urllib.parse.urlparse(raw_with_scheme)
    except Exception:
        return None

    scheme = parsed.scheme.lower() or "http"
    host = parsed.hostname or ""  # hostname is already lowercased by urlparse
    if not host:
        return None

    # Decode percent-encoding in path once
    path = urllib.parse.unquote(parsed.path)

    # Strip tracking query params; remove fragment entirely
    clean_query = _strip_tracking(parsed.query)

    # Rebuild the canonical URL
    normalised = urllib.parse.urlunparse(
        (scheme, parsed.netloc.lower(), path, parsed.params, clean_query, "")
    )

    # tldextract gives us registered_domain, subdomain, suffix
    ext = tldextract.extract(host)
    # Use top_domain_under_public_suffix (new name) with fallback for older versions
    reg_domain_raw = (
        ext.top_domain_under_public_suffix
        if hasattr(ext, "top_domain_under_public_suffix")
        else ext.registered_domain  # type: ignore[attr-defined]
    )
    registered_domain = reg_domain_raw.lower() if reg_domain_raw else host.lower()
    subdomain = ext.subdomain.lower()
    suffix = ext.suffix.lower()

    is_ip = bool(_IPV4_RE.match(host)) or host.startswith("[")  # IPv6

    return NormalizedURL(
        original=url,
        normalised=normalised,
        scheme=scheme,
        host=host,
        registered_domain=registered_domain,
        subdomain=subdomain,
        suffix=suffix,
        path=path,
        is_ip=is_ip,
    )


def normalize_url_string(url: str) -> str:
    """
    Convenience wrapper – returns the canonical URL string,
    or the original (stripped) URL if normalisation fails.
    """
    result = normalize(url)
    if result is None:
        return url.strip()
    return result.normalised
