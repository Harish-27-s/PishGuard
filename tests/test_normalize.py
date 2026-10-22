"""
tests/test_normalize.py – Unit tests for app/normalize.py
"""

import pytest
import sys
from pathlib import Path

# Ensure repo root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.normalize import normalize, normalize_url_string, NormalizedURL


# ── Basic parsing ──────────────────────────────────────────────────────────────

def test_returns_dataclass():
    result = normalize("http://example.com/path")
    assert isinstance(result, NormalizedURL)


def test_none_on_empty():
    assert normalize("") is None
    assert normalize("   ") is None


def test_none_on_no_host():
    # A string that has no host after scheme stripping
    assert normalize("http://") is None


# ── Scheme handling ────────────────────────────────────────────────────────────

def test_missing_scheme_added():
    result = normalize("example.com/path")
    assert result is not None
    assert result.scheme == "http"


def test_https_preserved():
    result = normalize("https://example.com/")
    assert result.scheme == "https"


def test_scheme_lowercased():
    result = normalize("HTTP://EXAMPLE.COM/")
    assert result is not None
    assert result.scheme == "http"


# ── Host normalisation ────────────────────────────────────────────────────────

def test_host_lowercased():
    result = normalize("https://SBI.CO.IN/home")
    assert result is not None
    assert result.host == "sbi.co.in"


def test_registered_domain():
    result = normalize("https://login.sbi.co.in/netbanking")
    assert result is not None
    assert result.registered_domain == "sbi.co.in"


def test_subdomain_extracted():
    result = normalize("https://www.paypal-login.com/")
    assert result is not None
    assert result.subdomain == "www"


def test_ip_address_detected():
    result = normalize("http://192.168.1.1/phish")
    assert result is not None
    assert result.is_ip is True


def test_normal_domain_not_ip():
    result = normalize("https://sbi.co.in/")
    assert result is not None
    assert result.is_ip is False


# ── Tracking parameter stripping ──────────────────────────────────────────────

def test_utm_params_stripped():
    result = normalize(
        "https://example.com/page?utm_source=email&utm_medium=cpc&keep=1"
    )
    assert result is not None
    assert "utm_source" not in result.normalised
    assert "utm_medium" not in result.normalised
    assert "keep=1" in result.normalised


def test_fbclid_stripped():
    result = normalize("https://example.com/?fbclid=abc123&page=home")
    assert result is not None
    assert "fbclid" not in result.normalised
    assert "page=home" in result.normalised


def test_gclid_stripped():
    result = normalize("https://example.com/?gclid=XYZ&q=test")
    assert result is not None
    assert "gclid" not in result.normalised


def test_no_params_unchanged():
    result = normalize("https://example.com/search?q=phishing")
    assert result is not None
    assert "q=phishing" in result.normalised


# ── Fragment removal ──────────────────────────────────────────────────────────

def test_fragment_removed():
    result = normalize("https://example.com/page#section2")
    assert result is not None
    assert "#" not in result.normalised


def test_fragment_only_url():
    result = normalize("https://example.com/#top")
    assert result is not None
    assert "#" not in result.normalised


# ── Path handling ─────────────────────────────────────────────────────────────

def test_path_preserved():
    result = normalize("https://example.com/login/secure")
    assert result is not None
    assert result.path == "/login/secure"


def test_percent_encoding_decoded_in_path():
    result = normalize("https://example.com/p%61th")  # 'a' encoded
    assert result is not None
    assert result.path == "/path"


# ── TLD extraction ────────────────────────────────────────────────────────────

def test_gov_in_tld():
    result = normalize("https://incometax.gov.in/")
    assert result is not None
    assert result.suffix == "gov.in"
    assert result.registered_domain == "incometax.gov.in"


def test_co_in_tld():
    result = normalize("https://sbi.co.in/")
    assert result is not None
    assert result.suffix == "co.in"


# ── Convenience wrapper ────────────────────────────────────────────────────────

def test_normalize_url_string_returns_string():
    url = "https://example.com/?utm_source=x&keep=yes"
    result = normalize_url_string(url)
    assert isinstance(result, str)
    assert "utm_source" not in result


def test_normalize_url_string_fallback_on_empty():
    result = normalize_url_string("   ")
    assert isinstance(result, str)


# ── Whitelist-relevant tests ───────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected_domain", [
    ("https://sbi.co.in/", "sbi.co.in"),
    ("https://irctc.co.in/", "irctc.co.in"),
    ("https://google.com/", "google.com"),
    ("https://incometax.gov.in/", "incometax.gov.in"),
])
def test_known_safe_domains_parse_correctly(url, expected_domain):
    result = normalize(url)
    assert result is not None
    assert result.registered_domain == expected_domain
