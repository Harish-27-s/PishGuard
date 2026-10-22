"""
tests/test_rules.py – Unit tests for Stage 3 rule engine (app/rules.py).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.normalize import normalize
from app.rules import (
    check_lookalike,
    check_url_structure,
    check_apk,
    check_domain_age,
    check_message_text,
    evaluate_rules,
)


# ── Genuine Sites Must NOT Be Flagged ─────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "https://sbi.co.in/",
        "https://sbi.co.in/portal/web/home",
        "https://irctc.co.in/",
        "https://www.irctc.co.in/nget/train-search",
        "https://google.com/",
        "https://www.google.com/search?q=test",
        "https://incometax.gov.in/",
        "https://eportal.incometax.gov.in/iec/foservices/",
    ],
)
def test_genuine_sites_never_flagged(url: str, tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(url, db_path=db_file, skip_network=True)
    assert points == 0, f"Expected 0 points for genuine URL {url}, got {points} with reasons: {reasons}"
    assert any("verified official domain" in r.lower() or "legitimate" in r.lower() or "no suspicious" in r.lower() for r in reasons)


# ── Bank Lookalike Domains Must Be Flagged ────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "http://onlinesbii.co.in/login",
        "http://sbi-kyc-verification.top/",
        "https://hdfc-netbanking-alert.site/login.php",
        "http://icici-bank-update.xyz/",
        "http://secure-portal.com/sbi/netbanking",
    ],
)
def test_bank_lookalikes_flagged(url: str, tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(url, db_path=db_file, skip_network=True)
    assert points >= 35, f"Expected lookalike URL {url} to be flagged (points >= 35), got {points}"
    reasons_text = " ".join(reasons).lower()
    assert (
        "lookalike" in reasons_text
        or "brand keyword" in reasons_text
        or "homoglyph" in reasons_text
        or "unusual or high-risk" in reasons_text
    )


# ── Government Lookalike Portals Must Be Flagged ──────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "http://echallan-parivahan-gov.in/pay",
        "http://parivahan-gov.site/challan",
        "http://incometax-gov.online/refund",
        "http://uidai-aadhaar-update.xyz/verify",
    ],
)
def test_fake_government_domains_flagged(url: str, tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(url, db_path=db_file, skip_network=True)
    assert points >= 45
    reasons_text = " ".join(reasons).lower()
    assert "fake government portal lookalike" in reasons_text or "lookalike" in reasons_text


# ── APK Links Must Be Flagged ─────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "http://echallan-notice.com/download/echallan.apk",
        "https://traffic-police-app.in/vahan_service.apk",
        "http://sbi-rewards.site/sbi_security_update.apk",
    ],
)
def test_apk_links_flagged(url: str, tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(url, db_path=db_file, skip_network=True)
    assert points >= 60, f"Expected APK URL {url} to score >= 60, got {points}"
    reasons_text = " ".join(reasons).lower()
    assert ".apk" in reasons_text or "android application package" in reasons_text


# ── Fake Challan Message Must Be Flagged ──────────────────────────────────────

def test_fake_challan_message_flagged(tmp_path: Path) -> None:
    message = (
        "Traffic Police Notice: Your vehicle challan is pending. "
        "Pay immediately within 24 hours to avoid court warrant: "
        "http://echallan-parivahan-gov.site/pay"
    )
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(message, db_path=db_file, skip_network=True)
    assert points >= 50
    reasons_text = " ".join(reasons).lower()
    assert "challan" in reasons_text
    assert "urgency" in reasons_text or "government portal lookalike" in reasons_text


# ── Multilingual Message Scam Patterns ────────────────────────────────────────

def test_hindi_kyc_message_flagged(tmp_path: Path) -> None:
    message = "प्रिय ग्राहक, आपका बैंक खाता ब्लॉक कर दिया गया है। तुरंत केवाईसी अपडेट करें http://bank-kyc-update.xyz"
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(message, db_path=db_file, skip_network=True)
    assert points >= 40
    reasons_text = " ".join(reasons).lower()
    assert "kyc" in reasons_text or "block" in reasons_text


def test_hinglish_challan_apk_message(tmp_path: Path) -> None:
    message = "Aapka challan pending hai. Turant challan pay karein ya parivahan apk install karein http://echallan.site/pay.apk"
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(message, db_path=db_file, skip_network=True)
    assert points >= 65
    reasons_text = " ".join(reasons).lower()
    assert "challan" in reasons_text
    assert "apk" in reasons_text


def test_tamil_kyc_message_flagged(tmp_path: Path) -> None:
    message = "உங்கள் வங்கி கணக்கு முடக்கப்பட்டது. உடனடியாக கேஒய்சி புதுப்பிக்கவும் http://sbi-kyc-tamil.top"
    db_file = tmp_path / "test.db"
    points, reasons = evaluate_rules(message, db_path=db_file, skip_network=True)
    assert points >= 50
    reasons_text = " ".join(reasons).lower()
    assert "kyc" in reasons_text or "முடக்கப்பட்டது" in message


# ── Structural URL Rules ──────────────────────────────────────────────────────

def test_ip_address_host_flagged() -> None:
    norm = normalize("http://192.168.1.100/login")
    assert norm is not None
    signals = check_url_structure(norm)
    assert any("raw ip address" in s[1].lower() for s in signals)


def test_excessive_subdomain_depth_flagged() -> None:
    norm = normalize("http://a.b.c.d.phishing-portal.com/test")
    assert norm is not None
    signals = check_url_structure(norm)
    assert any("subdomain depth" in s[1].lower() for s in signals)


def test_at_symbol_in_url_flagged() -> None:
    norm = normalize("http://sbi.co.in@evil-phish.com/login")
    assert norm is not None
    signals = check_url_structure(norm)
    assert any("@" in s[1] for s in signals)


# ── RDAP / WHOIS Timeout and Safe Fallback ────────────────────────────────────

def test_domain_age_timeout_safe_fallback(tmp_path: Path) -> None:
    norm = normalize("http://nonexistent-sample-domain-123456789.com")
    assert norm is not None
    db_file = tmp_path / "test_cache.db"

    # Mock requests.get to simulate timeout
    with patch("requests.get", side_effect=Exception("Connection timed out")):
        pts, rsn = check_domain_age(norm, db_path=db_file, timeout=0.1)
        assert pts == 0
        assert rsn is None  # Safe fallback, never crashes!
