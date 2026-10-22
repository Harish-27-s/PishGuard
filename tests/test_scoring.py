"""
tests/test_scoring.py – Unit tests for Stage 4 (model inference & scoring engine).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.database import init_db, insert_bulk
from app.model import extract_features, predict_proba
from app.scoring import score_input


# ── Database Hit Tests ────────────────────────────────────────────────────────

def test_database_exact_hit(tmp_path: Path) -> None:
    db_file = tmp_path / "test_phish.db"
    init_db(db_file)
    insert_bulk(
        [
            {
                "url": "http://evil-banking-portal.com/login",
                "domain": "evil-banking-portal.com",
                "source": "PhishTank",
                "date_added": "2026-10-22",
            }
        ],
        db_path=db_file,
    )

    res = score_input("http://evil-banking-portal.com/login", db_path=db_file)
    assert res["verdict"] == "Dangerous"
    assert res["score"] == 100
    assert res["source"] == "database"
    assert any("found in known-phishing database" in r.lower() for r in res["reasons"])
    assert "PhishTank" in res["reasons"][0]


def test_database_domain_hit(tmp_path: Path) -> None:
    db_file = tmp_path / "test_phish.db"
    init_db(db_file)
    insert_bulk(
        [
            {
                "url": "http://evil-bank.com/path1",
                "domain": "evil-bank.com",
                "source": "OpenPhish",
                "date_added": "2026-10-22",
            }
        ],
        db_path=db_file,
    )

    # Different path on known phishing domain
    res = score_input("http://evil-bank.com/different-path", db_path=db_file)
    assert res["verdict"] == "Dangerous"
    assert res["score"] == 100
    assert res["source"] == "database"


# ── Genuine Sites ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "https://sbi.co.in/",
        "https://irctc.co.in/",
        "https://google.com/",
        "https://incometax.gov.in/",
    ],
)
def test_genuine_sites_score_safe(url: str, tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    res = score_input(url, db_path=db_file)
    assert res["verdict"] == "Safe"
    assert res["score"] == 0
    assert len(res["reasons"]) >= 1


def test_verified_domain_subdomain_is_safe(tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    res = score_input("https://login.onlinesbi.sbi/netbanking", db_path=db_file)
    assert res["verdict"] == "Safe"
    assert res["score"] == 0


def test_brand_lookalike_outside_verified_domain_is_not_allowlisted(tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    res = score_input("https://onlinesbi.sbi.bank.in/", db_path=db_file)
    assert res["verdict"] == "Suspicious"
    assert res["score"] >= 35
    assert any("brand keyword" in reason.lower() for reason in res["reasons"])


# ── Suspicious & Dangerous Rule / ML Triggers ─────────────────────────────────

def test_bank_lookalike_scores_suspicious_or_dangerous(tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    res = score_input("http://onlinesbii.co.in/netbanking/login", db_path=db_file)
    assert res["verdict"] in ("Suspicious", "Dangerous")
    assert res["score"] >= 35
    assert len(res["reasons"]) >= 1


def test_apk_link_scores_dangerous(tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    res = score_input("http://echallan-portal.site/download/app.apk", db_path=db_file)
    assert res["verdict"] == "Dangerous"
    assert res["score"] >= 65


def test_fake_challan_message_scoring(tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    message = (
        "Traffic Police: Your e-challan of Rs 1000 is pending. "
        "Pay immediately or vehicle registration blocked: http://echallan-morth.site/pay"
    )
    res = score_input(message, db_path=db_file)
    assert res["verdict"] in ("Suspicious", "Dangerous")
    assert res["score"] >= 35
    assert any("challan" in r.lower() for r in res["reasons"])


# ── Machine Learning Model Unit Tests ─────────────────────────────────────────

def test_feature_extraction_vector_length() -> None:
    features = extract_features("https://sbi.co.in/portal/web/home")
    assert len(features) == 12
    assert all(isinstance(f, (int, float)) for f in features)


def test_predict_proba_range() -> None:
    prob = predict_proba("http://sample-test-domain-12345.xyz/login.php")
    assert 0.0 <= prob <= 1.0


def test_always_returns_reasons(tmp_path: Path) -> None:
    db_file = tmp_path / "empty.db"
    res = score_input("https://unknown-random-domain.org", db_path=db_file)
    assert len(res["reasons"]) >= 1
    assert all(isinstance(r, str) for r in res["reasons"])
