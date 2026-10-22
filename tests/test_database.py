"""
tests/test_database.py – Unit tests for app/database.py

Uses a temporary in-memory-style SQLite file (pytest tmp_path fixture)
so the production database is never touched.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.database import (
    init_db,
    insert_bulk,
    lookup,
    db_stats,
    cache_domain_age,
    get_cached_domain_age,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path: Path) -> Path:
    """Return a path to a fresh temporary database, pre-seeded with test rows."""
    db_path = tmp_path / "test_phishguard.db"
    init_db(db_path)

    rows = [
        {
            "url": "http://fake-sbi-login.com/netbanking",
            "domain": "fake-sbi-login.com",
            "source": "OpenPhish",
            "date_added": "2026-10-22",
        },
        {
            "url": "http://phishtank-example.com/login",
            "domain": "phishtank-example.com",
            "source": "PhishTank",
            "date_added": "2026-10-20",
        },
        {
            "url": "http://another-phish.net/steal",
            "domain": "another-phish.net",
            "source": "OpenPhish",
            "date_added": "2026-10-21",
        },
    ]
    insert_bulk(rows, db_path=db_path)
    return db_path


# ── init_db ───────────────────────────────────────────────────────────────────

def test_init_db_creates_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "init_test.db"
    init_db(db_path)
    assert db_path.exists()

    import sqlite3
    with sqlite3.connect(str(db_path)) as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "phishing" in tables
    assert "domain_age_cache" in tables


def test_init_db_idempotent(tmp_path: Path) -> None:
    """Calling init_db twice must not raise."""
    db_path = tmp_path / "idempotent.db"
    init_db(db_path)
    init_db(db_path)  # second call – no error


# ── insert_bulk ────────────────────────────────────────────────────────────────

def test_insert_bulk_returns_count(tmp_path: Path) -> None:
    db_path = tmp_path / "insert_test.db"
    rows = [
        {"url": "http://a.com/", "domain": "a.com", "source": "X", "date_added": "2026-01-01"},
        {"url": "http://b.com/", "domain": "b.com", "source": "X", "date_added": "2026-01-01"},
    ]
    n = insert_bulk(rows, db_path=db_path)
    assert n == 2


def test_insert_bulk_ignores_duplicates(tmp_path: Path) -> None:
    db_path = tmp_path / "dup_test.db"
    rows = [
        {"url": "http://dup.com/", "domain": "dup.com", "source": "X", "date_added": "2026-01-01"},
    ]
    first = insert_bulk(rows, db_path=db_path)
    second = insert_bulk(rows, db_path=db_path)
    assert first == 1
    assert second == 0  # duplicate – ignored


# ── lookup – HIT ──────────────────────────────────────────────────────────────

def test_lookup_exact_url_hit(db: Path) -> None:
    result = lookup(
        "http://fake-sbi-login.com/netbanking",
        "fake-sbi-login.com",
        db_path=db,
    )
    assert result is not None
    assert result["match_type"] == "url"
    assert result["source"] == "OpenPhish"
    assert result["domain"] == "fake-sbi-login.com"
    assert result["date_added"] == "2026-10-22"


def test_lookup_domain_hit(db: Path) -> None:
    """A different URL on the same phishing domain should still be caught."""
    result = lookup(
        "http://fake-sbi-login.com/otp-verify",   # different path, same domain
        "fake-sbi-login.com",
        db_path=db,
    )
    assert result is not None
    assert result["match_type"] == "domain"
    assert result["domain"] == "fake-sbi-login.com"


def test_lookup_phishtank_hit(db: Path) -> None:
    result = lookup(
        "http://phishtank-example.com/login",
        "phishtank-example.com",
        db_path=db,
    )
    assert result is not None
    assert result["source"] == "PhishTank"


# ── lookup – MISS ─────────────────────────────────────────────────────────────

def test_lookup_miss_unknown_url(db: Path) -> None:
    result = lookup("https://sbi.co.in/", "sbi.co.in", db_path=db)
    assert result is None


def test_lookup_miss_unknown_domain(db: Path) -> None:
    result = lookup("https://google.com/", "google.com", db_path=db)
    assert result is None


def test_lookup_miss_partial_domain(db: Path) -> None:
    """A *subdomain* of a known phishing domain is not automatically a hit
    unless the *registered domain* is the same."""
    result = lookup(
        "http://sub.not-in-db.com/",
        "not-in-db.com",
        db_path=db,
    )
    assert result is None


def test_lookup_no_db_returns_none(tmp_path: Path) -> None:
    """Querying a non-existent DB path should return None, not raise."""
    result = lookup("http://example.com/", "example.com", db_path=tmp_path / "nofile.db")
    assert result is None


# ── db_stats ──────────────────────────────────────────────────────────────────

def test_db_stats_total(db: Path) -> None:
    stats = db_stats(db)
    assert stats["total"] == 3


def test_db_stats_by_source(db: Path) -> None:
    stats = db_stats(db)
    assert stats["by_source"]["OpenPhish"] == 2
    assert stats["by_source"]["PhishTank"] == 1


def test_db_stats_missing_db(tmp_path: Path) -> None:
    stats = db_stats(tmp_path / "missing.db")
    assert stats["total"] == 0
    assert stats["by_source"] == {}


# ── WHOIS cache ───────────────────────────────────────────────────────────────

def test_cache_domain_age_stores_and_retrieves(tmp_path: Path) -> None:
    db_path = tmp_path / "cache_test.db"
    cache_domain_age("newdomain.com", "2026-09-01", db_path=db_path)
    result = get_cached_domain_age("newdomain.com", db_path=db_path)
    assert result == "2026-09-01"


def test_cache_domain_age_unknown(tmp_path: Path) -> None:
    db_path = tmp_path / "cache_unknown.db"
    cache_domain_age("mystery.com", None, db_path=db_path)
    result = get_cached_domain_age("mystery.com", db_path=db_path)
    assert result == "unknown"


def test_cache_domain_age_miss(tmp_path: Path) -> None:
    db_path = tmp_path / "cache_miss.db"
    init_db(db_path)
    result = get_cached_domain_age("notcached.com", db_path=db_path)
    assert result is None


def test_cache_domain_age_upsert(tmp_path: Path) -> None:
    """Caching a domain twice should update, not duplicate."""
    db_path = tmp_path / "upsert.db"
    cache_domain_age("upd.com", "2020-01-01", db_path=db_path)
    cache_domain_age("upd.com", "2024-06-15", db_path=db_path)
    result = get_cached_domain_age("upd.com", db_path=db_path)
    assert result == "2024-06-15"
