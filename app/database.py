"""
app/database.py – SQLite known-phishing database layer.

Table
-----
phishing(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,        -- normalised URL
    domain      TEXT NOT NULL,        -- registered domain
    source      TEXT NOT NULL,        -- 'OpenPhish' | 'PhishTank' | …
    date_added  TEXT NOT NULL         -- ISO date string, e.g. '2026-10-22'
)

Indexes on url and domain for fast O(log n) lookups.

Public API
----------
init_db(db_path)          – create tables and indexes if absent
insert_bulk(rows, db_path) – fast bulk insert (used by build_db.py)
lookup(normalised_url, domain, db_path) -> dict | None
    Returns {'url', 'domain', 'source', 'date_added'} or None.

WHOIS cache table (used by rules.py to cache domain-age lookups):
domain_age_cache(
    domain      TEXT PRIMARY KEY,
    created_date TEXT | NULL,         -- ISO date or None if unknown
    cached_at   TEXT NOT NULL         -- ISO datetime
)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

# Default DB path (relative to repo root)
_DEFAULT_DB = Path(__file__).resolve().parent.parent / "phishguard.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Enable WAL for better concurrent read performance
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path = _DEFAULT_DB) -> None:
    """Create the database schema if it does not already exist."""
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS phishing (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT NOT NULL,
                domain      TEXT NOT NULL,
                source      TEXT NOT NULL,
                date_added  TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_phishing_url
                ON phishing(url);

            CREATE INDEX IF NOT EXISTS idx_phishing_domain
                ON phishing(domain);

            -- WHOIS / RDAP domain-age cache (used by rules.py)
            CREATE TABLE IF NOT EXISTS domain_age_cache (
                domain       TEXT PRIMARY KEY,
                created_date TEXT,          -- ISO date string or NULL if unknown
                cached_at    TEXT NOT NULL   -- ISO datetime
            );
            """
        )


def insert_bulk(
    rows: list[dict],
    db_path: Path = _DEFAULT_DB,
    batch_size: int = 5_000,
) -> int:
    """
    Insert rows into the phishing table, ignoring duplicates by URL.

    Each row must have keys: url, domain, source, date_added.
    Returns the number of rows actually inserted.
    """
    init_db(db_path)
    inserted = 0
    with _connect(db_path) as conn:
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            result = conn.executemany(
                """
                INSERT OR IGNORE INTO phishing (url, domain, source, date_added)
                VALUES (:url, :domain, :source, :date_added)
                """,
                batch,
            )
            inserted += result.rowcount
    return inserted


def lookup(
    normalised_url: str,
    domain: str,
    db_path: Path = _DEFAULT_DB,
) -> Optional[dict]:
    """
    Look up a URL in the known-phishing database.

    Checks by normalised URL first (exact match), then by registered domain.
    Returns a plain dict with keys {url, domain, source, date_added, match_type}
    or None if not found.

    match_type is either 'url' (exact URL match) or 'domain' (domain match).
    """
    if not Path(db_path).exists():
        return None

    with _connect(db_path) as conn:
        # 1. Exact URL match
        row = conn.execute(
            "SELECT url, domain, source, date_added FROM phishing WHERE url = ? LIMIT 1",
            (normalised_url,),
        ).fetchone()
        if row:
            return {**dict(row), "match_type": "url"}

        # 2. Domain match (catches URL variations of a known phishing domain)
        if domain:
            row = conn.execute(
                "SELECT url, domain, source, date_added FROM phishing WHERE domain = ? LIMIT 1",
                (domain,),
            ).fetchone()
            if row:
                return {**dict(row), "match_type": "domain"}

    return None


def db_stats(db_path: Path = _DEFAULT_DB) -> dict:
    """Return total row count and per-source counts."""
    if not Path(db_path).exists():
        return {"total": 0, "by_source": {}}

    with _connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM phishing").fetchone()[0]
        rows = conn.execute(
            "SELECT source, COUNT(*) AS cnt FROM phishing GROUP BY source ORDER BY cnt DESC"
        ).fetchall()
        by_source = {r["source"]: r["cnt"] for r in rows}

    return {"total": total, "by_source": by_source}


# ── WHOIS cache helpers (used by rules.py) ────────────────────────────────────

def cache_domain_age(
    domain: str,
    created_date: Optional[str],
    db_path: Path = _DEFAULT_DB,
) -> None:
    """Persist a WHOIS/RDAP result for *domain* into the cache table."""
    from datetime import datetime, timezone

    cached_at = datetime.now(timezone.utc).isoformat()
    init_db(db_path)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO domain_age_cache (domain, created_date, cached_at)
            VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                created_date = excluded.created_date,
                cached_at    = excluded.cached_at
            """,
            (domain, created_date, cached_at),
        )


def get_cached_domain_age(
    domain: str,
    db_path: Path = _DEFAULT_DB,
    max_age_hours: int = 24,
) -> Optional[str]:
    """
    Return the cached created_date for *domain*, or None if not cached
    or if the cache entry is older than *max_age_hours*.

    Returns the string 'unknown' if the domain was looked up but had no
    creation date, or an ISO date string like '2024-03-15'.
    """
    if not Path(db_path).exists():
        return None

    from datetime import datetime, timezone, timedelta

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT created_date, cached_at FROM domain_age_cache WHERE domain = ?",
            (domain,),
        ).fetchone()

    if row is None:
        return None

    # Check cache freshness
    try:
        cached_at = datetime.fromisoformat(row["cached_at"])
        if datetime.now(timezone.utc) - cached_at > timedelta(hours=max_age_hours):
            return None
    except Exception:
        return None

    # Return 'unknown' sentinel or the actual date
    return row["created_date"] if row["created_date"] is not None else "unknown"
