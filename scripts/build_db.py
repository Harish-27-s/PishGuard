"""
scripts/build_db.py – Load the DB split into the SQLite phishing database.

Reads  data/processed/phishing_db.csv  (written by split_data.py) and
data/processed/sources.json  (written by fetch_data.py) and bulk-inserts
all rows into  phishguard.db.

After loading, prints:
  - Total rows in the database
  - Per-source row counts
  - Sample rows (first 5)

Usage
-----
    python scripts/build_db.py [--db PATH]

Options
-------
--db PATH   Path to the SQLite database file.
            Default: phishguard.db in the repo root.
--reset     Drop and recreate the phishing table before loading
            (use this to rebuild from scratch).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.database import init_db, insert_bulk, db_stats

PROCESSED = ROOT / "data" / "processed"
DEFAULT_DB = ROOT / "phishguard.db"


def load_db_csv(csv_path: Path) -> list[dict]:
    """Read the phishing_db.csv and return rows ready for insert_bulk."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(
                {
                    "url": row["normalised_url"],     # store the normalised URL
                    "domain": row["registered_domain"],
                    "source": row["source"],
                    "date_added": _download_date(row["source"]),
                }
            )
    return rows


def _download_date(source: str) -> str:
    """Look up the download date for *source* from sources.json."""
    sources_path = PROCESSED / "sources.json"
    if not sources_path.exists():
        return "unknown"
    try:
        sources = json.loads(sources_path.read_text(encoding="utf-8"))
        for s in sources:
            if s.get("name", "").lower() == source.lower():
                return s.get("download_date", "unknown")
    except Exception:
        pass
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the PhishGuard SQLite database.")
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help=f"Path to SQLite DB file (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop and recreate the phishing table before loading.",
    )
    args = parser.parse_args()

    db_path = Path(args.db)

    print("=" * 60)
    print("PhishGuard – build_db.py")
    print(f"Database    : {db_path}")
    print("=" * 60)

    # Optional reset
    if args.reset and db_path.exists():
        import sqlite3

        print("  --reset: dropping existing phishing table …")
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DROP TABLE IF EXISTS phishing")
            conn.execute("DROP INDEX IF EXISTS idx_phishing_url")
            conn.execute("DROP INDEX IF EXISTS idx_phishing_domain")
        print("  Done.")

    # Initialise schema
    init_db(db_path)

    # Load DB CSV
    csv_path = PROCESSED / "phishing_db.csv"
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found. Run scripts/split_data.py first.")
        sys.exit(1)

    print(f"\nLoading {csv_path.name} …")
    rows = load_db_csv(csv_path)
    print(f"  Rows to insert : {len(rows):>7,}")

    inserted = insert_bulk(rows, db_path=db_path)
    skipped = len(rows) - inserted
    print(f"  Inserted       : {inserted:>7,}")
    print(f"  Skipped (dup)  : {skipped:>7,}")

    # Report stats
    stats = db_stats(db_path)
    print(f"\nDatabase size  : {stats['total']:>7,} rows")
    print("Per-source counts:")
    for source, count in stats["by_source"].items():
        print(f"  {source:15s}: {count:>7,}")

    # Sample rows
    import sqlite3
    print("\nSample rows (first 5):")
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        for r in conn.execute(
            "SELECT url, domain, source, date_added FROM phishing LIMIT 5"
        ).fetchall():
            print(f"  [{r['source']:12s}] {r['domain']:30s}  {r['url'][:70]}")

    print(f"\n✓ Database ready at {db_path}")
    print("Done. Run  python train.py  next (Stage 4) or  python app/main.py  (Stage 5).")


if __name__ == "__main__":
    main()
