"""
fetch_data.py – Download public phishing and benign URL feeds.

Phishing feeds used
-------------------
1. OpenPhish (free community feed)
   URL: https://openphish.com/feed.txt
   Format: one URL per line, no auth required.

2. PhishTank (free JSON bulk data, no API key needed for anonymous download
   of the "full" database but requires registration for the API key version).
   We use the public CSV export at:
   https://data.phishtank.com/data/online-valid.csv
   NOTE: PhishTank limits anonymous downloads to once per hour.
   If the download fails we fall back to OpenPhish only and report it.

Benign feed
-----------
Tranco top-1M list (https://tranco-list.eu/).
We download the current list and keep the top 10 000 domains,
then build plausible URLs as  https://<domain>/

All raw files go into  data/raw/  (git-ignored).
A sources.json manifest is written to data/processed/sources.json.

Usage
-----
    python scripts/fetch_data.py
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
RAW.mkdir(parents=True, exist_ok=True)
PROCESSED.mkdir(parents=True, exist_ok=True)

TIMEOUT = 60  # seconds per request

DOWNLOAD_DATE = datetime.now(timezone.utc).strftime("%Y-%m-%d")


def download(url: str, dest: Path, description: str) -> bool:
    """Download *url* to *dest*. Returns True on success."""
    print(f"  Downloading {description} …", flush=True)
    try:
        resp = requests.get(url, timeout=TIMEOUT, stream=True)
        resp.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                fh.write(chunk)
        size_kb = dest.stat().st_size // 1024
        print(f"  ✓ Saved {dest.name}  ({size_kb} KB)", flush=True)
        return True
    except Exception as exc:
        print(f"  ✗ Failed: {exc}", flush=True)
        return False


# ── OpenPhish ─────────────────────────────────────────────────────────────────
def fetch_openphish() -> dict | None:
    dest = RAW / "openphish.txt"
    ok = download(
        "https://openphish.com/feed.txt",
        dest,
        "OpenPhish community feed",
    )
    if not ok:
        return None
    lines = dest.read_text(encoding="utf-8", errors="replace").splitlines()
    urls = [ln.strip() for ln in lines if ln.strip().startswith("http")]
    print(f"  OpenPhish: {len(urls)} phishing URLs")
    return {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "download_date": DOWNLOAD_DATE,
        "count": len(urls),
        "file": str(dest),
    }


# ── PhishTank ─────────────────────────────────────────────────────────────────
def fetch_phishtank() -> dict | None:
    """
    PhishTank publishes a public CSV of currently-online verified phishes.
    No API key is required; anonymous downloads are rate-limited to 1/hour.
    """
    dest = RAW / "phishtank.csv"
    ok = download(
        "https://data.phishtank.com/data/online-valid.csv",
        dest,
        "PhishTank online-valid CSV",
    )
    if not ok:
        return None
    try:
        with open(dest, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        count = len(rows)
        print(f"  PhishTank: {count} entries")
        return {
            "name": "PhishTank",
            "url": "https://data.phishtank.com/data/online-valid.csv",
            "download_date": DOWNLOAD_DATE,
            "count": count,
            "file": str(dest),
        }
    except Exception as exc:
        print(f"  ✗ Could not parse PhishTank CSV: {exc}")
        return None


# ── Tranco ────────────────────────────────────────────────────────────────────
def fetch_tranco(top_n: int = 10_000) -> dict | None:
    """
    Download the Tranco top-1M list (ZIP) and keep the top *top_n* domains.
    Saves a plain-text file of  https://<domain>/  URLs.
    """
    zip_dest = RAW / "tranco_top1m.csv.zip"
    ok = download(
        "https://tranco-list.eu/top-1m.csv.zip",
        zip_dest,
        "Tranco top-1M list (zip)",
    )
    if not ok:
        return None

    dest = RAW / f"tranco_top{top_n}.txt"
    try:
        with zipfile.ZipFile(zip_dest) as zf:
            name = zf.namelist()[0]  # usually 'top-1m.csv'
            with zf.open(name) as inner:
                text = io.TextIOWrapper(inner, encoding="utf-8")
                domains = []
                for i, line in enumerate(text):
                    if i >= top_n:
                        break
                    parts = line.strip().split(",", 1)
                    if len(parts) == 2:
                        domains.append(parts[1].strip())

        # Write plausible HTTPS URLs
        urls = [f"https://{d}/" for d in domains]
        dest.write_text("\n".join(urls), encoding="utf-8")
        print(f"  Tranco: {len(urls)} benign URLs (top {top_n} domains)")
        return {
            "name": "Tranco",
            "url": "https://tranco-list.eu/top-1m.csv.zip",
            "download_date": DOWNLOAD_DATE,
            "count": len(urls),
            "note": f"Top {top_n} domains, converted to https://<domain>/",
            "file": str(dest),
        }
    except Exception as exc:
        print(f"  ✗ Could not process Tranco ZIP: {exc}")
        return None


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    print("=" * 60)
    print("PhishGuard – fetch_data.py")
    print(f"Download date : {DOWNLOAD_DATE}")
    print("=" * 60)

    sources: list[dict] = []

    print("\n[1/3] OpenPhish …")
    info = fetch_openphish()
    if info:
        sources.append(info)
    else:
        print("  WARNING: OpenPhish failed. Check connectivity.")

    print("\n[2/3] PhishTank …")
    info = fetch_phishtank()
    if info:
        sources.append(info)
    else:
        print(
            "  WARNING: PhishTank failed (rate-limit or connectivity).\n"
            "  Continuing with OpenPhish only."
        )

    print("\n[3/3] Tranco …")
    info = fetch_tranco(top_n=10_000)
    if info:
        sources.append(info)
    else:
        print("  ERROR: Tranco download failed. Cannot build benign set.")
        sys.exit(1)

    if not any(s["name"] in ("OpenPhish", "PhishTank") for s in sources):
        print(
            "\nERROR: No phishing feed was downloaded successfully.\n"
            "Please check your internet connection and retry."
        )
        sys.exit(1)

    # Write manifest
    manifest_path = PROCESSED / "sources.json"
    manifest_path.write_text(json.dumps(sources, indent=2), encoding="utf-8")
    print(f"\n✓ sources.json written to {manifest_path}")
    print("\nSummary:")
    for s in sources:
        print(f"  {s['name']:12s}: {s['count']:>6,} entries  (date: {s['download_date']})")
    print("\nDone. Run  python scripts/split_data.py  next.")


if __name__ == "__main__":
    main()
