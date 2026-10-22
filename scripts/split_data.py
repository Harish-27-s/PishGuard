"""
split_data.py – Split phishing and benign URLs into three disjoint sets.

Sets produced
-------------
DB set    : phishing URLs loaded into SQLite (known-phishing database).
Train set : phishing + benign URLs for model training (may share domains
            with the DB set since both are "known threats", but NEVER
            shares domains with the test set).
Test set  : phishing + benign URLs withheld from everything else.
            Deduplicated by normalised URL *and* by registered domain.

Split ratios
------------
Phishing : DB 40 % | Train 30 % | Test 30 %
Benign   : Train 70 % | Test 30 %
(Benign URLs are not added to the DB – the DB is phishing-only.)

Random seed: 42 (fixed for reproducibility).

Deduplication
-------------
1. Normalise every URL (lowercase host, strip tracking params, etc.).
2. Drop duplicates by normalised URL.
3. Ensure no registered_domain appears in both train and test by
   resolving conflicts in favour of the test set (conservative).

Outputs  (all in data/processed/)
-------
phishing_db.csv    – DB set
phishing_train.csv – phishing portion of train set
phishing_test.csv  – phishing portion of test set
benign_train.csv   – benign portion of train set
benign_test.csv    – benign portion of test set

Each CSV has columns: url, normalised_url, registered_domain, source
"""

from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

# Resolve repo root (scripts/ is one level down)
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.normalize import normalize

RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
PROCESSED.mkdir(parents=True, exist_ok=True)

SEED = 42

# Split fractions for phishing URLs
PHISH_DB_FRAC = 0.40
PHISH_TRAIN_FRAC = 0.30
# remaining 0.30 → test

# Split fraction for benign URLs
BENIGN_TEST_FRAC = 0.30


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_openphish() -> list[dict]:
    path = RAW / "openphish.txt"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        url = line.strip()
        if url.startswith("http"):
            rows.append({"url": url, "source": "OpenPhish"})
    return rows


def load_phishtank() -> list[dict]:
    path = RAW / "phishtank.csv"
    if not path.exists():
        return []
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            url = row.get("url", "").strip()
            if url.startswith("http"):
                rows.append({"url": url, "source": "PhishTank"})
    return rows


def load_tranco(top_n: int = 10_000) -> list[dict]:
    path = RAW / f"tranco_top{top_n}.txt"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        url = line.strip()
        if url:
            rows.append({"url": url, "source": "Tranco"})
    return rows


def normalise_rows(rows: list[dict]) -> list[dict]:
    """Add normalised_url and registered_domain; drop un-parseable URLs."""
    result = []
    for r in rows:
        n = normalize(r["url"])
        if n is None or not n.registered_domain:
            continue
        result.append(
            {
                "url": r["url"],
                "normalised_url": n.normalised,
                "registered_domain": n.registered_domain,
                "source": r["source"],
            }
        )
    return result


def dedup_by_url(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for r in rows:
        key = r["normalised_url"]
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = ["url", "normalised_url", "registered_domain", "source"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def enforce_domain_disjoint(
    train: list[dict], test: list[dict]
) -> tuple[list[dict], list[dict]]:
    """
    Remove from *train* any row whose registered_domain appears in *test*.
    We preserve the test set unchanged (conservative).
    """
    test_domains = {r["registered_domain"] for r in test}
    clean_train = [r for r in train if r["registered_domain"] not in test_domains]
    removed = len(train) - len(clean_train)
    if removed:
        print(
            f"    Domain-disjoint enforcement: removed {removed} train row(s) "
            f"whose domain also appeared in test."
        )
    return clean_train, test


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    rng = random.Random(SEED)

    print("=" * 60)
    print("PhishGuard – split_data.py  (seed=42)")
    print("=" * 60)

    # ── Load phishing ──────────────────────────────────────────────────────────
    print("\nLoading phishing URLs …")
    phish_raw = load_openphish() + load_phishtank()
    if not phish_raw:
        print("ERROR: No phishing data found in data/raw/. Run fetch_data.py first.")
        sys.exit(1)
    print(f"  Raw phishing rows : {len(phish_raw):>7,}")

    phish = normalise_rows(phish_raw)
    print(f"  After normalise   : {len(phish):>7,}")
    phish = dedup_by_url(phish)
    print(f"  After URL-dedup   : {len(phish):>7,}")

    # ── Load benign ────────────────────────────────────────────────────────────
    print("\nLoading benign URLs …")
    benign_raw = load_tranco(top_n=10_000)
    if not benign_raw:
        print("ERROR: No benign data found. Run fetch_data.py first.")
        sys.exit(1)
    print(f"  Raw benign rows   : {len(benign_raw):>7,}")

    benign = normalise_rows(benign_raw)
    print(f"  After normalise   : {len(benign):>7,}")
    benign = dedup_by_url(benign)
    print(f"  After URL-dedup   : {len(benign):>7,}")

    # ── Shuffle ────────────────────────────────────────────────────────────────
    rng.shuffle(phish)
    rng.shuffle(benign)

    # ── Phishing split ─────────────────────────────────────────────────────────
    n = len(phish)
    n_db = int(n * PHISH_DB_FRAC)
    n_train = int(n * PHISH_TRAIN_FRAC)
    # remainder goes to test (avoids off-by-one)
    n_test = n - n_db - n_train

    phish_db = phish[:n_db]
    phish_train = phish[n_db : n_db + n_train]
    phish_test = phish[n_db + n_train :]

    # ── Benign split ───────────────────────────────────────────────────────────
    nb = len(benign)
    nb_test = int(nb * BENIGN_TEST_FRAC)
    nb_train = nb - nb_test

    benign_test = benign[:nb_test]
    benign_train = benign[nb_test:]

    # ── Enforce domain-disjointness (train vs test for phishing) ───────────────
    print("\nEnforcing domain-disjointness between phishing train and test …")
    phish_train, phish_test = enforce_domain_disjoint(phish_train, phish_test)

    # Also check benign (Tranco domains shouldn't overlap phishing test domains)
    phish_test_domains = {r["registered_domain"] for r in phish_test}
    benign_train_clean = [
        r for r in benign_train if r["registered_domain"] not in phish_test_domains
    ]
    benign_test_clean = [
        r for r in benign_test if r["registered_domain"] not in phish_test_domains
    ]

    # ── Write splits ───────────────────────────────────────────────────────────
    splits = {
        "phishing_db.csv": phish_db,
        "phishing_train.csv": phish_train,
        "phishing_test.csv": phish_test,
        "benign_train.csv": benign_train_clean,
        "benign_test.csv": benign_test_clean,
    }

    print("\nWriting split files to data/processed/ …")
    for fname, rows in splits.items():
        p = PROCESSED / fname
        write_csv(p, rows)
        print(f"  {fname:25s}: {len(rows):>6,} rows")

    # ── Summary ────────────────────────────────────────────────────────────────
    total_phish = len(phish_db) + len(phish_train) + len(phish_test)
    total_benign = len(benign_train_clean) + len(benign_test_clean)
    train_phish = len(phish_train)
    train_benign = len(benign_train_clean)
    ratio = train_phish / train_benign if train_benign else float("inf")

    print(f"""
Split summary
─────────────────────────────────────────────────────────
  Phishing total      : {total_phish:>6,}
    DB set            : {len(phish_db):>6,}  ({100*len(phish_db)/total_phish:.1f} %)
    Train set         : {len(phish_train):>6,}  ({100*len(phish_train)/total_phish:.1f} %)
    Test set          : {len(phish_test):>6,}  ({100*len(phish_test)/total_phish:.1f} %)

  Benign total        : {total_benign:>6,}
    Train set         : {len(benign_train_clean):>6,}  ({100*len(benign_train_clean)/total_benign:.1f} %)
    Test set          : {len(benign_test_clean):>6,}  ({100*len(benign_test_clean)/total_benign:.1f} %)

  Train class ratio   : 1 phish : {1/ratio:.2f} benign  ({ratio:.2f}:1 phish-to-benign)
  Random seed         : {SEED}
─────────────────────────────────────────────────────────
Deduplication: by normalised URL; domain-disjointness enforced
between phishing train and phishing test sets.
""")

    # Save split metadata
    meta = {
        "seed": SEED,
        "phish_db_frac": PHISH_DB_FRAC,
        "phish_train_frac": PHISH_TRAIN_FRAC,
        "benign_test_frac": BENIGN_TEST_FRAC,
        "counts": {
            "phishing_db": len(phish_db),
            "phishing_train": len(phish_train),
            "phishing_test": len(phish_test),
            "benign_train": len(benign_train_clean),
            "benign_test": len(benign_test_clean),
        },
        "train_phish_to_benign_ratio": round(ratio, 4),
    }
    (PROCESSED / "split_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    print("✓ split_meta.json written.")
    print("Done. Run  python scripts/build_db.py  next.")


if __name__ == "__main__":
    main()
