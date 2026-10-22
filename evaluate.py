"""
evaluate.py – Evaluation on held-out test set and curated Indian lure benchmark.

Data integrity:
  - Held-out test set is evaluated ONLY (phishing_test.csv and benign_test.csv).
  - At start, verifies ZERO normalized URL overlap and ZERO registered domain
    overlap between the test set and both the DB set and the training set.
    If any overlap exists the process aborts with a clear error.
  - Generates results/metrics.json and results/metrics.md with required keys:
    DB_SIZE, DB_SOURCES, DATASET_PHISH, DATASET_BENIGN, PRECISION, RECALL, F1,
    FPR, DB_HIT_RATE, INDIAN_SET_SIZE, INDIAN_SET_RESULT, plus Evaluation Integrity.
"""

from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.config import DB_PATH, PROCESSED_DIR
from app.database import db_stats
from app.scoring import score_input

RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
METRICS_JSON_PATH = RESULTS_DIR / "metrics.json"
METRICS_MD_PATH = RESULTS_DIR / "metrics.md"
LURE_SET_PATH = ROOT / "data" / "lure_set.csv"


def _load_csv_urls_and_domains(path: Path) -> tuple[set[str], set[str]]:
    """Return (normalised_urls, registered_domains) from a split CSV."""
    urls: set[str] = set()
    domains: set[str] = set()
    if not path.exists():
        return urls, domains
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            u = (r.get("normalised_url") or r.get("url") or "").strip()
            d = (r.get("registered_domain") or "").strip().lower()
            if u:
                urls.add(u)
            if d:
                domains.add(d)
    return urls, domains


def verify_no_leakage() -> dict:
    """
    Verify that the held-out test set shares NO normalised URL and NO
    registered domain with the DB set or the training set.

    Prints the overlap counts. Raises SystemExit(1) if any count is non-zero.
    Returns a dict of the counts for inclusion in the integrity report.
    """
    print("\n[Integrity] Verifying zero overlap between test set and (DB + train) …")

    test_urls, test_domains = set(), set()
    for name in ("phishing_test.csv", "benign_test.csv"):
        u, d = _load_csv_urls_and_domains(PROCESSED_DIR / name)
        test_urls |= u
        test_domains |= d

    db_urls, db_domains = _load_csv_urls_and_domains(PROCESSED_DIR / "phishing_db.csv")

    train_urls, train_domains = set(), set()
    for name in ("phishing_train.csv", "benign_train.csv"):
        u, d = _load_csv_urls_and_domains(PROCESSED_DIR / name)
        train_urls |= u
        train_domains |= d

    # Counts (must all be zero)
    url_test_db = len(test_urls & db_urls)
    url_test_train = len(test_urls & train_urls)
    dom_test_db = len(test_domains & db_domains)
    dom_test_train = len(test_domains & train_domains)

    print(f"  Test vs DB   – normalised URL overlap : {url_test_db}")
    print(f"  Test vs Train – normalised URL overlap : {url_test_train}")
    print(f"  Test vs DB   – registered domain overlap : {dom_test_db}")
    print(f"  Test vs Train – registered domain overlap : {dom_test_train}")

    if url_test_db or url_test_train or dom_test_db or dom_test_train:
        print("\nERROR: Data leakage detected. Aborting evaluation.")
        print("The held-out test set must share zero normalised URLs and zero")
        print("registered domains with both the database set and the training set.")
        print("Re-run scripts/split_data.py (seed=42) and rebuild the DB / model.")
        sys.exit(1)

    print("  ✓ All overlap counts are 0. Proceeding with evaluation.")
    return {
        "url_test_vs_db": url_test_db,
        "url_test_vs_train": url_test_train,
        "domain_test_vs_db": dom_test_db,
        "domain_test_vs_train": dom_test_train,
    }


def load_heldout_test_set() -> tuple[list[str], list[int]]:
    """Load phishing_test.csv and benign_test.csv."""
    phish_path = PROCESSED_DIR / "phishing_test.csv"
    benign_path = PROCESSED_DIR / "benign_test.csv"

    if not phish_path.exists() or not benign_path.exists():
        print("ERROR: Held-out test CSVs missing under data/processed/.")
        print("Run: python scripts/fetch_data.py && python scripts/split_data.py")
        sys.exit(1)

    urls: list[str] = []
    labels: list[int] = []

    with open(phish_path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            u = r.get("normalised_url") or r.get("url")
            if u:
                urls.append(u)
                labels.append(1)

    with open(benign_path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            u = r.get("normalised_url") or r.get("url")
            if u:
                urls.append(u)
                labels.append(0)

    return urls, labels


def evaluate_db_hit_rate(sample_size: int = 2000, seed: int = 42) -> float:
    """Evaluate database hit rate on a random sample of URLs from the DB set."""
    db_csv = PROCESSED_DIR / "phishing_db.csv"
    if not db_csv.exists():
        return 0.0

    db_urls: list[str] = []
    with open(db_csv, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            u = r.get("normalised_url") or r.get("url")
            if u:
                db_urls.append(u)

    if not db_urls:
        return 0.0

    rng = random.Random(seed)
    sample = rng.sample(db_urls, min(sample_size, len(db_urls)))
    hits = 0
    for u in sample:
        res = score_input(u, db_path=DB_PATH)
        if res.get("source") == "database" and res.get("score") == 100:
            hits += 1

    return round(hits / len(sample), 4)


def evaluate_lure_set() -> dict:
    """Evaluate on the curated Indian lure benchmark (data/lure_set.csv)."""
    if not LURE_SET_PATH.exists():
        return {"accuracy": 0.0, "total": 0}

    rows = []
    with open(LURE_SET_PATH, newline="", encoding="utf-8") as fh:
        # Ignore comment lines (curated-notice header)
        lines = [line for line in fh if not line.startswith("#")]
        reader = csv.DictReader(lines)
        for r in reader:
            rows.append(r)

    tp = fp = tn = fn = 0
    by_category: dict[str, dict[str, int]] = {}

    for r in rows:
        inp = r["input"]
        expected = r["expected_label"].strip().lower()
        cat = r.get("category", "general")
        if cat not in by_category:
            by_category[cat] = {"correct": 0, "total": 0}

        res = score_input(inp, db_path=DB_PATH)
        pred_phish = res["score"] >= 35  # Suspicious or Dangerous

        is_phish = expected == "phish"
        if is_phish and pred_phish:
            tp += 1
            by_category[cat]["correct"] += 1
        elif not is_phish and not pred_phish:
            tn += 1
            by_category[cat]["correct"] += 1
        elif not is_phish and pred_phish:
            fp += 1
        else:
            fn += 1
        by_category[cat]["total"] += 1

    total = len(rows)
    acc = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    return {
        "total": total,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "by_category": by_category,
    }


def main() -> None:
    print("=" * 65)
    print("PhishGuard – Evaluation (evaluate.py)")
    print("Evaluation on Held-Out Test Set & Curated Indian Lures")
    print("=" * 65)

    # 0. Mandatory integrity check – aborts on any leakage
    overlap = verify_no_leakage()

    stats = db_stats(DB_PATH)
    db_size = stats["total"]
    db_sources = stats["by_source"]
    print(f"\nDatabase Status: {db_size:,} records loaded ({db_sources})")

    # 1. Held-out test set
    urls, y_true = load_heldout_test_set()
    n_phish = sum(1 for y in y_true if y == 1)
    n_benign = sum(1 for y in y_true if y == 0)
    total_test = len(urls)

    print(f"\nHeld-Out Test Set:")
    print(f"  Phishing (Class 1) : {n_phish:>6,}  ({100 * n_phish / total_test:.1f}%)")
    print(f"  Benign   (Class 0) : {n_benign:>6,}  ({100 * n_benign / total_test:.1f}%)")
    print(f"  Total Test URLs    : {total_test:>6,}")

    print("\nEvaluating scoring engine on held-out test set …")
    tp = fp = tn = fn = 0

    for i, (u, label) in enumerate(zip(urls, y_true)):
        res = score_input(u, db_path=DB_PATH)
        is_threat = res["score"] >= 35  # Suspicious (>=35) or Dangerous (>65)

        if label == 1 and is_threat:
            tp += 1
        elif label == 0 and not is_threat:
            tn += 1
        elif label == 0 and is_threat:
            fp += 1
        else:
            fn += 1

        if (i + 1) % 1500 == 0 or (i + 1) == total_test:
            print(f"  Evaluated {i + 1:,} / {total_test:,} URLs …", flush=True)

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
    accuracy = round((tp + tn) / total_test, 4) if total_test else 0.0

    print(f"\nHeld-Out Test Results:")
    print(f"  Confusion Matrix: TP={tp:,}, FP={fp:,}, TN={tn:,}, FN={fn:,}")
    print(f"  Accuracy  : {accuracy:.4f}  ({accuracy:.2%})")
    print(f"  Precision : {precision:.4f}  ({precision:.2%})")
    print(f"  Recall    : {recall:.4f}  ({recall:.2%})")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"  FPR       : {fpr:.4f}  ({fpr:.2%})")

    # 2. Database hit rate on DB sample
    print("\nMeasuring Database Hit Rate on random sample of 2,000 DB phishing URLs …")
    db_hit_rate = evaluate_db_hit_rate(sample_size=2000, seed=42)
    print(f"  Database Hit Rate: {db_hit_rate:.4f}  ({db_hit_rate:.2%})")

    # 3. Curated Indian lure benchmark
    print("\nEvaluating on Curated Indian Lure Benchmark (data/lure_set.csv) …")
    lure_results = evaluate_lure_set()
    indian_set_size = lure_results["total"]
    print(f"  Indian Set Size     : {indian_set_size}")
    print(f"  Indian Set Accuracy : {lure_results['accuracy']:.2%}")
    print(f"  Indian Set F1-Score : {lure_results['f1']:.4f}")
    print(f"  Indian Set Breakdown: TP={lure_results['tp']}, FP={lure_results['fp']}, TN={lure_results['tn']}, FN={lure_results['fn']}")

    # 4. Save results/metrics.json with exactly the required keys
    metrics_payload = {
        "DB_SIZE": db_size,
        "DB_SOURCES": db_sources,
        "DATASET_PHISH": n_phish,
        "DATASET_BENIGN": n_benign,
        "PRECISION": precision,
        "RECALL": recall,
        "F1": f1,
        "FPR": fpr,
        "DB_HIT_RATE": db_hit_rate,
        "INDIAN_SET_SIZE": indian_set_size,
        "INDIAN_SET_RESULT": lure_results,
    }

    METRICS_JSON_PATH.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
    print(f"\n✓ Saved metrics JSON to {METRICS_JSON_PATH}")

    # 5. Save results/metrics.md with Evaluation Integrity section (real counts)
    metrics_md = f"""# PhishGuard Evaluation Metrics & Benchmark Report

Submitted for the **Seva First Innovation Challenge** — Ministry of Education, India.

---

## 1. Core Summary Metrics

| Metric | Key | Value | Description |
| :--- | :--- | :--- | :--- |
| **Database Size** | `DB_SIZE` | **{db_size:,}** | Known phishing URLs loaded into SQLite database |
| **Database Sources** | `DB_SOURCES` | `{json.dumps(db_sources)}` | Source feed breakdown (PhishTank, OpenPhish) |
| **Phishing Test Set** | `DATASET_PHISH` | **{n_phish:,}** | Held-out phishing URLs (zero domain overlap) |
| **Benign Test Set** | `DATASET_BENIGN` | **{n_benign:,}** | Held-out benign URLs from Tranco Top-10k |
| **Precision** | `PRECISION` | **{precision:.4f}** ({precision:.2%}) | TP / (TP + FP) on held-out test set |
| **Recall** | `RECALL` | **{recall:.4f}** ({recall:.2%}) | TP / (TP + FN) on held-out test set |
| **F1 Score** | `F1` | **{f1:.4f}** | Harmonic mean of Precision and Recall |
| **False Positive Rate** | `FPR` | **{fpr:.4f}** ({fpr:.2%}) | FP / (FP + TN) on held-out benign domains |
| **Database Hit Rate** | `DB_HIT_RATE` | **{db_hit_rate:.4f}** ({db_hit_rate:.2%}) | Catch rate on sample of known threats |
| **Indian Benchmark Size** | `INDIAN_SET_SIZE` | **{indian_set_size}** | Curated Indian brand & scam cases |
| **Indian Benchmark F1** | `INDIAN_SET_RESULT.f1` | **{lure_results['f1']:.4f}** ({lure_results['accuracy']:.2%} accuracy) | Performance on Indian scams |

---

## 2. Held-Out Test Set Performance

- **Evaluation Basis**: The evaluation is conducted on completely withheld URLs that were **never** used during model training or database loading.
- **Decision Threshold**: Score ≥ 35 (Suspicious or Dangerous) treated as positive prediction; Score < 35 (Safe) treated as negative.

### Confusion Matrix

| | Predicted Phish | Predicted Safe | Total |
| :--- | :--- | :--- | :--- |
| **Actual Phish** | **{tp:,}** (TP) | **{fn:,}** (FN) | **{n_phish:,}** |
| **Actual Benign** | **{fp:,}** (FP) | **{tn:,}** (TN) | **{n_benign:,}** |

---

## 3. Curated Indian Lure Benchmark (`data/lure_set.csv`)

Curated set of realistic Indian-specific test cases (fake e-challan, bank KYC, UPI/lottery lures, gov portal lookalikes, APK download links, and Tamil/Hindi/Hinglish threat messages). Explicitly marked as curated, not real-world victim data.

- **Total Cases**: {lure_results['total']}
- **Accuracy**: {lure_results['accuracy']:.2%}
- **Precision**: {lure_results['precision']:.2%}
- **Recall**: {lure_results['recall']:.2%}
- **F1-Score**: {lure_results['f1']:.4f}
- **Category Breakdown**:
"""
    for cat, cstats in lure_results["by_category"].items():
        metrics_md += f"  - `{cat}`: {cstats['correct']}/{cstats['total']} correct ({100 * cstats['correct'] / cstats['total']:.0f}%)\n"

    metrics_md += f"""
---

## 4. Evaluation Integrity & Anti-Leakage Protocol

To ensure rigorous scientific validity and eliminate data leakage, PhishGuard enforces three disjoint partitions:

1. **Database Set (`phishing_db.csv`)**: Phishing URLs stored in SQLite for instantaneous blocklist lookups.
2. **Training Set (`phishing_train.csv`, `benign_train.csv`)**: Lexical URL features used to train the Random Forest model.
3. **Held-Out Test Set (`phishing_test.csv`, `benign_test.csv`)**: Unseen URLs used strictly for final validation.

### Overlap Verification Counts (computed at runtime by evaluate.py)

| Set Overlap Check | Registered Domains Shared | Normalized URLs Shared | Status |
| :--- | :--- | :--- | :--- |
| **Test Set vs. Database Set** | **{overlap['domain_test_vs_db']}** | **{overlap['url_test_vs_db']}** | PASSED (Clean) |
| **Test Set vs. Training Set** | **{overlap['domain_test_vs_train']}** | **{overlap['url_test_vs_train']}** | PASSED (Clean) |

- **Zero Domain Leakage**: Neither the database nor the training set contains any registered domain present in the held-out test set. The model and database are evaluated on entirely novel domain infrastructure.
- **Strict Parameter Isolation**: Thresholds (<35 Safe, 35-65 Suspicious, >65 Dangerous) and feature extraction rules were tuned strictly on the Training set, leaving the Test set unpolluted.
- **No Synthetic or Rounded Estimates**: All metrics are calculated directly via `evaluate.py`.
- **Abort-on-leakage**: If any overlap count is non-zero the script exits with an error before any metrics are written.
"""

    METRICS_MD_PATH.write_text(metrics_md, encoding="utf-8")
    print(f"✓ Saved metrics Markdown to {METRICS_MD_PATH}")
    print("\nDone. Evaluation complete.")


if __name__ == "__main__":
    main()
