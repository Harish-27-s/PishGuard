"""
train.py – Train the Random Forest phishing detection model on the TRAIN set only.

Data integrity:
  - Only reads data/processed/phishing_train.csv and data/processed/benign_train.csv.
  - The held-out test set (phishing_test.csv, benign_test.csv) is strictly untouched.
  - Uses 12 lexical URL features extracted by app/model.py.
  - Reports exact class balance and cross-validation performance.
  - Saves trained model to model.joblib via joblib.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.config import PROCESSED_DIR
from app.model import FEATURE_NAMES, MODEL_PATH, extract_features


def load_train_data() -> tuple[list[str], np.ndarray]:
    """Load URLs and binary labels from the TRAIN split only."""
    phish_path = PROCESSED_DIR / "phishing_train.csv"
    benign_path = PROCESSED_DIR / "benign_train.csv"

    if not phish_path.exists() or not benign_path.exists():
        raise FileNotFoundError(
            f"Train split files not found in {PROCESSED_DIR}. Run scripts/split_data.py first."
        )

    urls: list[str] = []
    labels: list[int] = []

    # 1. Phishing train (label = 1)
    with open(phish_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            u = row.get("normalised_url") or row.get("url")
            if u:
                urls.append(u)
                labels.append(1)

    # 2. Benign train (label = 0)
    with open(benign_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            u = row.get("normalised_url") or row.get("url")
            if u:
                urls.append(u)
                labels.append(0)

    return urls, np.array(labels, dtype=np.int32)


def main() -> None:
    print("=" * 65)
    print("PhishGuard – Model Training (train.py)")
    print("Train Set Only (Strict Disjointness Enforced)")
    print("=" * 65)

    urls, y = load_train_data()

    n_phish = int(np.sum(y == 1))
    n_benign = int(np.sum(y == 0))
    total = len(y)
    ratio = n_phish / n_benign if n_benign else 0.0

    print(f"\nClass Balance (Train Set Only):")
    print(f"  Phishing (Class 1) : {n_phish:>6,}  ({100 * n_phish / total:.1f}%)")
    print(f"  Benign   (Class 0) : {n_benign:>6,}  ({100 * n_benign / total:.1f}%)")
    print(f"  Total              : {total:>6,}")
    print(f"  Ratio (Phish:Benign): 1 : {1 / ratio:.2f}  ({ratio:.2f}:1)")

    print(f"\nExtracting {len(FEATURE_NAMES)} lexical features for {total:,} URLs …")
    X_list = []
    for i, u in enumerate(urls):
        X_list.append(extract_features(u))
        if (i + 1) % 2500 == 0 or (i + 1) == total:
            print(f"  Processed {i + 1:,} / {total:,} URLs …", flush=True)

    X = np.array(X_list, dtype=np.float64)

    # Cross-validation on TRAIN set only
    print("\nRunning 5-Fold Stratified Cross-Validation on TRAIN set …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    rf_cv = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    f1_scores = cross_val_score(rf_cv, X, y, cv=cv, scoring="f1")
    auc_scores = cross_val_score(rf_cv, X, y, cv=cv, scoring="roc_auc")
    prec_scores = cross_val_score(rf_cv, X, y, cv=cv, scoring="precision")
    rec_scores = cross_val_score(rf_cv, X, y, cv=cv, scoring="recall")

    print(f"  Cross-Validation Metrics (Mean ± Std):")
    print(f"    Precision : {prec_scores.mean():.4f} ± {prec_scores.std():.4f}")
    print(f"    Recall    : {rec_scores.mean():.4f} ± {rec_scores.std():.4f}")
    print(f"    F1-Score  : {f1_scores.mean():.4f} ± {f1_scores.std():.4f}")
    print(f"    ROC-AUC   : {auc_scores.mean():.4f} ± {auc_scores.std():.4f}")

    # Train final model on entire TRAIN set
    print("\nTraining final Random Forest model on full TRAIN set …")
    final_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    final_model.fit(X, y)

    # Feature importances
    importances = final_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\nLexical Feature Importances:")
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"  {rank:2d}. {FEATURE_NAMES[idx]:24s} : {importances[idx]:.4f}")

    # Save model
    joblib.dump(final_model, MODEL_PATH)
    size_mb = MODEL_PATH.stat().st_size / (1024 * 1024)
    print(f"\n✓ Model successfully saved to {MODEL_PATH} ({size_mb:.2f} MB)")
    print("Done. Model is ready for app/scoring.py and app/main.py.")


if __name__ == "__main__":
    main()
