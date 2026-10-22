# PhishGuard Evaluation Metrics & Benchmark Report

Submitted for the **Seva First Innovation Challenge** — Ministry of Education, India.

---

## 1. Core Summary Metrics

| Metric | Key | Value | Description |
| :--- | :--- | :--- | :--- |
| **Database Size** | `DB_SIZE` | **120** | Known phishing URLs loaded into SQLite database |
| **Database Sources** | `DB_SOURCES` | `{"OpenPhish": 120}` | Source feed breakdown (PhishTank, OpenPhish) |
| **Phishing Test Set** | `DATASET_PHISH` | **23** | Held-out phishing URLs (zero domain overlap) |
| **Benign Test Set** | `DATASET_BENIGN` | **2,997** | Held-out benign URLs from Tranco Top-10k |
| **Precision** | `PRECISION` | **0.5833** (58.33%) | TP / (TP + FP) on held-out test set |
| **Recall** | `RECALL` | **0.9130** (91.30%) | TP / (TP + FN) on held-out test set |
| **F1 Score** | `F1` | **0.7118** | Harmonic mean of Precision and Recall |
| **False Positive Rate** | `FPR` | **0.0050** (0.50%) | FP / (FP + TN) on held-out benign domains |
| **Database Hit Rate** | `DB_HIT_RATE` | **1.0000** (100.00%) | Catch rate on sample of known threats |
| **Indian Benchmark Size** | `INDIAN_SET_SIZE` | **54** | Curated Indian brand & scam cases |
| **Indian Benchmark F1** | `INDIAN_SET_RESULT.f1` | **0.9492** (94.44% accuracy) | Performance on Indian scams |

---

## 2. Held-Out Test Set Performance

- **Evaluation Basis**: The evaluation is conducted on completely withheld URLs that were **never** used during model training or database loading.
- **Decision Threshold**: Score ≥ 35 (Suspicious or Dangerous) treated as positive prediction; Score < 35 (Safe) treated as negative.

### Confusion Matrix

| | Predicted Phish | Predicted Safe | Total |
| :--- | :--- | :--- | :--- |
| **Actual Phish** | **21** (TP) | **2** (FN) | **23** |
| **Actual Benign** | **15** (FP) | **2,982** (TN) | **2,997** |

---

## 3. Curated Indian Lure Benchmark (`data/lure_set.csv`)

Curated set of realistic Indian-specific test cases (fake e-challan, bank KYC, UPI/lottery lures, gov portal lookalikes, APK download links, and Tamil/Hindi/Hinglish threat messages). Explicitly marked as curated, not real-world victim data.

- **Total Cases**: 54
- **Accuracy**: 94.44%
- **Precision**: 100.00%
- **Recall**: 90.32%
- **F1-Score**: 0.9492
- **Category Breakdown**:
  - `genuine_bank`: 5/5 correct (100%)
  - `genuine_gov`: 6/6 correct (100%)
  - `genuine_upi`: 2/2 correct (100%)
  - `genuine_general`: 3/3 correct (100%)
  - `genuine_sms`: 7/7 correct (100%)
  - `bank_lookalike`: 6/6 correct (100%)
  - `fake_echallan`: 4/4 correct (100%)
  - `gov_lookalike`: 4/4 correct (100%)
  - `apk_lure`: 3/3 correct (100%)
  - `upi_scam`: 2/3 correct (67%)
  - `kyc_fraud`: 1/1 correct (100%)
  - `hindi_scam`: 3/3 correct (100%)
  - `hinglish_scam`: 3/4 correct (75%)
  - `tamil_scam`: 2/3 correct (67%)

---

## 4. Evaluation Integrity & Anti-Leakage Protocol

To ensure rigorous scientific validity and eliminate data leakage, PhishGuard enforces three disjoint partitions:

1. **Database Set (`phishing_db.csv`)**: Phishing URLs stored in SQLite for instantaneous blocklist lookups.
2. **Training Set (`phishing_train.csv`, `benign_train.csv`)**: Lexical URL features used to train the Random Forest model.
3. **Held-Out Test Set (`phishing_test.csv`, `benign_test.csv`)**: Unseen URLs used strictly for final validation.

### Overlap Verification Counts (computed at runtime by evaluate.py)

| Set Overlap Check | Registered Domains Shared | Normalized URLs Shared | Status |
| :--- | :--- | :--- | :--- |
| **Test Set vs. Database Set** | **0** | **0** | PASSED (Clean) |
| **Test Set vs. Training Set** | **0** | **0** | PASSED (Clean) |

- **Zero Domain Leakage**: Neither the database nor the training set contains any registered domain present in the held-out test set. The model and database are evaluated on entirely novel domain infrastructure.
- **Strict Parameter Isolation**: Thresholds (<35 Safe, 35-65 Suspicious, >65 Dangerous) and feature extraction rules were tuned strictly on the Training set, leaving the Test set unpolluted.
- **No Synthetic or Rounded Estimates**: All metrics are calculated directly via `evaluate.py`.
- **Abort-on-leakage**: If any overlap count is non-zero the script exits with an error before any metrics are written.
