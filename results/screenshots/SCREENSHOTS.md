# Screenshots to capture for submission

Take the following **5 screenshots** and place the image files in this folder (`results/screenshots/`).

Suggested filenames:

| # | Filename | What to capture |
|---|----------|-----------------|
| 1 | `01_api_health.png` | Browser or terminal showing `GET /health` (or Swagger at `/docs`) with `status: ok`, non-zero `db_rows`, `model_loaded: true`. |
| 2 | `02_web_safe.png` | Web UI after checking **Demo case 5** (IRCTC / genuine) — green **Safe** verdict, score 0, reasons. |
| 3 | `03_web_dangerous_apk.png` | Web UI after checking **Demo case 3** (e-challan + APK message) — red **Dangerous**, high score, reasons mentioning APK / challan. |
| 4 | `04_web_hindi_scam.png` | Web UI after checking **Demo case 4** (Hindi KYC message) — Suspicious or Dangerous with language / KYC reasons. |
| 5 | `05_extension_popup.png` | Chrome extension popup after checking a lookalike or genuine page — verdict card visible. |

Optional extras (if space allows):

- Confusion-matrix / metrics table from `results/metrics.md`
- Terminal output of `python evaluate.py` showing all four overlap counts = 0

Do **not** include any secrets, API keys, or personal data in screenshots.
