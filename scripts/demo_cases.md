# PhishGuard – Demo cases (exact inputs for video)

Use these **exact** strings in the web UI (one-click buttons) or when calling `POST /check`.

All examples are either from the curated `data/lure_set.csv` or realistic synthetic lures. They are **not** taken from real victim reports.

---

## 1. Lookalike / potential database or strong rules hit

**Input:**
```
http://onlinesbii.co.in/netbanking
```

**Expected:** Suspicious or Dangerous (brand lookalike + structural signals; may also hit DB depending on current feed).

---

## 2. Bank / government lookalike (not relying on DB)

**Input:**
```
http://sbi-kyc-verification.top/login.php
```

**Expected:** Suspicious or Dangerous (SBI brand + suspicious TLD + path).

---

## 3. Fake e-challan message with .apk link

**Input:**
```
Traffic Police Notice: Your vehicle challan of Rs 1500 is pending. Pay immediately: http://echallan-notice.com/download/echallan.apk
```

**Expected:** Dangerous (urgency + e-challan lure + `.apk` download).

---

## 4. Hindi KYC scam message

**Input:**
```
प्रिय ग्राहक, आपका बैंक खाता आज रात ब्लॉक कर दिया जाएगा। तुरंत अपना पैन कार्ड और आधार अपडेट करें http://bank-kyc-verify.top
```

**Expected:** Suspicious or Dangerous (Hindi urgency / KYC language + lookalike domain).

Optional Tamil variant (same button group if needed):
```
உங்கள் வங்கி கணக்கு முடக்கப்பட்டுள்ளது. உடனடியாக கேஒய்சி புதுப்பிக்கவும் இல்லை என்றால் கணக்கு நிரந்தரமாக ரத்து செய்யப்படும்: http://sbi-kyc-tamil.top
```

---

## 5. Genuine site (Safe)

**Input:**
```
https://irctc.co.in/
```

**Expected:** Safe (official domain on allowlist / no suspicious signals). Score 0.

Alternatives:
```
https://sbi.co.in/
https://parivahan.gov.in/parivahan/
```

---

## API one-liner (for terminal demos)

```bash
curl -s -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"input": "https://irctc.co.in/"}' | python -m json.tool
```
