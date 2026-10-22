"""
app/scoring.py – Verdict calculation and explainable scoring engine.

Output structure:
{
  "verdict": "Safe" | "Suspicious" | "Dangerous",
  "score": int (0 to 100),
  "reasons": list[str],
  "source": "database" | "rules" | "ml" | "combined"
}

Scoring logic:
1. If exact URL or registered domain is in the known-phishing SQLite DB:
   score = 100, verdict = "Dangerous", source = "database",
   reason = "Found in known-phishing database (<source>, <date_added>)".
2. Otherwise, combine rule points and ML probability:
   combined = round(WEIGHT_RULES * rule_points + WEIGHT_ML * (ml_prob * 100))
   capped between 0 and 100.
3. Thresholds (from app/config.py):
   score < 35  -> "Safe"
   35 <= score <= 65 -> "Suspicious"
   score > 65  -> "Dangerous"
4. Always returns at least one plain-language reason.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from app.config import (
    DB_PATH,
    THRESHOLD_SAFE_MAX,
    THRESHOLD_SUSP_MAX,
    WEIGHT_ML,
    WEIGHT_RULES,
    get_official_allowlist,
    is_official_host,
)
from app.database import lookup
from app.model import predict_proba
from app.normalize import normalize
from app.rules import evaluate_rules, extract_urls


def score_input(input_text: str, db_path: Path = DB_PATH) -> dict[str, Any]:
    """
    Score a URL or text message.
    Returns verdict, 0-100 score, reasons, and detection source.
    """
    raw = (input_text or "").strip()
    if not raw:
        return {
            "verdict": "Safe",
            "score": 0,
            "reasons": ["Empty input provided."],
            "source": "rules",
        }

    # Determine whether the input is a single direct URL or a message
    direct_norm = normalize(raw)
    is_direct_url = bool(
        direct_norm is not None
        and (" " not in raw or raw.startswith("http://") or raw.startswith("https://"))
        and len(raw.split()) <= 1
    )

    allowlist = get_official_allowlist()

    # ── LAYER 1: Database Check ────────────────────────────────────────────────
    if is_direct_url and direct_norm:
        # Check if direct URL is in allowlist first (genuine sites never flagged)
        if is_official_host(direct_norm.host, allowlist):
            return {
                "verdict": "Safe",
                "score": 0,
                "reasons": [
                    f"Verified official domain: '{direct_norm.registered_domain}' belongs to a legitimate and verified service."
                ],
                "source": "rules",
            }

        # Check SQLite known-phishing database
        hit = lookup(direct_norm.normalised, direct_norm.registered_domain, db_path=db_path)
        if hit:
            match_detail = f" (domain match: {hit['domain']})" if hit.get("match_type") == "domain" else ""
            return {
                "verdict": "Dangerous",
                "score": 100,
                "reasons": [
                    f"Found in known-phishing database ({hit['source']}, {hit['date_added']}){match_detail}"
                ],
                "source": "database",
            }
    else:
        # Message input: extract embedded URLs and check DB
        embedded_urls = extract_urls(raw)
        for u in embedded_urls:
            u_norm = normalize(u)
            if u_norm and not is_official_host(u_norm.host, allowlist):
                hit = lookup(u_norm.normalised, u_norm.registered_domain, db_path=db_path)
                if hit:
                    return {
                        "verdict": "Dangerous",
                        "score": 100,
                        "reasons": [
                            f"Embedded link '{u_norm.registered_domain}' found in known-phishing database ({hit['source']}, {hit['date_added']})"
                        ],
                        "source": "database",
                    }

    # ── LAYER 2: Rules + Machine Learning ─────────────────────────────────────
    # Evaluate rule engine
    rule_pts, raw_rule_reasons = evaluate_rules(raw, db_path=db_path)

    # Filter out placeholder "no suspicious signals" from raw rule reasons
    rule_reasons = [
        r for r in raw_rule_reasons if r != "No suspicious signals found."
    ]

    # Evaluate ML model
    ml_prob = 0.0
    if is_direct_url and direct_norm:
        ml_prob = predict_proba(direct_norm.original)
    else:
        embedded_urls = extract_urls(raw)
        if embedded_urls:
            ml_prob = max((predict_proba(u) for u in embedded_urls), default=0.0)
        else:
            # Pure text message without links: rules solely govern
            ml_prob = 0.0

    # Combine rule points and ML probability
    if not is_direct_url and not extract_urls(raw):
        # Text-only scam message (no URL)
        combined_score = rule_pts
        source = "rules"
    else:
        rule_component = WEIGHT_RULES * float(rule_pts)
        ml_component = WEIGHT_ML * (float(ml_prob) * 100.0)
        combined_score = round(rule_component + ml_component)

        # Source attribution
        if rule_pts > 0 and ml_prob >= 0.35:
            source = "combined"
        elif rule_pts > 0:
            source = "rules"
        elif ml_prob >= 0.50:
            source = "ml"
        else:
            source = "combined"

    final_score = max(0, min(100, int(combined_score)))

    # Determine verdict using thresholds in config.py
    if final_score < THRESHOLD_SAFE_MAX:
        verdict = "Safe"
    elif final_score <= THRESHOLD_SUSP_MAX:
        verdict = "Suspicious"
    else:
        verdict = "Dangerous"

    # Assemble reasons list
    reasons: list[str] = list(rule_reasons)

    if ml_prob >= 0.65:
        reasons.append(
            f"Machine learning lexical model flagged high phishing probability ({ml_prob:.1%})"
        )
    elif ml_prob >= 0.45:
        reasons.append(
            f"Machine learning lexical model identified elevated phishing risk ({ml_prob:.1%})"
        )

    # If allowlisted site scored low
    if is_direct_url and direct_norm and is_official_host(direct_norm.host, allowlist):
        final_score = 0
        verdict = "Safe"
        reasons = [
            f"Verified official domain: '{direct_norm.registered_domain}' is a legitimate service."
        ]

    if not reasons:
        reasons.append("No suspicious signals found.")

    return {
        "verdict": verdict,
        "score": final_score,
        "reasons": reasons,
        "source": source,
    }
