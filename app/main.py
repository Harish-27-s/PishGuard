"""
app/main.py – FastAPI entry point for the PhishGuard detection service.

Endpoints:
  GET  /health : Health check, database stats, and model availability.
  POST /check  : Classify a URL or text message; returns explainable JSON verdict.

CORS is enabled for web UI (localhost) and Chrome extension (chrome-extension://*).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.config import DB_PATH
from app.database import db_stats
from app.model import load_model
from app.scoring import score_input

app = FastAPI(
    title="PhishGuard API",
    description="Explainable phishing and domain-spoofing detection engine for Indian citizens",
    version="1.0.0",
)

# ── CORS Middleware ────────────────────────────────────────────────────────────
# Allow requests from Vite dev server (e.g. http://localhost:5173, http://localhost:3000)
# and Chrome browser extension origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_INPUT_LENGTH = 10_000


# ── Schemas ────────────────────────────────────────────────────────────────────
class CheckRequest(BaseModel):
    input: str = Field(
        ...,
        min_length=1,
        max_length=MAX_INPUT_LENGTH,
        description="A URL or message text to analyze",
        examples=["https://sbi.co.in/", "Your vehicle challan is pending: http://echallan-pay.site"],
    )


class CheckResponse(BaseModel):
    verdict: str = Field(..., description="Safe | Suspicious | Dangerous")
    score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    reasons: list[str] = Field(..., description="Plain-language explanations for the verdict")
    source: str = Field(..., description="Detection layer: database | rules | ml | combined")


class HealthResponse(BaseModel):
    status: str
    db_rows: int
    db_sources: dict[str, int]
    model_loaded: bool


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
def health() -> dict[str, Any]:
    """Check API health, database status, and ML model availability."""
    stats = db_stats(DB_PATH)
    model = load_model()
    return {
        "status": "ok",
        "db_rows": stats["total"],
        "db_sources": stats["by_source"],
        "model_loaded": model is not None,
    }


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest) -> dict[str, Any]:
    """
    Analyze input URL or text message.
    Auto-detects URL vs message, verifies known phishing database,
    evaluates rule signals, queries the ML lexical model, and outputs
    an explainable verdict.
    """
    text = req.input.strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Input string cannot be empty or blank.",
        )

    try:
        result = score_input(text, db_path=DB_PATH)
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error evaluating input: {str(exc)}",
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
