"""
tests/test_api.py – Unit and integration tests for FastAPI application in app/main.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["db_rows"] > 0
    assert data["model_loaded"] is True
    assert isinstance(data["db_sources"], dict)


def test_check_genuine_url() -> None:
    resp = client.post("/check", json={"input": "https://sbi.co.in/"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Safe"
    assert data["score"] == 0
    assert len(data["reasons"]) >= 1
    assert data["source"] in ("rules", "combined", "database")


def test_check_bank_lookalike_url() -> None:
    resp = client.post("/check", json={"input": "http://onlinesbii.co.in/login"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("Suspicious", "Dangerous")
    assert data["score"] >= 35
    assert len(data["reasons"]) >= 1


def test_check_apk_link() -> None:
    resp = client.post("/check", json={"input": "http://traffic-challan-app.site/challan.apk"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Dangerous"
    assert data["score"] >= 65
    assert any("apk" in r.lower() for r in data["reasons"])


def test_check_scam_message() -> None:
    message = (
        "Traffic Police: Your vehicle challan is pending. "
        "Pay immediately within 24 hours: http://parivahan-gov.site/pay"
    )
    resp = client.post("/check", json={"input": message})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("Suspicious", "Dangerous")
    assert data["score"] >= 35
    assert len(data["reasons"]) >= 1


def test_check_empty_input_returns_400() -> None:
    resp = client.post("/check", json={"input": "   "})
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


def test_cors_headers_present() -> None:
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
    }
    resp = client.options("/check", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"
