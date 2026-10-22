# PhishGuard Web UI

Simple single-page React + Vite front-end for the PhishGuard API.

## Prerequisites

- Node.js 18+
- PhishGuard API running (default `http://localhost:8000`)

```bash
# from repo root
uvicorn app.main:app --reload --port 8000
```

## Setup & run

```bash
cd web
cp .env.example .env   # edit VITE_API_BASE_URL if needed
npm install
npm run dev
```

Open http://localhost:5173

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Base URL of the FastAPI backend (no trailing slash) |

## Features

- Large paste box for URL or message text
- Check button with loading state
- Coloured verdict card (green / amber / red) + score + reasons
- Five one-click demo cases covering: DB/lookalike hit, bank lookalike, e-challan+APK, Hindi KYC scam, genuine IRCTC
- Error display for network / validation failures
