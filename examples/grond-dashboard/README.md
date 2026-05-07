# Grond — Analyst console (Next.js)

Production-style analyst UI for the Grond FastAPI service: dark theme, sidebar, investigation composer, and `POST /api/v1/scan` integration matching `ScanRequest` (`target`, `goal`, `analyst_id`, `run_nmap`, optional `investigation_profile`, optional `tavily_time_range`).

## Run backend (from repo root)

The UI shows “Cannot reach API …” if FastAPI is not listening. In a **separate terminal**, from **`/path/to/Grond`** (repo root):

```bash
uv sync --extra dev   # once, from repo root
cp .env.example .env  # once; edit DATABASE_URL, SECRET_KEY, API keys as needed
uv run uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload --env-file .env
```

Quick check: `curl -sS http://127.0.0.1:8000/` should return JSON with `"service": "grond"`.

**Startup fails with `str | None` / `|` TypeError:** the shell used **Python older than 3.12** (often system `uvicorn`). Always use **`uv run uvicorn …`** from repo root after **`uv sync`**, not bare `uvicorn`.

## Setup

```bash
cd examples/company-research-ui
cp .env.example .env.local
# NEXT_PUBLIC_GROND_API_URL must match where the browser reaches the API (default http://127.0.0.1:8000).
# Either http://127.0.0.1:8000 or http://localhost:8000 is fine locally; keep host/port aligned with uvicorn --host/--port.
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) (Intel). **Datasheet enrichment** (Tavily-style CSV prep for [tavily-sheets](https://github.com/tavily-ai/tavily-sheets)): [http://localhost:3000/datasheet](http://localhost:3000/datasheet).

## Routes

| Path | Purpose |
|------|---------|
| `/` | Intel — `POST /api/v1/scan` investigation thread |
| `/datasheet` | End-user table input → export CSV → continue in [Tavily Sheets](https://sheets.tavily.com/) or self-hosted repo (does not call Grond scan API) |

## Build

```bash
npm run build && npm start
```

## API

The browser calls `NEXT_PUBLIC_GROND_API_URL` (see `.env.example`). Set **`CORS_ORIGINS`** in the **repo root** `.env` (comma-separated) and start uvicorn with **`--env-file .env`** so `main.py` sees it; defaults already include `http://localhost:3000` and `http://127.0.0.1:3000`.

## Stack

Next.js App Router, TypeScript, Tailwind CSS, Radix-based UI primitives (shadcn-style), Lucide icons.
