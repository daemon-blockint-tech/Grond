# Grond — Agentic OSINT Platform

> Open Source Intelligence, orchestrated by AI agents.

Grond is a multi-agent OSINT stack: **Python** runs FastAPI tool adapters and a **LangGraph** pipeline (collect → enrich → verify → report); **TypeScript** (`orchestration/`) runs agentic loops (Claude or OpenRouter) and **BullMQ** workers against the same API. Tools include **Shodan**, **Tavily** (including public social–style site queries via `investigation_profile`), **Nmap** (authorized targets only), and optional **Twitter/X** when configured.

## Architecture

```
Analyst (HTTP / optional Next.js UI)
  ↓
FastAPI — /api/v1/scan, /api/v1/tools/*
  ↑
TypeScript orchestration — Claude Agent SDK or OpenRouter, BullMQ jobs → same API
  ↓
LangGraph (Python): parallel collectors (Shodan, Tavily, …) → enrich → verify → report
  ↓
Stores: PostgreSQL (+ pgvector), Redis, Neo4j, S3-compatible artifacts (see .env.example)
```

## Tech Stack

| Layer | Technology |
|---|---|
| API & pipeline | Python 3.12, FastAPI, LangGraph, Pydantic |
| Agent orchestration | TypeScript, BullMQ, Anthropic and/or OpenRouter |
| LLM | Claude (report synthesis, TS agents); optional OpenRouter model routing |
| OSINT | Shodan, Tavily, optional X API v2, python-nmap (HITL + authorization) |
| Data | PostgreSQL + async SQLAlchemy, pgvector or Qdrant, Neo4j |
| Cache / queue | Redis (BullMQ in `orchestration/`) |
| Example UI | Next.js 15 — `examples/company-research-ui` |

## Agents

| Agent File | Responsibility |
|---|---|
| `agents/osint-orchestrator.md` | Master planner & LangGraph routing |
| `agents/shodan-intel.md` | Passive network recon via Shodan |
| `agents/network-scanner.md` | Active scanning (Nmap/Ncrack, auth required) |
| `agents/web-intelligence.md` | WEBINT via Tavily |
| `agents/report-generator.md` | Fusion, confidence scoring, report synthesis |

## Quick Start

**Requires Python 3.12+.** If `python3 --version` shows 3.9 or 3.10, use [uv](https://docs.astral.sh/uv/) (recommended) or install Python 3.12 before `pip install -e`.

```bash
# 1. Clone and install (recommended: uv + project .venv on 3.12)
git clone https://github.com/your-org/grond.git
cd grond
uv sync --extra dev
# Alternative: pip install -e ".[dev]"  # only if `python -V` is 3.12+

# 2. Configure environment
cp .env.example .env
# Fill in SHODAN_API_KEY, TAVILY_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL, SECRET_KEY, ...

# 3. Run API from repo root (working directory must be the repo root so `src/` resolves)
#    Use `--env-file .env` so variables like CORS_ORIGINS are in the process env before the app imports.
uv run uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload --env-file .env
```

Use `--host 0.0.0.0` instead of `127.0.0.1` if other machines on your LAN must reach the API.

**Environment:** Uvicorn does not load `.env` unless you pass `--env-file` or export vars in your shell. `src/core/config.py` loads `.env` via pydantic-settings when `Settings` is built (tool/pipeline code paths); `CORS_ORIGINS` in `main.py` is read from `os.environ` at import time—either use `--env-file .env` or rely on the defaults (`http://localhost:3000`, `http://127.0.0.1:3000`). See `.env.example` for `CORS_ORIGINS`.

If **`Address already in use`** on 8000, either stop the old server (`lsof -nP -iTCP:8000 -sTCP:LISTEN` then `kill <PID>`) or use another port, e.g. `--port 8001`.

**`TypeError: Unable to evaluate type annotation 'str | None'` (or “unsupported operand type(s) for |”)** — you started **`uvicorn` with macOS/Xcode Python 3.9** (or anything older than 3.12). Grond declares **`requires-python = ">=3.12"`** in `pyproject.toml`. From repo root, use **`uv run uvicorn …`** after **`uv sync`** so the project venv’s interpreter runs the app—**do not** rely on a globally installed `uvicorn` alone.

- Health: http://127.0.0.1:8000/api/v1/health  
- Docs: http://127.0.0.1:8000/docs

### Example analyst UI

From repo root:

```bash
cd examples/company-research-ui
cp ../../.env.example ../../.env   # if you have not already
# In examples/company-research-ui/.env.local (or shell): NEXT_PUBLIC_GROND_API_URL=http://127.0.0.1:8000
npm install
npm run dev:clean    # first run or after a broken .next — see example README
# or: npm run dev:turbo
```

Ensure `CORS_ORIGINS` in the API `.env` includes `http://localhost:3000`. The UI calls `POST /api/v1/scan` with optional `investigation_profile` (`general` | `company` | `social`), `tavily_time_range`, and `run_nmap`.

### Active scans (Nmap) — local development

**Nmap is for targets you have explicit written authorization to probe.** The synchronous scan endpoint cannot resume LangGraph human-in-the-loop interrupts by itself. For local runs with `run_nmap: true`, configure **`ENVIRONMENT=development`**, **`GROND_DEV_BYPASS_NMAP_HITL=true`**, and **`GROND_AUTHORIZED_SCAN_TARGETS`** (CSV) so `nmap_tool` authorization matches your scope. See `.env.example` (Active scan / Nmap).

## Cursor Agent Coder Setup

This project ships with Cursor Agent definitions and rules. When working in Cursor:

1. `.cursor/rules/grond-core.mdc` — always-on project conventions
2. `.cursor/rules/security-ethics.mdc` — always-on legal/ethical guardrails
3. `.cursor/rules/osint-tools.mdc` — activates for `src/tools/` files
4. `.cursor/rules/agent-behavior.mdc` — activates for `src/core/` and `agents/` files

Load the appropriate agent (in `agents/`) for the layer you're building.

## Legal & Ethics

- **Passive OSINT** (Shodan, Tavily public/indexed or site-scoped queries, DNS) — treat public data and provider ToS as binding
- **Active scanning** (Nmap, Ncrack) — requires **explicit written authorization** from target owner
- All queries are audit-logged with analyst ID, timestamp, and legal basis
- See `.cursor/rules/security-ethics.mdc` for full policy
- **Operational notes:** authorization behavior (CSV grants, no built-in RBAC) — [`docs/security-authorization.md`](docs/security-authorization.md); incident checklist — [`docs/incident-response.md`](docs/incident-response.md)

## License

MIT — see [LICENSE](LICENSE)
