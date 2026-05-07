# Grond — Agent Memory & Learnings (v2)

## Project Summary

Grond is an Agentic OSINT platform with a **TypeScript + Python hybrid architecture**.
TypeScript handles agent orchestration (Claude Agent SDK); Python handles OSINT tool adapters, pipeline stages, and data persistence.

## Agent Routing Guide

| If you're working on... | Language | File / Module |
|---|---|---|
| OpenRouter Responses orchestrator (`ORCHESTRATOR_BACKEND=openrouter`) | TypeScript | `orchestration/src/agents/openrouter-osint-agent.ts` |
| Claude Agent SDK agentic loop (default) | TypeScript | `orchestration/src/agents/osint-orchestrator.ts` |
| HTTP tool wrappers → Python API | TypeScript | `orchestration/src/tools/grond-api.ts` |
| BullMQ job queue (producers + worker) | TypeScript | `orchestration/src/queue/jobs.ts` |
| Neo4j graph reads/writes (TS side) | TypeScript | `orchestration/src/graph/client.ts` |
| Shodan passive recon adapter | Python | `src/tools/shodan_tool.py` |
| Nmap/Ncrack active scan adapter | Python | `src/tools/nmap_tool.py` |
| Tavily web intelligence adapter | Python | `src/tools/tavily_tool.py` |
| Twitter/X OSINT adapter (X API v2) | Python | `src/tools/twitter_tool.py` |
| theHarvester email/host harvest (subprocess) | Python | `src/tools/harvester_tool.py` |
| ExifTool / Exiv2 file metadata (`exiftool` JSON, `exiv2 print -pa`; optional `engine` + `METADATA_ENGINE`) | Python | `src/tools/metadata_tool.py` |
| Twitter query builder (Bellingcat ops) | Python | `src/tools/twitter_query_builder.py` |
| Collect → Enrich → Verify → Report | Python | `src/pipeline/` |
| Entity graph indexing (Python side) | Python | `src/graph/indexer.py` |
| pgvector / Qdrant embedding + search | Python | `src/embeddings/` |
| S3 artifact storage | Python | `src/storage/artifact_store.py` |
| OpenTelemetry + Sentry setup | Python | `src/observability/setup.py` |
| FastAPI API endpoints | Python | `src/api/` |
| Evidence / Report Pydantic models | Python | `src/models/` |

## Conventions Established

### TypeScript (orchestration/)
- ES2022 modules (`"type": "module"` in package.json), `.js` imports in TS
- Zod **v4** dependency: use `import { z } from "zod/v3"` for existing tool/report schemas (`grond-api`, `evidence`, Anthropic orchestrator); use `import { z } from "zod/v4"` for `@openrouter/agent` `tool()` input schemas
- pino for structured JSON logging
- OpenTelemetry spans via `withSpan(name, fn, attributes?)` helper
- All Claude API calls use `anthropic` SDK, model `claude-sonnet-4-5`

### Python (src/)
- Python 3.12+, FastAPI, Pydantic v2, `ruff` lint, `pytest` tests
- All agent nodes / pipeline stages are `async def`
- `structlog` for structured audit logs
- `pipeline_span()` context manager for OTel spans in pipeline stages

### Data Flow (full stack)
```
Analyst (Next.js)
  → POST /api/v1/scan (FastAPI) OR enqueueScan() (BullMQ)
  → osint-orchestrator.ts (Claude Agent SDK agentic loop)
    → shodan_search tool → /api/v1/tools/shodan (FastAPI)
    → tavily_search tool → /api/v1/tools/tavily (FastAPI)
    → twitter_search tool → /api/v1/tools/twitter (FastAPI)  ← new
    → [HITL gate] → nmap_scan tool → /api/v1/tools/nmap (FastAPI)
    → generate_report tool → /api/v1/report (FastAPI)
  → Python pipeline: Collect → Enrich → Verify → Score
  → Persist: PostgreSQL (evidence) + S3 (artifacts) + Neo4j (graph)
  → Embed: pgvector or Qdrant (semantic search)
  → Response: IntelReport (all findings pending analyst review)
```

### Confidence Formula
`confidence = base_score × source_weight × e^(−0.02 × age_days)`

Source weights: `nmap=0.95`, `shodan=0.85`, `tavily=0.70`, `twitter=0.50`, `manual=1.00`
Corroboration bonus: `+0.10` per additional independent source (cap 0.30)

### Twitter OSINT decision matrix

| Goal | `intent` to use | Suggested filters |
|------|----------------|-------------------|
| Company reputation | `company_monitoring` | `exclude_retweets=true`, `days_back=30` |
| Person research | `person_research` | `from_accounts=[handle]` if known |
| Breach/leak alert | `breach_leak_monitor` | `min_likes=10` to cut noise |
| Protest / movement | `hashtag_campaign` | `language=<lang>`, `has_media=true` |
| Disinformation spread | `disinformation_tracking` | `min_retweets=50` |
| Visual evidence | `media_evidence` | `has_media=true`, tight date range |
| Account influence | `account_network` | `days_back=90` |

### Location search (Bellingcat)

Operators (standard search): **`near:place`** + **`within:radius`** (`mi` or `km`, e.g. `near:chicago within:2mi`), or **`geocode:lat,lon,radius`** (e.g. `geocode:40.7128,-74.0060,10mi`). Multi-word places use quotes (`near:"New York"`); slug-style tokens omit quotes (`near:estes-park`). **X caps geo radius at 25 mi** — Grond clamps via `within_miles` / `within_km` / `clamp_within_radius_str`.

**Limitations:** location signals combine post-declared place, profile location, and device GPS — noisy and spoofable. Historical/geo fidelity often weak beyond roughly the **last week** for profile-linked geo ([case study](https://www.bellingcat.com/resources/2021/05/19/geofenced-searches-on-twitter-a-case-study-detailing-south-asias-covid-crisis/)). **Ethics:** respect privacy; corroborate with Tavily/other sources per `.cursor/rules/accuracy-patterns.mdc`.

| Goal | `intent` / API fields | Notes |
|------|------------------------|-------|
| Situational / crisis geo monitor | `geo_event` + `near_place`/`within_radius` or `geocode_*` on `TwitterInput` | Use tight `since`/`until`; optional template `location_crisis_monitor` |
| Coordinate box | `geocode_lat`, `geocode_lon`, `geocode_radius` | Radius clamped to 25 mi |

Guides: [Bellingcat Twitter Location Search](https://bellingcat.gitbook.io/toolkit/more/all-tools/twitter-location-search) · [Advanced Search](https://bellingcat.gitbook.io/toolkit/more/all-tools/twitter-advanced-search).

Always cross-validate high-importance Twitter claims with `tavily_search` (MEDIA tier source).

## Known Gotchas

- Twitter free tier: 1 app/15-min window on `/tweets/search/recent` — use `full_archive=false` by default
- Twitter `TWITTER_BEARER_TOKEN` is app-only auth; no user context or DM access
- Twitter `possibly_sensitive=true` tweets auto-downgrade to `SourceTier.ANONYMOUS`
- Twitter verified accounts auto-upgrade to `SourceTier.MEDIA` — still requires analyst review before promoting to report
- Register FastAPI endpoint: `POST /api/v1/tools/twitter` → `twitter_search_endpoint(inp)`
- Shodan free tier: 1 req/sec — `asyncio.sleep(1)` between calls in `ShodanAdapter`
- `python-nmap` returns XML; access via `scanner[host]["tcp"][port]` dict
- Tavily `search_depth="advanced"` is required for OSINT quality results
- Neo4j `MERGE` is idempotent — always use MERGE not CREATE for graph writes
- pgvector requires `CREATE EXTENSION vector` in PostgreSQL (run once via Alembic migration)
- BullMQ `concurrency: 4` in the worker — don't increase beyond Shodan rate limits
- OTel trace IDs must be forwarded in `traceparent` header from TS → Python HTTP calls
- `aiobotocore` requires `contextvar` compatibility — always use `async with client()` pattern
- Qdrant upsert is idempotent; pgvector uses `ON CONFLICT (id) DO UPDATE`
- `sentence-transformers` loads the model lazily on first call — warm up at startup if latency matters

## Tavily — documentation index (agents)

- Fetch the complete documentation index at [https://docs.tavily.com/llms.txt](https://docs.tavily.com/llms.txt) and use it to discover pages before exploring deeper.
- **Data enrichment** (spreadsheet columns, CSV export): [sheets.tavily.com](https://sheets.tavily.com/); open-source app [tavily-ai/tavily-sheets](https://github.com/tavily-ai/tavily-sheets); API keys at [app.tavily.com](https://app.tavily.com).

## X API — official documentation (agents)

Use these **docs.x.com** entry points to discover the canonical X API and XDK documentation (including pages not listed in legacy developer portal links below).

| URL | Purpose |
|-----|---------|
| [docs.x.com/llms-full.txt](https://docs.x.com/llms-full.txt) | Full docs.x.com text corpus for broad agent/LLM discovery |
| [docs.x.com/x-api/llms.txt](https://docs.x.com/x-api/llms.txt) | X API documentation index (llms) |
| [docs.x.com/xdks/typescript/llms.txt](https://docs.x.com/xdks/typescript/llms.txt) | TypeScript XDK documentation index (llms) |
| [docs.x.com/skill.md](https://docs.x.com/skill.md) | Official agent skill reference for X platform integration |
| [docs.x.com/xdks/typescript/overview.md](https://docs.x.com/xdks/typescript/overview.md) | TypeScript XDK overview (human-readable starting point) |

**Implementation note:** The official TypeScript SDK package is **`@xdevplatform/xdk`** (see [skill.md](https://docs.x.com/skill.md) and the TypeScript XDK docs). Grond today calls **X API v2** from **Python** (`src/tools/twitter_tool.py` → `POST /api/v1/tools/twitter`); TypeScript orchestration can adopt the XDK later without changing the FastAPI contract.

## External References

| Tool | Docs / Repo |
|---|---|
| Claude Agent SDK | https://code.claude.com/docs/en/agent-sdk/overview |
| Shodan SDK | https://github.com/shadowscatcher/shodan |
| Nmap | https://github.com/nmap/nmap |
| Ncrack | https://github.com/nmap/ncrack |
| Tavily | https://docs.tavily.com/llms.txt |
| Tavily Company Intel | https://docs.tavily.com/examples/agent-toolkit/company-intelligence.md |
| Tavily Social Research | https://docs.tavily.com/examples/agent-toolkit/social-media-research.md |
| Tavily Data Enrichment (Sheets) | https://sheets.tavily.com/ |
| Tavily Sheets (open source) | https://github.com/tavily-ai/tavily-sheets |
| Tavily API / keys | https://app.tavily.com |
| Shodan Download API | https://help.shodan.io/guides/how-to-download-data-with-api |
| Bellingcat Toolkit | https://bellingcat.gitbook.io/toolkit/categories/companies-and-finance |
| Bellingcat Twitter Advanced Search | https://bellingcat.gitbook.io/toolkit/more/all-tools/twitter-advanced-search |
| Bellingcat Twitter Location Search | https://bellingcat.gitbook.io/toolkit/more/all-tools/twitter-location-search |
| Bellingcat geofenced Twitter search case study (2021) | https://www.bellingcat.com/resources/2021/05/19/geofenced-searches-on-twitter-a-case-study-detailing-south-asias-covid-crisis/ |
| OSINT Dojo — Dark Web Marketplace attack surface (DWM) | https://www.osintdojo.com/diagrams/dwm |
| OSINT Dojo — DWM diagram (PDF) | https://github.com/sinwindie/OSINT/raw/master/DarkWeb/DWM%20OSINT%20Attack%20Surface.pdf |
| OSINT Dojo — Dark Web resources | https://www.osintdojo.com/resources/#dark_web |
| X — official full doc corpus (llms) | https://docs.x.com/llms-full.txt |
| X API — official docs index (llms) | https://docs.x.com/x-api/llms.txt |
| X TypeScript XDK — official docs index (llms) | https://docs.x.com/xdks/typescript/llms.txt |
| X — official agent skill reference | https://docs.x.com/skill.md |
| X TypeScript XDK — overview | https://docs.x.com/xdks/typescript/overview.md |
| X API v2 Operator Reference | https://developer.twitter.com/en/docs/twitter-api/v1/rules-and-filtering/search-operators |
| igorbrigadir Extended Operators | https://github.com/igorbrigadir/twitter-advanced-search |
| X Developer Portal | https://developer.twitter.com/en/portal/dashboard |
| BullMQ | https://docs.bullmq.io |
| Neo4j Driver | https://neo4j.com/docs/javascript-manual/current/ |
| Qdrant | https://qdrant.tech/documentation/ |
| pgvector | https://github.com/pgvector/pgvector |
| OpenSearch | https://opensearch.org/docs/ |
| OpenTelemetry Python | https://opentelemetry-python.readthedocs.io/ |
| aiobotocore | https://aiobotocore.readthedocs.io/ |
