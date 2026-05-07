# Grond — Working Memory for Claude

## Project Identity

**Grond** is an Agentic Open Source Intelligence (OSINT) platform.
It uses a **hybrid TypeScript + Python architecture**:
- TypeScript (`orchestration/`) — Claude Agent SDK agents, BullMQ job queue, Neo4j graph client
- Python (`src/`) — FastAPI tool adapters, pipeline stages, embeddings, observability

## Codebase Map

```
orchestration/                         ← TypeScript primary orchestration
├── src/
│   ├── agents/
│   │   └── osint-orchestrator.ts      # Claude Agent SDK — main agentic loop
│   ├── tools/
│   │   ├── grond-api.ts               # HTTP wrappers → Python FastAPI endpoints
│   │   └── query-templates.ts         # Shodan / Tavily query templates
│   ├── graph/
│   │   └── client.ts                  # Neo4j Cypher read/write helpers
│   ├── queue/
│   │   └── jobs.ts                    # BullMQ producers + osint-scan worker
│   ├── observability/
│   │   ├── tracer.ts                  # OpenTelemetry SDK setup
│   │   └── logger.ts                  # pino structured logger
│   └── index.ts                       # Entry point, worker startup
├── package.json
└── tsconfig.json

src/                                   ← Python service layer
├── core/
│   ├── orchestrator.py                # LangGraph graph (still used for pipeline stages)
│   ├── config.py                      # pydantic-settings env config
│   ├── authorization.py               # require_authorization() gate for active scans
│   └── audit.py                       # AuditLogger (structlog)
├── tools/
│   ├── shodan_tool.py                 # Passive: Shodan API adapter
│   ├── nmap_tool.py                   # Active: Nmap subprocess adapter
│   └── tavily_tool.py                 # WEBINT: Tavily search adapter
├── pipeline/
│   ├── collector.py                   # Parallel tool orchestration
│   ├── enricher.py                    # NVD CVE enrichment, rDNS, etc.
│   ├── verifier.py                    # Dedup + cross-validation + confidence scoring
│   └── reporter.py                    # Deterministic report builder + LLM narrative
├── graph/
│   ├── client.py                      # Async Neo4j driver session wrapper
│   └── indexer.py                     # Evidence → entity graph (MERGE operations)
├── embeddings/
│   ├── indexer.py                     # Claim text → pgvector or Qdrant
│   └── retriever.py                   # Semantic search over evidence
├── observability/
│   ├── setup.py                       # OTel + Sentry bootstrap
│   └── tracing.py                     # pipeline_span() context manager
├── storage/
│   └── artifact_store.py              # S3-compatible raw output / PDF / STIX storage
├── models/
│   ├── evidence.py                    # Evidence, Provenance, ClaimType, SourceTool
│   └── report.py                      # IntelReport, ReportFinding, RiskLevel
└── api/
    └── main.py                        # FastAPI app entry point
```

## Key Design Decisions

1. **TypeScript orchestration** — `osint-orchestrator.ts` drives the agentic loop using Claude Agent SDK tool calling; Python never coordinates agents
2. **Python for pipelines** — all OSINT adapters, pipeline stages (collect/enrich/verify/report), and persistence are Python
3. **Evidence-first** — every claim has an immutable `Provenance`; confidence = `source_weight × corroboration × e^(−0.02×age_days)`
4. **HITL gate** — `allow_active_scan` flag must be `true` in `OrchestratorRequest` before Nmap runs; TS orchestrator enforces this
5. **Dual vector stores** — `pgvector` for co-located relational+vector queries; `Qdrant` as optional dedicated store (set `EMBEDDING_BACKEND=qdrant`)
6. **Graph** — Neo4j stores Entity–Port–CVE–WebMention relations for hop traversal
7. **BullMQ not Celery** — `osint-scan` queue is in TypeScript (co-located with orchestrator); Python handles synchronous pipeline execution per request
8. **OpenTelemetry everywhere** — every pipeline stage, tool call, and LLM call gets a span; trace IDs propagate across TS↔Python boundary via HTTP headers

## Environment Variables (Full)

```
# OSINT tools
SHODAN_API_KEY=
TAVILY_API_KEY=

# LLM
ANTHROPIC_API_KEY=

# PostgreSQL + pgvector
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/grond

# Redis (BullMQ)
REDIS_URL=redis://localhost:6379

# Neo4j entity graph
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=

# Vector store (pick one)
EMBEDDING_BACKEND=pgvector          # or "qdrant"
QDRANT_URL=http://localhost:6333    # if EMBEDDING_BACKEND=qdrant

# S3-compatible artifact store
S3_ENDPOINT=http://localhost:9000   # omit for AWS S3
S3_BUCKET=grond-artifacts
S3_ACCESS_KEY=
S3_SECRET_KEY=
S3_REGION=us-east-1

# OpenSearch / Elasticsearch
OPENSEARCH_URL=http://localhost:9200

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces
SENTRY_DSN=                         # optional
LOG_LEVEL=info
ENVIRONMENT=development

# FastAPI (called by TS orchestration layer)
GROND_API_URL=http://localhost:8000
SECRET_KEY=
```

## Do Not

- Use `requests` (sync) in async Python — always `httpx`
- Call Nmap/Ncrack without `require_authorization()` in Python + `allow_active_scan=true` in TypeScript
- Skip `AuditLogger.record()` for any tool call
- Use raw `dict` as data contracts — always Pydantic models (Python) / Zod schemas (TypeScript)
- Let the LLM invent evidence — it only synthesizes narrative from structured `Evidence[]`
- Access the graph driver outside `GraphClient.connect()` context manager
- Hardcode API keys or secrets anywhere
