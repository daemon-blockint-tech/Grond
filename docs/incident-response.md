# Incident response runbook (Grond)

Concise internal checklist for this repository’s **operational** stack. **Not legal advice.** Escalation paths, regulatory duties, and counsel engagement are organization-specific—fill placeholders with your own contacts and policies.

## Scope

Components implied by this repo: **FastAPI** (`src/api`), **Python pipeline** (LangGraph, tools), **TypeScript orchestration** (`orchestration/`, optional BullMQ worker), **PostgreSQL**, **Redis**, **Neo4j**, **S3-compatible artifacts**, external OSINT APIs (Shodan, Tavily, optional X), and LLM keys (Anthropic / OpenRouter).

## 1. Triage (first 30 minutes)

1. **Classify** — availability (API down, queue stuck), **integrity** (unexpected tool activity, data change), **confidentiality** (leak of keys, reports, or PII in logs).
2. **Timebox** — note incident start (UTC), who is on call, and the primary symptom (error rate, alert, user report).
3. **Preserve evidence** — export relevant **structured logs** (application + host), trace IDs if OpenTelemetry is enabled, and **job IDs** for BullMQ if used. Avoid destructive actions on primary DBs until scope is understood.
4. **Contain (if needed)** — rotate obviously exposed secrets (see **Secrets rotation** below), disable compromised credentials at the **provider** (Shodan, Tavily, cloud IAM), or restrict ingress (firewall / remove public exposure) per your change process.

## 2. Common technical checks

| Symptom | Where to look |
| --- | --- |
| API errors / 5xx | `uvicorn` / container logs; `GET /api/v1/health` |
| Pipeline stuck | LangGraph checkpoint / worker logs; Redis connectivity |
| Queue backlog | BullMQ dashboard or Redis; `orchestration` worker process |
| Bad or missing OSINT data | Provider status pages; rate limits in tool adapters |
| Auth / 401 on API | `SECRET_KEY` and any reverse-proxy auth you added |

## 3. Secrets rotation (pointers)

Rotate any credential that may have been exposed or was present on a compromised host. Cross-check `.env.example` for variable names; set new values in your **secret store** or host env—**never** commit `.env`.

Typical variables to review:

- `SECRET_KEY` (app signing / session material if you use it beyond defaults)
- `SHODAN_API_KEY`, `TAVILY_API_KEY`, `TWITTER_BEARER_TOKEN`
- `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`
- Database: `DATABASE_URL` user password rotation
- `NEO4J_PASSWORD`, Redis, S3 keys (`S3_ACCESS_KEY`, `S3_SECRET_KEY`)
- `SENTRY_DSN` if the DSN was leaked (revoke/replace in Sentry)

After rotation: restart services, verify health endpoints, run a **smoke** passive query (no active scan) if policy allows.

## 4. Audit logs and forensics

- Python tool and authorization events go through **structlog** / `AuditLogger`—ensure log retention and **restricted access** to log storage in production.
- Map incident window to **analyst_id** and **session_id** fields in logs when investigating tool misuse or data handling issues.
- Raw artifacts may live under your **S3 bucket** (`S3_BUCKET`); scope object prefixes by session when cleaning up test data vs. investigation evidence.

## 5. Communication and escalation

- **Internal:** [placeholder — security distribution list / Slack channel]
- **On-call engineering:** [placeholder]
- **Management / customer comms:** [placeholder]
- **Law enforcement / regulatory:** engage **your counsel**—this runbook does not prescribe notices or filings.

## 6. Post-incident

1. Short **timeline** (detection → containment → recovery).  
2. **Root cause** (config, dependency, leaked key, deployment error).  
3. **Corrective actions** — automation, alerts, reduced scope of env grants, tighter network policy.  
4. **Track** open items for replacing in-memory authorization with a durable audit-backed store if not already done.

## 7. Out of scope here

Active scanning against third parties without authorization, bypassing provider ToS, or using this stack for harassment or non-consensual tracking—those are policy and legal matters outside this technical runbook.
