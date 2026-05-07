# Authorization model (current state)

Short, factual description of how Grond gates **active** probes today. **Not RBAC**: there are no analyst roles (admin vs. read-only) in application code separate from whoever supplies `analyst_id` / session context.

## Passive vs. active

- **Passive OSINT** (e.g. Shodan queries, Tavily web search against public indices, DNS-style lookups where implemented) runs without `require_authorization` in the Python adapter sense.
- **Active techniques**—including **Nmap** (and any tool path that calls `require_authorization`)—must have a matching **authorization record** before execution. `require_authorization()` is defined in `src/core/authorization.py` and logs success or failure via the audit trail.

## Python: `AuthorizationService`

- **In-process store** by default: a list of `AuthorizationRecord` entries (target, `analyst_id`, tool, optional expiry, optional `legal_ref` / `notes`). Production deployments are expected to **swap** this for a database-backed implementation; the interface is the same.
- **Matching rules** (summary): exact IP/hostname; CIDR containment for IP targets; **parent hostname** (`customer.example`) also matches subdomains (`api.customer.example`); **`*.customer.example`** matches subdomains only (not the apex); if the requested target is a literal IP, hostname suffix rules do not apply. Tool must match or be `*`; `analyst_id` must match or be `*`; expired records are ignored.
- **CSV environment grants**: `GROND_AUTHORIZED_SCAN_TARGETS` (comma-separated IPs, CIDRs, hostnames, `*.sub.example.com`, or parent hosts) is parsed in `AuthorizationService.with_settings_grants()` and creates records with **`analyst_id="*"`**, **`tool="nmap"`**, and **`notes`** referencing that env flag. Intended for **narrow dev/staging scopes**, not broad production permissioning.
- **PostgreSQL grants**: When `GROND_ACTIVE_SCAN_AUTH_FROM_DB=true`, the API lifespan merges non-expired rows from table `grond_active_scan_authorization` into the same in-process service (see `src/core/active_scan_authorization_db.py`). After internal approval, automation can call **`POST /api/v1/admin/active-scan-authorizations`** with header **`X-Grond-Authorization-Admin-Key`** matching **`GROND_AUTHORIZATION_ADMIN_KEY`** (disabled if that env var is empty).

## Orchestration / API layering

- TypeScript orchestrators expose an explicit **`allow_active_scan`** (and often **`authorization_ref`**) on the scan request. The agent is instructed **not** to call `nmap_scan` (and similar) unless that flag is true and a reference to written authorization is available.
- That layer is **policy for the LLM and HTTP caller**; the **enforcement** for Nmap (and other adapters using `require_authorization`) remains in **Python** at tool execution time.

## LangGraph HITL and dev bypass

- The synchronous scan path cannot always resume human-in-the-loop interrupts. For local development only, `GROND_DEV_BYPASS_NMAP_HITL` together with `ENVIRONMENT=development` can pre-approve the graph flag; **it does not remove** the need for `require_authorization` + target grants for Nmap itself.
- See `.env.example` and `README.md` (active scan / Nmap section) for variable names.

## What is not implemented

- **No role-based access control (RBAC)** in-repo: no built-in admin/auditor roles, no per-route permission matrix keyed off identity providers.
- **No multi-tenant authorization partition** in the default `AuthorizationService`—records are global to the process unless you extend the service.
- **No public self-service “authorize my target” UI**: the admin POST is for trusted automation only; end-user input still does not imply permission.

## Related files

- `src/core/authorization.py` — `require_authorization`, `AuthorizationService`, CSV seeding, hostname / wildcard matching
- `src/core/active_scan_authorization_db.py` — PostgreSQL table + load/insert helpers
- `src/api/main.py` — lifespan DB merge, `POST /api/v1/admin/active-scan-authorizations`
- `src/core/config.py` — `grond_authorized_scan_targets`, `grond_active_scan_auth_from_db`, `grond_authorization_admin_key`, `grond_dev_bypass_nmap_hitl`, etc.
- `orchestration/src/agents/osint-orchestrator.ts`, `openrouter-osint-agent.ts` — `allow_active_scan`, `authorization_ref`
- `.cursor/rules/security-ethics.mdc` — ethical and legal guardrails for scanning
