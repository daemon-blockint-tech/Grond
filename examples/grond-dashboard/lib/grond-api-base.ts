/** Grond FastAPI base URL (same default as Intel page). */
export function getGrondApiBase(): string {
  return (
    process.env.NEXT_PUBLIC_GROND_API_URL?.replace(/\/$/, "") ||
    "http://127.0.0.1:8000"
  );
}

const ANALYST_KEY = "grond-analyst-id";

/** Stable analyst id from localStorage (matches Intel composer). */
export function ensureAnalystId(): string {
  if (typeof window === "undefined") return "analyst-local";
  let id = localStorage.getItem(ANALYST_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(ANALYST_KEY, id);
  }
  return id;
}

/**
 * Map `fetch` failures (offline API, wrong host, firewall) to an actionable message.
 * `Failed to fetch` / `TypeError` are typical when nothing listens on the configured base URL.
 */
export function formatGrondReachabilityError(err: unknown, base: string): string {
  if (
    (typeof DOMException !== "undefined" && err instanceof DOMException && err.name === "AbortError") ||
    (err instanceof Error && err.name === "AbortError")
  ) {
    return (
      "The request was aborted or timed out while waiting for the server. " +
      "Nmap runs synchronously on the API host and can take several minutes for standard/vuln profiles. " +
      "Try the Quick profile, narrow the port range, or check API logs."
    );
  }
  const msg = err instanceof Error ? err.message : "";
  if (msg === "Failed to fetch" || err instanceof TypeError) {
    return (
      `Cannot reach Grond API at ${base}. Start FastAPI (e.g. from repo root: ` +
      "`uv run uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload --env-file .env`" +
      `). If the UI runs elsewhere, set NEXT_PUBLIC_GROND_API_URL and ensure CORS_ORIGINS includes this page’s origin (see root .env.example).`
    );
  }
  return err instanceof Error ? err.message : "Network error";
}

/** Normalize FastAPI `detail` (string or object) for display. */
export function formatApiDetail(data: unknown, fallback: string): string {
  if (typeof data !== "object" || data === null || !("detail" in data)) {
    return fallback;
  }
  const detail = (data as { detail: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (typeof detail === "object" && detail !== null) {
    const o = detail as {
      message?: unknown;
      code?: unknown;
      actions?: unknown;
    };
    const parts: string[] = [];
    if (typeof o.code === "string") parts.push(`Code: ${o.code}`);
    if (typeof o.message === "string" && o.message) parts.push(o.message);
    if (Array.isArray(o.actions)) {
      const lines = o.actions.filter((a): a is string => typeof a === "string");
      if (lines.length) parts.push(lines.map((l) => `• ${l}`).join("\n"));
    }
    if (parts.length) return parts.join("\n\n");
    try {
      return JSON.stringify(detail, null, 2);
    } catch {
      return fallback;
    }
  }
  return fallback;
}

/** FastAPI may return `detail` as a string or structured object (e.g. 403 active-scan HITL). */
export function formatScanApiError(data: unknown, fallback: string): string {
  if (typeof data !== "object" || data === null || !("detail" in data)) {
    return fallback;
  }
  const detail = (data as { detail: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (typeof detail === "object" && detail !== null) {
    const o = detail as {
      message?: unknown;
      hint?: unknown;
      actions?: unknown;
    };
    const parts: string[] = [];
    if (typeof o.message === "string" && o.message) parts.push(o.message);
    if (typeof o.hint === "string" && o.hint) parts.push(o.hint);
    if (Array.isArray(o.actions)) {
      const lines = o.actions.filter((a): a is string => typeof a === "string");
      if (lines.length) parts.push(lines.map((l) => `• ${l}`).join("\n"));
    }
    if (parts.length) return parts.join("\n\n");
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return fallback;
  }
}
