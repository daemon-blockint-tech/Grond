/**
 * HTTP tool wrappers that call the Python FastAPI service.
 *
 * Each function is registered as a Claude Agent SDK tool.
 * All inputs/outputs are validated with Zod — no `any` crosses the boundary.
 */

import { z } from "zod/v3";
import { ClaimTypeSchema, EvidenceSchema, IntelReportSchema, type IntelReport } from "../types/evidence.js";
import { withSpan } from "../observability/tracer.js";

const API_BASE = process.env["GROND_API_URL"] ?? "http://localhost:8000";

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Grond API ${path} → ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

async function apiFetchMultipart<T>(path: string, form: FormData): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { method: "POST", body: form });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Grond API ${path} → ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Tool: run Shodan passive recon
// ---------------------------------------------------------------------------

export const ShodanQueryInput = z.object({
  target: z.string().describe("IP address, CIDR, or hostname"),
  query: z.string().describe("Full Shodan filter expression"),
  analyst_id: z.string(),
  session_id: z.string(),
  max_results: z.number().int().min(1).max(1000).default(100),
});
export type ShodanQueryInput = z.infer<typeof ShodanQueryInput>;

export const ShodanQueryOutput = z.object({
  evidence: z.array(EvidenceSchema),
  error: z.string().nullable(),
});

export async function runShodanQuery(
  input: ShodanQueryInput,
): Promise<z.infer<typeof ShodanQueryOutput>> {
  return withSpan("tool.shodan", async () => {
    const data = await apiFetch<unknown>("/api/v1/tools/shodan", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return ShodanQueryOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: run Tavily web intelligence
// ---------------------------------------------------------------------------

export const InvestigationProfileSchema = z.enum(["general", "company", "social"]);
export const SocialPlatformSchema = z.enum([
  "reddit",
  "x",
  "twitter",
  "tiktok",
  "instagram",
  "youtube",
  "linkedin",
  "hackernews",
]);

export const TavilyQueryInput = z.object({
  target: z
    .string()
    .describe("Investigation subject — entity, domain, person, hashtag, …"),
  query: z.string().describe("Search query string"),
  analyst_id: z.string(),
  session_id: z.string(),
  search_depth: z.enum(["basic", "advanced"]).default("advanced"),
  max_results: z.number().int().min(1).max(20).default(10),
  investigation_profile: InvestigationProfileSchema.default("general").describe(
    "general | company | social — social scopes via site: when platform is set",
  ),
  platform: SocialPlatformSchema.optional().describe(
    "With investigation_profile=social, narrow to this public platform (indexed pages only)",
  ),
  topic: z.enum(["general", "news", "finance"]).optional(),
  time_range: z.enum(["day", "week", "month", "year"]).optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
});
export type TavilyQueryInput = z.infer<typeof TavilyQueryInput>;

export const TavilySearchOutput = z.object({
  evidence: z.array(EvidenceSchema),
  error: z.string().nullable(),
});

export async function runTavilyQuery(
  input: TavilyQueryInput,
): Promise<z.infer<typeof TavilySearchOutput>> {
  return withSpan("tool.tavily", async () => {
    const payload = TavilyQueryInput.parse(input);
    const data = await apiFetch<unknown>("/api/v1/tools/tavily", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return TavilySearchOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: SEC EDGAR full-text search (Bellingcat edgar-tool)
// ---------------------------------------------------------------------------

export const EdgarTextSearchInput = z.object({
  target: z.string().describe("Investigation / case label"),
  analyst_id: z.string(),
  session_id: z.string(),
  query: z.string().optional().default("").describe("Audit label — derived from keywords/entity when empty"),
  keywords: z.array(z.string()).optional().default([]).describe("Terms that must all appear in the filing hit"),
  entity: z.string().optional().describe("Company name, ticker, or CIK"),
  filing_category: z.string().optional().describe("SEC filing category slug; omit if using single_forms"),
  single_forms: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Specific forms, e.g. ["10-K", "8-K"]'),
  date_range_select: z
    .string()
    .optional()
    .default("5y")
    .describe("SEC preset: all, 10y, 5y, 1y, 30d, or custom"),
  start_date: z.string().optional().describe("ISO date YYYY-MM-DD when date_range_select is custom"),
  end_date: z.string().optional().describe("ISO date YYYY-MM-DD when date_range_select is custom"),
  incorporated_in: z.string().optional(),
  principal_executive_offices_in: z.string().optional(),
  max_results: z.number().int().min(1).max(100).optional().default(25),
});
export type EdgarTextSearchInput = z.infer<typeof EdgarTextSearchInput>;

export const EdgarTextSearchOutput = z.object({
  evidence: z.array(EvidenceSchema),
  result_count: z.number(),
  error: z.string().nullable(),
});

export async function runEdgarTextSearch(
  input: EdgarTextSearchInput,
): Promise<z.infer<typeof EdgarTextSearchOutput>> {
  const payload = EdgarTextSearchInput.parse(input);
  return withSpan("tool.edgar", async () => {
    const data = await apiFetch<unknown>("/api/v1/tools/edgar", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return EdgarTextSearchOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: OSINTMap regional link catalog (cipher387 / cybdetective.com)
// ---------------------------------------------------------------------------

export const OsintmapQueryInput = z.object({
  target: z.string().describe("Investigation / case label"),
  region_query: z
    .string()
    .min(2)
    .describe("Country, state, or region — substring match on OSINTMap table row label"),
  analyst_id: z.string(),
  session_id: z.string(),
  query: z.string().optional().describe("Optional audit label (defaults to region_query)"),
  max_rows: z.number().int().min(1).max(50).default(8),
  max_links_per_row: z.number().int().min(1).max(150).default(40),
});
export type OsintmapQueryInput = z.infer<typeof OsintmapQueryInput>;

export const OsintmapQueryOutput = z.object({
  evidence: z.array(EvidenceSchema),
  error: z.string().nullable(),
});

export async function runOsintmapQuery(input: OsintmapQueryInput) {
  return withSpan("tool.osintmap", async () => {
    const payload: Record<string, unknown> = {
      target: input.target,
      region_query: input.region_query,
      analyst_id: input.analyst_id,
      session_id: input.session_id,
      max_rows: input.max_rows,
      max_links_per_row: input.max_links_per_row,
    };
    if (input.query !== undefined && input.query.length > 0) {
      payload["query"] = input.query;
    }
    const data = await apiFetch<unknown>("/api/v1/tools/osintmap", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return OsintmapQueryOutput.parse(data);
  });
}

export const TavilyExtractInput = z.object({
  target: z.string().describe("Investigation context / entity label"),
  urls: z.array(z.string().url()).min(1).max(20),
  query: z.string().optional().default("").describe("Optional audit label"),
  analyst_id: z.string(),
  session_id: z.string(),
  claim_type: ClaimTypeSchema.optional().default("web_mention"),
  extract_depth: z.enum(["basic", "advanced"]).default("advanced"),
  format: z.enum(["markdown", "text"]).default("markdown"),
  include_images: z.boolean().default(false),
  focus_query: z
    .string()
    .optional()
    .describe("Rerank chunks for relevance (Tavily Extract query)"),
  chunks_per_source: z.number().int().min(1).max(5).optional(),
});
export type TavilyExtractInput = z.infer<typeof TavilyExtractInput>;

export const TavilyExtractOutput = z.object({
  evidence: z.array(EvidenceSchema),
  failed_results: z.array(
    z.object({ url: z.string(), error: z.string() }),
  ),
  error: z.string().nullable(),
});

export async function runTavilyExtract(input: TavilyExtractInput) {
  return withSpan("tool.tavily.extract", async () => {
    const data = await apiFetch<unknown>("/api/v1/tools/tavily/extract", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return TavilyExtractOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: run Nmap active scan (requires HITL authorization)
// ---------------------------------------------------------------------------

export const NmapScanInput = z.object({
  target: z.string().describe("IP, CIDR, or hostname — MUST have written authorization"),
  analyst_id: z.string(),
  session_id: z.string(),
  profile: z.enum(["quick", "standard", "thorough", "udp", "vuln"]).default("standard"),
  authorization_ref: z
    .string()
    .describe("Reference to the written authorization document or SOW section"),
});
export type NmapScanInput = z.infer<typeof NmapScanInput>;

export async function runNmapScan(input: NmapScanInput) {
  return withSpan("tool.nmap", async () => {
    const data = await apiFetch<unknown>("/api/v1/tools/nmap", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return ShodanQueryOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: theHarvester (subprocess — passive default)
// ---------------------------------------------------------------------------

export const HarvesterQueryInput = z.object({
  target: z.string().describe("Domain or company string (theHarvester -d)"),
  analyst_id: z.string(),
  session_id: z.string(),
  query: z.string().optional().default(""),
  sources: z
    .string()
    .default("duckduckgo,crtsh")
    .describe("Comma-separated theHarvester -b sources (passive default)"),
  limit: z.number().int().min(1).max(5000).default(200),
  start: z.number().int().min(0).default(0),
  quiet: z.boolean().default(true),
  allow_active_techniques: z
    .boolean()
    .default(false)
    .describe("Must be true for DNS brute, resolve, takeover, screenshots, API scan, Shodan -s"),
  dns_brute: z.boolean().default(false),
  dns_lookup: z.boolean().default(false),
  dns_resolve: z.string().default(""),
  takeover: z.boolean().default(false),
  screenshot_dir: z.string().default(""),
  api_scan: z.boolean().default(false),
  wordlist: z.string().default(""),
  shodan_lookup: z.boolean().default(false),
  dns_server: z.string().default(""),
  proxies: z.boolean().default(false),
  timeout_seconds: z.number().int().min(60).max(7200).optional(),
});
export type HarvesterQueryInput = z.infer<typeof HarvesterQueryInput>;

export async function runHarvesterQuery(input: HarvesterQueryInput) {
  return withSpan("tool.theharvester", async () => {
    const data = await apiFetch<unknown>("/api/v1/tools/harvester", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return ShodanQueryOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: ExifTool file metadata (upload multipart — Metaforge-class stack)
// ---------------------------------------------------------------------------

export const MetadataAnalyzeInput = z.object({
  target: z.string().describe("Investigation / case label"),
  analyst_id: z.string(),
  session_id: z.string(),
  /** Node 18+ / browser `Blob` (e.g. `new Blob([bytes])`). */
  file: z.custom<Blob>(
    (v) =>
      typeof v === "object" &&
      v !== null &&
      typeof (v as Blob).arrayBuffer === "function",
  ),
  file_name: z.string().min(1).default("upload.bin"),
  /** Overrides server `METADATA_ENGINE` for this upload. */
  engine: z.enum(["exiftool", "exiv2", "auto"]).optional(),
});
export type MetadataAnalyzeInput = z.infer<typeof MetadataAnalyzeInput>;

export const MetadataAnalyzeOutput = z.object({
  evidence: z.array(EvidenceSchema),
  error: z.string().nullable(),
});

export async function runMetadataAnalyze(
  input: MetadataAnalyzeInput,
): Promise<z.infer<typeof MetadataAnalyzeOutput>> {
  return withSpan("tool.metadata.file", async () => {
    const form = new FormData();
    form.append("target", input.target);
    form.append("analyst_id", input.analyst_id);
    form.append("session_id", input.session_id);
    form.append("file", input.file, input.file_name);
    if (input.engine !== undefined) {
      form.append("engine", input.engine);
    }
    const data = await apiFetchMultipart<unknown>("/api/v1/tools/metadata", form);
    return MetadataAnalyzeOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: Twitter / X OSINT search
// ---------------------------------------------------------------------------

/**
 * OSINT intents mapped from Bellingcat's Twitter Advanced Search methodology.
 * The Python layer (twitter_query_builder.py) builds the X API v2 query string.
 */
export const OSINT_INTENTS = [
  "company_monitoring",
  "person_research",
  "hashtag_campaign",
  "geo_event",
  "disinformation_tracking",
  "breach_leak_monitor",
  "sentiment_analysis",
  "media_evidence",
  "account_network",
] as const;
export type OsintIntent = (typeof OSINT_INTENTS)[number];

export const TwitterSearchInput = z.object({
  target: z.string().describe("Company name, domain, person name, or hashtag"),
  query: z.string().default("").describe(
    "Raw X API v2 query string — leave blank to use intent-based templates",
  ),
  intent: z.enum(OSINT_INTENTS).optional().describe(
    "Bellingcat OSINT intent — selects a pre-built query template when set",
  ),
  analyst_id: z.string(),
  session_id: z.string(),
  // Bellingcat operator overrides
  language: z.string().optional().describe("BCP-47 language code, e.g. 'en', 'id', 'ar'"),
  since: z.string().optional().describe("Start date YYYY-MM-DD"),
  until: z.string().optional().describe("End date YYYY-MM-DD"),
  min_likes: z.number().int().min(0).default(0),
  min_retweets: z.number().int().min(0).default(0),
  min_replies: z.number().int().min(0).default(0),
  exclude_retweets: z.boolean().default(true),
  has_media: z.boolean().default(false),
  from_accounts: z.array(z.string()).default([]),
  to_accounts: z.array(z.string()).default([]),
  mentions: z.array(z.string()).default([]),
  near_place: z
    .string()
    .optional()
    .describe(
      "Bellingcat near: slug or token (no spaces), e.g. estes-park — paired with within_radius",
    ),
  within_radius: z
    .string()
    .optional()
    .describe("within: radius e.g. 2mi or 10km — clamped to 25 mi max in Python builder"),
  geocode_lat: z.number().optional(),
  geocode_lon: z.number().optional(),
  geocode_radius: z
    .string()
    .optional()
    .describe("geocode: radius — max 25 mi per X API; e.g. 10mi"),
  max_results: z.number().int().min(10).max(500).default(100),
  full_archive: z
    .boolean()
    .default(false)
    .describe("Use /tweets/search/all — requires Academic/Pro tier bearer token"),
});
export type TwitterSearchInput = z.infer<typeof TwitterSearchInput>;

export const TwitterSearchOutput = z.object({
  evidence: z.array(EvidenceSchema),
  total_found: z.number(),
  query_used: z.string(),
  error: z.string().nullable(),
});

export async function runTwitterSearch(
  input: TwitterSearchInput,
): Promise<z.infer<typeof TwitterSearchOutput>> {
  return withSpan("tool.twitter", async () => {
    const data = await apiFetch<unknown>("/api/v1/tools/twitter", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return TwitterSearchOutput.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Tool: generate intel report from a session's evidence
// ---------------------------------------------------------------------------

export const ReportInput = z.object({
  session_id: z.string(),
  target: z.string(),
  goal: z.string(),
  analyst_id: z.string(),
  generate_llm_summaries: z.boolean().default(true),
});

export async function generateReport(input: z.infer<typeof ReportInput>) {
  return withSpan("tool.report", async () => {
    const data = await apiFetch<unknown>("/api/v1/report", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return IntelReportSchema.parse(data);
  });
}

// ---------------------------------------------------------------------------
// Full pipeline scan (FastAPI LangGraph — not the Claude agent loop)
// ---------------------------------------------------------------------------

export const GrondScanRequest = z.object({
  target: z.string(),
  goal: z.string(),
  analyst_id: z.string(),
  run_nmap: z.boolean().default(false),
  investigation_profile: InvestigationProfileSchema.default("general"),
  tavily_time_range: z.enum(["day", "week", "month", "year"]).optional(),
});
export type GrondScanRequest = z.infer<typeof GrondScanRequest>;

export async function runGrondScan(
  input: z.infer<typeof GrondScanRequest>,
): Promise<IntelReport> {
  return withSpan("grond.scan", async () => {
    const payload = GrondScanRequest.parse(input);
    const data = await apiFetch<unknown>("/api/v1/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return IntelReportSchema.parse(data);
  });
}
