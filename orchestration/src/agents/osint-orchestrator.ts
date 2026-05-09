/**
 * OSINT Orchestrator — primary Claude Agent SDK agent.
 *
 * Receives a (target, goal, analyst_id) tuple and:
 *  1. Plans which tools to run (always passive first).
 *  2. Dispatches shodan + tavily in parallel.
 *  3. Presents a HITL confirmation request before any active Nmap scan.
 *  4. Calls the Python pipeline to fuse results.
 *  5. Generates and returns the final IntelReport.
 *
 * Principle: the orchestrator decides WHAT to do; each tool does HOW.
 * No OSINT logic lives here — only routing and sequencing.
 */

import Anthropic from "@anthropic-ai/sdk";
import { Buffer } from "node:buffer";
import { z } from "zod/v3";
import { withSpan } from "../observability/tracer.js";
import { logger } from "../observability/logger.js";
import {
  runShodanQuery,
  runTavilyQuery,
  runNmapScan,
  runTwitterSearch,
  runHarvesterQuery,
  runMetadataAnalyze,
  runOsintmapQuery,
  runEdgarTextSearch,
  generateReport,
  MetadataAnalyzeInput,
  NmapScanInput,
  TwitterSearchInput,
  TavilyQueryInput,
  HarvesterQueryInput,
  OsintmapQueryInput,
  EdgarTextSearchInput,
  type OsintIntent,
} from "../tools/grond-api.js";
import { buildTavilyQueries, buildDeepOsintQueries, goalSuggestsDwmMarketplaceOsint } from "../tools/query-templates.js";
import type { IntelReport } from "../types/evidence.js";

// ---------------------------------------------------------------------------
// Tool schemas for the Agent SDK
// ---------------------------------------------------------------------------

const TOOLS: Anthropic.Tool[] = [
  {
    name: "shodan_search",
    description:
      "Passive Shodan query for exposed services, banners, CVEs. " +
      "Use for any IP, CIDR, hostname, or org name. No authorization needed.",
    input_schema: {
      type: "object" as const,
      required: ["target", "query", "session_id"],
      properties: {
        target: { type: "string", description: "IP, CIDR, domain, or org name" },
        query: { type: "string", description: "Full Shodan filter expression" },
        session_id: { type: "string" },
      },
    },
  },
  {
    name: "tavily_search",
    description:
      "Web intelligence via Tavily (public indexed content). Use search_depth=advanced. " +
      "For public social/discourse signals use investigation_profile=social and optional platform " +
      "(reddit, x, …) or site: in the query — indexed pages only; do not target private profiles. " +
      "For dark-web marketplace–style goals, use clearnet pivots only (news, LE releases, research, blockchain reporting) " +
      "per OSINT Dojo DWM — do not attempt onion-market access from this tool.",
    input_schema: {
      type: "object" as const,
      required: ["target", "query", "session_id"],
      properties: {
        target: { type: "string" },
        query: { type: "string" },
        session_id: { type: "string" },
        search_depth: { type: "string", enum: ["basic", "advanced"], default: "advanced" },
        max_results: { type: "number", description: "1–20", default: 10 },
        investigation_profile: {
          type: "string",
          enum: ["general", "company", "social"],
          default: "general",
        },
        platform: {
          type: "string",
          enum: ["reddit", "x", "twitter", "tiktok", "instagram", "youtube", "linkedin", "hackernews"],
        },
        topic: { type: "string", enum: ["general", "news", "finance"] },
        time_range: { type: "string", enum: ["day", "week", "month", "year"] },
        start_date: { type: "string", description: "YYYY-MM-DD" },
        end_date: { type: "string", description: "YYYY-MM-DD" },
      },
    },
  },
  {
    name: "edgar_text_search",
    description:
      "SEC EDGAR full-text search (US public company filings) via Bellingcat edgar-tool. " +
      "REGULATOR-tier indexed hits — use for registered issuers: entity/ticker/CIK, form types (10-K, 8-K), " +
      "and keywords in risk factors or MD&A. Passive public data — no API key; cap max_results; follow SEC access policy.",
    input_schema: {
      type: "object" as const,
      required: ["target", "session_id"],
      properties: {
        target: { type: "string", description: "Investigation / case label" },
        session_id: { type: "string" },
        keywords: {
          type: "array",
          items: { type: "string" },
          description: "Filing text must match all terms (AND). At least one of keywords, entity, filing_category, or single_forms required",
        },
        entity: {
          type: "string",
          description: "Company name, ticker symbol, or CIK",
        },
        filing_category: {
          type: "string",
          description: "SEC EDGAR filing category; omit if using single_forms",
        },
        single_forms: {
          type: "array",
          items: { type: "string" },
          description: 'Form types e.g. "10-K", "8-K"',
        },
        date_range_select: {
          type: "string",
          description: "all | 10y | 5y | 1y | 30d | custom",
          default: "5y",
        },
        start_date: { type: "string", description: "With custom range only, YYYY-MM-DD" },
        end_date: { type: "string", description: "With custom range only, YYYY-MM-DD" },
        max_results: { type: "number", description: "Cap results (1–100)", default: 25 },
      },
    },
  },
  {
    name: "osintmap_lookup",
    description:
      "Regional public OSINT starting points from cipher387 OSINTMap (GitHub README table): " +
      "business registries, cadastral maps, court listings, yellow pages, transport trackers, etc. " +
      "Pass region_query as a country/state/city label substring (e.g. Belgium, Texas, Berlin). " +
      "Passive — one HTTP fetch of public raw markdown from GitHub; verify each linked portal. " +
      "Does not replace jurisdiction-specific legal review or authorization for active scans.",
    input_schema: {
      type: "object" as const,
      required: ["target", "region_query", "session_id"],
      properties: {
        target: { type: "string", description: "Investigation / case label" },
        region_query: {
          type: "string",
          description: "Country, state, or region substring matching OSINTMap table row",
        },
        session_id: { type: "string" },
        max_rows: { type: "number", description: "Max table rows to return", default: 8 },
        max_links_per_row: {
          type: "number",
          description: "Cap anchors parsed per row",
          default: 40,
        },
      },
    },
  },
  {
    name: "theharvester_search",
    description:
      "OSINT subdomain/email/host harvest via theHarvester CLI (public sources). " +
      "Default is PASSIVE (e.g. duckduckgo,crtsh). DNS brute, DNS resolve/lookup, takeover checks, " +
      "screenshots, API scan, or Shodan follow-up require allow_active_scan=true on the session " +
      "AND written authorization in the Python AuthorizationService — treat like Nmap.",
    input_schema: {
      type: "object" as const,
      required: ["target", "session_id"],
      properties: {
        target: { type: "string", description: "Domain or company name (theHarvester -d)" },
        session_id: { type: "string" },
        sources: {
          type: "string",
          description: "Comma-separated -b sources; default duckduckgo,crtsh",
          default: "duckduckgo,crtsh",
        },
        limit: { type: "number", description: "Result limit (-l)", default: 200 },
        dns_brute: { type: "boolean", description: "ACTIVE: -c DNS brute (needs authorization)", default: false },
        dns_lookup: { type: "boolean", description: "ACTIVE: -n (needs authorization)", default: false },
        dns_resolve: { type: "string", description: "ACTIVE: -r (needs authorization) when non-empty" },
        takeover: { type: "boolean", description: "ACTIVE: -t (needs authorization)", default: false },
        screenshot_dir: {
          type: "string",
          description: "ACTIVE: --screenshot dir (needs authorization) when non-empty",
        },
        api_scan: { type: "boolean", description: "ACTIVE: -a (needs authorization)", default: false },
        shodan_lookup: { type: "boolean", description: "ACTIVE: -s (needs authorization)", default: false },
      },
    },
  },
  {
    name: "nmap_scan",
    description:
      "ACTIVE port/service scan using Nmap. " +
      "ONLY call this tool if the analyst has confirmed written authorization. " +
      "Always include the authorization_ref field.",
    input_schema: {
      type: "object" as const,
      required: ["target", "session_id", "authorization_ref"],
      properties: {
        target: { type: "string" },
        session_id: { type: "string" },
        profile: {
          type: "string",
          enum: ["quick", "standard", "thorough", "udp", "vuln"],
          default: "standard",
        },
        authorization_ref: {
          type: "string",
          description: "Citation for the written authorization (e.g. SOW-2024-01 §3)",
        },
      },
    },
  },
  {
    name: "twitter_search",
    description:
      "X / Twitter OSINT search using Bellingcat advanced search methodology. " +
      "Use for: company reputation, person research, hashtag campaigns, " +
      "breach/leak announcements, disinformation tracking, geo-events, account networks. " +
      "For location-bound monitoring use intent geo_event with near_place + within_radius or geocode_* fields; geo radius max 25 mi. " +
      "Passive tool — no authorization required.",
    input_schema: {
      type: "object" as const,
      required: ["target", "session_id"],
      properties: {
        target: {
          type: "string",
          description: "Company name, domain, person name, or hashtag to investigate",
        },
        intent: {
          type: "string",
          enum: [
            "company_monitoring",
            "person_research",
            "hashtag_campaign",
            "geo_event",
            "disinformation_tracking",
            "breach_leak_monitor",
            "sentiment_analysis",
            "media_evidence",
            "account_network",
          ],
          description: "Bellingcat OSINT intent — selects a pre-built query template",
        },
        query: {
          type: "string",
          description: "Raw X API v2 query (optional — leave blank to use intent template)",
        },
        session_id: { type: "string" },
        language: {
          type: "string",
          description: "BCP-47 language code. Tip: translate keywords first for non-English",
        },
        since: { type: "string", description: "Start date YYYY-MM-DD" },
        until: { type: "string", description: "End date YYYY-MM-DD" },
        min_likes: { type: "number", description: "Minimum engagement threshold (likes)" },
        min_retweets: { type: "number" },
        has_media: {
          type: "boolean",
          description: "Return only tweets with attached images or video",
        },
        from_accounts: {
          type: "array",
          items: { type: "string" },
          description: "Filter posts authored by these handles",
        },
        to_accounts: {
          type: "array",
          items: { type: "string" },
          description: "Filter posts replying to these handles",
        },
        near_place: {
          type: "string",
          description:
            "near: place slug/token for geo-focused searches (e.g. estes-park); pair with within_radius",
        },
        within_radius: {
          type: "string",
          description: "within: radius such as 2mi or 10km — X API geo radius max 25 mi",
        },
        geocode_lat: { type: "number", description: "Latitude for geocode:lat,lon,radius" },
        geocode_lon: { type: "number", description: "Longitude for geocode:lat,lon,radius" },
        geocode_radius: {
          type: "string",
          description: "geocode radius (e.g. 10mi); maximum 25 mi per X API",
        },
        exclude_retweets: { type: "boolean", default: true },
        max_results: { type: "number", default: 100 },
      },
    },
  },
  {
    name: "exiftool_metadata",
    description:
      "Extract file metadata from an artifact: ExifTool (broad formats) or Exiv2 (image Exif/IPTC/XMP). " +
      "Use when the analyst provides file content as base64. Set engine to exiv2 for image-heavy work, " +
      "exiftool for PDF/office/video-sidecar cases, or auto (server default: try Exiv2 then ExifTool). " +
      "Network-passive; only analyze material you are authorized to process; output may include GPS/device/PII—review-flagged.",
    input_schema: {
      type: "object" as const,
      required: ["target", "session_id", "file_base64", "file_name"],
      properties: {
        target: { type: "string", description: "Investigation / case label" },
        session_id: { type: "string" },
        file_base64: {
          type: "string",
          description: "Base64-encoded file bytes (standard encoding, no data: URL prefix)",
        },
        file_name: {
          type: "string",
          description: "Original filename with extension (e.g. photo.jpg, report.pdf)",
        },
        engine: {
          type: "string",
          enum: ["exiftool", "exiv2", "auto"],
          description: "Metadata backend; auto uses server METADATA_ENGINE / fallback chain",
        },
      },
    },
  },
  {
    name: "generate_report",
    description:
      "Generate the final intel report from all collected evidence. " +
      "Call this after all collection tools have completed.",
    input_schema: {
      type: "object" as const,
      required: ["session_id", "target", "goal"],
      properties: {
        session_id: { type: "string" },
        target: { type: "string" },
        goal: { type: "string" },
        generate_llm_summaries: { type: "boolean", default: true },
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Orchestrator request
// ---------------------------------------------------------------------------

export interface OrchestratorRequest {
  target: string;
  goal: string;
  analyst_id: string;
  session_id: string;
  allow_active_scan?: boolean;
  authorization_ref?: string;
  /** Aligns with FastAPI ``ScanRequest`` / Python collector (default general). */
  investigation_profile?: "general" | "company" | "social";
  tavily_time_range?: "day" | "week" | "month" | "year";
}

// ---------------------------------------------------------------------------
// Main orchestrator — agentic loop
// ---------------------------------------------------------------------------

export async function runOsintOrchestrator(
  req: OrchestratorRequest,
): Promise<IntelReport> {
  return withSpan("orchestrator.run", async () => {
    const client = new Anthropic();

    const systemPrompt = buildSystemPrompt(req);
    const dwmHint =
      goalSuggestsDwmMarketplaceOsint(req.goal) ?
        `Suggested clearnet Tavily seeds (OSINT Dojo DWM–style; adapt as needed):\n${buildTavilyQueries(req.target, "dwm").map((q) => `- ${q}`).join("\n")}\n`
      : "";
    // Always inject deep OSINT query hints for the agent to use as starting points
    const deepHints = buildDeepOsintQueries(req.target);
    const deepHintBlock =
      `\nDeep OSINT query bank (run tavily_search for EACH, search_depth=advanced, max_results=10):\n` +
      deepHints.map((q) => `- ${q}`).join("\n") +
      "\n";
    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content:
          `Target: ${req.target}\n` +
          `Goal: ${req.goal}\n` +
          `Session ID: ${req.session_id}\n` +
          `Active scan authorized: ${req.allow_active_scan ? "YES" : "NO"}\n` +
          `Investigation profile: ${req.investigation_profile ?? "general"}\n` +
          (req.tavily_time_range ? `Tavily time_range: ${req.tavily_time_range}\n` : "") +
          (req.authorization_ref ? `Authorization ref: ${req.authorization_ref}\n` : "") +
          (dwmHint ? `\n${dwmHint}` : "") +
          deepHintBlock +
          "\nBegin the investigation. Run ALL query categories above via tavily_search before calling generate_report.",
      },
    ];

    let report: IntelReport | null = null;

    // Agentic tool-calling loop
    while (true) {
      const response = await client.messages.create({
        model: "claude-sonnet-4-5",
        max_tokens: 4096,
        system: systemPrompt,
        tools: TOOLS,
        messages,
      });

      // Push assistant response to conversation
      messages.push({ role: "assistant", content: response.content });

      if (response.stop_reason === "end_turn") {
        break;
      }

      if (response.stop_reason !== "tool_use") {
        break;
      }

      // Dispatch tool calls
      const toolResults: Anthropic.ToolResultBlockParam[] = [];

      for (const block of response.content) {
        if (block.type !== "tool_use") continue;

        logger.info(
          {
            tool: block.name,
            session: req.session_id,
            target: req.target,
          },
          "tool_dispatch",
        );

        let result: unknown;
        try {
          result = await dispatchTool(block.name, block.input as Record<string, unknown>, req);
          if (block.name === "generate_report") {
            report = result as IntelReport;
          }
        } catch (err) {
          result = { error: String(err) };
          logger.warn({ tool: block.name, error: String(err) }, "tool_error");
        }

        toolResults.push({
          type: "tool_result",
          tool_use_id: block.id,
          content: JSON.stringify(result),
        });
      }

      messages.push({ role: "user", content: toolResults });
    }

    if (!report) {
      throw new Error("Orchestrator completed without generating a report");
    }

    return report;
  });
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

function harvesterActiveRequested(input: Record<string, unknown>): boolean {
  const dr = input["dns_resolve"];
  const sd = input["screenshot_dir"];
  return Boolean(
    input["dns_brute"] ||
      input["dns_lookup"] ||
      (typeof dr === "string" && dr.trim() !== "") ||
      input["takeover"] ||
      (typeof sd === "string" && sd.trim() !== "") ||
      input["api_scan"] ||
      input["shodan_lookup"],
  );
}

async function dispatchTool(
  name: string,
  input: Record<string, unknown>,
  req: OrchestratorRequest,
): Promise<unknown> {
  const analyst_id = req.analyst_id;
  const session_id = req.session_id;

  switch (name) {
    case "shodan_search":
      return runShodanQuery({
        target: String(input["target"]),
        query: String(input["query"]),
        analyst_id,
        session_id,
        max_results: Number(input["max_results"] ?? 100),
      });

    case "tavily_search": {
      const rawProf = input["investigation_profile"];
      const investigation_profile =
        rawProf === "company" || rawProf === "social" || rawProf === "general"
          ? rawProf
          : (req.investigation_profile ?? "general");
      const rawTime = input["time_range"];
      const time_range =
        rawTime === "day" || rawTime === "week" || rawTime === "month" || rawTime === "year"
          ? rawTime
          : req.tavily_time_range;
      const payload: Record<string, unknown> = {
        target: String(input["target"]),
        query: String(input["query"]),
        analyst_id,
        session_id,
        search_depth: (input["search_depth"] as "basic" | "advanced") ?? "advanced",
        max_results: Number(input["max_results"] ?? 10),
        investigation_profile,
      };
      if (time_range !== undefined) {
        payload["time_range"] = time_range;
      }
      if (input["platform"] !== undefined) {
        payload["platform"] = input["platform"];
      }
      if (input["topic"] !== undefined) {
        payload["topic"] = input["topic"];
      }
      if (input["start_date"] !== undefined) {
        payload["start_date"] = String(input["start_date"]);
      }
      if (input["end_date"] !== undefined) {
        payload["end_date"] = String(input["end_date"]);
      }
      return runTavilyQuery(TavilyQueryInput.parse(payload));
    }

    case "edgar_text_search": {
      const parsed = EdgarTextSearchInput.parse({
        target: String(input["target"]),
        analyst_id,
        session_id,
        query: input["query"] !== undefined ? String(input["query"]) : "",
        keywords: input["keywords"] as string[] | undefined,
        entity: input["entity"] !== undefined ? String(input["entity"]) : undefined,
        filing_category:
          input["filing_category"] !== undefined ? String(input["filing_category"]) : undefined,
        single_forms: input["single_forms"] as string[] | undefined,
        date_range_select:
          input["date_range_select"] !== undefined ? String(input["date_range_select"]) : undefined,
        start_date: input["start_date"] !== undefined ? String(input["start_date"]) : undefined,
        end_date: input["end_date"] !== undefined ? String(input["end_date"]) : undefined,
        incorporated_in:
          input["incorporated_in"] !== undefined ? String(input["incorporated_in"]) : undefined,
        principal_executive_offices_in:
          input["principal_executive_offices_in"] !== undefined
            ? String(input["principal_executive_offices_in"])
            : undefined,
        max_results: input["max_results"] !== undefined ? Number(input["max_results"]) : undefined,
      });
      return runEdgarTextSearch(parsed);
    }

    case "osintmap_lookup": {
      const parsed = OsintmapQueryInput.parse({
        target: String(input["target"]),
        region_query: String(input["region_query"]),
        analyst_id,
        session_id,
        max_rows: input["max_rows"] !== undefined ? Number(input["max_rows"]) : undefined,
        max_links_per_row:
          input["max_links_per_row"] !== undefined
            ? Number(input["max_links_per_row"])
            : undefined,
      });
      return runOsintmapQuery(parsed);
    }

    case "theharvester_search": {
      const active = harvesterActiveRequested(input);
      if (active && !req.allow_active_scan) {
        throw new Error(
          "theHarvester active options requested but allow_active_scan=false. " +
            "Confirm written authorization for DNS brute, resolve, takeover, screenshots, API scan, or Shodan follow-up.",
        );
      }
      const parsed = HarvesterQueryInput.parse({
        ...input,
        analyst_id,
        session_id,
        allow_active_techniques: active ? Boolean(req.allow_active_scan) : false,
      });
      return runHarvesterQuery(parsed);
    }

    case "nmap_scan": {
      // Nmap requires explicit allow_active_scan flag from the orchestration caller
      if (!req.allow_active_scan) {
        throw new Error(
          "Active scan requested but allow_active_scan=false. " +
          "Analyst must confirm written authorization before this tool can run.",
        );
      }
      const parsed = NmapScanInput.parse({ ...input, analyst_id, session_id });
      return runNmapScan(parsed);
    }

    case "twitter_search": {
      const parsed = TwitterSearchInput.parse({
        ...input,
        analyst_id,
        session_id,
        intent: (input["intent"] as OsintIntent | undefined) ?? undefined,
      });
      return runTwitterSearch(parsed);
    }

    case "exiftool_metadata": {
      const b64 = String(input["file_base64"] ?? "");
      const raw = Buffer.from(b64, "base64");
      if (raw.length === 0) {
        throw new Error("exiftool_metadata: empty or invalid base64 payload");
      }
      const file = new Blob([raw]);
      const parsed = MetadataAnalyzeInput.parse({
        target: String(input["target"]),
        analyst_id,
        session_id,
        file,
        file_name: String(input["file_name"] ?? "upload.bin"),
        engine: input["engine"] as "exiftool" | "exiv2" | "auto" | undefined,
      });
      return runMetadataAnalyze(parsed);
    }

    case "generate_report":
      return generateReport({
        session_id,
        target: String(input["target"]),
        goal: String(input["goal"]),
        analyst_id,
        generate_llm_summaries: Boolean(input["generate_llm_summaries"] ?? true),
      });

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

function buildSystemPrompt(req: OrchestratorRequest): string {
  return `You are the OSINT Orchestrator for Grond — an advanced intelligence analysis platform used by professional analysts.

## Your Mission
Produce intelligence at the **NKRI standard**: deep, structured, analytical, cross-corroborated. You do not merely collect facts — you interrogate them. Every finding must be challenged: What is the real intent? Who are the actual backers? What are the hidden connections? What does this reveal that was not obvious?

## Mandatory Collection Sequence
1. **Passive collection first** (always):
   - shodan_search: exposed infrastructure, services, CVEs, banners
   - tavily_search: run a FULL FAN-OUT across ALL query categories (see Query Strategy below)
   - theharvester_search: subdomains, emails, hosts (passive sources: duckduckgo, crtsh)
   - edgar_text_search: if target is or may be a US public filer (company name, ticker, CIK)
   - osintmap_lookup: if goal references a specific country/jurisdiction
   - twitter_search: 3–5 calls across multiple intents

2. **Deep query fan-out via tavily_search** (REQUIRED for every target):
   Run at minimum ONE tavily_search call for EACH of these categories, using search_depth=advanced and max_results=10:
   - **Company basics**: leadership, tech stack, news, breach history
   - **Affiliations**: investors, subsidiaries, partners, board members, government contracts
   - **Key persons**: CEO/founder background, CTO, CISO — include "was formerly", "prior to" pivots; search LinkedIn/social by name
   - **Intent analysis**: what is the entity's actual goal? Controversies, allegations, regulatory actions, sanctions
   - **Financial/legal**: court filings, SEC disclosures, bankruptcy, fraud allegations, money laundering
   - **Leaked documents**: Scribd, DocumentCloud, filetype:pdf, pastebin dumps, breach databases
   - **Social/reputation**: Reddit, X/Twitter, YouTube, LinkedIn — public indexed discourse

3. **Twitter multi-intent sweep** (REQUIRED):
   Issue twitter_search with EACH relevant intent:
   - company_monitoring (exclude_retweets=true)
   - person_research (for each identified key person)
   - breach_leak_monitor (min_likes=10 to cut noise)
   - account_network (for mapping influence)

4. **Active scan** — only if allow_active_scan=true AND authorization_ref provided:
   - nmap_scan with the provided profile

5. **generate_report** — ALWAYS the final tool call.

## Critical Questioning (REQUIRED for all findings)
After collecting evidence, before calling generate_report, ask yourself and encode into the goal field of generate_report:
- **"What is their real intention?"** — Does stated purpose match observed behavior?
- **"Who really controls this?"** — Named executives vs actual beneficial owners/backers?
- **"What are the hidden connections?"** — Affiliates, shell companies, cross-directorships?
- **"What does this MEAN for the analyst?"** — So what? What action should be taken?
- **"What is still unknown?"** — Where are the gaps? What could not be verified?

## Key Person Deep-Dive Protocol
For each C-level / founder / key person identified:
1. Search their full name + company + "background" OR "history"
2. Search their LinkedIn profile (site:linkedin.com + name)
3. Search their Twitter/X handle if known (investigation_profile=social)
4. Search "formerly" / "prior to" pivots — previous companies, roles
5. Search for photos (site:instagram.com OR site:facebook.com + name) — visual corroboration
6. Note: generate a per-person mini-profile in the goal field of generate_report

## Twitter OSINT Rules (Bellingcat methodology)
- Use intent-based queries rather than raw queries unless you have a specific X API v2 operator need.
- For non-English targets, set the language field to the appropriate BCP-47 code.
- For trending/breaking events, keep the date range tight (since/until within ±2 days).
- For high-engagement signal filtering, set min_likes ≥ 100 or min_retweets ≥ 50.
- For media evidence (visual verification), set has_media: true.
- Use from_accounts to focus on specific handles of interest once identified.
- Location search (geo_event): use near_place + within_radius or geocode_*; X caps radius at 25 mi.
- Twitter/X data is COMMUNITY tier by default; cross-validate important claims with tavily_search.

## Dark Web Marketplace OSINT (OSINT Dojo DWM)
- Methodology: [OSINT Dojo DWM](https://www.osintdojo.com/diagrams/dwm) — clearnet pivots ONLY.
- Sources: LE takedowns, sanctions, blockchain analytics, academic/security research, court docs.
- Tag unverified forum/leak mentions as low confidence; cross-validate with edgar_text_search.
- Never attempt onion-service access or illicit marketplace interaction.

## Tool Calling Rules
- shodan_search: precise filter expressions (hostname:${req.target} OR ip:${req.target})
- tavily_search: search_depth=advanced, max_results=10; issue 8–15 focused queries across ALL categories
- theharvester_search: passive only (duckduckgo,crtsh) unless active scan authorized
- edgar_text_search: combine entity + keywords + single_forms; corroborate with tavily_search
- osintmap_lookup: vetted public country/region portals; corroborate links
- twitter_search: 3–5 searches across company_monitoring, person_research, breach_leak_monitor, account_network
- nmap_scan: NEVER call unless active scan explicitly authorized; always include authorization_ref
- generate_report: call EXACTLY ONCE, as the VERY LAST tool

## Analytical Standards
- Every claim must trace to a tool call result — never invent facts.
- Raise suspicion flags for: mismatched stated vs observed purpose, unusual corporate structures, sanctioned affiliates, abnormally high breach/leak signals.
- Cross-validate: any single-source claim stays unverified until corroborated by a second independent tool.
- Prefer breadth of query coverage over repeating the same query.
- Missing data is itself a signal — note it in the report goal field.

## Current Session
Target: ${req.target}
Goal: ${req.goal}
Investigation profile: ${req.investigation_profile ?? "general"}
${req.tavily_time_range ? `Tavily time_range: ${req.tavily_time_range}\n` : ""}Active scan authorized: ${req.allow_active_scan ? "YES — authorization ref: " + (req.authorization_ref ?? "provided") : "NO"}
`;
}
