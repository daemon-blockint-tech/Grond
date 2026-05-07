/**
 * OpenRouter-powered OSINT orchestrator using LangChain Deep Agents + ChatOpenRouter.
 *
 * - {@link https://docs.langchain.com/oss/javascript/deepagents | Deep Agents} —
 *   `createDeepAgent` (planning, optional filesystem/subagents; we rely on tool calling).
 * - {@link https://reference.langchain.com/javascript/langchain-openrouter/ChatOpenRouter | ChatOpenRouter}
 *   — OpenRouter via `@langchain/openrouter` (tool calling, unified routing).
 *
 * **Request shape:** same as {@link runOsintOrchestrator} (`OrchestratorRequest` from `osint-orchestrator.ts`).
 * **Returns:** {@link IntelReport} from `generate_report` (Python `/api/v1/report`), same as the Anthropic path.
 */

import { ChatOpenRouter } from "@langchain/openrouter";
import { tool, type ToolRuntime } from "@langchain/core/tools";
import { createDeepAgent } from "deepagents";
import { z } from "zod/v4";

import type { OrchestratorRequest } from "./osint-orchestrator.js";
import {
  EdgarTextSearchInput,
  generateReport,
  NmapScanInput,
  runEdgarTextSearch,
  runNmapScan,
  runShodanQuery,
  TavilyQueryInput,
  runTavilyQuery,
  runTwitterSearch,
  TwitterSearchInput,
  type OsintIntent,
  type TavilyQueryInput as TavilyQueryPayload,
} from "../tools/grond-api.js";
import { withSpan } from "../observability/tracer.js";
import { logger } from "../observability/logger.js";
import type { IntelReport } from "../types/evidence.js";
import { buildTavilyQueries, goalSuggestsDwmMarketplaceOsint } from "../tools/query-templates.js";

/** Per-invoke runtime context for Grond tools (`invoke` options `context`, not the LLM prompt). */
const osintRuntimeContextSchema = z.object({
  analyst_id: z.string(),
  session_id: z.string(),
  target: z.string(),
  goal: z.string(),
  allow_active_scan: z.boolean(),
  authorization_ref: z.string().optional(),
  investigation_profile: z.enum(["general", "company", "social"]).default("general"),
  tavily_time_range: z.enum(["day", "week", "month", "year"]).optional(),
});

type OsintRuntimeContext = z.infer<typeof osintRuntimeContextSchema>;

function requireOsintRuntimeContext(
  runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
): OsintRuntimeContext {
  const parsed = osintRuntimeContextSchema.safeParse(runtime.context);
  if (!parsed.success) {
    throw new Error(
      "OpenRouter OSINT tools require invoke context: analyst_id, session_id, target, goal, allow_active_scan",
    );
  }
  return parsed.data;
}

const TOOL_CONCISE_HINT =
  " When interpreting results in chat, summarize key findings—do not paste large raw API payloads; use write_file for verbatim excerpts if needed.";

function requireApiKey(): string {
  const key = process.env["OPENROUTER_API_KEY"];
  if (!key?.trim()) {
    throw new Error("OPENROUTER_API_KEY is required for OpenRouter orchestration");
  }
  return key.trim();
}

function buildSystemPrompt(req: OrchestratorRequest): string {
  return `You are the OSINT Orchestrator for Grond, an intelligence analysis platform.

## Job
Given a target and goal, call tools to collect passive intelligence, then call generate_report exactly once at the end.

## Rules
1. Start with passive tools: shodan_search, tavily_search (search_depth advanced), edgar_text_search for US SEC filings when the target is a public registrant, twitter_search as appropriate.
2. Issue multiple tavily_search queries for footprint, news, breaches, leadership, tech stack, and public indexed social/discourse when relevant (investigation_profile=social or site: filters). For dark web / darknet marketplace goals, add clearnet-only pivots (takedowns, sanctions, blockchain reporting, security research) per OSINT Dojo DWM — never attempt onion-market access via tools.
3. Only call nmap_scan if Active scan authorized below is YES. Prefer calling nmap_scan directly in this thread so the tool receives invoke context (including authorization_ref). Do not delegate active scans via the \`task\` subagent unless unavoidable; if you must use \`task\`, paste verbatim into the task description: authorization_ref, session_id, analyst_id, target, allow_active_scan=YES, and tell the subagent to call nmap_scan with that ref.
4. Always finish by calling generate_report with session_id, target, and goal.
5. Do not invent facts — only report what tools return.
6. Deep-agent extras (write_todos, filesystem): use write_todos only if it helps you track steps; avoid read_file/write_file unless you truly need scratch notes — the deliverable is generate_report.
7. After tool calls, summarize in your own words for the user thread; do not dump full raw JSON—store long excerpts under /workspace/ if you need them.

## Session
Target: ${req.target}
Goal: ${req.goal}
Session ID: ${req.session_id}
Investigation profile: ${req.investigation_profile ?? "general"}
${req.tavily_time_range ? `Tavily time_range: ${req.tavily_time_range}\n` : ""}Active scan authorized: ${req.allow_active_scan ? `YES — ref: ${req.authorization_ref ?? "(invoke context; optional in nmap_scan args)"}` : "NO — do not call nmap_scan"}

## Dark web marketplace OSINT (OSINT Dojo DWM)
- [Dark Web Marketplace OSINT Attack Surface](https://www.osintdojo.com/diagrams/dwm) — [PDF diagram](https://github.com/sinwindie/OSINT/raw/master/DarkWeb/DWM%20OSINT%20Attack%20Surface.pdf); [Dark Web resources index](https://www.osintdojo.com/resources/#dark_web).
- Use indexed clearnet and public records; corroborate low-trust sources; do not instruct or simulate access to illicit marketplaces.
`;
}

function grondTools(reportHolder: { report: IntelReport | null }) {
  const shodanTool = tool(
    async (
      input: { target: string; query: string; max_results?: number },
      runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
    ) => {
      const ctx = requireOsintRuntimeContext(runtime);
      logger.info(
        { tool: "shodan_search", session: ctx.session_id, target: ctx.target },
        "tool_dispatch",
      );
      return runShodanQuery({
        target: input.target,
        query: input.query,
        analyst_id: ctx.analyst_id,
        session_id: ctx.session_id,
        max_results: input.max_results ?? 100,
      });
    },
    {
      name: "shodan_search",
      description:
        "Passive Shodan query for exposed services and banners. No authorization needed. Build a precise Shodan filter query." +
        TOOL_CONCISE_HINT,
      schema: z.object({
        target: z.string(),
        query: z.string(),
        max_results: z.number().int().min(1).max(1000).optional(),
      }),
    },
  );

  const tavilyTool = tool(
    async (
      input: {
        target: string;
        query: string;
        search_depth?: "basic" | "advanced";
        max_results?: number;
        investigation_profile?: "general" | "company" | "social";
        platform?: TavilyQueryPayload["platform"];
        topic?: TavilyQueryPayload["topic"];
        time_range?: TavilyQueryPayload["time_range"];
        start_date?: string;
        end_date?: string;
      },
      runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
    ) => {
      const ctx = requireOsintRuntimeContext(runtime);
      logger.info(
        { tool: "tavily_search", session: ctx.session_id, target: ctx.target },
        "tool_dispatch",
      );
      const payload: Record<string, unknown> = {
        target: input.target,
        query: input.query,
        analyst_id: ctx.analyst_id,
        session_id: ctx.session_id,
        search_depth: input.search_depth ?? "advanced",
        max_results: input.max_results ?? 10,
        investigation_profile:
          input.investigation_profile ?? ctx.investigation_profile ?? "general",
      };
      if (input.platform !== undefined) {
        payload["platform"] = input.platform;
      }
      if (input.topic !== undefined) {
        payload["topic"] = input.topic;
      }
      const timeRange = input.time_range ?? ctx.tavily_time_range;
      if (timeRange !== undefined) {
        payload["time_range"] = timeRange;
      }
      if (input.start_date !== undefined) {
        payload["start_date"] = input.start_date;
      }
      if (input.end_date !== undefined) {
        payload["end_date"] = input.end_date;
      }
      return runTavilyQuery(TavilyQueryInput.parse(payload));
    },
    {
      name: "tavily_search",
      description:
        "Web intelligence via Tavily (public indexed content). Use search_depth advanced. " +
        "For social/discourse, use investigation_profile=social and optional platform or site: in the query. " +
        "For DWM-style goals, clearnet pivots only (no onion-market access)." +
        TOOL_CONCISE_HINT,
      schema: z.object({
        target: z.string(),
        query: z.string(),
        search_depth: z.enum(["basic", "advanced"]).optional(),
        max_results: z.number().int().min(1).max(20).optional(),
        investigation_profile: z.enum(["general", "company", "social"]).optional(),
        platform: z
          .enum(["reddit", "x", "twitter", "tiktok", "instagram", "youtube", "linkedin", "hackernews"])
          .optional(),
        topic: z.enum(["general", "news", "finance"]).optional(),
        time_range: z.enum(["day", "week", "month", "year"]).optional(),
        start_date: z.string().optional(),
        end_date: z.string().optional(),
      }),
    },
  );

  const nmapTool = tool(
    async (
      input: {
        target: string;
        profile?: "quick" | "standard" | "thorough" | "udp" | "vuln";
        authorization_ref?: string;
      },
      runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
    ) => {
      const ctx = requireOsintRuntimeContext(runtime);
      logger.info(
        { tool: "nmap_scan", session: ctx.session_id, target: ctx.target },
        "tool_dispatch",
      );
      if (!ctx.allow_active_scan) {
        throw new Error(
          "Active scan requested but allow_active_scan=false. Analyst must confirm written authorization.",
        );
      }
      const ref =
        (input.authorization_ref?.trim() || "").length > 0 ?
          input.authorization_ref!.trim()
        : (ctx.authorization_ref?.trim() ?? "");
      if (!ref) {
        throw new Error(
          "nmap_scan needs authorization_ref: pass it in the tool call or set authorization_ref on the scan job (OrchestratorRequest).",
        );
      }
      const parsed = NmapScanInput.parse({
        target: input.target,
        analyst_id: ctx.analyst_id,
        session_id: ctx.session_id,
        profile: input.profile ?? "standard",
        authorization_ref: ref,
      });
      return runNmapScan(parsed);
    },
    {
      name: "nmap_scan",
      description:
        "ACTIVE Nmap scan. ONLY if written authorization exists and passive goals require it. " +
        "authorization_ref may be omitted when the scan job already provided it (invoke context)." +
        TOOL_CONCISE_HINT,
      schema: z.object({
        target: z.string(),
        profile: z.enum(["quick", "standard", "thorough", "udp", "vuln"]).optional(),
        authorization_ref: z
          .string()
          .optional()
          .describe("Written authorization id; falls back to job invoke context if omitted"),
      }),
    },
  );

  const twitterTool = tool(
    async (
      input: {
        target: string;
        intent?: string;
        query?: string;
        language?: string;
        since?: string;
        until?: string;
        min_likes?: number;
        min_retweets?: number;
        has_media?: boolean;
        from_accounts?: string[];
        exclude_retweets?: boolean;
        max_results?: number;
      },
      runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
    ) => {
      const ctx = requireOsintRuntimeContext(runtime);
      logger.info(
        { tool: "twitter_search", session: ctx.session_id, target: ctx.target },
        "tool_dispatch",
      );
      const parsed = TwitterSearchInput.parse({
        target: input.target,
        query: input.query ?? "",
        intent: input.intent as OsintIntent | undefined,
        analyst_id: ctx.analyst_id,
        session_id: ctx.session_id,
        language: input.language,
        since: input.since,
        until: input.until,
        min_likes: input.min_likes ?? 0,
        min_retweets: input.min_retweets ?? 0,
        has_media: input.has_media ?? false,
        from_accounts: input.from_accounts ?? [],
        exclude_retweets: input.exclude_retweets ?? true,
        max_results: input.max_results ?? 100,
      });
      return runTwitterSearch(parsed);
    },
    {
      name: "twitter_search",
      description:
        "X / Twitter OSINT (Bellingcat-style). Use intent when unsure; raw query optional. Passive — no auth needed." +
        TOOL_CONCISE_HINT,
      schema: z.object({
        target: z.string(),
        intent: z
          .enum([
            "company_monitoring",
            "person_research",
            "hashtag_campaign",
            "geo_event",
            "disinformation_tracking",
            "breach_leak_monitor",
            "sentiment_analysis",
            "media_evidence",
            "account_network",
          ])
          .optional(),
        query: z.string().optional(),
        language: z.string().optional(),
        since: z.string().optional(),
        until: z.string().optional(),
        min_likes: z.number().int().optional(),
        min_retweets: z.number().int().optional(),
        has_media: z.boolean().optional(),
        from_accounts: z.array(z.string()).optional(),
        exclude_retweets: z.boolean().optional(),
        max_results: z.number().int().optional(),
      }),
    },
  );

  const edgarTool = tool(
    async (
      input: {
        target: string;
        keywords?: string[];
        entity?: string;
        filing_category?: string;
        single_forms?: string[];
        date_range_select?: string;
        start_date?: string;
        end_date?: string;
        max_results?: number;
      },
      runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
    ) => {
      const ctx = requireOsintRuntimeContext(runtime);
      logger.info(
        { tool: "edgar_text_search", session: ctx.session_id, target: ctx.target },
        "tool_dispatch",
      );
      const parsed = EdgarTextSearchInput.parse({
        target: input.target,
        analyst_id: ctx.analyst_id,
        session_id: ctx.session_id,
        query: "",
        keywords: input.keywords ?? [],
        entity: input.entity,
        filing_category: input.filing_category,
        single_forms: input.single_forms ?? [],
        date_range_select: input.date_range_select ?? "5y",
        start_date: input.start_date,
        end_date: input.end_date,
        max_results: input.max_results ?? 25,
      });
      return runEdgarTextSearch(parsed);
    },
    {
      name: "edgar_text_search",
      description:
        "SEC EDGAR full-text search for US public company filings (Bellingcat edgar-tool). REGULATOR tier. No API key." +
        TOOL_CONCISE_HINT,
      schema: z.object({
        target: z.string(),
        keywords: z.array(z.string()).optional(),
        entity: z.string().optional(),
        filing_category: z.string().optional(),
        single_forms: z.array(z.string()).optional(),
        date_range_select: z.string().optional(),
        start_date: z.string().optional(),
        end_date: z.string().optional(),
        max_results: z.number().int().min(1).max(100).optional(),
      }),
    },
  );

  const reportTool = tool(
    async (
      input: {
        session_id: string;
        target: string;
        goal: string;
        generate_llm_summaries?: boolean;
      },
      runtime: ToolRuntime<unknown, typeof osintRuntimeContextSchema>,
    ) => {
      const ctx = requireOsintRuntimeContext(runtime);
      logger.info(
        { tool: "generate_report", session: ctx.session_id, target: ctx.target },
        "tool_dispatch",
      );
      if (input.session_id !== ctx.session_id) {
        throw new Error(`session_id mismatch: expected ${ctx.session_id}`);
      }
      const report = await generateReport({
        session_id: input.session_id,
        target: input.target,
        goal: input.goal,
        analyst_id: ctx.analyst_id,
        generate_llm_summaries: input.generate_llm_summaries ?? true,
      });
      reportHolder.report = report;
      return report;
    },
    {
      name: "generate_report",
      description:
        "Generate the final IntelReport from collected session evidence. Call once at the end. session_id must match runtime context." +
        TOOL_CONCISE_HINT,
      schema: z.object({
        session_id: z.string(),
        target: z.string(),
        goal: z.string(),
        generate_llm_summaries: z.boolean().optional(),
      }),
    },
  );

  return [shodanTool, tavilyTool, nmapTool, twitterTool, edgarTool, reportTool] as const;
}

function recursionLimitFromEnv(): number {
  const explicit = process.env["OPENROUTER_RECURSION_LIMIT"];
  if (explicit?.trim()) {
    const n = Number(explicit);
    if (Number.isFinite(n) && n > 4) return Math.floor(n);
  }
  const maxSteps = Number(process.env["OPENROUTER_MAX_STEPS"] ?? "16");
  const steps = Number.isFinite(maxSteps) && maxSteps > 0 ? maxSteps : 16;
  // Graph steps exceed model "turns" (tools + agent nodes); keep headroom.
  return Math.min(200, Math.max(40, steps * 8));
}

/**
 * Run the OSINT workflow via OpenRouter (ChatOpenRouter) and Grond FastAPI tools inside a Deep Agent.
 *
 * @param req Same contract as `runOsintOrchestrator` in `osint-orchestrator.ts`.
 * @returns Parsed {@link IntelReport} once the model invokes `generate_report`.
 */
export async function runOpenRouterOsintAgent(req: OrchestratorRequest): Promise<IntelReport> {
  return withSpan("orchestrator.openrouter.run", async () => {
    const modelId = process.env["OPENROUTER_MODEL"]?.trim() || "openrouter/auto";

    const referer = process.env["OPENROUTER_HTTP_REFERER"]?.trim();
    const appTitle = process.env["OPENROUTER_APP_TITLE"]?.trim() ?? "Grond";
    const llm = new ChatOpenRouter({
      model: modelId,
      temperature: 0,
      maxTokens: 8192,
      apiKey: requireApiKey(),
      ...(referer ? { siteUrl: referer } : {}),
      siteName: appTitle,
    });

    const reportHolder: { report: IntelReport | null } = { report: null };
    const tools = [...grondTools(reportHolder)];

    const agent = createDeepAgent({
      model: llm,
      tools,
      systemPrompt: buildSystemPrompt(req),
      contextSchema: osintRuntimeContextSchema,
    });

    const dwmHint =
      goalSuggestsDwmMarketplaceOsint(req.goal) ?
        `\nSuggested clearnet Tavily seeds (OSINT Dojo DWM–style):\n${buildTavilyQueries(req.target, "dwm").map((q) => `- ${q}`).join("\n")}\n`
      : "";
    const userContent =
      `Target: ${req.target}\n` +
      `Goal: ${req.goal}\n` +
      `Session ID: ${req.session_id}\n` +
      `Analyst ID: ${req.analyst_id}\n` +
      `Investigation profile: ${req.investigation_profile ?? "general"}\n` +
      (req.tavily_time_range ? `Tavily time_range: ${req.tavily_time_range}\n` : "") +
      `Active scan authorized: ${req.allow_active_scan ? "YES" : "NO"}\n` +
      (req.authorization_ref ? `Authorization ref: ${req.authorization_ref}\n` : "") +
      dwmHint +
      "\nPlan and execute passive collection, then call generate_report to finalize.";

    await agent.invoke(
      { messages: [{ role: "user", content: userContent }] },
      {
        recursionLimit: recursionLimitFromEnv(),
        configurable: { thread_id: req.session_id },
        context: {
          analyst_id: req.analyst_id,
          session_id: req.session_id,
          target: req.target,
          goal: req.goal,
          allow_active_scan: req.allow_active_scan ?? false,
          investigation_profile: req.investigation_profile ?? "general",
          ...(req.tavily_time_range !== undefined ? { tavily_time_range: req.tavily_time_range } : {}),
          ...(req.authorization_ref !== undefined && req.authorization_ref !== ""
            ? { authorization_ref: req.authorization_ref }
            : {}),
        },
      },
    );

    if (!reportHolder.report) {
      throw new Error("OpenRouter orchestrator completed without generate_report");
    }

    return reportHolder.report;
  });
}
