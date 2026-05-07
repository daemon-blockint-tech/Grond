import { z } from "zod";

/** Mirrors FastAPI `IntelReport` / `src/models/report.py` (snake_case JSON). */

const ReportFindingSchema = z
  .object({
    id: z.string().optional(),
    title: z.string().optional().default("Finding"),
    description: z.string().optional().default(""),
    claim_type: z.string().optional(),
    risk_level: z.string().optional(),
    confidence: z.number().optional(),
    evidence_ids: z.array(z.string()).optional().default([]),
    sources_used: z.array(z.string()).optional().default([]),
    conflict_flag: z.boolean().optional(),
    requires_review: z.boolean().optional(),
  })
  .passthrough();

const ReportSectionSchema = z
  .object({
    heading: z.string().optional().default("Section"),
    summary: z.string().optional().default(""),
    findings: z.array(ReportFindingSchema).optional().default([]),
  })
  .passthrough();

const ProvenanceSchema = z
  .object({
    source_tool: z.string().optional(),
    source_tier: z.string().optional(),
    source_url: z.string().nullable().optional(),
    raw_snippet: z.string().nullable().optional(),
    extractor: z.string().optional(),
    collection_query: z.string().optional(),
    collected_at: z.union([z.string(), z.null()]).optional(),
  })
  .passthrough();

const EvidenceSchema = z
  .object({
    id: z.string().optional(),
    target: z.string().optional(),
    claim: z.string().optional().default(""),
    claim_type: z.string().optional(),
    value: z.record(z.string(), z.unknown()).optional().default({}),
    provenance: ProvenanceSchema.optional(),
  })
  .passthrough();

export const IntelReportSchema = z
  .object({
    id: z.string().optional(),
    session_id: z.string().optional(),
    generated_at: z.union([z.string(), z.null()]).optional(),
    target: z.string().optional(),
    goal: z.string().optional(),
    analyst_id: z.string().optional(),
    overall_risk: z.string().optional(),
    avg_confidence: z.number().optional(),
    total_evidence_items: z.number().optional(),
    corroborated_findings: z.number().optional(),
    conflict_count: z.number().optional(),
    pending_review_count: z.number().optional(),
    sources_used: z.array(z.string()).optional().default([]),
    executive_summary: z.string().optional().default(""),
    key_takeaways: z.array(z.string()).optional().default([]),
    sections: z.array(ReportSectionSchema).optional().default([]),
    conflict_items: z.array(z.unknown()).optional().default([]),
    evidence: z.array(EvidenceSchema).optional().default([]),
    disclaimer: z.string().optional(),
  })
  .passthrough();

export type IntelReport = z.infer<typeof IntelReportSchema>;
export type ReportSection = z.infer<typeof ReportSectionSchema>;
export type ReportFinding = z.infer<typeof ReportFindingSchema>;
export type EvidenceItem = z.infer<typeof EvidenceSchema>;

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function coerceFinding(raw: unknown): ReportFinding {
  const parsed = ReportFindingSchema.safeParse(raw);
  if (parsed.success) return parsed.data;
  const o = asRecord(raw);
  const merged = {
    id: typeof o?.id === "string" ? o.id : undefined,
    title: typeof o?.title === "string" ? o.title : "Finding",
    description: typeof o?.description === "string" ? o.description : "",
    claim_type: typeof o?.claim_type === "string" ? o.claim_type : undefined,
    risk_level: typeof o?.risk_level === "string" ? o.risk_level : undefined,
    confidence: typeof o?.confidence === "number" ? o.confidence : undefined,
    evidence_ids: Array.isArray(o?.evidence_ids)
      ? o.evidence_ids.filter((x): x is string => typeof x === "string")
      : [],
    sources_used: Array.isArray(o?.sources_used)
      ? o.sources_used.filter((x): x is string => typeof x === "string")
      : [],
    conflict_flag: typeof o?.conflict_flag === "boolean" ? o.conflict_flag : undefined,
    requires_review: typeof o?.requires_review === "boolean" ? o.requires_review : undefined,
  };
  const again = ReportFindingSchema.safeParse(merged);
  return again.success ? again.data : ReportFindingSchema.parse(merged);
}

function coerceSection(raw: unknown): ReportSection {
  const o = asRecord(raw);
  const findingsRaw = Array.isArray(o?.findings) ? o.findings : [];
  const findings = findingsRaw.map(coerceFinding);
  const heading = typeof o?.heading === "string" ? o.heading : "Section";
  const summary = typeof o?.summary === "string" ? o.summary : "";
  const merged = { ...o, heading, summary, findings };
  const parsed = ReportSectionSchema.safeParse(merged);
  return parsed.success ? parsed.data : ReportSectionSchema.parse({ heading, summary, findings });
}

function coerceEvidence(raw: unknown): EvidenceItem {
  const parsed = EvidenceSchema.safeParse(raw);
  if (parsed.success) return parsed.data;
  const o = asRecord(raw);
  const prov = asRecord(o?.provenance);
  const merged = {
    id: typeof o?.id === "string" ? o.id : undefined,
    target: typeof o?.target === "string" ? o.target : undefined,
    claim: typeof o?.claim === "string" ? o.claim : "",
    claim_type: typeof o?.claim_type === "string" ? o.claim_type : undefined,
    value: asRecord(o?.value) ?? {},
    provenance: prov ?? undefined,
  };
  const again = EvidenceSchema.safeParse(merged);
  return again.success ? again.data : EvidenceSchema.parse(merged);
}

/** Parse API JSON into `IntelReport`; coerce nested arrays so bad rows never drop the whole report. */
export function parseIntelReport(raw: unknown):
  | { ok: true; data: IntelReport }
  | { ok: false; error: z.ZodError; data: IntelReport } {
  const top = asRecord(raw);
  const preprocessed =
    top === null
      ? {}
      : {
          ...top,
          sections: Array.isArray(top.sections)
            ? top.sections.map(coerceSection)
            : [],
          evidence: Array.isArray(top.evidence)
            ? top.evidence.map(coerceEvidence)
            : [],
          key_takeaways: Array.isArray(top.key_takeaways)
            ? top.key_takeaways.filter((x): x is string => typeof x === "string")
            : [],
          sources_used: Array.isArray(top.sources_used)
            ? top.sources_used.filter((x): x is string => typeof x === "string")
            : [],
          conflict_items: Array.isArray(top.conflict_items) ? top.conflict_items : [],
        };

  const result = IntelReportSchema.safeParse(preprocessed);
  if (result.success) return { ok: true, data: result.data };

  const fallback = IntelReportSchema.safeParse({
    executive_summary:
      top && typeof top.executive_summary === "string" ? top.executive_summary : "",
    target: typeof top?.target === "string" ? top.target : "",
    goal: typeof top?.goal === "string" ? top.goal : "",
    ...(preprocessed as Record<string, unknown>),
  });

  return {
    ok: false,
    error: result.error,
    data: fallback.success ? fallback.data : IntelReportSchema.parse({}),
  };
}

function isHttpUrl(s: string): boolean {
  return /^https?:\/\//i.test(s.trim());
}

export function collectUniqueUrls(report: IntelReport): string[] {
  const set = new Set<string>();
  for (const ev of report.evidence ?? []) {
    const url = ev.provenance?.source_url;
    if (url && isHttpUrl(url)) set.add(url);
    const v = ev.value ?? {};
    for (const key of ["url", "media_url", "evidence_url", "link"]) {
      const u = v[key];
      if (typeof u === "string" && isHttpUrl(u)) set.add(u);
    }
  }
  return [...set];
}

const IMAGE_RE = /\.(png|jpe?g|gif|webp|svg)(\?|$)/i;

export function filterImageUrls(urls: string[]): string[] {
  return urls.filter((u) => IMAGE_RE.test(u) || /pbs\.twimg\.com|i\.imgur\.com/i.test(u));
}

export function countFindings(report: IntelReport): number {
  return (report.sections ?? []).reduce(
    (n, s) => n + (Array.isArray(s.findings) ? s.findings.length : 0),
    0,
  );
}

export function sourceCount(report: IntelReport): number {
  const nUrls = collectUniqueUrls(report).length;
  const nEv = report.evidence?.length ?? 0;
  const header = report.total_evidence_items;
  return Math.max(nUrls, nEv, typeof header === "number" ? header : 0);
}

export function emptyIntelReport(): IntelReport {
  return IntelReportSchema.parse({});
}
