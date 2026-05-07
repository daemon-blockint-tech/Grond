/**
 * Shared TypeScript types mirroring the Python Pydantic models.
 * Used by tool call inputs/outputs so the TS layer never works with `any`.
 */

import { z } from "zod/v3";

export const ClaimTypeSchema = z.enum([
  "open_port",
  "service_banner",
  "vulnerability",
  "hostname",
  "asn",
  "geolocation",
  "web_mention",
  "social_profile",
  "company_info",
  "credential_exposure",
  "certificate",
  "dns_record",
  "whois",
  "tech_stack",
  "social_post",
  "hashtag_activity",
  "account_network",
  "media_mention",
  "subdomain",
  "email_discovery",
  "host_discovery",
  "file_metadata",
]);
export type ClaimType = z.infer<typeof ClaimTypeSchema>;

export const SourceToolSchema = z.enum([
  "shodan",
  "nmap",
  "ncrack",
  "tavily",
  "twitter",
  "theharvester",
  "osintmap",
  "edgar",
  "exiftool",
  "exiv2",
  "manual",
]);
export type SourceTool = z.infer<typeof SourceToolSchema>;

export const ProvenanceSchema = z.object({
  source_tool: SourceToolSchema,
  collection_query: z.string(),
  api_endpoint: z.string().nullable(),
  collected_at: z.string(), // ISO 8601
  analyst_id: z.string(),
  session_id: z.string(),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

export const EvidenceSchema = z.object({
  id: z.string().uuid(),
  target: z.string(),
  claim: z.string(),
  claim_type: ClaimTypeSchema,
  value: z.record(z.unknown()),
  provenance: ProvenanceSchema,
  confidence: z.number().min(0).max(1),
  verified: z.boolean(),
  verified_by: z.array(SourceToolSchema),
  verification_note: z.string().nullable(),
  enrichments: z.record(z.unknown()),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const RiskLevelSchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "informational",
]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const IntelReportSchema = z.object({
  id: z.string().uuid(),
  generated_at: z.string(),
  target: z.string(),
  goal: z.string(),
  analyst_id: z.string(),
  session_id: z.string(),
  overall_risk: RiskLevelSchema,
  avg_confidence: z.number(),
  total_evidence_items: z.number(),
  corroborated_findings: z.number(),
  sources_used: z.array(SourceToolSchema),
  executive_summary: z.string(),
  sections: z.array(z.object({
    heading: z.string(),
    summary: z.string(),
    findings: z.array(z.object({
      id: z.string(),
      title: z.string(),
      risk_level: RiskLevelSchema,
      confidence: z.number(),
      corroborated: z.boolean(),
      analyst_status: z.enum(["pending", "confirmed", "disputed", "stale"]),
    })),
  })),
  disclaimer: z.string(),
});
export type IntelReport = z.infer<typeof IntelReportSchema>;
