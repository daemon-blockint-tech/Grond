/**
 * Reusable query templates for Tavily and Shodan.
 * The orchestrator agent selects from these based on the goal.
 * Extended to NKRI-level deep OSINT standard: affiliations, key persons,
 * intent analysis, financial/legal, leaked docs, geo/infra.
 */

export const COMPANY_INTEL_QUERIES = [
  "{target} leadership team executives CEO CTO",
  "{target} technology stack infrastructure cloud provider",
  "{target} recent news funding acquisition merger",
  "{target} data breach security incident leak exposure",
  "{target} job postings engineering security operations",
];

/** Affiliations, investors, partners, corporate structure */
export const AFFILIATION_QUERIES = [
  "{target} investors backers venture capital funding partners",
  "{target} affiliates subsidiaries parent company corporate structure",
  "{target} board of directors advisors shareholders",
  "{target} strategic partnerships alliances joint venture",
  "{target} contracts government clients customers",
];

/** Key person research — C-level, founders, operators */
export const KEY_PERSON_QUERIES = [
  "{target} CEO founder owner operator background history",
  "{target} CTO CISO security lead engineer",
  "{target} key personnel management team biography",
  '"{target}" executive director "was formerly" OR "previously" OR "prior to"',
  "{target} founder LinkedIn profile social media accounts",
];

/** Intent and operational analysis — what are they doing and why */
export const INTENT_QUERIES = [
  "{target} purpose mission statement objectives goals",
  "{target} strategy expansion plans roadmap",
  "{target} controversies criticism allegations fraud",
  "{target} legal action lawsuit court judgment",
  "{target} sanctions OFAC regulatory action investigation",
];

/** Financial and legal intelligence */
export const FINANCIAL_LEGAL_QUERIES = [
  "{target} financial statements revenue annual report",
  "{target} bankruptcy insolvency debt default",
  "{target} SEC filing 10-K 8-K regulatory disclosure",
  "{target} court case lawsuit indictment criminal",
  "{target} money laundering fraud financial crime",
];

/** Leaked documents and exposed data — Scribd, DocCloud, filetype searches */
export const LEAKED_DOC_QUERIES = [
  '"{target}" site:scribd.com OR site:documentcloud.org',
  '"{target}" filetype:pdf disclosure report leak',
  '"{target}" pastebin hastebin leaked credentials dump',
  '"{target}" (breach OR leak OR dump) (data OR credentials OR emails)',
  '"{target}" site:wikileaks.org OR site:icij.org OR site:ddosecrets.com',
];

/** Geographic and infrastructure intelligence */
export const GEO_INFRASTRUCTURE_QUERIES = [
  "{target} headquarters office location address",
  "{target} registered address country jurisdiction",
  "{target} IP range ASN network infrastructure hosting",
  "{target} CDN hosting provider registrar WHOIS",
];

export const SOCIAL_INTEL_QUERIES = [
  '"{target}" site:linkedin.com',
  '"{target}" site:twitter.com OR site:x.com profile',
  '"{target}" github.com organization repository',
  '"{target}" email address contact public',
];

/** Site-scoped templates for public indexed social/discourse (Tavily ``.Search`` best-effort). */
export const PUBLIC_SOCIAL_TAVILY_QUERIES = [
  '"{target}" site:reddit.com',
  '"{target}" (site:x.com OR site:twitter.com)',
  '"{target}" site:tiktok.com',
  '"{target}" site:instagram.com',
  '"{target}" site:youtube.com',
  '"{target}" site:news.ycombinator.com',
  '"{target}" site:linkedin.com',
];

/**
 * Clearnet / indexed pivots aligned with the
 * [OSINT Dojo DWM attack surface diagram](https://www.osintdojo.com/diagrams/dwm)
 * ([PDF](https://github.com/sinwindie/OSINT/raw/master/DarkWeb/DWM%20OSINT%20Attack%20Surface.pdf)).
 * Use for public reporting, legal filings, blockchain analytics summaries, and researcher write-ups —
 * not for accessing onion services or illicit marketplaces.
 */
export const DARK_WEB_MARKETPLACE_INTEL_QUERIES = [
  '"{target}" (darknet OR "dark web") marketplace (seizure OR seized OR indictment OR arrest OR takedown OR "law enforcement")',
  '"{target}" (bitcoin OR BTC OR monero OR XMR) (marketplace OR ransom OR laundering) (analysis OR report OR tracing OR sanctions OR OFAC)',
  '"{target}" (vendor OR seller OR admin) (PGP OR "pgp key" OR canary OR pastebin) (site:gov OR site:edu OR news OR court)',
  '"{target}" (ransomware OR stealer OR infostealer OR "credential theft") marketplace OR forum (research OR report OR analysis)',
  '"{target}" (Tor OR onion) marketplace OSINT OR investigation',
];

export const SHODAN_TEMPLATES = {
  /** Broad sweep of an organization's exposed attack surface */
  orgSweep: (org: string) => `org:"${org}"`,
  /** All hosts in a CIDR range */
  cidr: (cidr: string) => `net:${cidr}`,
  /** Direct IP lookup */
  ip: (ip: string) => `ip:${ip}`,
  /** Hostname/domain sweep */
  hostname: (domain: string) => `hostname:${domain}`,
  /** Specific product version (e.g. outdated nginx) */
  product: (product: string, version?: string) =>
    version ? `product:"${product}" version:"${version}"` : `product:"${product}"`,
  /** CVE exposed globally */
  cve: (cveId: string) => `vuln:${cveId}`,
  /** Exposed databases */
  exposedDbs: () => "port:3306 OR port:5432 OR port:27017 OR port:6379 OR port:9200",
};

/**
 * Deep OSINT query banks keyed by category (NKRI standard).
 * Use buildDeepOsintQueries() for the full fan-out.
 */
export const DEEP_OSINT_QUERY_BANKS: Record<string, string[]> = {
  company: COMPANY_INTEL_QUERIES,
  affiliations: AFFILIATION_QUERIES,
  key_persons: KEY_PERSON_QUERIES,
  intent: INTENT_QUERIES,
  financial_legal: FINANCIAL_LEGAL_QUERIES,
  leaked_docs: LEAKED_DOC_QUERIES,
  geo_infra: GEO_INFRASTRUCTURE_QUERIES,
};

export function buildTavilyQueries(
  target: string,
  mode: "company" | "social" | "general" | "full" | "dwm" | "deep",
): string[] {
  let templates: string[];
  if (mode === "company") {
    templates = COMPANY_INTEL_QUERIES;
  } else if (mode === "social") {
    templates = PUBLIC_SOCIAL_TAVILY_QUERIES;
  } else if (mode === "dwm") {
    templates = DARK_WEB_MARKETPLACE_INTEL_QUERIES;
  } else if (mode === "deep") {
    // Full NKRI-level fan-out: all banks
    templates = [
      ...COMPANY_INTEL_QUERIES,
      ...AFFILIATION_QUERIES,
      ...KEY_PERSON_QUERIES,
      ...INTENT_QUERIES,
      ...FINANCIAL_LEGAL_QUERIES,
      ...LEAKED_DOC_QUERIES,
      ...GEO_INFRASTRUCTURE_QUERIES,
    ];
  } else if (mode === "general") {
    templates = [...COMPANY_INTEL_QUERIES, ...AFFILIATION_QUERIES, ...KEY_PERSON_QUERIES];
  } else {
    // full
    templates = [
      ...COMPANY_INTEL_QUERIES,
      ...AFFILIATION_QUERIES,
      ...KEY_PERSON_QUERIES,
      ...PUBLIC_SOCIAL_TAVILY_QUERIES,
    ];
  }
  return templates.map((t) => t.replace(/\{target\}/g, target));
}

/**
 * Build a flat list of deep OSINT queries across specific bank keys.
 * Default: company + affiliations + key_persons + intent + financial_legal + geo_infra.
 */
export function buildDeepOsintQueries(
  target: string,
  banks?: string[],
): string[] {
  const defaults = ["company", "affiliations", "key_persons", "intent", "financial_legal", "geo_infra"];
  const selected = banks ?? defaults;
  const out: string[] = [];
  for (const key of selected) {
    const templates = DEEP_OSINT_QUERY_BANKS[key] ?? [];
    out.push(...templates.map((t) => t.replace(/\{target\}/g, target)));
  }
  return out;
}

/** True when the analyst goal suggests dark-web–marketplace style clearnet OSINT (DWM seeds). */
export function goalSuggestsDwmMarketplaceOsint(goal: string): boolean {
  return /\b(dark\s*web|darknet|dwm\b|tor\s+market|onion\s+market|cryptomarket|crypto\s+market|marketplace\s+vendor|ransomware\s+(market|forum|gang))\b/i.test(
    goal,
  );
}
