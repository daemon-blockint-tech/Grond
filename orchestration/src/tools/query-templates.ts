/**
 * Reusable query templates for Tavily and Shodan.
 * The orchestrator agent selects from these based on the goal.
 */

export const COMPANY_INTEL_QUERIES = [
  "{target} leadership team executives CEO CTO",
  "{target} technology stack infrastructure cloud provider",
  "{target} recent news funding acquisition merger",
  "{target} data breach security incident leak exposure",
  "{target} job postings engineering security operations",
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

export function buildTavilyQueries(
  target: string,
  mode: "company" | "social" | "general" | "full" | "dwm",
): string[] {
  let templates: string[];
  if (mode === "company") {
    templates = COMPANY_INTEL_QUERIES;
  } else if (mode === "social") {
    templates = PUBLIC_SOCIAL_TAVILY_QUERIES;
  } else if (mode === "dwm") {
    templates = DARK_WEB_MARKETPLACE_INTEL_QUERIES;
  } else if (mode === "general") {
    templates = [...COMPANY_INTEL_QUERIES];
  } else {
    templates = [...COMPANY_INTEL_QUERIES, ...PUBLIC_SOCIAL_TAVILY_QUERIES];
  }
  return templates.map((t) => t.replace(/\{target\}/g, target));
}

/** True when the analyst goal suggests dark-web–marketplace style clearnet OSINT (DWM seeds). */
export function goalSuggestsDwmMarketplaceOsint(goal: string): boolean {
  return /\b(dark\s*web|darknet|dwm\b|tor\s+market|onion\s+market|cryptomarket|crypto\s+market|marketplace\s+vendor|ransomware\s+(market|forum|gang))\b/i.test(
    goal,
  );
}
