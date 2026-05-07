/**
 * Neo4j graph client for entity relationship storage.
 *
 * Entity model:
 *   (:Target {name, type})           — the investigation subject
 *   (:IPAddress {ip, asn, country})  — a host
 *   (:Port {number, protocol})       — an open port
 *   (:CVE {id, cvss, severity})      — a vulnerability
 *   (:Domain {name})                 — a domain/hostname
 *   (:Organization {name})           — an org/ASN holder
 *
 * Relationships:
 *   (Target)-[:RESOLVES_TO]->(IPAddress)
 *   (IPAddress)-[:EXPOSED_ON]->(Port)
 *   (Port)-[:RUNS]->(Service {product, version})
 *   (Port)-[:AFFECTED_BY]->(CVE)
 *   (IPAddress)-[:BELONGS_TO]->(Organization)
 *   (Target)-[:MENTIONED_IN]->(WebMention {url, title})
 */

import neo4j, { Driver, Session } from "neo4j-driver";
import type { Evidence } from "../types/evidence.js";

let _driver: Driver | null = null;

export function getDriver(): Driver {
  if (!_driver) {
    const uri = process.env["NEO4J_URI"] ?? "bolt://localhost:7687";
    const user = process.env["NEO4J_USER"] ?? "neo4j";
    const password = process.env["NEO4J_PASSWORD"] ?? "password";
    _driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  }
  return _driver;
}

export async function closeDriver(): Promise<void> {
  if (_driver) {
    await _driver.close();
    _driver = null;
  }
}

function session(): Session {
  return getDriver().session();
}

// ---------------------------------------------------------------------------
// Write operations
// ---------------------------------------------------------------------------

/** Index a batch of Evidence items into the graph. */
export async function indexEvidence(evidence: Evidence[]): Promise<void> {
  const s = session();
  try {
    const tx = s.beginTransaction();
    for (const ev of evidence) {
      await indexOneEvidence(tx, ev);
    }
    await tx.commit();
  } finally {
    await s.close();
  }
}

async function indexOneEvidence(tx: ReturnType<Session["beginTransaction"]>, ev: Evidence) {
  const { claim_type, target, value } = ev;

  if (claim_type === "open_port") {
    await tx.run(
      `MERGE (ip:IPAddress {ip: $ip})
       MERGE (port:Port {number: $port, protocol: $proto})
       MERGE (ip)-[:EXPOSED_ON]->(port)
       SET ip.updated = timestamp(), port.confidence = $confidence`,
      {
        ip: String(value["ip"] ?? target),
        port: value["port"],
        proto: value["protocol"] ?? "tcp",
        confidence: ev.confidence,
      },
    );
  } else if (claim_type === "vulnerability") {
    await tx.run(
      `MERGE (cve:CVE {id: $cveId})
       SET cve.cvss = $cvss, cve.severity = $severity
       MERGE (port:Port {number: $port, protocol: $proto})
       MERGE (port)-[:AFFECTED_BY]->(cve)`,
      {
        cveId: value["cve_id"],
        cvss: value["cvss"] ?? null,
        severity: (ev.enrichments["nvd"] as Record<string, unknown> | undefined)?.["cvss3_severity"] ?? null,
        port: value["port"],
        proto: value["protocol"] ?? "tcp",
      },
    );
  } else if (claim_type === "web_mention" || claim_type === "company_info") {
    await tx.run(
      `MERGE (t:Target {name: $target})
       MERGE (w:WebMention {url: $url})
       SET w.title = $title, w.confidence = $confidence
       MERGE (t)-[:MENTIONED_IN]->(w)`,
      {
        target,
        url: value["url"],
        title: value["title"] ?? "",
        confidence: ev.confidence,
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Read operations
// ---------------------------------------------------------------------------

/** Find all CVEs reachable from a target IP (up to 3 hops). */
export async function findVulnsForTarget(ip: string): Promise<Array<{
  cve: string;
  cvss: number | null;
  port: number;
}>> {
  const s = session();
  try {
    const result = await s.run(
      `MATCH (ip:IPAddress {ip: $ip})-[:EXPOSED_ON]->(port:Port)-[:AFFECTED_BY]->(cve:CVE)
       RETURN cve.id AS cve, cve.cvss AS cvss, port.number AS port
       ORDER BY cve.cvss DESC`,
      { ip },
    );
    return result.records.map((r) => ({
      cve: String(r.get("cve")),
      cvss: r.get("cvss") as number | null,
      port: Number(r.get("port")),
    }));
  } finally {
    await s.close();
  }
}

/** Find organizations sharing the same CVE exposure. */
export async function findRelatedOrgs(cveId: string): Promise<string[]> {
  const s = session();
  try {
    const result = await s.run(
      `MATCH (org:Organization)-[:OWNS]->(ip:IPAddress)-[:EXPOSED_ON]->(:Port)-[:AFFECTED_BY]->(cve:CVE {id: $cveId})
       RETURN DISTINCT org.name AS org`,
      { cveId },
    );
    return result.records.map((r) => String(r.get("org")));
  } finally {
    await s.close();
  }
}
