"""
Enrichment stage.

Augments Evidence items with contextual metadata that was not available at
collection time — CVE details, ASN/GeoIP info, reverse DNS, certificate data.

Design principle: enrichment is additive.  It writes into `evidence.enrichments`
and never modifies `evidence.value`, `evidence.confidence`, or
`evidence.provenance`.  The original claim and citation chain are immutable.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import structlog

from src.core.audit import AuditEvent, AuditLogger
from src.models.evidence import ClaimType, Evidence

log = structlog.get_logger("grond.pipeline.enricher")

# ---------------------------------------------------------------------------
# NVD CVE enrichment (public, no key required for basic use)
# ---------------------------------------------------------------------------

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


async def _fetch_cve_detail(cve_id: str) -> dict[str, Any]:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(NVD_CVE_URL.format(cve_id=cve_id))
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_item = vulns[0].get("cve", {})
                    metrics = cve_item.get("metrics", {})
                    cvss3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    return {
                        "cve_id": cve_id,
                        "description": (
                            cve_item.get("descriptions", [{}])[0].get("value", "")
                        ),
                        "cvss3_score": cvss3.get("baseScore"),
                        "cvss3_severity": cvss3.get("baseSeverity"),
                        "published": cve_item.get("published"),
                        "last_modified": cve_item.get("lastModified"),
                    }
    except Exception as exc:
        log.debug("CVE enrichment failed", cve_id=cve_id, error=str(exc))
    return {}


# ---------------------------------------------------------------------------
# Enrichment stage
# ---------------------------------------------------------------------------


@dataclass
class EnrichmentResult:
    evidence: list[Evidence]
    enriched_count: int
    skipped_count: int


class Enricher:
    """
    Adds metadata to Evidence items in-place (into `evidence.enrichments`).

    Currently enriches:
    - ClaimType.VULNERABILITY → NVD CVE details (CVSS3 score, description)

    More enrichers (GeoIP, ASN, rDNS, certificate CT) can be added as
    additional `_enrich_*` methods following the same pattern.
    """

    def __init__(self, audit: AuditLogger) -> None:
        self._audit = audit

    async def enrich(self, evidence: list[Evidence]) -> EnrichmentResult:
        tasks = [self._enrich_one(ev) for ev in evidence]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched = sum(1 for r in results if r is True)
        skipped = len(results) - enriched

        self._audit.record(
            AuditEvent.ENRICHMENT_COMPLETE,
            enriched_count=enriched,
            skipped_count=skipped,
        )

        return EnrichmentResult(
            evidence=evidence,
            enriched_count=enriched,
            skipped_count=skipped,
        )

    async def _enrich_one(self, ev: Evidence) -> bool:
        """Returns True if any enrichment was applied."""
        if ev.claim_type == ClaimType.VULNERABILITY:
            return await self._enrich_cve(ev)
        return False

    @staticmethod
    async def _enrich_cve(ev: Evidence) -> bool:
        cve_id = ev.value.get("cve_id", "")
        if not cve_id:
            return False
        detail = await _fetch_cve_detail(cve_id)
        if detail:
            ev.enrichments["nvd"] = detail
            # Optionally upgrade confidence for high CVSS
            cvss = detail.get("cvss3_score")
            if isinstance(cvss, float) and cvss >= 9.0:
                ev.enrichments["critical_cve"] = True
            return True
        return False
