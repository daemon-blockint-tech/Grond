"""
GraphIndexer — writes Evidence items into Neo4j as a structured entity graph.

Called by the pipeline reporter after evidence has been verified and scored.
All MERGE operations are idempotent; re-indexing the same evidence is safe.
"""

from __future__ import annotations

import structlog

from src.models.evidence import ClaimType, Evidence
from .client import GraphClient

log = structlog.get_logger(__name__)


class GraphIndexer:
    def __init__(self, client: GraphClient) -> None:
        self._client = client

    async def index_batch(self, evidence: list[Evidence], target: str) -> None:
        """Index a verified evidence batch for a given target."""
        log.info("graph.index_batch.start", target=target, count=len(evidence))
        # Ensure target node exists
        await self._client.run_write(
            "MERGE (t:Target {name: $name}) SET t.updated = timestamp()",
            name=target,
        )
        for ev in evidence:
            try:
                await self._index_one(ev, target)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "graph.index_one.error",
                    evidence_id=str(ev.id),
                    claim_type=ev.claim_type,
                    error=str(exc),
                )
        log.info("graph.index_batch.done", target=target)

    async def _index_one(self, ev: Evidence, target: str) -> None:
        v = ev.value
        match ev.claim_type:
            case ClaimType.OPEN_PORT:
                await self._client.run_write(
                    """
                    MERGE (ip:IPAddress {ip: $ip})
                    MERGE (port:Port {number: $port, protocol: $proto})
                    MERGE (ip)-[:EXPOSED_ON]->(port)
                    SET ip.updated = timestamp(), port.confidence = $confidence
                    """,
                    ip=str(v.get("ip", target)),
                    port=int(v.get("port", 0)),
                    proto=str(v.get("protocol", "tcp")),
                    confidence=float(ev.confidence),
                )

            case ClaimType.SERVICE_BANNER:
                await self._client.run_write(
                    """
                    MERGE (port:Port {number: $port, protocol: $proto})
                    MERGE (svc:Service {product: $product, version: $version})
                    MERGE (port)-[:RUNS]->(svc)
                    """,
                    port=int(v.get("port", 0)),
                    proto=str(v.get("protocol", "tcp")),
                    product=str(v.get("product", "unknown")),
                    version=str(v.get("version", "")),
                )

            case ClaimType.VULNERABILITY:
                enrichments = ev.enrichments.get("nvd", {})
                await self._client.run_write(
                    """
                    MERGE (cve:CVE {id: $cve_id})
                    SET cve.cvss = $cvss, cve.severity = $severity
                    MERGE (port:Port {number: $port, protocol: $proto})
                    MERGE (port)-[:AFFECTED_BY]->(cve)
                    """,
                    cve_id=str(v.get("cve_id", "")),
                    cvss=float(enrichments.get("cvss3_score", 0.0) or 0.0),
                    severity=str(enrichments.get("cvss3_severity", "unknown")),
                    port=int(v.get("port", 0)),
                    proto=str(v.get("protocol", "tcp")),
                )

            case ClaimType.WEB_MENTION | ClaimType.COMPANY_INFO:
                await self._client.run_write(
                    """
                    MERGE (t:Target {name: $target})
                    MERGE (w:WebMention {url: $url})
                    SET w.title = $title, w.confidence = $confidence
                    MERGE (t)-[:MENTIONED_IN]->(w)
                    """,
                    target=target,
                    url=str(v.get("url", "")),
                    title=str(v.get("title", "")),
                    confidence=float(ev.confidence),
                )

            case ClaimType.SOCIAL_PROFILE:
                await self._client.run_write(
                    """
                    MERGE (t:Target {name: $target})
                    MERGE (sp:SocialProfile {url: $url, platform: $platform})
                    SET sp.username = $username
                    MERGE (t)-[:HAS_PROFILE]->(sp)
                    """,
                    target=target,
                    url=str(v.get("url", "")),
                    platform=str(v.get("platform", "unknown")),
                    username=str(v.get("username", "")),
                )

            case _:
                # Unhandled claim type — log but don't fail
                log.debug(
                    "graph.index_one.skip",
                    claim_type=ev.claim_type,
                    evidence_id=str(ev.id),
                )

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    async def get_exposure_summary(self, ip: str) -> list[dict]:
        """Return all CVEs reachable from an IP address."""
        return await self._client.run(
            """
            MATCH (ip:IPAddress {ip: $ip})-[:EXPOSED_ON]->(port:Port)-[:AFFECTED_BY]->(cve:CVE)
            RETURN port.number AS port, port.protocol AS protocol,
                   cve.id AS cve_id, cve.cvss AS cvss, cve.severity AS severity
            ORDER BY cve.cvss DESC
            """,
            ip=ip,
        )

    async def get_related_targets(self, cve_id: str, limit: int = 20) -> list[str]:
        """Find other targets exposed to the same CVE."""
        rows = await self._client.run(
            """
            MATCH (t:Target)-[:RESOLVES_TO]->(ip:IPAddress)
                  -[:EXPOSED_ON]->(port:Port)-[:AFFECTED_BY]->(cve:CVE {id: $cve_id})
            RETURN DISTINCT t.name AS target LIMIT $limit
            """,
            cve_id=cve_id,
            limit=limit,
        )
        return [r["target"] for r in rows]
