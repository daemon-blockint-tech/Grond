"""
Shodan tool adapter.

Wraps the `shadowscatcher/shodan` client against the official REST API
(`https://api.shodan.io`). Machine-readable contract:
https://developer.shodan.io/api/openapi.json

Each matching host record becomes a separate Evidence object — one per
(IP, port) pair — so the verification layer can cross-check individual claims
rather than whole hosts.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from pydantic import BaseModel, Field

from src.core.audit import AuditLogger
from src.core.config import get_settings
from src.core.exceptions import ToolAuthError, ToolExecutionError, ToolRateLimitError
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTool
from src.tools.base import RateLimiter, ToolAdapter

log = structlog.get_logger("grond.tools.shodan")

SHODAN_SEARCH_ENDPOINT = "https://api.shodan.io/shodan/host/search"
SHODAN_HOST_ENDPOINT = "https://api.shodan.io/shodan/host/{ip}"


# ---------------------------------------------------------------------------
# Typed input
# ---------------------------------------------------------------------------


class ShodanInput(BaseModel):
    target: str  # query string or bare IP
    query: str  # the full Shodan filter expression
    analyst_id: str
    session_id: str
    max_results: int = Field(default=100, ge=1, le=1000)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class ShodanAdapter(ToolAdapter[ShodanInput]):
    """
    Passive network intelligence via Shodan.

    Produces `ClaimType.OPEN_PORT`, `ClaimType.SERVICE_BANNER`, and
    `ClaimType.VULNERABILITY` Evidence items.
    """

    tool_name = SourceTool.SHODAN

    def __init__(self, audit: AuditLogger, api_key: str | None = None) -> None:
        settings = get_settings()
        rate = RateLimiter(settings.shodan_rate_limit_rps)
        super().__init__(audit=audit, rate_limiter=rate)
        self._api_key = api_key or settings.shodan_api_key

    async def _execute(self, input: ShodanInput) -> list[Evidence]:
        try:
            from shodan import Shodan  # type: ignore[import]
        except ImportError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="shodan library not installed — run: pip install shodan",
                cause=exc,
            ) from exc

        try:
            # The shadowscatcher/shodan library exposes a sync client with
            # async methods via aiohttp under the hood.
            client = Shodan(self._api_key)
            raw: dict[str, Any] = client.search(input.query, limit=input.max_results)
        except Exception as exc:
            msg = str(exc).lower()
            if "401" in msg or "invalid api key" in msg:
                raise ToolAuthError(
                    tool=self.tool_name, message="Invalid Shodan API key"
                ) from exc
            if "429" in msg or "rate limit" in msg:
                raise ToolRateLimitError(
                    tool=self.tool_name, message="Shodan rate limit exceeded"
                ) from exc
            raise ToolExecutionError(
                tool=self.tool_name, message=str(exc), cause=exc
            ) from exc

        evidence_items: list[Evidence] = []
        for match in raw.get("matches", []):
            evidence_items.extend(self._match_to_evidence(match, input))

        return evidence_items

    # ------------------------------------------------------------------
    # Parsing helpers — keep tightly coupled to the Shodan API schema
    # ------------------------------------------------------------------

    def _match_to_evidence(
        self, match: dict[str, Any], input: ShodanInput
    ) -> list[Evidence]:
        items: list[Evidence] = []
        settings = get_settings()
        ip = match.get("ip_str", "")
        port = match.get("port", 0)
        transport = match.get("transport", "tcp")
        collected_at = datetime.now(timezone.utc)

        prov = Provenance(
            source_tool=SourceTool.SHODAN,
            collection_query=input.query,
            api_endpoint=SHODAN_SEARCH_ENDPOINT,
            collected_at=collected_at,
            analyst_id=input.analyst_id,
            session_id=input.session_id,
            raw_response=match,
        )

        # --- open port claim ---
        items.append(
            Evidence(
                target=ip,
                claim=f"Port {port}/{transport} open on {ip}",
                claim_type=ClaimType.OPEN_PORT,
                value={
                    "ip": ip,
                    "port": port,
                    "transport": transport,
                    "org": match.get("org"),
                    "asn": match.get("asn"),
                    "country_code": match.get("location", {}).get("country_code"),
                },
                provenance=prov,
                confidence=settings.confidence_weight_shodan,
            )
        )

        # --- service banner claim (only when banner data present) ---
        product = match.get("product") or match.get("http", {}).get("server")
        if product:
            items.append(
                Evidence(
                    target=ip,
                    claim=f"{product} identified on {ip}:{port}",
                    claim_type=ClaimType.SERVICE_BANNER,
                    value={
                        "ip": ip,
                        "port": port,
                        "product": product,
                        "version": match.get("version"),
                        "cpe": match.get("cpe", []),
                        "banner": match.get("data", "")[:500],  # truncate
                    },
                    provenance=prov,
                    confidence=settings.confidence_weight_shodan,
                )
            )

        # --- vulnerability claims (one per CVE) ---
        for cve_id, cve_data in match.get("vulns", {}).items():
            items.append(
                Evidence(
                    target=ip,
                    claim=f"{cve_id} present on {ip}:{port} ({product or 'unknown service'})",
                    claim_type=ClaimType.VULNERABILITY,
                    value={
                        "ip": ip,
                        "port": port,
                        "cve_id": cve_id,
                        "cvss": cve_data.get("cvss"),
                        "summary": cve_data.get("summary", ""),
                        "verified": cve_data.get("verified", False),
                    },
                    provenance=prov,
                    # Shodan's unverified vuln flags are less reliable
                    confidence=(
                        settings.confidence_weight_shodan
                        if cve_data.get("verified")
                        else settings.confidence_weight_shodan * 0.6
                    ),
                )
            )

        return items
