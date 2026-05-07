"""
OSINTMap adapter — cipher387 worldwide curated public OSINT links.

Fetches the project README (markdown table) from GitHub raw; parses ``country | links`` rows;
returns ``WEB_MENTION`` evidence per matched region. Passive HTTP only.

Upstream: https://github.com/cipher387/osintmap
Live map: https://cybdetective.com/osintmap/
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field, model_validator

from src.core.audit import AuditLogger
from src.core.config import get_settings
from src.core.exceptions import ToolExecutionError
from src.models.evidence import (
    TOOL_DEFAULT_TIER,
    ClaimType,
    Evidence,
    Provenance,
    SourceTool,
)
from src.tools.base import ToolAdapter

log = structlog.get_logger("grond.tools.osintmap")

_OSINTMAP_CATALOG = "https://cybdetective.com/osintmap/"
_OSINTMAP_REPO = "https://github.com/cipher387/osintmap"
_ROW_RE = re.compile(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|$")
_ANCHOR_RE = re.compile(
    r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)


class OsintmapInput(BaseModel):
    """Lookup regional entries in the OSINTMap README table."""

    target: str = Field(..., min_length=1, description="Investigation / case label")
    query: str = Field(
        default="",
        description="Audit log line — defaults to region_query when empty",
    )
    region_query: str = Field(
        ...,
        min_length=2,
        max_length=120,
        description=(
            "Country, state, or region substring; case-insensitive match on table row label"
        ),
    )
    analyst_id: str
    session_id: str
    max_rows: int = Field(default=8, ge=1, le=50)
    max_links_per_row: int = Field(default=40, ge=1, le=150)

    @model_validator(mode="after")
    def _default_query_for_audit(self) -> OsintmapInput:
        if self.query.strip():
            return self
        return self.model_copy(update={"query": self.region_query})


class OsintmapOutput(BaseModel):
    evidence: list[Evidence]
    error: str | None = None


def _strip_html_fragment(html: str, max_len: int = 500) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len]


def _extract_anchor_links(links_cell: str, limit: int) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for m in _ANCHOR_RE.finditer(links_cell):
        url = (m.group(1) or "").strip()
        if not url:
            continue
        label_raw = m.group(2) or ""
        label = _strip_html_fragment(label_raw, 300) or url
        out.append({"url": url, "label": label})
        if len(out) >= limit:
            break
    return out


def _iter_readme_rows(markdown: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in markdown.splitlines():
        line = line.strip()
        m = _ROW_RE.match(line)
        if not m:
            continue
        country = m.group(1).strip()
        links_cell = m.group(2).strip()
        cl = country.casefold()
        bad_cell = links_cell.startswith("---")
        if cl in ("country", "---", "") or country.startswith("---") or bad_cell:
            continue
        rows.append((country, links_cell))
    return rows


def _matching_rows(
    markdown: str,
    region_query: str,
    max_rows: int,
) -> list[tuple[str, str]]:
    needle = region_query.casefold().strip()
    matches: list[tuple[str, str]] = []
    for country, links_cell in _iter_readme_rows(markdown):
        if needle not in country.casefold():
            continue
        matches.append((country, links_cell))
        if len(matches) >= max_rows:
            break
    return matches


class OsintmapAdapter(ToolAdapter[OsintmapInput]):
    """Fetch OSINTMap README and emit one Evidence per matched table row."""

    tool_name = SourceTool.OSINTMAP

    def __init__(self, audit: AuditLogger) -> None:
        super().__init__(audit=audit, rate_limiter=None)

    async def _execute(self, inp: OsintmapInput) -> list[Evidence]:
        settings = get_settings()
        readme_url = settings.osintmap_readme_url
        timeout = httpx.Timeout(45.0, connect=10.0)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(readme_url, headers={"User-Agent": "Grond-OSINT/1.0"})
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"OSINTMap README HTTP {exc.response.status_code}",
                cause=exc,
            ) from exc
        except httpx.HTTPError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message=f"OSINTMap README fetch failed: {exc}",
                cause=exc,
            ) from exc

        markdown = resp.text
        pairs = _matching_rows(markdown, inp.region_query, inp.max_rows)
        if not pairs:
            log.info("osintmap.no_matches", region=inp.region_query)
            return []

        collected_at = datetime.now(UTC)
        tier = TOOL_DEFAULT_TIER[SourceTool.OSINTMAP]
        base_confidence = settings.confidence_weight_osintmap
        evidence_items: list[Evidence] = []

        for country, links_cell in pairs:
            resource_links = _extract_anchor_links(links_cell, inp.max_links_per_row)
            primary_url = resource_links[0]["url"] if resource_links else _OSINTMAP_CATALOG
            title = f"OSINTMap — {country}"
            snippet = _strip_html_fragment(links_cell, 500)
            raw_response: dict[str, Any] = {
                "country": country,
                "resource_links": resource_links,
                "links_cell_html": links_cell[:4000],
            }
            prov = Provenance(
                source_tool=SourceTool.OSINTMAP,
                source_tier=tier,
                source_url=primary_url,
                raw_snippet=snippet or None,
                extractor="osintmap.readme_table_row",
                collection_query=inp.region_query,
                api_endpoint=readme_url,
                collected_at=collected_at,
                analyst_id=inp.analyst_id,
                session_id=inp.session_id,
                raw_response=raw_response,
            )
            n_links = len(resource_links)
            claim = (
                f"OSINTMap registry row «{country}» — {n_links} linked public resource(s) "
                f"(curated catalog; verify each destination before use)"
            )
            evidence_items.append(
                Evidence(
                    target=inp.target,
                    claim=claim,
                    claim_type=ClaimType.WEB_MENTION,
                    value={
                        "url": primary_url,
                        "title": title,
                        "country": country,
                        "resource_links": resource_links,
                        "catalog_url": _OSINTMAP_CATALOG,
                        "repository_url": _OSINTMAP_REPO,
                        "attribution": "cipher387/osintmap via cybdetective.com",
                    },
                    provenance=prov,
                    confidence=base_confidence if resource_links else base_confidence * 0.85,
                )
            )

        return evidence_items


async def osintmap_search_endpoint(
    inp: OsintmapInput,
    *,
    audit: AuditLogger,
) -> OsintmapOutput:
    adapter = OsintmapAdapter(audit=audit)
    try:
        evidence = await adapter.run(inp)
        return OsintmapOutput(evidence=evidence, error=None)
    except ToolExecutionError as exc:
        return OsintmapOutput(evidence=[], error=str(exc))
