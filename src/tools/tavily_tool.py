"""
Tavily web intelligence adapter.

Wraps the Tavily search + extract API.  Produces `ClaimType.WEB_MENTION`,
`ClaimType.COMPANY_INFO`, `ClaimType.SOCIAL_PROFILE`, and
`ClaimType.TECH_STACK` Evidence items.

The installed **tavily-python** client exposes ``TavilyClient.search`` (with
``topic``, ``time_range``, date bounds) but **not** a separate
``search_social_media`` helper. Public “social” coverage is implemented as
**site-scoped** queries plus ``topic=\"general\"`` where appropriate — indexed
public pages only; do not use Grond to bypass platform ToS or enumerate private
profiles.

Each Tavily search result becomes exactly one Evidence item.  Callers
compose multiple queries via the pipeline collector — this adapter does
not fan out internally.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from pydantic import BaseModel, Field, field_validator

from src.core.audit import AuditLogger
from src.core.config import get_settings
from src.core.exceptions import (
    ToolAuthError,
    ToolExecutionError,
    ToolRateLimitError,
)
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTool
from src.tools.base import ToolAdapter

log = structlog.get_logger("grond.tools.tavily")

TAVILY_SEARCH_ENDPOINT = "https://api.tavily.com/search"
TAVILY_EXTRACT_ENDPOINT = "https://api.tavily.com/extract"

# Query templates used by the collection layer.  Kept here so callers
# can import and reuse them without duplicating string logic.
COMPANY_INTEL_QUERIES = [
    "{target} leadership team executives management",
    "{target} technology stack infrastructure cloud",
    "{target} recent news funding acquisition breach",
    "{target} job postings engineering security",
    "{target} data breach security incident leak",
]

SOCIAL_INTEL_QUERIES = [
    '"{target}" site:linkedin.com',
    '"{target}" site:twitter.com OR site:x.com',
    '"{target}" github.com profile',
    '"{target}" email address contact',
]

# Indexed public-discourse templates (Tavily ``search`` + site: filters). Tavily Python
# SDK (0.5+) does **not** expose a dedicated ``search_social_media`` — these are
# best-effort WEBINT for publicly indexed pages only; do not target non-public profiles.
PUBLIC_SOCIAL_TAVILY_QUERIES = [
    '"{target}" site:reddit.com',
    '"{target}" (site:x.com OR site:twitter.com)',
    '"{target}" site:tiktok.com',
    '"{target}" site:instagram.com',
    '"{target}" site:youtube.com',
    '"{target}" site:news.ycombinator.com',
    '"{target}" site:linkedin.com',
]

InvestigationProfile = Literal["general", "company", "social"]
SocialPlatform = Literal[
    "reddit",
    "x",
    "twitter",
    "tiktok",
    "instagram",
    "youtube",
    "linkedin",
    "hackernews",
]

# fragment after quoted term, e.g. ``"Acme" site:reddit.com``
SOCIAL_PLATFORM_SCOPE: dict[str, str] = {
    "reddit": "site:reddit.com",
    "x": "(site:x.com OR site:twitter.com)",
    "twitter": "(site:x.com OR site:twitter.com)",
    "tiktok": "site:tiktok.com",
    "instagram": "site:instagram.com",
    "youtube": "site:youtube.com",
    "linkedin": "site:linkedin.com",
    "hackernews": "site:news.ycombinator.com",
}


def build_public_social_tavily_queries(target: str) -> list[str]:
    """Return site-scoped queries for parallel Tavily runs (public indexed content only)."""
    return [t.format(target=target) for t in PUBLIC_SOCIAL_TAVILY_QUERIES]


# ---------------------------------------------------------------------------
# Typed input
# ---------------------------------------------------------------------------


class TavilyInput(BaseModel):
    target: str  # investigation subject (company, domain, person, hashtag, …)
    query: str  # the exact search string to issue
    claim_type: ClaimType = ClaimType.WEB_MENTION
    analyst_id: str
    session_id: str
    search_depth: str = Field(default="advanced", pattern="^(basic|advanced)$")
    max_results: int = Field(default=10, ge=1, le=20)
    investigation_profile: InvestigationProfile = "general"
    platform: SocialPlatform | None = None
    topic: Literal["general", "news", "finance"] | None = None
    time_range: Literal["day", "week", "month", "year"] | None = None
    start_date: str | None = Field(default=None, description="YYYY-MM-DD when using a date window")
    end_date: str | None = Field(default=None, description="YYYY-MM-DD when using a date window")

    @field_validator("query")
    @classmethod
    def strip_query(cls, v: str) -> str:
        return v.strip()

    @field_validator("start_date", "end_date")
    @classmethod
    def strip_dates(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        return s if s else None


class TavilyExtractInput(BaseModel):
    """
    Input for Tavily Extract — clean markdown/text from one or many URLs
    (batch up to 20). Optional ``focus_query`` enables chunk reranking.
    """

    target: str = Field(..., description="Investigation context / entity label")
    urls: list[str] = Field(..., min_length=1, max_length=20)
    query: str = Field(
        default="",
        description="Audit / trace label for this call (optional).",
    )
    analyst_id: str
    session_id: str
    claim_type: ClaimType = ClaimType.WEB_MENTION
    extract_depth: Literal["basic", "advanced"] = "advanced"
    format: Literal["markdown", "text"] = "markdown"
    include_images: bool = False
    focus_query: str | None = Field(
        default=None,
        description="When set, Tavily reranks chunks for relevance (maps to Extract `query`).",
    )
    chunks_per_source: int | None = Field(default=None, ge=1, le=5)


class TavilyExtractFailed(BaseModel):
    url: str
    error: str


class TavilyExtractOutput(BaseModel):
    evidence: list[Evidence]
    failed_results: list[TavilyExtractFailed] = Field(default_factory=list)
    error: str | None = None


class TavilySearchOutput(BaseModel):
    evidence: list[Evidence]
    error: str | None = None


def resolve_tavily_search_query(inp: TavilyInput) -> str:
    """Apply optional ``platform`` scoping for ``investigation_profile=\"social\"``."""
    if inp.investigation_profile == "social" and inp.platform:
        spec = SOCIAL_PLATFORM_SCOPE.get(inp.platform)
        if spec:
            term = inp.target.strip() or inp.query
            if term:
                return f'"{term}" {spec}'
    return inp.query


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class TavilyAdapter(ToolAdapter[TavilyInput]):
    """
    WEBINT via Tavily search API.

    Uses `search_depth="advanced"` by default — returns richer snippets
    suitable for OSINT analysis.
    """

    tool_name = SourceTool.TAVILY

    def __init__(self, audit: AuditLogger, api_key: str | None = None) -> None:
        super().__init__(audit=audit, rate_limiter=None)  # Tavily has generous limits
        settings = get_settings()
        self._api_key = api_key or settings.tavily_api_key

    async def _execute(self, input: TavilyInput) -> list[Evidence]:
        try:
            from tavily import TavilyClient  # type: ignore[import]
        except ImportError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="tavily-python not installed — run: pip install tavily-python",
                cause=exc,
            ) from exc

        try:
            client = TavilyClient(api_key=self._api_key)
            q = resolve_tavily_search_query(input)
            search_kwargs: dict[str, Any] = {
                "query": q,
                "search_depth": input.search_depth,
                "max_results": input.max_results,
                "include_answer": False,
                "include_raw_content": False,
            }
            if input.topic is not None:
                search_kwargs["topic"] = input.topic
            elif input.investigation_profile == "social":
                search_kwargs["topic"] = "general"
            if input.time_range is not None:
                search_kwargs["time_range"] = input.time_range
            if input.start_date:
                search_kwargs["start_date"] = input.start_date
            if input.end_date:
                search_kwargs["end_date"] = input.end_date
            raw: dict[str, Any] = client.search(**search_kwargs)
        except Exception as exc:
            msg = str(exc).lower()
            if "401" in msg or "unauthorized" in msg:
                raise ToolAuthError(tool=self.tool_name, message="Invalid Tavily API key") from exc
            if "429" in msg or "rate" in msg:
                raise ToolRateLimitError(tool=self.tool_name, message="Tavily rate limit") from exc
            raise ToolExecutionError(tool=self.tool_name, message=str(exc), cause=exc) from exc

        settings = get_settings()
        evidence_items: list[Evidence] = []
        collected_at = datetime.now(UTC)

        for result in raw.get("results", []):
            prov = Provenance(
                source_tool=SourceTool.TAVILY,
                collection_query=q,
                api_endpoint=TAVILY_SEARCH_ENDPOINT,
                collected_at=collected_at,
                analyst_id=input.analyst_id,
                session_id=input.session_id,
                raw_response=result,
            )

            url = result.get("url", "")
            title = result.get("title", "")
            content = result.get("content", "")[:800]  # truncate for storage
            relevance = float(result.get("score", 0.5))

            # Scale Tavily's relevance (0–1) against our source weight
            confidence = settings.confidence_weight_tavily * relevance

            claim_type = self._infer_claim_type(url, title, input.claim_type)

            evidence_items.append(
                Evidence(
                    target=input.target,
                    claim=f"{title} — {url}",
                    claim_type=claim_type,
                    value={
                        "url": url,
                        "title": title,
                        "snippet": content,
                        "published_date": result.get("published_date"),
                        "domain": self._extract_domain(url),
                        "search_query": q,
                        "relevance_score": relevance,
                    },
                    provenance=prov,
                    confidence=confidence,
                )
            )

        return evidence_items

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _title_from_raw(raw: str) -> str:
        if not raw or not raw.strip():
            return "Extracted web content"
        first = raw.strip().split("\n", 1)[0].strip()
        if first.startswith("#"):
            return first.lstrip("#").strip()[:400]
        return first[:400]

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            from urllib.parse import urlparse

            return urlparse(url).netloc
        except Exception:
            return ""

    @staticmethod
    def _infer_claim_type(url: str, title: str, default: ClaimType) -> ClaimType:
        url_l = url.lower()
        title_l = title.lower()
        if "linkedin.com" in url_l:
            return ClaimType.SOCIAL_PROFILE
        if "github.com" in url_l:
            return ClaimType.TECH_STACK
        if any(k in title_l for k in ("breach", "leak", "exposure", "credential")):
            return ClaimType.CREDENTIAL_EXPOSURE
        if any(k in title_l for k in ("stack", "technology", "infra", "cloud")):
            return ClaimType.TECH_STACK
        if any(k in title_l for k in ("ceo", "cto", "founder", "executive", "team")):
            return ClaimType.COMPANY_INFO
        return default


# ---------------------------------------------------------------------------
# Extract adapter
# ---------------------------------------------------------------------------


class TavilyExtractAdapter(ToolAdapter[TavilyExtractInput]):
    """WEBINT via Tavily Extract API — clean markdown/text from URLs."""

    tool_name = SourceTool.TAVILY

    def __init__(self, audit: AuditLogger, api_key: str | None = None) -> None:
        super().__init__(audit=audit, rate_limiter=None)
        settings = get_settings()
        self._api_key = api_key or settings.tavily_api_key
        self._last_extract_response: dict[str, Any] | None = None

    async def _execute(self, input: TavilyExtractInput) -> list[Evidence]:
        try:
            from tavily import TavilyClient  # type: ignore[import]
        except ImportError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="tavily-python not installed — run: pip install tavily-python",
                cause=exc,
            ) from exc

        def _call() -> dict[str, Any]:
            client = TavilyClient(api_key=self._api_key)
            return client.extract(
                urls=input.urls,
                include_images=input.include_images,
                extract_depth=input.extract_depth,
                format=input.format,
                query=input.focus_query,
                chunks_per_source=input.chunks_per_source,
            )

        try:
            raw = await asyncio.to_thread(_call)
            self._last_extract_response = raw
        except Exception as exc:
            msg = str(exc).lower()
            if "401" in msg or "unauthorized" in msg:
                raise ToolAuthError(tool=self.tool_name, message="Invalid Tavily API key") from exc
            if "429" in msg or "rate" in msg:
                raise ToolRateLimitError(tool=self.tool_name, message="Tavily rate limit") from exc
            raise ToolExecutionError(tool=self.tool_name, message=str(exc), cause=exc) from exc

        settings = get_settings()
        evidence_items: list[Evidence] = []
        collected_at = datetime.now(UTC)
        coll_q = input.query or f"extract:{len(input.urls)}_urls"

        for result in raw.get("results", []):
            url = str(result.get("url", ""))
            body = str(result.get("raw_content", "") or "")
            title = self._title_from_raw(body)
            snippet = body[:800] if body else ""

            prov = Provenance(
                source_tool=SourceTool.TAVILY,
                collection_query=coll_q,
                api_endpoint=TAVILY_EXTRACT_ENDPOINT,
                collected_at=collected_at,
                analyst_id=input.analyst_id,
                session_id=input.session_id,
                source_url=url or None,
                raw_snippet=snippet or None,
                raw_response=result,
            )

            claim_type = self._infer_claim_type(url, title, input.claim_type)
            relevance = 0.85 if input.focus_query else 0.75
            confidence = settings.confidence_weight_tavily * relevance

            evidence_items.append(
                Evidence(
                    target=input.target,
                    claim=f"{title} — {url}",
                    claim_type=claim_type,
                    value={
                        "url": url,
                        "title": title,
                        "domain": self._extract_domain(url),
                        "extract_depth": input.extract_depth,
                        "content_length": len(body),
                        "focus_query": input.focus_query,
                        "format": input.format,
                    },
                    provenance=prov,
                    confidence=confidence,
                )
            )

        return evidence_items


async def tavily_search_endpoint(
    inp: TavilyInput,
    *,
    audit: AuditLogger,
) -> TavilySearchOutput:
    audit.record(
        "tavily_search_request",
        tool="tavily",
        target=inp.target,
        query=inp.query,
        investigation_profile=inp.investigation_profile,
        platform=inp.platform,
        time_range=inp.time_range,
        topic=inp.topic,
    )
    adapter = TavilyAdapter(audit=audit)
    try:
        evidence = await adapter.run(inp)
        return TavilySearchOutput(evidence=evidence, error=None)
    except ToolExecutionError as exc:
        return TavilySearchOutput(evidence=[], error=str(exc))


async def tavily_extract_endpoint(
    inp: TavilyExtractInput,
    *,
    audit: AuditLogger,
) -> TavilyExtractOutput:
    digest = ",".join(inp.urls[:3])
    if len(inp.urls) > 3:
        digest += f",+{len(inp.urls) - 3}"
    lab = inp.query.strip() or f"extract:{digest}"
    inp = inp.model_copy(update={"query": lab})

    adapter = TavilyExtractAdapter(audit=audit)
    try:
        evidence = await adapter.run(inp)
    except ToolExecutionError as exc:
        return TavilyExtractOutput(evidence=[], failed_results=[], error=str(exc))

    raw = adapter._last_extract_response or {}
    failed = [
        TavilyExtractFailed(url=str(fr.get("url", "")), error=str(fr.get("error", "")))
        for fr in raw.get("failed_results", [])
    ]
    return TavilyExtractOutput(evidence=evidence, failed_results=failed, error=None)
