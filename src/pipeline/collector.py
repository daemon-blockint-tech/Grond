"""
Collection stage.

Runs all applicable tool adapters concurrently and aggregates their Evidence
output.  A partial failure in one tool does NOT abort the collection — the
stage continues and records which tools failed.

Design principle: collection is purely mechanical.  No interpretation, no
deduplication, no scoring changes happen here.  Raw Evidence flows out exactly
as the adapters produced it.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Literal

import structlog

from src.core.audit import AuditEvent, AuditLogger
from src.core.authorization import AuthorizationService
from src.models.evidence import Evidence
from src.pipeline.domain_relevance import build_tavily_queries_for_target
from src.tools.nmap_tool import NmapAdapter, NmapInput, ScanProfile
from src.tools.shodan_tool import ShodanAdapter, ShodanInput
from src.tools.tavily_tool import TavilyAdapter, TavilyInput, build_public_social_tavily_queries

log = structlog.get_logger("grond.pipeline.collector")

InvestigationProfile = Literal["general", "company", "social"]
TavilyTimeRange = Literal["day", "week", "month", "year"]


def goal_suggests_public_social(goal: str) -> bool:
    """Heuristic: expand Tavily with public site-scoped social queries."""
    g = goal.lower()
    needles = (
        "social",
        "reddit",
        "twitter",
        "tiktok",
        "instagram",
        "youtube",
        " x.com",
        "x.com",
        "hashtag",
        "#",
        "sentiment",
        "community",
        "discourse",
        "mastodon",
        "threads",
        "subreddit",
        "tik tok",
    )
    return any(n in g for n in needles)


# ---------------------------------------------------------------------------
# Collection request
# ---------------------------------------------------------------------------


@dataclass
class CollectionRequest:
    target: str
    goal: str
    analyst_id: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_profile: InvestigationProfile = "general"
    tavily_time_range: TavilyTimeRange | None = None

    # Which passive tools to run (always safe)
    run_shodan: bool = True
    shodan_query: str = ""  # if blank, auto-built from target

    run_tavily: bool = True
    tavily_query_templates: list[str] = field(default_factory=list)

    # Active tools — only run when authorization_confirmed
    run_nmap: bool = False
    nmap_profile: ScanProfile = ScanProfile.STANDARD

    def effective_shodan_query(self) -> str:
        return self.shodan_query or f"hostname:{self.target} OR ip:{self.target}"

    def effective_tavily_queries(self) -> list[str]:
        if self.tavily_query_templates:
            return [t.format(target=self.target) for t in self.tavily_query_templates]
        base = build_tavily_queries_for_target(self.target)
        want_social = self.investigation_profile == "social" or (
            self.investigation_profile == "general" and goal_suggests_public_social(self.goal)
        )
        if want_social:
            return base + build_public_social_tavily_queries(self.target)
        return base

    def tavily_topic_for_pipeline(self) -> str | None:
        if self.investigation_profile == "social":
            return "general"
        if self.investigation_profile == "general" and goal_suggests_public_social(self.goal):
            return "general"
        return None


@dataclass
class CollectionResult:
    session_id: str
    target: str
    evidence: list[Evidence]
    tool_errors: dict[str, str]  # tool_name → error message
    tools_run: list[str]

    @property
    def partial_failure(self) -> bool:
        return bool(self.tool_errors)

    @property
    def total(self) -> int:
        return len(self.evidence)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class Collector:
    def __init__(
        self,
        audit: AuditLogger,
        auth_service: AuthorizationService | None = None,
        shodan_api_key: str | None = None,
        tavily_api_key: str | None = None,
    ) -> None:
        self._audit = audit
        self._auth = auth_service or AuthorizationService()
        self._shodan = ShodanAdapter(audit=audit, api_key=shodan_api_key)
        self._tavily = TavilyAdapter(audit=audit, api_key=tavily_api_key)
        self._nmap = NmapAdapter(audit=audit, auth_service=self._auth)

    async def collect(self, req: CollectionRequest) -> CollectionResult:
        self._audit.record(
            AuditEvent.PIPELINE_START,
            target=req.target,
            goal=req.goal,
            session_id=req.session_id,
        )

        tasks: list[asyncio.Task[list[Evidence]]] = []
        task_names: list[str] = []

        if req.run_shodan:
            tasks.append(asyncio.create_task(self._run_shodan(req)))
            task_names.append("shodan")

        if req.run_tavily:
            tasks.append(asyncio.create_task(self._run_tavily(req)))
            task_names.append("tavily")

        if req.run_nmap:
            tasks.append(asyncio.create_task(self._run_nmap(req)))
            task_names.append("nmap")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_evidence: list[Evidence] = []
        errors: dict[str, str] = {}

        for name, result in zip(task_names, results, strict=True):
            if isinstance(result, Exception):
                errors[name] = str(result)
                log.warning("collector tool failed", tool=name, error=str(result))
            else:
                all_evidence.extend(result)

        self._audit.record(
            AuditEvent.COLLECTION_COMPLETE,
            target=req.target,
            result_count=len(all_evidence),
            errors=errors or None,
        )

        return CollectionResult(
            session_id=req.session_id,
            target=req.target,
            evidence=all_evidence,
            tool_errors=errors,
            tools_run=[n for n in task_names if n not in errors],
        )

    # ------------------------------------------------------------------
    # Per-tool runners — isolated so a single tool's exception is caught
    # ------------------------------------------------------------------

    async def _run_shodan(self, req: CollectionRequest) -> list[Evidence]:
        inp = ShodanInput(
            target=req.target,
            query=req.effective_shodan_query(),
            analyst_id=req.analyst_id,
            session_id=req.session_id,
        )
        return await self._shodan.run(inp)

    async def _run_tavily(self, req: CollectionRequest) -> list[Evidence]:
        queries = req.effective_tavily_queries()
        topic = req.tavily_topic_for_pipeline()
        subtasks = [
            self._tavily.run(
                TavilyInput(
                    target=req.target,
                    query=q,
                    analyst_id=req.analyst_id,
                    session_id=req.session_id,
                    investigation_profile=req.investigation_profile,
                    topic=topic,
                    time_range=req.tavily_time_range,
                )
            )
            for q in queries
        ]
        nested = await asyncio.gather(*subtasks, return_exceptions=True)
        evidence: list[Evidence] = []
        for item in nested:
            if isinstance(item, list):
                evidence.extend(item)
        return evidence

    async def _run_nmap(self, req: CollectionRequest) -> list[Evidence]:
        inp = NmapInput(
            target=req.target,
            analyst_id=req.analyst_id,
            session_id=req.session_id,
            profile=req.nmap_profile,
        )
        return await self._nmap.run(inp)
