"""
LangGraph orchestrator for the Grond OSINT pipeline.

Graph topology:
  planner → [collect] → enrich → verify → report → END
                ↑
          (HITL interrupt for active scans)

Each node is a thin wrapper that calls a pipeline stage and writes
partial state updates.  Business logic lives in src/pipeline/, not here.
"""
from __future__ import annotations

import uuid
from typing import Literal

import structlog
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import interrupt
from pydantic import BaseModel, Field

from src.core.audit import AuditLogger
from src.core.authorization import AuthorizationService
from src.core.config import get_settings
from src.core.exceptions import (
    ActiveScanApprovalRequiredError,
    PipelineAbortedError,
    PipelineInputError,
)
from src.models.evidence import Evidence
from src.models.report import IntelReport
from src.pipeline import (
    CollectionRequest,
    Collector,
    Enricher,
    Reporter,
    ReporterConfig,
    Verifier,
)
from src.tools.nmap_tool import ScanProfile

log = structlog.get_logger("grond.orchestrator")


def _initial_authorization_confirmed_for_nmap(run_nmap: bool, settings: object) -> bool:
    """
    Synchronous ``POST /api/v1/scan`` cannot resume LangGraph interrupt payloads.

    When ``GROND_DEV_BYPASS_NMAP_HITL`` is true **and** ``ENVIRONMENT=development``,
    pre-approve the graph flag so the planner does not call ``interrupt()``.
    """
    if not run_nmap:
        return False
    bypass = bool(getattr(settings, "grond_dev_bypass_nmap_hitl", False))
    env_name = str(getattr(settings, "environment", ""))
    if bypass and env_name == "development":
        log.warning(
            "dev_nmap_hitl_bypass",
            message=(
                "GROND_DEV_BYPASS_NMAP_HITL: skipping LangGraph active-scan HITL "
                "(development only). Ensure GROND_AUTHORIZED_SCAN_TARGETS or explicit "
                "grants cover require_authorization in Nmap."
            ),
            environment=env_name,
        )
        return True
    if bypass and env_name != "development":
        log.warning(
            "dev_nmap_hitl_bypass_ignored",
            message="GROND_DEV_BYPASS_NMAP_HITL is set but ignored unless ENVIRONMENT=development",
            environment=env_name,
        )
    return False


# ---------------------------------------------------------------------------
# Graph state
# ---------------------------------------------------------------------------


class GrondState(BaseModel):
    """Typed state threaded through all graph nodes."""

    # Input
    target: str
    goal: str
    analyst_id: str
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    investigation_profile: Literal["general", "company", "social"] = "general"
    tavily_time_range: Literal["day", "week", "month", "year"] | None = None

    # Stage outputs (accumulated, not replaced)
    evidence: list[Evidence] = Field(default_factory=list)
    report: IntelReport | None = None

    # Control flags
    run_nmap: bool = False
    nmap_profile: ScanProfile = ScanProfile.STANDARD
    authorization_confirmed: bool = False

    # Error tracking per stage
    stage_errors: dict[str, str] = Field(default_factory=dict)

    # Pipeline progress bookkeeping
    completed_stages: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Node factories
# ---------------------------------------------------------------------------


def make_planner_node() -> object:
    """
    Planner node: validate inputs and decide whether active scans are needed.
    If `run_nmap=True` and `authorization_confirmed=False`, interrupts for HITL.
    """
    async def planner(state: GrondState) -> dict:
        if not state.target:
            return {"stage_errors": {"planner": "target is required"}}

        if state.run_nmap and not state.authorization_confirmed:
            confirmed: bool = interrupt(
                {
                    "type": "authorization_request",
                    "message": (
                        f"Active Nmap scan requested for target '{state.target}'. "
                        "Provide explicit written authorization before proceeding."
                    ),
                    "target": state.target,
                    "analyst_id": state.analyst_id,
                }
            )
            if not confirmed:
                log.warning(
                    "active scan declined by analyst",
                    target=state.target,
                    analyst=state.analyst_id,
                )
                return {
                    "run_nmap": False,
                    "completed_stages": state.completed_stages + ["planner"],
                }
            return {
                "authorization_confirmed": True,
                "completed_stages": state.completed_stages + ["planner"],
            }

        return {"completed_stages": state.completed_stages + ["planner"]}

    return planner


def make_collect_node(
    audit_factory: "_AuditFactory",
    auth_service: AuthorizationService,
) -> object:
    async def collect(state: GrondState) -> dict:
        audit = audit_factory(state)
        collector = Collector(
            audit=audit,
            auth_service=auth_service,
        )
        req = CollectionRequest(
            target=state.target,
            goal=state.goal,
            analyst_id=state.analyst_id,
            session_id=state.session_id,
            investigation_profile=state.investigation_profile,
            tavily_time_range=state.tavily_time_range,
            run_nmap=state.run_nmap and state.authorization_confirmed,
            nmap_profile=state.nmap_profile,
        )
        result = await collector.collect(req)
        errors = {f"collect.{k}": v for k, v in result.tool_errors.items()}
        return {
            "evidence": result.evidence,
            "stage_errors": {**state.stage_errors, **errors},
            "completed_stages": state.completed_stages + ["collect"],
        }

    return collect


def make_enrich_node(audit_factory: "_AuditFactory") -> object:
    async def enrich(state: GrondState) -> dict:
        if not state.evidence:
            return {"completed_stages": state.completed_stages + ["enrich"]}
        audit = audit_factory(state)
        enricher = Enricher(audit=audit)
        result = await enricher.enrich(state.evidence)
        return {
            "evidence": result.evidence,
            "completed_stages": state.completed_stages + ["enrich"],
        }

    return enrich


def make_verify_node(audit_factory: "_AuditFactory") -> object:
    async def verify(state: GrondState) -> dict:
        if not state.evidence:
            return {"completed_stages": state.completed_stages + ["verify"]}
        audit = audit_factory(state)
        verifier = Verifier(audit=audit)
        result = verifier.verify(state.evidence, investigation_target=state.target)
        return {
            "evidence": result.deduplicated,
            "completed_stages": state.completed_stages + ["verify"],
        }

    return verify


def make_report_node(audit_factory: "_AuditFactory") -> object:
    async def report(state: GrondState) -> dict:
        audit = audit_factory(state)
        reporter = Reporter(
            audit=audit,
            config=ReporterConfig(generate_llm_summaries=True),
        )
        intel_report = await reporter.generate(
            evidence=state.evidence,
            target=state.target,
            goal=state.goal,
            analyst_id=state.analyst_id,
            session_id=state.session_id,
        )
        return {
            "report": intel_report,
            "completed_stages": state.completed_stages + ["report"],
        }

    return report


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def should_abort(state: GrondState) -> Literal["collect", "__end__"]:
    """Abort if the planner found a fatal error."""
    if "planner" in state.stage_errors:
        return END
    return "collect"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


class _AuditFactory:
    def __call__(self, state: GrondState) -> AuditLogger:
        return AuditLogger(
            analyst_id=state.analyst_id,
            session_id=state.session_id,
        )


def build_graph(
    auth_service: AuthorizationService | None = None,
    checkpointer: object | None = None,
) -> object:
    """
    Compile and return the Grond LangGraph.

    Parameters
    ----------
    auth_service:
        Authorization store for active scan gating.
        Pass None to use the default in-memory store (dev only).
    checkpointer:
        LangGraph checkpointer for session persistence.
        Defaults to MemorySaver if not provided.
    """
    auth = auth_service or AuthorizationService()
    audit_factory = _AuditFactory()
    cp = checkpointer or MemorySaver()

    graph = StateGraph(GrondState)

    graph.add_node("planner",  make_planner_node())
    graph.add_node("collect",  make_collect_node(audit_factory, auth))
    graph.add_node("enrich",   make_enrich_node(audit_factory))
    graph.add_node("verify",   make_verify_node(audit_factory))
    graph.add_node("report",   make_report_node(audit_factory))

    graph.set_entry_point("planner")
    graph.add_conditional_edges("planner", should_abort)
    graph.add_edge("collect", "enrich")
    graph.add_edge("enrich",  "verify")
    graph.add_edge("verify",  "report")
    graph.add_edge("report",  END)

    return graph.compile(checkpointer=cp)


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------


def _first_interrupt_payload(final: dict) -> dict | None:
    raw = final.get("__interrupt__")
    if not raw:
        return None
    first = raw[0]
    val = getattr(first, "value", None)
    if isinstance(val, dict):
        return val
    return None


async def run_pipeline(
    target: str,
    goal: str,
    analyst_id: str,
    run_nmap: bool = False,
    investigation_profile: Literal["general", "company", "social"] = "general",
    tavily_time_range: Literal["day", "week", "month", "year"] | None = None,
    auth_service: AuthorizationService | None = None,
) -> IntelReport:
    """
    End-to-end pipeline runner.

    Raises
    ------
    PipelineInputError
        Early validation failed (e.g. empty target).
    ActiveScanApprovalRequiredError
        ``run_nmap`` was set without a way to complete LangGraph HITL on this path.
    PipelineAbortedError
        The graph ended without a report for an unexpected reason.
    """
    settings = get_settings()
    authorization_confirmed = _initial_authorization_confirmed_for_nmap(run_nmap, settings)
    auth = auth_service or AuthorizationService.with_settings_grants(settings)
    compiled = build_graph(auth_service=auth)
    initial_state = GrondState(
        target=target,
        goal=goal,
        analyst_id=analyst_id,
        run_nmap=run_nmap,
        investigation_profile=investigation_profile,
        tavily_time_range=tavily_time_range,
        authorization_confirmed=authorization_confirmed,
    )
    config = {"configurable": {"thread_id": initial_state.session_id}}
    final = await compiled.ainvoke(initial_state, config=config)
    report = final.get("report")
    if report is not None:
        return report

    intr = _first_interrupt_payload(final)
    if intr and intr.get("type") == "authorization_request":
        msg = str(
            intr.get("message")
            or (
                "Active Nmap scan requires written authorization and human approval. "
                "This API request cannot resume the in-graph approval step."
            )
        )
        raise ActiveScanApprovalRequiredError(msg)

    planner_err = (final.get("stage_errors") or {}).get("planner")
    if planner_err:
        raise PipelineInputError(str(planner_err))

    raise PipelineAbortedError(
        "Pipeline ended without a report — check server logs and pipeline configuration."
    )
