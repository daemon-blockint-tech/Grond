"""
SEC EDGAR full-text search via Bellingcat's ``edgar-tool`` library.

Wraps https://github.com/bellingcat/EDGAR (PyPI: ``edgar-tool``). Queries the SEC's
public EDGAR full-text API through the upstream client's rate-limited ``requests``
session; work is isolated in ``asyncio.to_thread`` so the FastAPI event loop stays responsive.

Passive public regulatory data — respect SEC politeness; default ``max_results`` is capped.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, date, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field, model_validator

from src.core.audit import AuditLogger
from src.core.config import get_settings
from src.core.exceptions import ToolExecutionError
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTier, SourceTool
from src.tools.base import ToolAdapter

log = structlog.get_logger("grond.tools.sec_edgar")

_SEC_SEARCH_UI = "https://www.sec.gov/edgar/search/"
_ATTRIBUTION = "Bellingcat edgar-tool — https://github.com/bellingcat/EDGAR"


class EdgarTextSearchInput(BaseModel):
    """Parameters mirroring ``edgar_tool.search_params.SearchParams`` (subset + sane defaults)."""

    target: str = Field(..., min_length=1, description="Investigation / case label")
    analyst_id: str
    session_id: str
    query: str = Field(
        default="",
        description="Audit log label — auto-derived from keywords/entity when empty",
    )
    keywords: list[str] = Field(
        default_factory=list,
        description="Terms that must all appear (use a single string with spaces for phrase-style AND)",
    )
    entity: str | None = Field(
        default=None,
        description="SEC entity: company name, ticker, CIK, or individual",
    )
    filing_category: str | None = Field(
        default=None,
        description=(
            "e.g. all_annual_quarterly_and_current_reports, registration_statements — "
            "omit when using single_forms"
        ),
    )
    single_forms: list[str] = Field(
        default_factory=list,
        description="Specific SEC form types (e.g. 10-K, 8-K); sets filing category to custom upstream",
    )
    date_range_select: str | None = Field(
        default="5y",
        description="SEC UI preset: all, 10y, 5y, 1y, 30d, or custom",
    )
    start_date: date | None = None
    end_date: date | None = None
    incorporated_in: str | None = Field(
        default=None,
        description="ISO location code for place of incorporation (see edgar-tool docs)",
    )
    principal_executive_offices_in: str | None = Field(
        default=None,
        description="ISO location code for principal executive office (mutually exclusive with incorporated_in)",
    )
    max_results: int = Field(default=25, ge=1, le=100)

    @model_validator(mode="after")
    def _default_audit_query(self) -> EdgarTextSearchInput:
        if self.query.strip():
            return self
        parts = [k.strip() for k in self.keywords if k.strip()]
        if self.entity and self.entity.strip():
            parts.append(f"entity:{self.entity.strip()}")
        label = " ".join(parts) if parts else "edgar-text-search"
        return self.model_copy(update={"query": label})

    @model_validator(mode="after")
    def _validate_inputs(self) -> EdgarTextSearchInput:
        has_kw = any(k.strip() for k in self.keywords)
        has_ent = bool(self.entity and self.entity.strip())
        has_forms = bool(self.single_forms)
        fc = (self.filing_category or "").strip()
        has_fc = bool(fc and fc != "all")
        if not (has_kw or has_ent or has_forms or has_fc):
            raise ValueError(
                "Provide keywords, entity, single_forms, and/or a non-'all' filing_category."
            )
        if self.incorporated_in and self.principal_executive_offices_in:
            raise ValueError(
                "Specify only one of incorporated_in or principal_executive_offices_in."
            )
        dr = (self.date_range_select or "").lower()
        if dr == "custom":
            if self.start_date is None or self.end_date is None:
                raise ValueError("date_range_select=custom requires start_date and end_date.")
        elif self.start_date is not None or self.end_date is not None:
            raise ValueError(
                "start_date/end_date only allowed when date_range_select is custom."
            )
        return self


class EdgarTextSearchOutput(BaseModel):
    evidence: list[Evidence]
    result_count: int = 0
    error: str | None = None


def _build_search_params(inp: EdgarTextSearchInput) -> Any:
    try:
        from edgar_tool.search_params import SearchParams
    except ImportError as exc:
        raise ToolExecutionError(
            tool=str(SourceTool.EDGAR),
            message="edgar-tool not installed — add dependency edgar-tool (pip/uv)",
            cause=exc,
        ) from exc

    kw = [k.strip() for k in inp.keywords if k.strip()] or None
    sp_kwargs: dict[str, Any] = {}
    if kw:
        sp_kwargs["keywords"] = kw
    if inp.entity and inp.entity.strip():
        sp_kwargs["entity"] = inp.entity.strip()

    if inp.single_forms:
        sp_kwargs["single_forms"] = inp.single_forms
        sp_kwargs["filing_category"] = "custom"
    elif inp.filing_category and inp.filing_category.strip():
        sp_kwargs["filing_category"] = inp.filing_category.strip()

    dr = inp.date_range_select or "5y"
    if dr.lower() == "custom":
        sp_kwargs["date_range_select"] = "custom"
        sp_kwargs["start_date"] = inp.start_date
        sp_kwargs["end_date"] = inp.end_date
    else:
        sp_kwargs["date_range_select"] = dr

    if inp.incorporated_in and inp.incorporated_in.strip():
        sp_kwargs["inc_in"] = inp.incorporated_in.strip()
    if inp.principal_executive_offices_in and inp.principal_executive_offices_in.strip():
        sp_kwargs["peo_in"] = inp.principal_executive_offices_in.strip()

    try:
        return SearchParams(**sp_kwargs)
    except ValueError as exc:
        raise ToolExecutionError(
            tool=str(SourceTool.EDGAR),
            message=f"Invalid SEC EDGAR search parameters: {exc}",
            cause=exc,
        ) from exc


def _sync_edgar_search(search_params: Any, max_results: int) -> list[dict[str, Any]]:
    from edgar_tool.text_search import search as edgar_search

    raw = edgar_search(search_params, output=None, max_results=max_results)
    if not raw:
        return []
    if not isinstance(raw, list):
        return []
    return raw


def _jsonish_row(row: dict[str, Any]) -> dict[str, Any]:
    """Make row JSON-serializable for provenance.raw_response."""

    out: dict[str, Any] = {}
    for k, v in row.items():
        if v is None or isinstance(v, str | int | float | bool):
            out[k] = v
        else:
            out[k] = json.loads(json.dumps(v, default=str))
    return out


def _row_to_evidence(
    row: dict[str, Any],
    *,
    inp: EdgarTextSearchInput,
    collected_at: datetime,
    confidence: float,
) -> Evidence:
    entity = str(row.get("entity_name") or "Unknown filer")
    form = str(row.get("root_form") or "")
    title = str(row.get("form_name") or form or "SEC filing")
    filed_at = str(row.get("filed_at") or "")
    url = row.get("filing_details_url") or row.get("filing_document_url") or _SEC_SEARCH_UI
    url_s = str(url) if url else _SEC_SEARCH_UI
    cik = row.get("company_cik_trimmed") or row.get("company_cik")
    ticker = row.get("ticker")

    claim = f"SEC EDGAR index: {entity} — form {form} filed {filed_at}".strip()
    snippet = f"{entity} {form} {filed_at} {ticker or ''}".strip()[:500]

    raw_response = _jsonish_row(row)
    raw_response["integration"] = {
        "library": _ATTRIBUTION,
        "guide": "https://www.sec.gov/edgar/search/",
    }

    prov = Provenance(
        source_tool=SourceTool.EDGAR,
        source_tier=SourceTier.REGULATOR,
        source_url=url_s,
        raw_snippet=snippet or None,
        extractor="edgar_tool.text_search.search",
        collection_query=inp.query,
        api_endpoint=_SEC_SEARCH_UI,
        collected_at=collected_at,
        analyst_id=inp.analyst_id,
        session_id=inp.session_id,
        raw_response=raw_response,
    )

    value: dict[str, Any] = {
        "url": url_s,
        "title": title,
        "entity_name": entity,
        "form": form,
        "filed_at": filed_at,
        "cik": cik,
        "ticker": ticker,
        "filing_document_url": row.get("filing_document_url"),
        "file_num_search_url": row.get("file_num_search_url"),
    }

    return Evidence(
        target=inp.target,
        claim=claim,
        claim_type=ClaimType.COMPANY_INFO,
        value=value,
        provenance=prov,
        confidence=confidence,
    )


class EdgarTextSearchAdapter(ToolAdapter[EdgarTextSearchInput]):
    """Run Bellingcat edgar-tool SEC search in a worker thread."""

    tool_name = SourceTool.EDGAR

    async def _execute(self, inp: EdgarTextSearchInput) -> list[Evidence]:
        sp = _build_search_params(inp)
        settings = get_settings()
        collected_at = datetime.now(UTC)

        try:
            rows = await asyncio.to_thread(_sync_edgar_search, sp, inp.max_results)
        except Exception as exc:
            log.exception("edgar.search_failed")
            raise ToolExecutionError(
                tool=str(SourceTool.EDGAR),
                message=f"SEC EDGAR search failed: {exc}",
                cause=exc,
            ) from exc

        base_conf = settings.confidence_weight_edgar
        evidence_items: list[Evidence] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            evidence_items.append(
                _row_to_evidence(
                    row,
                    inp=inp,
                    collected_at=collected_at,
                    confidence=base_conf,
                )
            )
        log.info("edgar.results", count=len(evidence_items))
        return evidence_items


async def edgar_text_search_endpoint(
    inp: EdgarTextSearchInput,
    *,
    audit: AuditLogger,
) -> EdgarTextSearchOutput:
    adapter = EdgarTextSearchAdapter(audit=audit)
    try:
        evidence = await adapter.run(inp)
        return EdgarTextSearchOutput(
            evidence=evidence,
            result_count=len(evidence),
            error=None,
        )
    except ToolExecutionError as exc:
        return EdgarTextSearchOutput(evidence=[], result_count=0, error=str(exc))
