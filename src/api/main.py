"""FastAPI application entry point."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field
from starlette.middleware.cors import CORSMiddleware

from src.core.audit import AuditLogger
from src.core.authorization import AuthorizationRecord, AuthorizationService
from src.core.config import get_settings
from src.core.exceptions import (
    ActiveScanApprovalRequiredError,
    PipelineAbortedError,
    PipelineInputError,
    ToolExecutionError,
    ToolTimeoutError,
    UnauthorizedScanError,
)
from src.core.orchestrator import run_pipeline
from src.models.report import IntelReport
from src.tools.harvester_tool import (
    HarvesterInput,
    HarvesterOutput,
    harvester_endpoint,
)
from src.tools.metadata_tool import MetadataToolOutput, metadata_upload_endpoint
from src.tools.nmap_tool import NmapInput, NmapToolOutput, nmap_scan_endpoint
from src.tools.osintmap_tool import OsintmapInput, OsintmapOutput, osintmap_search_endpoint
from src.tools.sec_edgar_tool import (
    EdgarTextSearchInput,
    EdgarTextSearchOutput,
    edgar_text_search_endpoint,
)
from src.tools.tavily_tool import (
    TavilyExtractInput,
    TavilyExtractOutput,
    TavilyInput,
    TavilySearchOutput,
    tavily_extract_endpoint,
    tavily_search_endpoint,
)
from src.tools.stego_tool import StegoOutput, stego_upload_endpoint

logger = logging.getLogger(__name__)

_authorization_service = AuthorizationService.with_settings_grants(get_settings())


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    settings = get_settings()
    if settings.grond_active_scan_auth_from_db:
        try:
            from src.core.active_scan_authorization_db import load_active_scan_grants

            records = await load_active_scan_grants(settings.database_url)
            for rec in records:
                _authorization_service.grant(rec)
            logger.info("merged %d active-scan authorization row(s) from database", len(records))
        except Exception as exc:
            logger.warning("active-scan DB authorization merge failed: %s", exc)
    yield


app = FastAPI(
    title="Grond OSINT API",
    version="0.1.0",
    description="Agentic Open Source Intelligence Platform",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> dict:
    """Landing metadata — interactive docs live under ``/docs``."""
    return {
        "service": "grond",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/api/v1/health",
    }


@app.post("/api/v1/tools/harvester", response_model=HarvesterOutput)
async def harvester_scan(inp: HarvesterInput) -> HarvesterOutput:
    """
    Passive-first theHarvester wrapper. Active flags require authorization
    (``AuthorizationService``) matching ``analyst_id`` + ``target``.
    """
    audit = AuditLogger(analyst_id=inp.analyst_id, session_id=inp.session_id)
    try:
        return await harvester_endpoint(inp, audit=audit, auth_service=_authorization_service)
    except UnauthorizedScanError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ToolTimeoutError as exc:
        return HarvesterOutput(evidence=[], error=str(exc))
    except ToolExecutionError as exc:
        return HarvesterOutput(evidence=[], error=str(exc))


@app.post("/api/v1/tools/edgar", response_model=EdgarTextSearchOutput)
async def edgar_text_search(inp: EdgarTextSearchInput) -> EdgarTextSearchOutput:
    """
    SEC EDGAR full-text search via Bellingcat `edgar-tool`.

    Passive public regulatory filings index — no API key. See
    https://github.com/bellingcat/EDGAR and SEC fair-access / rate guidelines.
    """
    audit = AuditLogger(analyst_id=inp.analyst_id, session_id=inp.session_id)
    return await edgar_text_search_endpoint(inp, audit=audit)


@app.post("/api/v1/tools/osintmap", response_model=OsintmapOutput)
async def osintmap_search(inp: OsintmapInput) -> OsintmapOutput:
    """
    OSINTMap — passive lookup in cipher387's worldwide curated public OSINT link table.

    Fetches the upstream README from GitHub (config: ``osintmap_readme_url``); rows
    match ``region_query`` as a case-insensitive substring of the country/region label.
    """
    audit = AuditLogger(analyst_id=inp.analyst_id, session_id=inp.session_id)
    return await osintmap_search_endpoint(inp, audit=audit)


@app.post("/api/v1/tools/tavily", response_model=TavilySearchOutput)
async def tavily_search(inp: TavilyInput) -> TavilySearchOutput:
    """Tavily Search — returns search-result snippets as Evidence."""
    audit = AuditLogger(analyst_id=inp.analyst_id, session_id=inp.session_id)
    return await tavily_search_endpoint(inp, audit=audit)


@app.post("/api/v1/tools/tavily/extract", response_model=TavilyExtractOutput)
async def tavily_extract(inp: TavilyExtractInput) -> TavilyExtractOutput:
    """Tavily Extract — clean markdown/text from URLs (batch up to 20)."""
    audit = AuditLogger(analyst_id=inp.analyst_id, session_id=inp.session_id)
    return await tavily_extract_endpoint(inp, audit=audit)


@app.post("/api/v1/tools/metadata", response_model=MetadataToolOutput)
async def metadata_extract(
    file: Annotated[UploadFile, File()],
    target: Annotated[str, Form()],
    analyst_id: Annotated[str, Form()],
    session_id: Annotated[str, Form()],
    engine: Annotated[str | None, Form()] = None,
) -> MetadataToolOutput:
    """
    File metadata via **ExifTool** (broad formats) and/or **Exiv2** (image Exif/IPTC/XMP).

    Use optional ``engine`` form field: ``exiftool``, ``exiv2``, or ``auto`` (default from env
    ``METADATA_ENGINE``). See https://github.com/Exiv2/exiv2 and ExifTool / Metaforge-class flows.

    Passive: analyst must only upload material they are authorized to hold and analyze.
    """
    audit = AuditLogger(analyst_id=analyst_id, session_id=session_id)
    name = file.filename or "upload"
    data = await file.read()
    if not data:
        return MetadataToolOutput(evidence=[], error="Empty upload")
    return await metadata_upload_endpoint(
        audit=audit,
        target=target,
        analyst_id=analyst_id,
        session_id=session_id,
        original_filename=name,
        data=data,
        engine=engine,
    )


@app.post("/api/v1/tools/stego", response_model=StegoOutput)
async def stego_analyze(
    file: Annotated[UploadFile, File()],
    target: Annotated[str, Form()],
    analyst_id: Annotated[str, Form()],
    session_id: Annotated[str, Form()],
    engine: Annotated[str, Form()] = "auto",
    password: Annotated[str, Form()] = "",
) -> StegoOutput:
    """
    Steganography analysis via **stegoVeritas** (comprehensive) and/or **LSB fallback** (Pillow).

    Use optional ``engine`` form field: ``stegoveritas``, ``lsb``, or ``auto``
    (default from env ``STEGO_ENGINE``).

    Passive: analyst must only upload material they are authorized to analyze.
    """
    audit = AuditLogger(analyst_id=analyst_id, session_id=session_id)
    name = file.filename or "upload"
    data = await file.read()
    if not data:
        return StegoOutput(evidence=[], error="Empty upload")
    return await stego_upload_endpoint(
        audit=audit,
        target=target,
        analyst_id=analyst_id,
        session_id=session_id,
        original_filename=name,
        data=data,
        engine=engine,
        password=password,
    )


@app.post("/api/v1/tools/nmap", response_model=NmapToolOutput)
async def nmap_scan(inp: NmapInput) -> NmapToolOutput:
    """
    Run an **authorized** Nmap active scan. Requires a matching entry in the
    authorization store (env CSV, DB table when enabled, or an admin grant).
    """
    audit = AuditLogger(analyst_id=inp.analyst_id, session_id=inp.session_id)
    try:
        return await nmap_scan_endpoint(
            inp,
            audit=audit,
            auth_service=_authorization_service,
        )
    except UnauthorizedScanError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


class ActiveScanAuthorizationCreate(BaseModel):
    """Register a persisted active-scan grant (after your approval workflow)."""

    target: str = Field(
        ...,
        min_length=1,
        description="IP, CIDR, hostname, *.sub.example.com, or parent host",
    )
    analyst_id: str = Field(default="*", description="Analyst UUID or * for any")
    tool: str = Field(default="nmap", description="nmap, ncrack, theharvester, or *")
    legal_ref: str = ""
    notes: str = ""
    expires_at: datetime | None = None


class ActiveScanAuthorizationCreateResponse(BaseModel):
    id: UUID
    ok: bool = True


@app.post(
    "/api/v1/admin/active-scan-authorizations",
    response_model=ActiveScanAuthorizationCreateResponse,
)
async def admin_create_active_scan_authorization(
    body: ActiveScanAuthorizationCreate,
    x_grond_authorization_admin_key: Annotated[
        str | None,
        Header(alias="X-Grond-Authorization-Admin-Key"),
    ] = None,
) -> ActiveScanAuthorizationCreateResponse:
    """
    Insert a grant into PostgreSQL and the in-process ``AuthorizationService``.

    Disabled unless ``GROND_AUTHORIZATION_ADMIN_KEY`` is set; requires matching header.
    Intended for internal automation after contract/ticket approval — not end-user self-serve.
    """
    settings = get_settings()
    expected = (settings.grond_authorization_admin_key or "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin grant API disabled (set GROND_AUTHORIZATION_ADMIN_KEY).",
        )
    if (x_grond_authorization_admin_key or "").strip() != expected:
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing X-Grond-Authorization-Admin-Key.",
        )

    from src.core.active_scan_authorization_db import insert_active_scan_grant

    now = datetime.now(UTC)
    rec = AuthorizationRecord(
        target=body.target.strip(),
        analyst_id=(body.analyst_id.strip() or "*"),
        tool=(body.tool.strip() or "nmap"),
        authorized_at=now,
        expires_at=body.expires_at,
        legal_ref=body.legal_ref.strip(),
        notes=(body.notes.strip() or "admin_api"),
    )
    row_id = await insert_active_scan_grant(
        settings.database_url,
        target=rec.target,
        analyst_id=rec.analyst_id,
        tool=rec.tool,
        legal_ref=rec.legal_ref,
        notes=rec.notes,
        expires_at=rec.expires_at,
    )
    _authorization_service.grant(
        AuthorizationRecord(
            target=rec.target,
            analyst_id=rec.analyst_id,
            tool=rec.tool,
            authorized_at=rec.authorized_at,
            expires_at=rec.expires_at,
            legal_ref=rec.legal_ref,
            notes=rec.notes,
        )
    )
    return ActiveScanAuthorizationCreateResponse(id=row_id)


class NcrackPlaceholderInput(BaseModel):
    target: str
    analyst_id: str
    session_id: str


@app.post("/api/v1/tools/ncrack")
async def ncrack_scan(_inp: NcrackPlaceholderInput) -> None:
    """Reserved for future Ncrack adapter — returns HTTP 501."""
    raise HTTPException(
        status_code=501,
        detail={
            "code": "NCRACK_NOT_IMPLEMENTED",
            "message": "Ncrack is not exposed via Grond API yet.",
            "actions": [
                "Run Ncrack CLI on an authorized engagement workstation.",
                "See agents/network-scanner.md for the planned adapter.",
            ],
        },
    )


@app.get("/api/v1/tools/npcap/info")
async def npcap_info() -> dict[str, str]:
    """
    Static orientation for **Npcap** (Windows driver/SDK). Not invoked server-side.
    """
    return {
        "name": "Npcap",
        "role": "Windows packet capture driver and SDK for Nmap, Wireshark, and similar tools.",
        "install_url": "https://npcap.com/#download",
        "guide_url": "https://npcap.com/guide/npcap-users-guide.html",
        "devguide_url": "https://npcap.com/guide/npcap-devguide.html",
        "note": (
            "Npcap is not executed by the Grond API. Install it on Windows hosts where you run "
            "Nmap with raw capture or use Wireshark."
        ),
    }


class ScanRequest(BaseModel):
    target: str
    goal: str
    analyst_id: str
    run_nmap: bool = False
    investigation_profile: Literal["general", "company", "social"] = "general"
    tavily_time_range: Literal["day", "week", "month", "year"] | None = None


@app.post("/api/v1/scan", response_model=IntelReport)
async def create_scan(req: ScanRequest) -> IntelReport:
    try:
        return await run_pipeline(
            target=req.target,
            goal=req.goal,
            analyst_id=req.analyst_id,
            run_nmap=req.run_nmap,
            investigation_profile=req.investigation_profile,
            tavily_time_range=req.tavily_time_range,
            auth_service=_authorization_service,
        )
    except ActiveScanApprovalRequiredError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "ACTIVE_SCAN_APPROVAL_REQUIRED",
                "message": str(exc),
                "hint": (
                    "Synchronous POST /api/v1/scan cannot resume the LangGraph "
                    "human-in-the-loop step. Use passive-only (run_nmap=false) unless "
                    "your deployment completes active-scan approval through a checkpoint resume."
                ),
                "actions": [
                    "Uncheck active Nmap for a passive-only Shodan/Tavily-style scan.",
                    "If Nmap is required, record written authorization for the target "
                    "and complete approval via an orchestration flow that resumes the graph "
                    "(not this bare scan endpoint alone). "
                    "For local development only: set GROND_DEV_BYPASS_NMAP_HITL=true with "
                    "ENVIRONMENT=development and list targets in GROND_AUTHORIZED_SCAN_TARGETS.",
                ],
            },
        ) from exc
    except PipelineInputError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_SCAN_INPUT",
                "message": str(exc),
            },
        ) from exc
    except PipelineAbortedError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "PIPELINE_ABORTED",
                "message": str(exc),
            },
        ) from exc


@app.get("/api/v1/health")
async def health() -> dict:
    return {"status": "ok"}
