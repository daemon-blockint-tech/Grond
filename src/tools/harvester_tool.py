"""
theHarvester OSINT adapter (subprocess).

Install (pick one; not bundled as a normal PyPI dependency for this project):

  uv pip install "git+https://github.com/laramies/theHarvester"
  # or: pip install git+https://github.com/laramies/theHarvester
  # or: Kali/apt package `theharvester` → `theHarvester` on PATH

Run checks:

  theHarvester -h
  uv run python -m theHarvester -h

**Passive-first:** default ``sources`` is ``duckduckgo,crtsh`` (public / CT style).

**Active techniques** (DNS brute ``-c``, DNS lookup ``-n``, DNS resolve ``-r``,
takeover ``-t``, screenshots ``--screenshot``, API scan ``-a``, Shodan host
lookup ``-s``) require ``allow_active_techniques=True`` **and**
``require_authorization(...)`` — same authorization store as Nmap.

API keys for optional theHarvester modules are configured per upstream docs
(``api-keys.yaml`` / wiki): https://github.com/laramies/theHarvester/wiki
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field, field_validator

from src.core.audit import AuditLogger
from src.core.authorization import AuthorizationService, require_authorization
from src.core.config import get_settings
from src.core.exceptions import ToolError, ToolExecutionError, ToolTimeoutError
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTier, SourceTool
from src.tools.base import ToolAdapter

log = structlog.get_logger("grond.tools.harvester")

_DEFAULT_PASSIVE_SOURCES = "duckduckgo,crtsh"


class HarvesterInput(BaseModel):
    """Input for a theHarvester run — `target` is the ``-d`` domain / company string."""

    target: str = Field(..., min_length=1, description="Domain / company string (theHarvester -d)")
    analyst_id: str
    session_id: str
    query: str = Field(
        default="",
        description="Audit log line — defaults to sources summary when empty",
    )
    sources: str = Field(
        default=_DEFAULT_PASSIVE_SOURCES,
        description="Comma-separated theHarvester -b sources (passive default)",
    )
    limit: int = Field(default=200, ge=1, le=5000)
    start: int = Field(default=0, ge=0)
    quiet: bool = Field(default=True, description="Pass -q to suppress key warnings")
    allow_active_techniques: bool = Field(
        default=False,
        description=(
            "Opt-in for active / intrusive CLI flags. Still requires authorization "
            "against `target` when any active flag is set."
        ),
    )
    dns_brute: bool = Field(default=False, description="theHarvester -c (authorized only)")
    dns_lookup: bool = Field(default=False, description="theHarvester -n (authorized only)")
    dns_resolve: str = Field(
        default="",
        description="theHarvester -r resolvers or file path (authorized only when non-empty)",
    )
    takeover: bool = Field(default=False, description="theHarvester -t (authorized only)")
    screenshot_dir: str = Field(
        default="",
        description="theHarvester --screenshot output dir (authorized only when non-empty)",
    )
    api_scan: bool = Field(default=False, description="theHarvester -a (authorized only)")
    wordlist: str = Field(default="", description="theHarvester -w (API scan wordlist)")
    shodan_lookup: bool = Field(default=False, description="theHarvester -s (authorized only)")
    dns_server: str = Field(default="", description="theHarvester -e")
    proxies: bool = Field(default=False, description="theHarvester -p")
    timeout_seconds: int | None = Field(
        default=None,
        description="Override settings theharvester_timeout_seconds when set",
    )

    @field_validator("sources")
    @classmethod
    def _normalize_sources(cls, v: str) -> str:
        parts = [p.strip() for p in v.split(",") if p.strip()]
        if not parts:
            return _DEFAULT_PASSIVE_SOURCES
        return ",".join(parts)


class HarvesterOutput(BaseModel):
    evidence: list[Evidence]
    error: str | None = None


def harvest_json_to_evidence(
    data: dict[str, Any],
    *,
    domain: str,
    analyst_id: str,
    session_id: str,
    tier: SourceTier,
    source_label: str,
    cli_snippet: str,
    stderr_text: str,
    exit_code: int,
) -> list[Evidence]:
    """Map a theHarvester JSON report dict to ``Evidence`` items (unit-testable)."""
    settings = get_settings()
    collected_at = datetime.now(timezone.utc)
    raw_bundle: dict[str, Any] = {
        "harvester_json": data,
        "stderr": stderr_text[-4000:] if stderr_text else "",
        "exit_code": exit_code,
    }

    prov_base = Provenance(
        source_tool=SourceTool.THEHARVESTER,
        source_tier=tier,
        extractor="theharvester.json_report",
        collection_query=cli_snippet[:2000],
        api_endpoint=None,
        collected_at=collected_at,
        analyst_id=analyst_id,
        session_id=session_id,
        raw_response=raw_bundle,
        raw_snippet=cli_snippet[:500] if cli_snippet else None,
    )

    items: list[Evidence] = []
    dom_lower = domain.lower().strip()

    for host in data.get("hosts") or []:
        if not host or not isinstance(host, str):
            continue
        hn = host.strip()
        claim_type = ClaimType.SUBDOMAIN
        if dom_lower and hn.lower().rstrip(".") == dom_lower.rstrip("."):
            claim_type = ClaimType.HOSTNAME
        items.append(
            Evidence(
                target=domain,
                claim=f"Host / subdomain discovered: {hn} ({source_label})",
                claim_type=claim_type,
                value={"hostname": hn, "domain": domain, "sources": source_label},
                provenance=prov_base.model_copy(
                    update={
                        "raw_snippet": hn[:500],
                    }
                ),
                confidence=settings.confidence_weight_theharvester,
            )
        )

    for em in data.get("emails") or []:
        if not em or not isinstance(em, str):
            continue
        addr = em.strip()
        items.append(
            Evidence(
                target=domain,
                claim=f"Email address discovered: {addr}",
                claim_type=ClaimType.EMAIL_DISCOVERY,
                value={"email": addr, "domain": domain, "sources": source_label},
                provenance=prov_base.model_copy(update={"raw_snippet": addr[:500]}),
                confidence=settings.confidence_weight_theharvester * 0.85,
                requires_review=True,
                review_reason="Email addresses may constitute PII — verify legal basis before retention",
            )
        )

    for ip in data.get("ips") or []:
        if not ip or not isinstance(ip, str):
            continue
        ip_s = ip.strip()
        if not _looks_like_ip(ip_s):
            continue
        items.append(
            Evidence(
                target=domain,
                claim=f"IP associated with harvest: {ip_s}",
                claim_type=ClaimType.HOST_DISCOVERY,
                value={"ip": ip_s, "domain": domain, "sources": source_label},
                provenance=prov_base.model_copy(update={"raw_snippet": ip_s}),
                confidence=settings.confidence_weight_theharvester,
            )
        )

    for url in data.get("interesting_urls") or []:
        if not url or not isinstance(url, str):
            continue
        u = url.strip()
        items.append(
            Evidence(
                target=domain,
                claim=f"Interesting URL from harvest: {u}",
                claim_type=ClaimType.WEB_MENTION,
                value={"url": u, "title": "", "domain": domain, "sources": source_label},
                provenance=prov_base.model_copy(
                    update={"raw_snippet": u[:500], "source_url": u[:2000]}
                ),
                confidence=settings.confidence_weight_theharvester * 0.9,
            )
        )

    for asn in data.get("asns") or []:
        if asn is None:
            continue
        items.append(
            Evidence(
                target=domain,
                claim=f"ASN reference: {asn!s}",
                claim_type=ClaimType.ASN,
                value={"asn": str(asn), "org": "", "domain": domain, "sources": source_label},
                provenance=prov_base.model_copy(update={"raw_snippet": str(asn)[:500]}),
                confidence=settings.confidence_weight_theharvester,
            )
        )

    return items


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


def _source_tier_for_modules(sources_csv: str) -> SourceTier:
    parts = {p.strip().lower() for p in sources_csv.split(",") if p.strip()}
    if parts <= {"crtsh", "certspotter"}:
        return SourceTier.OFFICIAL
    return SourceTier.COMMUNITY


def _active_flags_set(inp: HarvesterInput) -> set[str]:
    flags: set[str] = set()
    if inp.dns_brute:
        flags.add("dns_brute")
    if inp.dns_lookup:
        flags.add("dns_lookup")
    if inp.takeover:
        flags.add("takeover")
    if inp.api_scan:
        flags.add("api_scan")
    if inp.shodan_lookup:
        flags.add("shodan_lookup")
    if inp.dns_resolve.strip():
        flags.add("dns_resolve")
    if inp.screenshot_dir.strip():
        flags.add("screenshot")
    return flags


def _resolve_harvester_argv() -> list[str]:
    settings = get_settings()
    if settings.theharvester_bin.strip():
        return [settings.theharvester_bin.strip()]
    path = shutil.which("theHarvester")
    if path:
        return [path]
    return [sys.executable, "-m", "theHarvester"]


def _build_cmd(inp: HarvesterInput, json_path: Path) -> list[str]:
    argv = _resolve_harvester_argv()
    cmd: list[str] = [*argv, "-d", inp.target, "-b", inp.sources, "-l", str(inp.limit)]
    if inp.start:
        cmd.extend(["-S", str(inp.start)])
    if inp.quiet:
        cmd.append("-q")
    if inp.dns_server:
        cmd.extend(["-e", inp.dns_server])
    if inp.proxies:
        cmd.append("-p")
    if inp.dns_brute:
        cmd.append("-c")
    if inp.dns_lookup:
        cmd.append("-n")
    if inp.dns_resolve.strip():
        cmd.extend(["-r", inp.dns_resolve.strip()])
    if inp.takeover:
        cmd.append("-t")
    if inp.shodan_lookup:
        cmd.append("-s")
    if inp.api_scan:
        cmd.append("-a")
    if inp.wordlist:
        cmd.extend(["-w", inp.wordlist])
    if inp.screenshot_dir.strip():
        cmd.extend(["--screenshot", inp.screenshot_dir.strip()])
    cmd.extend(["-f", str(json_path)])
    return cmd


class HarvesterAdapter(ToolAdapter[HarvesterInput]):
    tool_name = SourceTool.THEHARVESTER

    def __init__(self, audit: AuditLogger, auth_service: AuthorizationService) -> None:
        super().__init__(audit=audit, rate_limiter=None)
        self._auth = auth_service

    async def _execute(self, input: HarvesterInput) -> list[Evidence]:
        active = _active_flags_set(input)

        if active and not input.allow_active_techniques:
            raise ToolError(
                tool=self.tool_name,
                message=(
                    f"Active theHarvester options require allow_active_techniques=true "
                    f"(attempted: {sorted(active)})"
                ),
            )

        if active:
            await require_authorization(
                target=input.target,
                analyst_id=input.analyst_id,
                tool=str(SourceTool.THEHARVESTER),
                audit=self._audit,
                auth_service=self._auth,
            )

        settings = get_settings()
        timeout = float(input.timeout_seconds or settings.theharvester_timeout_seconds)

        self._audit.record(
            "harvester_invocation",
            tool=str(self.tool_name),
            target=input.target,
            active_flags=sorted(active),
            passive_only=not bool(active),
        )

        fd, tmp_path = tempfile.mkstemp(prefix="grond_harvest_", suffix=".json")
        os.close(fd)
        out_path = Path(tmp_path)
        cmd = _build_cmd(input, out_path)
        cli_snippet = " ".join(cmd[:12]) + (" ..." if len(cmd) > 12 else "")

        log.info("theharvester.exec", cmd=cli_snippet, target=input.target)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy(),
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError as exc:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                raise ToolTimeoutError(
                    tool=self.tool_name,
                    message=f"theHarvester timed out after {int(timeout)}s",
                ) from exc

            stderr_text = (stderr_b or b"").decode(errors="replace")
            stdout_text = (stdout_b or b"").decode(errors="replace")

            if proc.returncode != 0:
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message=(
                        f"theHarvester exited {proc.returncode}: "
                        f"{stderr_text[:1500] or stdout_text[:1500]}"
                    ),
                )

            if not out_path.is_file() or out_path.stat().st_size == 0:
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message="theHarvester produced no JSON output — is the CLI installed?",
                    cause=None,
                )

            raw = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(raw, dict):
                raise ToolExecutionError(
                    tool=self.tool_name,
                    message="theHarvester JSON root is not an object",
                )

            tier = _source_tier_for_modules(input.sources)
            return harvest_json_to_evidence(
                raw,
                domain=input.target,
                analyst_id=input.analyst_id,
                session_id=input.session_id,
                tier=tier,
                source_label=input.sources,
                cli_snippet=cli_snippet + " | " + str(raw.get("cmd", ""))[:500],
                stderr_text=stderr_text,
                exit_code=proc.returncode or 0,
            )
        finally:
            out_path.unlink(missing_ok=True)


async def harvester_endpoint(
    inp: HarvesterInput,
    *,
    audit: AuditLogger,
    auth_service: AuthorizationService,
) -> HarvesterOutput:
    adapter = HarvesterAdapter(audit=audit, auth_service=auth_service)
    q = inp.query or f"sources={inp.sources}"
    inp = inp.model_copy(update={"query": q})
    try:
        evidence = await adapter.run(inp)
        return HarvesterOutput(evidence=evidence, error=None)
    except ToolError as exc:
        return HarvesterOutput(evidence=[], error=str(exc))
