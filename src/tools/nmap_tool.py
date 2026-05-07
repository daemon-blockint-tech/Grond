"""
Nmap tool adapter — ACTIVE SCANNING ONLY.

Authorization is checked before any subprocess is spawned.  The adapter
refuses to run without a valid AuthorizationRecord.

Each open port becomes one `ClaimType.OPEN_PORT` Evidence item.
Each detected service becomes one `ClaimType.SERVICE_BANNER` item.
NSE script outputs are stored verbatim in the raw_response for analyst review.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from src.core.audit import AuditLogger
from src.core.authorization import AuthorizationService, require_authorization
from src.core.config import get_settings
from src.core.exceptions import ToolExecutionError, ToolTimeoutError, UnauthorizedScanError
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTool
from src.tools.base import ToolAdapter

log = structlog.get_logger("grond.tools.nmap")


# ---------------------------------------------------------------------------
# Scan profiles — deterministic nmap argument strings
# ---------------------------------------------------------------------------


class ScanProfile(StrEnum):
    QUICK = "quick"       # fast, broad open-port detection
    STANDARD = "standard" # service version + default scripts
    THOROUGH = "thorough" # OS detection + all ports + version scripts
    UDP = "udp"           # top UDP ports
    VULN = "vuln"         # NSE vuln scripts (slower, noisier)


PROFILE_ARGS: dict[ScanProfile, str] = {
    ScanProfile.QUICK:    "-sV --open -T4 -F",
    ScanProfile.STANDARD: "-sV -sC --open -T3",
    ScanProfile.THOROUGH: "-A --open -T3 -p-",
    ScanProfile.UDP:      "-sU --open -T3 --top-ports 200",
    ScanProfile.VULN:     "-sV --script vuln --open -T3",
}


# ---------------------------------------------------------------------------
# Typed input
# ---------------------------------------------------------------------------


class NmapInput(BaseModel):
    target: str  # IP, CIDR, or hostname
    analyst_id: str
    session_id: str
    profile: ScanProfile = ScanProfile.STANDARD
    port_range: str = ""  # e.g. "80,443,8080-8090" — overrides profile if set
    timeout_seconds: int = Field(default=300, ge=30, le=1800)
    authorization_ref: str | None = Field(
        default=None,
        description="Written authorization reference (audit trail / orchestration contract)",
    )


class NmapToolOutput(BaseModel):
    evidence: list[Evidence]
    error: str | None = None


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class NmapAdapter(ToolAdapter[NmapInput]):
    """
    Active port/service scanner using python-nmap.

    Will raise `UnauthorizedScanError` if the target has no authorization
    record — this check cannot be bypassed.
    """

    tool_name = SourceTool.NMAP

    def __init__(
        self,
        audit: AuditLogger,
        auth_service: AuthorizationService,
    ) -> None:
        super().__init__(audit=audit, rate_limiter=None)
        self._auth = auth_service

    async def _execute(self, input: NmapInput) -> list[Evidence]:
        # Authorization gate — this runs before any subprocess
        await require_authorization(
            target=input.target,
            analyst_id=input.analyst_id,
            tool=self.tool_name,
            audit=self._audit,
            auth_service=self._auth,
        )

        try:
            import nmap  # type: ignore[import]
        except ImportError as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message="python-nmap not installed — run: pip install python-nmap",
                cause=exc,
            ) from exc

        args = PROFILE_ARGS[input.profile]
        ports = input.port_range or ""

        try:
            scanner = nmap.PortScanner()
            # nmap is synchronous — run in executor to avoid blocking the event loop
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: scanner.scan(
                        hosts=input.target,
                        ports=ports or None,
                        arguments=args,
                    ),
                ),
                timeout=float(input.timeout_seconds),
            )
        except asyncio.TimeoutError as exc:
            raise ToolTimeoutError(
                tool=self.tool_name,
                message=f"Nmap scan of {input.target} timed out after {input.timeout_seconds}s",
            ) from exc
        except Exception as exc:
            raise ToolExecutionError(
                tool=self.tool_name,
                message=str(exc),
                cause=exc,
            ) from exc

        return self._parse_scan(scanner, input)

    # ------------------------------------------------------------------
    # Parser — one Evidence per (host, port) pair
    # ------------------------------------------------------------------

    def _parse_scan(self, scanner: Any, input: NmapInput) -> list[Evidence]:
        settings = get_settings()
        items: list[Evidence] = []
        collected_at = datetime.now(timezone.utc)

        for host in scanner.all_hosts():
            host_data = scanner[host]
            state = host_data.state()
            hostname = host_data.hostname()

            if state != "up":
                continue

            for proto in host_data.all_protocols():
                for port, port_info in host_data[proto].items():
                    port_state = port_info.get("state", "")
                    if port_state != "open":
                        continue

                    prov = Provenance(
                        source_tool=SourceTool.NMAP,
                        collection_query=f"nmap {PROFILE_ARGS[input.profile]} {input.target}",
                        collected_at=collected_at,
                        analyst_id=input.analyst_id,
                        session_id=input.session_id,
                        raw_response={
                            "host": host,
                            "port": port,
                            "proto": proto,
                            "port_info": port_info,
                        },
                    )

                    # Open port claim
                    items.append(
                        Evidence(
                            target=host,
                            claim=f"Port {port}/{proto} open on {host} ({state})",
                            claim_type=ClaimType.OPEN_PORT,
                            value={
                                "ip": host,
                                "hostname": hostname,
                                "port": port,
                                "protocol": proto,
                                "state": port_state,
                            },
                            provenance=prov,
                            confidence=settings.confidence_weight_nmap,
                        )
                    )

                    # Service banner claim (when nmap detected a product)
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    if product:
                        banner = f"{product} {version}".strip()
                        items.append(
                            Evidence(
                                target=host,
                                claim=f"{banner} on {host}:{port}/{proto}",
                                claim_type=ClaimType.SERVICE_BANNER,
                                value={
                                    "ip": host,
                                    "port": port,
                                    "protocol": proto,
                                    "product": product,
                                    "version": version,
                                    "extrainfo": port_info.get("extrainfo", ""),
                                    "cpe": port_info.get("cpe", ""),
                                    "script_output": port_info.get("script", {}),
                                },
                                provenance=prov,
                                confidence=settings.confidence_weight_nmap,
                            )
                        )

        return items


async def nmap_scan_endpoint(
    inp: NmapInput,
    *,
    audit: AuditLogger,
    auth_service: AuthorizationService,
) -> NmapToolOutput:
    """HTTP handler: run Nmap adapter and return evidence list (or structured error)."""
    if inp.authorization_ref:
        audit.record(
            "nmap_authorization_ref",
            tool=SourceTool.NMAP.value,
            target=inp.target,
            ref=inp.authorization_ref[:500],
        )
    adapter = NmapAdapter(audit=audit, auth_service=auth_service)
    try:
        evidence = await adapter.run(inp)
    except ToolTimeoutError as exc:
        return NmapToolOutput(evidence=[], error=str(exc))
    except ToolExecutionError as exc:
        return NmapToolOutput(evidence=[], error=str(exc))
    return NmapToolOutput(evidence=evidence)
