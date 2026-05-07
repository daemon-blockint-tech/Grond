"""
Authorization service.

Active scans (Nmap, Ncrack) must never run without an authorization record.
This module provides a simple in-process store for development and an
interface for production database-backed authorization.

Usage (in every active tool adapter):

    await require_authorization(target, analyst_id, tool, audit_log)
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.core.audit import AuditEvent, AuditLogger
from src.core.exceptions import UnauthorizedScanError

if TYPE_CHECKING:
    from src.core.config import Settings


@dataclass
class AuthorizationRecord:
    target: str  # IP, CIDR, or domain
    analyst_id: str
    tool: str  # "nmap" | "ncrack" | "*" for all
    authorized_at: datetime
    expires_at: datetime | None = None
    legal_ref: str = ""  # e.g. "SOW-2024-001 §3.2"
    notes: str = ""


class AuthorizationService:
    """
    In-process authorization store (swap for a DB-backed implementation in prod).

    Matching rules (in order):
    1. Exact IP / hostname match (hostnames compared case-insensitively)
    2. CIDR range containment when both sides parse as IP/network
    3. **Hostname scope**: authorized ``customer.test`` matches ``customer.test`` and
       ``api.customer.test`` (suffix after a dot). Does not match ``othercustomer.test``.
    4. **Wildcard host**: authorized ``*.customer.test`` matches subdomains only
       (e.g. ``api.customer.test``), not the apex ``customer.test``.
    5. Wildcard tool ("*") matches any tool
    6. Record analyst_id "*" matches any analyst (use sparingly; env CSV grants only)
    7. Expired records are rejected

    If ``requested`` is a literal IP address, only exact match and CIDR rules apply
    (no suffix wildcard).
    """

    def __init__(self) -> None:
        self._records: list[AuthorizationRecord] = []

    def grant(self, record: AuthorizationRecord) -> None:
        self._records.append(record)

    def is_authorized(self, target: str, analyst_id: str, tool: str) -> bool:
        now = datetime.now(UTC)
        for r in self._records:
            if r.expires_at and r.expires_at < now:
                continue
            if r.analyst_id != analyst_id and r.analyst_id != "*":
                continue
            if r.tool not in (tool, "*"):
                continue
            if self._target_matches(r.target, target):
                return True
        return False

    @staticmethod
    def _target_matches(authorized: str, requested: str) -> bool:
        auth = (authorized or "").strip()
        req = (requested or "").strip()
        if not auth or not req:
            return False
        if auth == req:
            return True

        try:
            network = ipaddress.ip_network(auth, strict=False)
            addr = ipaddress.ip_address(req)
            return addr in network
        except ValueError:
            pass

        try:
            ipaddress.ip_address(req)
            return False
        except ValueError:
            pass

        req_h = req.casefold()
        auth_h = auth.casefold()
        if auth_h == req_h:
            return True

        if auth_h.startswith("*.") and len(auth_h) > 2:
            suffix = auth_h[2:].strip(".")
            if not suffix:
                return False
            if req_h == suffix:
                return False
            return req_h.endswith("." + suffix)

        return req_h.endswith("." + auth_h)

    @classmethod
    def with_settings_grants(cls, settings: Settings) -> AuthorizationService:
        """
        Empty store plus grants parsed from ``settings.grond_authorized_scan_targets``.

        Each CSV token becomes an ``AuthorizationRecord`` with ``analyst_id="*"`` and
        ``tool="nmap"``.

        Tokens may be: IPv4/IPv6, CIDR, hostname, ``*.sub.example.com`` (subdomains only), or a
        registrable-style hostname that also authorizes subdomains (``example.com`` matches
        ``api.example.com``). Use narrow scopes in production.
        """
        svc = cls()
        raw = (settings.grond_authorized_scan_targets or "").strip()
        if not raw:
            return svc
        now = datetime.now(UTC)
        for part in raw.split(","):
            t = part.strip()
            if not t:
                continue
            svc.grant(
                AuthorizationRecord(
                    target=t,
                    analyst_id="*",
                    tool="nmap",
                    authorized_at=now,
                    notes="GROND_AUTHORIZED_SCAN_TARGETS",
                )
            )
        return svc


async def require_authorization(
    target: str,
    analyst_id: str,
    tool: str,
    audit: AuditLogger,
    auth_service: AuthorizationService,
) -> None:
    """
    Raise `UnauthorizedScanError` if there is no valid authorization record.

    Must be called at the top of every active tool adapter's `execute()`.
    The audit log entry is written regardless of outcome.
    """
    audit.record(AuditEvent.AUTHORIZATION_CHECK, tool=tool, target=target)

    if not auth_service.is_authorized(target=target, analyst_id=analyst_id, tool=tool):
        audit.unauthorized_attempt(tool=tool, target=target)
        raise UnauthorizedScanError(target=target, analyst_id=analyst_id, tool=tool)

    audit.record(AuditEvent.AUTHORIZATION_GRANTED, tool=tool, target=target)
