"""PostgreSQL persistence for active-scan authorization grants (Nmap, etc.)."""

from __future__ import annotations

import uuid
from datetime import datetime

import asyncpg

from src.core.authorization import AuthorizationRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS grond_active_scan_authorization (
    id UUID PRIMARY KEY,
    target TEXT NOT NULL,
    analyst_id TEXT NOT NULL DEFAULT '*',
    tool TEXT NOT NULL DEFAULT 'nmap',
    legal_ref TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    authorized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS idx_grond_active_scan_auth_expires
    ON grond_active_scan_authorization (expires_at);
"""


def _normalize_dsn(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://")


async def ensure_active_scan_auth_table(conn: asyncpg.Connection) -> None:
    await conn.execute(_SCHEMA)


async def load_active_scan_grants(database_url: str) -> list[AuthorizationRecord]:
    """Return non-expired rows as AuthorizationRecord (for merging into AuthorizationService)."""
    dsn = _normalize_dsn(database_url)
    conn = await asyncpg.connect(dsn)
    try:
        await ensure_active_scan_auth_table(conn)
        rows = await conn.fetch(
            """
            SELECT target, analyst_id, tool, legal_ref, notes, authorized_at, expires_at
            FROM grond_active_scan_authorization
            WHERE expires_at IS NULL OR expires_at > NOW()
            """,
        )
        out: list[AuthorizationRecord] = []
        for r in rows:
            out.append(
                AuthorizationRecord(
                    target=r["target"],
                    analyst_id=r["analyst_id"],
                    tool=r["tool"],
                    authorized_at=r["authorized_at"],
                    expires_at=r["expires_at"],
                    legal_ref=r["legal_ref"] or "",
                    notes=r["notes"] or "",
                )
            )
        return out
    finally:
        await conn.close()


async def insert_active_scan_grant(
    database_url: str,
    *,
    target: str,
    analyst_id: str,
    tool: str,
    legal_ref: str,
    notes: str,
    expires_at: datetime | None,
) -> uuid.UUID:
    row_id = uuid.uuid4()
    dsn = _normalize_dsn(database_url)
    conn = await asyncpg.connect(dsn)
    try:
        await ensure_active_scan_auth_table(conn)
        await conn.execute(
            """
            INSERT INTO grond_active_scan_authorization
                (id, target, analyst_id, tool, legal_ref, notes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            row_id,
            target.strip(),
            analyst_id.strip() or "*",
            tool.strip() or "nmap",
            legal_ref.strip(),
            notes.strip(),
            expires_at,
        )
    finally:
        await conn.close()
    return row_id
