"""
Structured audit logger.

Every tool call, pipeline stage transition, and authorization decision is
logged here.  The audit trail is append-only — events are never mutated.
Use `AuditLogger` everywhere a tool runs or an authorization decision is made;
never bypass it.
"""
from __future__ import annotations

import structlog
from datetime import datetime, timezone
from typing import Any

logger = structlog.get_logger("grond.audit")


class AuditEvent:
    # Collection
    TOOL_CALL_START = "tool_call_start"
    TOOL_CALL_SUCCESS = "tool_call_success"
    TOOL_CALL_FAILURE = "tool_call_failure"
    TOOL_CALL_RETRY = "tool_call_retry"

    # Authorization
    AUTHORIZATION_CHECK = "authorization_check"
    AUTHORIZATION_GRANTED = "authorization_granted"
    AUTHORIZATION_DENIED = "authorization_denied"
    UNAUTHORIZED_SCAN_ATTEMPT = "unauthorized_scan_attempt"

    # Pipeline
    PIPELINE_START = "pipeline_start"
    COLLECTION_COMPLETE = "collection_complete"
    ENRICHMENT_COMPLETE = "enrichment_complete"
    VERIFICATION_COMPLETE = "verification_complete"
    REPORT_GENERATED = "report_generated"

    # Access
    REPORT_ACCESSED = "report_accessed"


class AuditLogger:
    """
    Wrapper around structlog that enforces a consistent schema.

    Every record includes: event, analyst_id, session_id, timestamp, and
    optional tool/target/detail fields.
    """

    def __init__(self, analyst_id: str, session_id: str) -> None:
        self._analyst_id = analyst_id
        self._session_id = session_id
        self._log = logger.bind(
            analyst_id=analyst_id,
            session_id=session_id,
        )

    def record(
        self,
        event: str,
        *,
        tool: str | None = None,
        target: str | None = None,
        query: str | None = None,
        result_count: int | None = None,
        error: str | None = None,
        **extra: Any,
    ) -> None:
        fields: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        if tool is not None:
            fields["tool"] = tool
        if target is not None:
            fields["target"] = target
        if query is not None:
            fields["query"] = query
        if result_count is not None:
            fields["result_count"] = result_count
        if error is not None:
            fields["error"] = error
        fields.update(extra)

        if error:
            self._log.warning(event, **fields)
        else:
            self._log.info(event, **fields)

    # Convenience shorthands

    def tool_start(self, tool: str, target: str, query: str) -> None:
        self.record(AuditEvent.TOOL_CALL_START, tool=tool, target=target, query=query)

    def tool_success(self, tool: str, target: str, result_count: int) -> None:
        self.record(
            AuditEvent.TOOL_CALL_SUCCESS,
            tool=tool,
            target=target,
            result_count=result_count,
        )

    def tool_failure(self, tool: str, target: str, error: str) -> None:
        self.record(AuditEvent.TOOL_CALL_FAILURE, tool=tool, target=target, error=error)

    def unauthorized_attempt(self, tool: str, target: str) -> None:
        self.record(
            AuditEvent.UNAUTHORIZED_SCAN_ATTEMPT,
            tool=tool,
            target=target,
            error="No authorization record found",
        )
