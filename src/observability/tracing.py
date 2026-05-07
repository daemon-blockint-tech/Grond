"""
Convenience helpers for manual tracing in pipeline code.

Usage:
    async with pipeline_span("pipeline.verify", target=target, session=session_id):
        ...
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Any

import structlog
from opentelemetry import trace
from opentelemetry.trace import StatusCode

log = structlog.get_logger(__name__)


def _tracer() -> trace.Tracer:
    return trace.get_tracer("grond-api", "0.2.0")


@asynccontextmanager
async def pipeline_span(
    name: str, **attributes: Any
) -> AsyncGenerator[trace.Span, None]:
    """Context manager that starts a named OTel span with optional attributes."""
    tracer = _tracer()
    with tracer.start_as_current_span(name) as span:
        for k, v in attributes.items():
            span.set_attribute(k, str(v))
        try:
            yield span
            span.set_status(StatusCode.OK)
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            log.error("pipeline_span.error", span=name, error=str(exc))
            raise
