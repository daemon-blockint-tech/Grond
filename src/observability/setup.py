"""
OpenTelemetry + Sentry bootstrap for the Python FastAPI service.

Call `configure_telemetry()` once at application startup (lifespan hook).
All FastAPI requests, httpx calls, and SQLAlchemy queries are auto-instrumented.
"""

from __future__ import annotations

import os

import sentry_sdk
import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

log = structlog.get_logger(__name__)


def configure_telemetry(app=None) -> None:  # type: ignore[no-untyped-def]
    """Bootstrap OpenTelemetry tracing and Sentry error tracking."""
    _setup_otel()
    _setup_sentry()
    if app is not None:
        FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor().instrument()
    SQLAlchemyInstrumentor().instrument()
    log.info("telemetry.configured")


def _setup_otel() -> None:
    endpoint = os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces"
    )
    resource = Resource.create(
        {
            "service.name": "grond-api",
            "service.version": "0.2.0",
            "deployment.environment": os.environ.get("ENVIRONMENT", "development"),
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    log.info("otel.configured", endpoint=endpoint)


def _setup_sentry() -> None:
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return
    sentry_sdk.init(
        dsn=dsn,
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.1")),
        environment=os.environ.get("ENVIRONMENT", "development"),
        release=f"grond@0.2.0",
    )
    log.info("sentry.configured")
