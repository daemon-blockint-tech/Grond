"""Typed exception hierarchy for Grond.

Every external failure is converted to one of these before propagating up the
pipeline.  This means callers never need to know which third-party library was
used — they catch `ToolExecutionError` and inspect `.tool`.
"""
from __future__ import annotations


class GrondError(Exception):
    """Base class for all Grond exceptions."""


# ---------------------------------------------------------------------------
# Tool / adapter layer
# ---------------------------------------------------------------------------


class ToolExecutionError(GrondError):
    """A tool adapter failed to collect evidence."""

    def __init__(self, tool: str, message: str, cause: Exception | None = None) -> None:
        self.tool = tool
        self.message = message
        self.cause = cause
        super().__init__(f"[{tool}] {message}")


class ToolRateLimitError(ToolExecutionError):
    """The external API returned a rate-limit response."""


class ToolAuthError(ToolExecutionError):
    """The API key or credentials were rejected."""


class ToolTimeoutError(ToolExecutionError):
    """The tool cap timed out before completion."""


class ToolError(ToolExecutionError):
    """Recoverable tool failure (often returned to clients as a structured error)."""


# ---------------------------------------------------------------------------
# Authorization layer
# ---------------------------------------------------------------------------


class UnauthorizedScanError(GrondError):
    """Active scan attempted without a valid authorization record."""

    def __init__(self, target: str, analyst_id: str, tool: str) -> None:
        self.target = target
        self.analyst_id = analyst_id
        self.tool = tool
        super().__init__(
            f"No authorization on record for active scan: "
            f"target={target} analyst={analyst_id} tool={tool}"
        )


# ---------------------------------------------------------------------------
# Pipeline layer
# ---------------------------------------------------------------------------


class CollectionError(GrondError):
    """One or more collectors failed during the collection stage."""

    def __init__(self, failures: dict[str, str]) -> None:
        self.failures = failures
        detail = ", ".join(f"{k}={v}" for k, v in failures.items())
        super().__init__(f"Collection stage failures: {detail}")


class VerificationError(GrondError):
    """The verification stage encountered an unrecoverable error."""


class ReportGenerationError(GrondError):
    """Report could not be generated from the available evidence."""


class PipelineInputError(GrondError):
    """Planner or early pipeline validation failed (bad request inputs)."""


class ActiveScanApprovalRequiredError(GrondError):
    """
    Active scan was requested but the run cannot complete human-in-the-loop approval.

    Typical for synchronous HTTP callers: LangGraph emits an interrupt that only a
    checkpoint resume can satisfy.
    """


class PipelineAbortedError(GrondError):
    """Pipeline finished without an ``IntelReport`` for an unexpected reason."""
