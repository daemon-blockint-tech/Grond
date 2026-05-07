"""
Abstract ToolAdapter base class.

Every external data source is wrapped as a ToolAdapter with:
- Typed input  (Pydantic model — validated before execution)
- Typed output (list[Evidence] — validated after execution)
- Retry with exponential backoff
- Structured audit logging on every call
- Rate limiting via a per-adapter token bucket

Downstream pipeline stages only import ToolAdapter, never the third-party
library directly.  This isolates the blast radius of API changes.
"""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

import structlog
from pydantic import BaseModel

from src.core.audit import AuditLogger
from src.core.exceptions import ToolError, ToolExecutionError, ToolRateLimitError, ToolTimeoutError
from src.models.evidence import Evidence

log = structlog.get_logger("grond.tools")

InputT = TypeVar("InputT", bound=BaseModel)


# ---------------------------------------------------------------------------
# Simple async token-bucket rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Leaky-bucket limiter: `rate_rps` calls per second, burst of 1."""

    def __init__(self, rate_rps: float) -> None:
        self._interval = 1.0 / rate_rps
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


# ---------------------------------------------------------------------------
# ToolAdapter ABC
# ---------------------------------------------------------------------------


class ToolAdapter(ABC, Generic[InputT]):
    """
    Base class for all OSINT tool wrappers.

    Subclasses implement `_execute()` and return raw Evidence objects.
    `run()` handles retry, rate limiting, audit logging, and error conversion.
    """

    tool_name: str  # must be set by each subclass
    _MAX_RETRIES: int = 3
    _BASE_BACKOFF: float = 1.0  # seconds; doubles on each retry

    def __init__(self, audit: AuditLogger, rate_limiter: RateLimiter | None = None) -> None:
        self._audit = audit
        self._rate_limiter = rate_limiter
        self._log = log.bind(tool=self.tool_name)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self, input: InputT) -> list[Evidence]:
        """
        Execute the tool with retry and rate limiting.

        Returns a (possibly empty) list of Evidence items.
        Raises `ToolExecutionError` (or a subclass) after all retries are
        exhausted — callers must catch this and decide whether to abort or
        continue with partial results.
        """
        target = getattr(input, "target", "<unknown>")
        query = getattr(input, "query", str(input))

        self._audit.tool_start(tool=self.tool_name, target=target, query=query)

        last_exc: Exception | None = None
        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                if self._rate_limiter:
                    await self._rate_limiter.acquire()
                results = await self._execute(input)
                self._audit.tool_success(
                    tool=self.tool_name, target=target, result_count=len(results)
                )
                return results

            except ToolRateLimitError as exc:
                self._audit.record(
                    "tool_call_retry",
                    tool=self.tool_name,
                    attempt=attempt,
                    reason="rate_limit",
                    error=str(exc),
                )
                backoff = self._BASE_BACKOFF * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)
                last_exc = exc

            except ToolTimeoutError as exc:
                self._audit.tool_failure(
                    tool=self.tool_name, target=target, error=str(exc)
                )
                raise  # timeouts are not retried

            except ToolError as exc:
                self._audit.tool_failure(
                    tool=self.tool_name, target=target, error=str(exc)
                )
                raise  # validation / policy — do not retry

            except ToolExecutionError as exc:
                self._audit.tool_failure(
                    tool=self.tool_name, target=target, error=str(exc)
                )
                if attempt < self._MAX_RETRIES:
                    backoff = self._BASE_BACKOFF * (2 ** (attempt - 1))
                    self._log.warning(
                        "retrying after error",
                        attempt=attempt,
                        backoff=backoff,
                        error=str(exc),
                    )
                    await asyncio.sleep(backoff)
                last_exc = exc

        # All retries exhausted
        raise ToolExecutionError(
            tool=self.tool_name,
            message=f"All {self._MAX_RETRIES} retries failed",
            cause=last_exc,
        )

    # ------------------------------------------------------------------
    # Subclass contract
    # ------------------------------------------------------------------

    @abstractmethod
    async def _execute(self, input: InputT) -> list[Evidence]:
        """
        Perform the actual API call / subprocess and return Evidence items.

        - Map every claim to exactly one Evidence object.
        - Set `provenance.raw_response` to the unmodified API payload.
        - Set `confidence` using source defaults (see Settings).
        - Do NOT aggregate, filter, or enrich here — that is pipeline work.
        """
        ...
