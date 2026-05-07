"""Tavily social-style search paths (mocked client — no network)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.core.audit import AuditLogger
from src.tools.tavily_tool import (
    TavilyAdapter,
    TavilyInput,
    build_public_social_tavily_queries,
    resolve_tavily_search_query,
)


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    from src.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _audit() -> AuditLogger:
    return AuditLogger(analyst_id="analyst-1", session_id="sess-1")


def test_build_public_social_includes_reddit() -> None:
    qs = build_public_social_tavily_queries("Acme")
    assert any("reddit.com" in q for q in qs)


def test_resolve_social_platform_query() -> None:
    inp = TavilyInput(
        target="Acme",
        query="ignored when platform set",
        analyst_id="a",
        session_id="s",
        investigation_profile="social",
        platform="reddit",
    )
    assert "site:reddit.com" in resolve_tavily_search_query(inp)


@patch.dict(
    "os.environ",
    {
        "SHODAN_API_KEY": "test",
        "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test",
        "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    },
)
async def test_adapter_passes_time_range_and_social_topic() -> None:
    with patch("tavily.TavilyClient") as MockClient:
        mock_inst = MagicMock()
        mock_inst.search.return_value = {"results": []}
        MockClient.return_value = mock_inst

        adapter = TavilyAdapter(audit=_audit(), api_key="k")
        inp = TavilyInput(
            target="t",
            query="q",
            analyst_id="a",
            session_id="s",
            investigation_profile="social",
            time_range="week",
        )
        await adapter.run(inp)

    mock_inst.search.assert_called_once()
    kw = mock_inst.search.call_args.kwargs
    assert kw.get("time_range") == "week"
    assert kw.get("topic") == "general"


@patch.dict(
    "os.environ",
    {
        "SHODAN_API_KEY": "test",
        "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test",
        "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    },
)
async def test_adapter_company_profile_no_forced_topic() -> None:
    with patch("tavily.TavilyClient") as MockClient:
        mock_inst = MagicMock()
        mock_inst.search.return_value = {"results": []}
        MockClient.return_value = mock_inst

        adapter = TavilyAdapter(audit=_audit(), api_key="k")
        inp = TavilyInput(
            target="t",
            query="q",
            analyst_id="a",
            session_id="s",
            investigation_profile="company",
        )
        await adapter.run(inp)

    kw = mock_inst.search.call_args.kwargs
    assert "topic" not in kw
