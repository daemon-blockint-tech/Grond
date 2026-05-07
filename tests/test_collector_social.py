"""Collector Tavily query planning for social / general profiles."""

from __future__ import annotations

from src.pipeline.collector import CollectionRequest, goal_suggests_public_social


def test_goal_suggests_reddit() -> None:
    assert goal_suggests_public_social("What is Reddit saying about the breach?")


def test_effective_tavily_queries_social_profile_adds_site_scoped() -> None:
    req = CollectionRequest(
        target="Acme",
        goal="general news",
        analyst_id="a",
        session_id="s",
        investigation_profile="social",
        run_shodan=False,
        run_tavily=False,
    )
    qs = req.effective_tavily_queries()
    assert any("reddit.com" in q for q in qs)


def test_effective_queries_general_with_goal_hint() -> None:
    req = CollectionRequest(
        target="Acme",
        goal="Summarize twitter chatter",
        analyst_id="a",
        session_id="s",
        investigation_profile="general",
        run_shodan=False,
        run_tavily=False,
    )
    qs = req.effective_tavily_queries()
    assert any("reddit.com" in q or "x.com" in q for q in qs)


def test_company_profile_skips_social_even_if_goal_mentions_twitter() -> None:
    req = CollectionRequest(
        target="Acme",
        goal="twitter chatter",
        analyst_id="a",
        session_id="s",
        investigation_profile="company",
        run_shodan=False,
        run_tavily=False,
    )
    qs = req.effective_tavily_queries()
    assert not any("reddit.com" in q for q in qs)
