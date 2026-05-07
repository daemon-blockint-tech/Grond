"""
Twitter / X OSINT adapter for Grond.

Wraps the X API v2 search endpoints with:
  - Full claim-evidence binding (URL, timestamp, raw_snippet, extractor)
  - Source tier assignment (COMMUNITY by default; upgraded for verified accounts)
  - Operator builder integration (see twitter_query_builder.py)
  - Rate-limit aware retry with exponential back-off
  - Structured provenance for every tweet

API Reference:
  GET /2/tweets/search/recent    — last 7 days, free tier
  GET /2/tweets/search/all       — full archive, Academic/Enterprise access
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from src.core.config import get_settings
from src.core.exceptions import ToolError, ToolRateLimitError
from src.models.evidence import (
    ClaimType,
    ConfidenceComponents,
    Evidence,
    Provenance,
    SourceTier,
    SourceTool,
    TIER_RELIABILITY,
)
from src.tools.base import ToolAdapter, ToolInput, ToolOutput
from src.tools.twitter_query_builder import (
    OsintIntent,
    TwitterOsintTemplates,
    TwitterQueryBuilder,
)

log = structlog.get_logger(__name__)

_X_API_BASE = "https://api.twitter.com/2"
_TWEET_FIELDS = "id,text,author_id,created_at,public_metrics,entities,possibly_sensitive"
_USER_FIELDS = "id,name,username,verified,public_metrics,description"
_EXPANSIONS = "author_id"


# ---------------------------------------------------------------------------
# Input / output schemas
# ---------------------------------------------------------------------------

class TwitterInput(ToolInput):
    query: str                            # raw X API v2 query string OR intent key
    intent: OsintIntent | None = None     # if set, templates override raw query
    target: str = ""                      # the entity being investigated
    max_results: int = 100                # 10-100 for recent, 10-500 for full archive
    full_archive: bool = False            # requires Academic/Pro tier bearer token
    # Optional Bellingcat-style filter overrides
    language: str | None = None
    since: str | None = None             # YYYY-MM-DD
    until: str | None = None             # YYYY-MM-DD
    min_likes: int = 0
    min_retweets: int = 0
    min_replies: int = 0
    exclude_retweets: bool = True
    has_media: bool = False
    from_accounts: list[str] = []
    to_accounts: list[str] = []
    mentions: list[str] = []
    # Optional geo (Bellingcat location operators); radius clamped to 25 mi in builder
    near_place: str | None = None  # slug e.g. estes-park or quoted multi-word via builder
    within_radius: str | None = None  # e.g. "2mi", "10km"; applies with near_place or as fallback for geocode
    geocode_lat: float | None = None
    geocode_lon: float | None = None
    geocode_radius: str | None = None  # e.g. "10mi"; defaults with coordinates


def _apply_optional_geo(inp: TwitterInput, builder: TwitterQueryBuilder) -> None:
    """Append ``near:`` / ``geocode:`` clauses from API fields (not used when intent is geo_event — template consumes geo there)."""
    if inp.geocode_lat is not None and inp.geocode_lon is not None:
        radius = inp.geocode_radius or inp.within_radius or "25mi"
        builder.geocode(inp.geocode_lat, inp.geocode_lon, radius)
    elif inp.near_place:
        builder.near(inp.near_place, inp.within_radius or "25mi")


class TwitterOutput(ToolOutput):
    tweets: list[dict[str, Any]]          # raw tweet objects
    total_found: int = 0
    query_used: str = ""
    endpoint: str = ""


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class TwitterAdapter(ToolAdapter[TwitterInput, TwitterOutput]):
    """
    Grond adapter for X API v2 tweet search.

    Maps each tweet to an Evidence item with fully populated Provenance,
    following the Bellingcat OSINT methodology for source evaluation.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._bearer_token: str = self._settings.twitter_bearer_token

    # ------------------------------------------------------------------
    # ToolAdapter interface
    # ------------------------------------------------------------------

    async def execute(self, inp: TwitterInput) -> TwitterOutput:
        query = self._resolve_query(inp)
        log.info("twitter.search", query=query, full_archive=inp.full_archive)

        endpoint = (
            f"{_X_API_BASE}/tweets/search/all"
            if inp.full_archive
            else f"{_X_API_BASE}/tweets/search/recent"
        )

        params: dict[str, Any] = {
            "query": query,
            "max_results": min(inp.max_results, 100 if not inp.full_archive else 500),
            "tweet.fields": _TWEET_FIELDS,
            "user.fields": _USER_FIELDS,
            "expansions": _EXPANSIONS,
        }
        if inp.since:
            params["start_time"] = f"{inp.since}T00:00:00Z"
        if inp.until:
            params["end_time"] = f"{inp.until}T23:59:59Z"

        raw = await self._get(endpoint, params)

        tweets: list[dict[str, Any]] = raw.get("data", [])
        users: dict[str, dict] = {
            u["id"]: u for u in raw.get("includes", {}).get("users", [])
        }

        # Attach user info to each tweet for downstream enrichment
        for tweet in tweets:
            author = users.get(tweet.get("author_id", ""), {})
            tweet["_author"] = author

        log.info("twitter.results", count=len(tweets), query=query)
        return TwitterOutput(
            tweets=tweets,
            total_found=raw.get("meta", {}).get("result_count", len(tweets)),
            query_used=query,
            endpoint=endpoint,
        )

    def to_evidence(self, output: TwitterOutput, target: str) -> list[Evidence]:
        """Convert tweet results into Evidence items with full provenance."""
        items: list[Evidence] = []
        for tweet in output.tweets:
            ev = self._tweet_to_evidence(tweet, target)
            if ev:
                items.append(ev)
        return items

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_query(self, inp: TwitterInput) -> str:
        """
        Build a final X API v2 query string.

        Priority:
          1. If an intent is set, use the matching template builder
          2. Otherwise, start from the raw query and apply any extra filters
        """
        if inp.intent:
            templates = self._templates_for_intent(inp)
            # Use first template; caller can invoke multiple times for full coverage
            builder = templates[0] if templates else TwitterQueryBuilder().all_words(inp.target)
        else:
            # Start from raw query, applying any explicit filters
            builder = TwitterQueryBuilder()
            if inp.query:
                builder._parts.append(inp.query)

        # Apply optional overrides from input
        if inp.language:
            builder.language(inp.language)
        if inp.since:
            builder.since(inp.since)
        if inp.until:
            builder.until(inp.until)
        if inp.min_likes:
            builder.min_likes(inp.min_likes)
        if inp.min_retweets:
            builder.min_retweets(inp.min_retweets)
        if inp.min_replies:
            builder.min_replies(inp.min_replies)
        if inp.exclude_retweets:
            builder.exclude_retweets()
        if inp.has_media:
            builder.has_media()
        for h in inp.from_accounts:
            builder.from_account(h)
        for h in inp.to_accounts:
            builder.to_account(h)
        for h in inp.mentions:
            builder.mentions(h)

        if inp.intent != "geo_event":
            _apply_optional_geo(inp, builder)

        return builder.build()

    def _templates_for_intent(self, inp: TwitterInput) -> list[TwitterQueryBuilder]:
        """Map an OsintIntent to the appropriate template factory."""
        intent = inp.intent
        target = inp.target

        if intent == "company_monitoring":
            return TwitterOsintTemplates.company_mentions(
                target,
                days_back=30,
            )
        elif intent == "person_research":
            return TwitterOsintTemplates.person_research(target)
        elif intent == "hashtag_campaign":
            return TwitterOsintTemplates.hashtag_campaign(target, language=inp.language)
        elif intent == "geo_event":
            lat_lon: tuple[float, float] | None = None
            if inp.geocode_lat is not None and inp.geocode_lon is not None:
                lat_lon = (inp.geocode_lat, inp.geocode_lon)
            radius = inp.geocode_radius or inp.within_radius or "25km"
            return TwitterOsintTemplates.geo_event(
                [target] if target else [],
                location=None if lat_lon else inp.near_place,
                lat_lon=lat_lon,
                radius=radius,
            )
        elif intent == "breach_leak_monitor":
            return TwitterOsintTemplates.breach_leak_monitor(target)
        elif intent == "account_network":
            return TwitterOsintTemplates.account_network(target)
        elif intent == "disinformation_tracking":
            return TwitterOsintTemplates.disinformation_tracking(target)
        else:
            return [TwitterQueryBuilder().all_words(target)]

    def _tweet_to_evidence(
        self, tweet: dict[str, Any], target: str
    ) -> Evidence | None:
        """
        Map a single tweet to an Evidence item.

        Source tier logic (Bellingcat provenance principle):
          - Verified account → MEDIA (establishes authority tier)
          - Default              → COMMUNITY
          - Sensitive content    → ANONYMOUS (extra scrutiny)
        """
        tweet_id = tweet.get("id", "")
        text: str = tweet.get("text", "")
        created_at_raw: str = tweet.get("created_at", "")
        author = tweet.get("_author", {})
        handle: str = author.get("username", "unknown")
        is_verified: bool = author.get("verified", False)
        is_sensitive: bool = tweet.get("possibly_sensitive", False)
        metrics: dict = tweet.get("public_metrics", {})

        if not tweet_id or not text:
            return None

        # Build permanent link
        tweet_url = f"https://x.com/{handle}/status/{tweet_id}"

        # Determine source tier
        if is_sensitive:
            tier = SourceTier.ANONYMOUS
        elif is_verified:
            tier = SourceTier.MEDIA
        else:
            tier = SourceTier.COMMUNITY

        # Determine claim type from content signals
        claim_type = self._infer_claim_type(text, tweet, target)

        # Parse timestamp
        try:
            collected_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            collected_at = datetime.now(UTC)

        provenance = Provenance(
            tool=SourceTool.TWITTER,
            collected_at=collected_at,
            source_url=tweet_url,
            raw_snippet=text[:500],             # Bellingcat: preserve raw snippet
            extractor="twitter_adapter_v2",
            source_tier=tier,
        )

        # Build value dict aligned to CLAIM_VALUE_KEYS
        value: dict[str, Any] = {
            "tweet_id": tweet_id,
            "author_handle": handle,
            "text": text,
            "url": tweet_url,
            "created_at": created_at_raw,
            "likes": metrics.get("like_count", 0),
            "retweets": metrics.get("retweet_count", 0),
            "replies": metrics.get("reply_count", 0),
            "author_verified": is_verified,
            "author_followers": author.get("public_metrics", {}).get("followers_count", 0),
        }

        if claim_type == ClaimType.MEDIA_MENTION:
            value["media_url"] = self._extract_media_url(tweet)

        # Bootstrap confidence from tier reliability only
        # (full 4-component scoring happens in Verifier)
        tier_score = TIER_RELIABILITY[tier]
        initial_confidence = ConfidenceComponents(
            source_reliability=tier_score,
            cross_source_agreement=0.5,       # unknown until Verifier runs
            freshness=1.0,                    # just collected
            evidence_completeness=0.5,
            w_s=0.35, w_c=0.25, w_t=0.20, w_e=0.20,
        )

        return Evidence(
            target=target,
            claim_type=claim_type,
            value=value,
            confidence=initial_confidence.total,
            confidence_components=initial_confidence,
            provenance=[provenance],
        )

    @staticmethod
    def _infer_claim_type(
        text: str, tweet: dict[str, Any], target: str
    ) -> ClaimType:
        """
        Heuristic claim type inference based on tweet content.

        Follows the Bellingcat principle: label before you lose context.
        """
        text_lower = text.lower()
        has_media = bool(tweet.get("attachments", {}).get("media_keys"))

        breach_keywords = {"breach", "leak", "dump", "exposed", "hacked", "pwned", "stolen"}
        if any(kw in text_lower for kw in breach_keywords):
            return ClaimType.CREDENTIAL_EXPOSURE

        if has_media:
            return ClaimType.MEDIA_MENTION

        # Hashtag-heavy post
        entities = tweet.get("entities", {})
        hashtags = entities.get("hashtags", [])
        if len(hashtags) >= 3:
            return ClaimType.HASHTAG_ACTIVITY

        # Default: generic mention
        return ClaimType.SOCIAL_POST

    @staticmethod
    def _extract_media_url(tweet: dict[str, Any]) -> str:
        """Best-effort media URL extraction from tweet entity data."""
        entities = tweet.get("entities", {})
        urls = entities.get("urls", [])
        for u in urls:
            expanded = u.get("expanded_url", "")
            if any(domain in expanded for domain in ("pic.twitter.com", "t.co", "pbs.twimg")):
                return expanded
        return ""

    async def _get(
        self, url: str, params: dict[str, Any], retries: int = 3
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._bearer_token}"}
        last_exc: Exception | None = None

        async with httpx.AsyncClient(timeout=30.0) as client:
            for attempt in range(retries):
                try:
                    resp = await client.get(url, params=params, headers=headers)

                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("retry-after", 60))
                        log.warning("twitter.rate_limited", retry_after=retry_after)
                        raise ToolRateLimitError(
                            f"X API rate limit — retry after {retry_after}s"
                        )

                    if resp.status_code == 401:
                        raise ToolError("X API auth failed — check TWITTER_BEARER_TOKEN")

                    resp.raise_for_status()
                    return resp.json()

                except ToolRateLimitError:
                    raise
                except httpx.HTTPStatusError as exc:
                    last_exc = exc
                    wait = 2**attempt
                    log.warning("twitter.http_error", status=exc.response.status_code, attempt=attempt, wait=wait)
                    await asyncio.sleep(wait)
                except httpx.RequestError as exc:
                    last_exc = exc
                    wait = 2**attempt
                    log.warning("twitter.request_error", error=str(exc), attempt=attempt)
                    await asyncio.sleep(wait)

        raise ToolError(f"X API request failed after {retries} attempts: {last_exc}")


# ---------------------------------------------------------------------------
# FastAPI endpoint helper
# (register in src/api/main.py as: /tools/twitter/search)
# ---------------------------------------------------------------------------

async def twitter_search_endpoint(inp: TwitterInput) -> TwitterOutput:
    """
    FastAPI-compatible handler that the TypeScript orchestrator calls via HTTP.
    Returns raw TwitterOutput; the TS layer decides whether to convert to Evidence.
    """
    adapter = TwitterAdapter()
    return await adapter.execute(inp)
