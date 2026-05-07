"""
Twitter / X Advanced Search query builder.

Implements the full operator set documented by Bellingcat:
  https://bellingcat.gitbook.io/toolkit/more/all-tools/twitter-advanced-search

And the extended operator reference:
  https://github.com/igorbrigadir/twitter-advanced-search

The builder produces valid X API v2 search query strings.
All methods are pure functions — no I/O, no side effects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Literal

# X Standard Search / operator docs: `geocode:` radius is capped at 25 miles maximum.
# Bellingcat location guide: https://bellingcat.gitbook.io/toolkit/more/all-tools/twitter-location-search
MAX_X_API_GEOCODE_RADIUS_MI = 25
_MAX_WITHIN_KM = MAX_X_API_GEOCODE_RADIUS_MI / 0.621371  # 25 mi in km (~40.23 km)


def within_miles(miles: float) -> str:
    """
    Return a `within:` radius string in miles, clamped to X API max (25 mi).

    Use with `near:` / `geocode:` — combine e.g. `near:chicago` + `within:2mi`.
    """
    m = min(max(float(miles), 0.0), float(MAX_X_API_GEOCODE_RADIUS_MI))
    part = str(int(m)) if m.is_integer() else str(m)
    return f"{part}mi"


def within_km(km: float) -> str:
    """Return a `within:` radius string in km, clamped to the km equivalent of 25 mi."""
    k = min(max(float(km), 0.0), _MAX_WITHIN_KM)
    part = str(int(k)) if k.is_integer() else str(k)
    return f"{part}km"


def clamp_within_radius_str(radius: str) -> str:
    """
    Normalize `within:` / `geocode:` radius strings (e.g. ``10mi``, ``25 km``) and
    clamp to the X API maximum (25 mi).
    """
    s = radius.strip().lower().replace(" ", "")
    m = re.match(r"^([\d.]+)(mi|km)$", s)
    if not m:
        return radius.strip()
    val = float(m.group(1))
    unit = m.group(2)
    return within_miles(val) if unit == "mi" else within_km(val)


# ---------------------------------------------------------------------------
# OSINT intent categories
# Based on Bellingcat's documented use cases for Twitter OSINT
# ---------------------------------------------------------------------------

OsintIntent = Literal[
    "company_monitoring",     # Track what's being said about a company
    "person_research",        # Find mentions of / by a specific person
    "hashtag_campaign",       # Map a hashtag or movement (e.g., protest tracking)
    "geo_event",              # Locate and document a real-world event
    "disinformation_tracking",# Track narrative spread and coordinated behaviour
    "breach_leak_monitor",    # Detect credential dumps or data leak announcements
    "sentiment_analysis",     # Gauge public reaction to an entity or event
    "media_evidence",         # Find image/video evidence of a specific event
    "account_network",        # Map interactions between accounts
]


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

@dataclass
class TwitterQueryBuilder:
    """
    Fluent builder for X API v2 search queries.

    Implements every operator from the Bellingcat advanced search guide
    plus the extended igorbrigadir operator reference.

    Usage:
        q = (
            TwitterQueryBuilder()
            .all_words("nginx", "apache")
            .exact_phrase("data breach")
            .from_account("troyhunt")
            .since(date(2024, 1, 1))
            .min_likes(100)
            .has_links()
            .exclude_retweets()
            .build()
        )
    """

    _parts: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # WORDS operators (Bellingcat §WORDS)
    # ------------------------------------------------------------------

    def all_words(self, *words: str) -> "TwitterQueryBuilder":
        """All of these words must appear (implicit AND)."""
        for w in words:
            self._parts.append(_quote_if_needed(w))
        return self

    def exact_phrase(self, phrase: str) -> "TwitterQueryBuilder":
        """Exact phrase match — equivalent to "quoted search"."""
        self._parts.append(f'"{phrase}"')
        return self

    def any_word(self, *words: str) -> "TwitterQueryBuilder":
        """Any of these words (OR)."""
        if len(words) == 1:
            self._parts.append(_quote_if_needed(words[0]))
        else:
            self._parts.append("(" + " OR ".join(_quote_if_needed(w) for w in words) + ")")
        return self

    def none_of(self, *words: str) -> "TwitterQueryBuilder":
        """Exclude posts containing these words (NOT)."""
        for w in words:
            self._parts.append(f"-{_quote_if_needed(w)}")
        return self

    def hashtag(self, *tags: str) -> "TwitterQueryBuilder":
        """Filter by hashtag(s). '#' prefix is optional."""
        for tag in tags:
            t = tag.lstrip("#")
            self._parts.append(f"#{t}")
        return self

    def language(self, lang_code: str) -> "TwitterQueryBuilder":
        """
        Filter by language (BCP-47 code, e.g. 'en', 'id', 'nl', 'ar').

        Tip from Bellingcat: translate keywords first if targeting non-English content.
        """
        self._parts.append(f"lang:{lang_code}")
        return self

    # ------------------------------------------------------------------
    # ACCOUNTS operators (Bellingcat §ACCOUNTS)
    # ------------------------------------------------------------------

    def from_account(self, *handles: str) -> "TwitterQueryBuilder":
        """Posts authored by these accounts ('From these accounts')."""
        handles_clean = [h.lstrip("@") for h in handles]
        if len(handles_clean) == 1:
            self._parts.append(f"from:{handles_clean[0]}")
        else:
            self._parts.append("(" + " OR ".join(f"from:{h}" for h in handles_clean) + ")")
        return self

    def to_account(self, *handles: str) -> "TwitterQueryBuilder":
        """Posts replying to these accounts ('To these accounts')."""
        handles_clean = [h.lstrip("@") for h in handles]
        if len(handles_clean) == 1:
            self._parts.append(f"to:{handles_clean[0]}")
        else:
            self._parts.append("(" + " OR ".join(f"to:{h}" for h in handles_clean) + ")")
        return self

    def mentions(self, *handles: str) -> "TwitterQueryBuilder":
        """Posts that mention these accounts (not just replies)."""
        for h in handles:
            self._parts.append(f"@{h.lstrip('@')}")
        return self

    # ------------------------------------------------------------------
    # FILTERS operators (Bellingcat §Filters)
    # ------------------------------------------------------------------

    def only_replies(self) -> "TwitterQueryBuilder":
        """Return only reply tweets."""
        self._parts.append("is:reply")
        return self

    def exclude_replies(self) -> "TwitterQueryBuilder":
        """Exclude reply tweets — return only original posts."""
        self._parts.append("-is:reply")
        return self

    def has_links(self) -> "TwitterQueryBuilder":
        """Return only posts containing URLs."""
        self._parts.append("has:links")
        return self

    def url_contains(self, domain_or_path: str) -> "TwitterQueryBuilder":
        """
        Filter posts linking to a specific domain or URL path.

        Bellingcat tip: use this instead of 'has_links' when you need a specific domain.
        Equivalent to the 'url:example.com' search bar operator.
        """
        self._parts.append(f"url:{domain_or_path}")
        return self

    def exclude_retweets(self) -> "TwitterQueryBuilder":
        """Exclude retweets — original content only."""
        self._parts.append("-is:retweet")
        return self

    def only_verified(self) -> "TwitterQueryBuilder":
        """Only posts from verified (blue-check) accounts."""
        self._parts.append("is:verified")
        return self

    def has_media(self) -> "TwitterQueryBuilder":
        """Posts containing any media (images or videos)."""
        self._parts.append("has:media")
        return self

    def has_images(self) -> "TwitterQueryBuilder":
        """Posts containing images only."""
        self._parts.append("has:images")
        return self

    def has_video(self) -> "TwitterQueryBuilder":
        """Posts containing native video."""
        self._parts.append("filter:native_video")
        return self

    def near(self, location: str, within: str = "25km") -> "TwitterQueryBuilder":
        """
        Geo filter: `near:` place + `within:` radius (mi or km).

        Bellingcat slug style (no spaces): ``near:estes-park within:2mi``.
        Multi-word places use quotes: ``near:"New York" within:10km``.

        Location provenance on X is mixed (post location, profile, device GPS); treat
        hits as noisy — corroborate and warn analysts in reporting.

        Radius is clamped to **25 mi max** (X API limit for ``geocode:`` / geo search).
        Prefer ``within_miles`` / ``within_km`` helpers for clamped strings.
        """
        loc = location.strip()
        w = clamp_within_radius_str(within)
        if " " in loc:
            self._parts.append(f'near:"{loc}" within:{w}')
        else:
            self._parts.append(f"near:{loc} within:{w}")
        return self

    def geocode(self, lat: float, lon: float, radius: str = "25km") -> "TwitterQueryBuilder":
        """
        Precise geo filter: ``geocode:lat,lon,radius`` (e.g. ``geocode:40.7128,-74.0060,10mi``).

        **25 mi maximum radius** per X API — larger values are clamped via ``clamp_within_radius_str``.
        """
        r = clamp_within_radius_str(radius)
        self._parts.append(f"geocode:{lat},{lon},{r}")
        return self

    # ------------------------------------------------------------------
    # ENGAGEMENTS operators (Bellingcat §ENGAGEMENTS)
    # ------------------------------------------------------------------

    def min_replies(self, n: int) -> "TwitterQueryBuilder":
        """Minimum reply count threshold."""
        self._parts.append(f"min_replies:{n}")
        return self

    def min_likes(self, n: int) -> "TwitterQueryBuilder":
        """Minimum like count threshold."""
        self._parts.append(f"min_faves:{n}")
        return self

    def min_retweets(self, n: int) -> "TwitterQueryBuilder":
        """Minimum retweet count threshold."""
        self._parts.append(f"min_retweets:{n}")
        return self

    # ------------------------------------------------------------------
    # DATES operators (Bellingcat §DATES)
    # ------------------------------------------------------------------

    def since(self, dt: date | datetime | str) -> "TwitterQueryBuilder":
        """
        Return posts on or after this date.
        Bellingcat tip: add a few buffer days to ensure full coverage.
        """
        self._parts.append(f"since:{_format_date(dt)}")
        return self

    def until(self, dt: date | datetime | str) -> "TwitterQueryBuilder":
        """Return posts on or before this date."""
        self._parts.append(f"until:{_format_date(dt)}")
        return self

    def date_range(
        self,
        from_dt: date | datetime | str,
        to_dt: date | datetime | str,
    ) -> "TwitterQueryBuilder":
        """Convenience: set both since and until in one call."""
        return self.since(from_dt).until(to_dt)

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self) -> str:
        """Return the final X API v2 query string."""
        return " ".join(self._parts).strip()

    def __str__(self) -> str:
        return self.build()


# ---------------------------------------------------------------------------
# OSINT query templates
# Encode the Bellingcat use-case patterns as ready-made query factories
# ---------------------------------------------------------------------------


class TwitterOsintTemplates:
    """
    Pre-built query factories for common OSINT intents.

    Each method returns a TwitterQueryBuilder so the caller can refine further.
    Based on Bellingcat's documented use cases and operator guide.
    """

    @staticmethod
    def company_mentions(
        company_name: str,
        *,
        min_engagement: int = 0,
        exclude_retweets: bool = True,
        days_back: int | None = None,
    ) -> list[TwitterQueryBuilder]:
        """
        Multiple query variants for company monitoring.
        Returns a list because wide coverage requires several focused queries.
        """
        from datetime import date, timedelta

        queries: list[TwitterQueryBuilder] = []

        # Variant 1: direct company name mentions
        q1 = TwitterQueryBuilder().exact_phrase(company_name)
        if exclude_retweets:
            q1.exclude_retweets()
        if min_engagement:
            q1.min_likes(min_engagement)
        if days_back:
            q1.since(date.today() - timedelta(days=days_back))
        queries.append(q1)

        # Variant 2: company + security/breach signals
        q2 = (
            TwitterQueryBuilder()
            .exact_phrase(company_name)
            .any_word("breach", "hack", "leak", "vuln", "CVE", "exploit", "exposed")
        )
        if exclude_retweets:
            q2.exclude_retweets()
        if days_back:
            q2.since(date.today() - timedelta(days=days_back))
        queries.append(q2)

        # Variant 3: high-engagement posts only (cuts noise)
        q3 = (
            TwitterQueryBuilder()
            .any_word(company_name, f"#{company_name.replace(' ', '')}")
            .min_likes(100)
            .exclude_retweets()
        )
        if days_back:
            q3.since(date.today() - timedelta(days=days_back))
        queries.append(q3)

        return queries

    @staticmethod
    def person_research(
        full_name: str,
        handle: str | None = None,
        *,
        organisation: str | None = None,
    ) -> list[TwitterQueryBuilder]:
        """
        Map a person's Twitter presence and mentions.
        Returns queries for different investigation angles.
        """
        queries: list[TwitterQueryBuilder] = []

        # What they post
        if handle:
            q1 = TwitterQueryBuilder().from_account(handle).exclude_retweets()
            queries.append(q1)
            # What others say TO them
            q2 = TwitterQueryBuilder().to_account(handle)
            queries.append(q2)
            # Who mentions them
            q3 = TwitterQueryBuilder().mentions(handle)
            queries.append(q3)

        # Name-based discovery (catches accounts that don't @ them)
        q4 = TwitterQueryBuilder().exact_phrase(full_name).exclude_retweets()
        if organisation:
            q4.any_word(organisation)
        queries.append(q4)

        return queries

    @staticmethod
    def hashtag_campaign(
        hashtag: str,
        *,
        language: str | None = None,
        min_engagement: int = 10,
        days_back: int = 30,
    ) -> list[TwitterQueryBuilder]:
        """
        Map a hashtag campaign — based on Bellingcat's protest/movement research method.
        """
        from datetime import date, timedelta
        since = date.today() - timedelta(days=days_back)
        queries: list[TwitterQueryBuilder] = []

        # High-engagement posts — the amplification layer
        q1 = (
            TwitterQueryBuilder()
            .hashtag(hashtag)
            .min_likes(min_engagement)
            .exclude_retweets()
            .since(since)
        )
        if language:
            q1.language(language)
        queries.append(q1)

        # Media content — visual evidence (Bellingcat §Limitations #8)
        q2 = (
            TwitterQueryBuilder()
            .hashtag(hashtag)
            .has_media()
            .since(since)
        )
        queries.append(q2)

        # Original posts only — strips amplification noise
        q3 = (
            TwitterQueryBuilder()
            .hashtag(hashtag)
            .exclude_retweets()
            .exclude_replies()
            .since(since)
        )
        if language:
            q3.language(language)
        queries.append(q3)

        return queries

    @staticmethod
    def geo_event(
        keywords: list[str],
        location: str | None = None,
        lat_lon: tuple[float, float] | None = None,
        radius: str = "25km",
        *,
        has_media: bool = True,
        since: date | None = None,
        until: date | None = None,
    ) -> list[TwitterQueryBuilder]:
        """
        Locate and document a real-world event using geo + keyword filters.

        **Limitations (Bellingcat / X):** geo relevance can reflect profile or declared
        location, not the camera; spoofing and ambiguity are common. Historical/geo
        fidelity often drops beyond roughly the last week for profile-based signals
        (see Bellingcat 2021 COVID geofence case study). Cross-check with media,
        independent sources, and tight date windows — align with accuracy-patterns
        (corroboration, human review).
        """
        queries: list[TwitterQueryBuilder] = []

        q1 = TwitterQueryBuilder().all_words(*keywords)
        if location:
            q1.near(location, radius)
        elif lat_lon:
            q1.geocode(lat_lon[0], lat_lon[1], radius)
        if has_media:
            q1.has_media()
        if since:
            q1.since(since)
        if until:
            q1.until(until)
        queries.append(q1)

        # Non-geo fallback — keywords + date range only
        q2 = TwitterQueryBuilder().all_words(*keywords)
        if since:
            q2.since(since)
        if until:
            q2.until(until)
        q2.exclude_retweets().min_likes(5)
        queries.append(q2)

        return queries

    @staticmethod
    def location_crisis_monitor(
        keywords: list[str],
        *,
        near_place: str | None = None,
        lat_lon: tuple[float, float] | None = None,
        radius: str = "15mi",
        has_media: bool = True,
        since: date | None = None,
        until: date | None = None,
    ) -> list[TwitterQueryBuilder]:
        """
        Location-focused crisis / incident monitoring (fires, floods, unrest, outages).

        Uses the same geo operators as ``geo_event`` (``near:`` + ``within:`` or
        ``geocode:``), with defaults tuned for shorter-radius situational awareness.
        Prefer ``within_miles`` / ``within_km`` for radius strings capped at 25 mi.
        """
        return TwitterOsintTemplates.geo_event(
            keywords,
            location=near_place,
            lat_lon=lat_lon,
            radius=radius,
            has_media=has_media,
            since=since,
            until=until,
        )

    @staticmethod
    def breach_leak_monitor(
        company_or_domain: str,
    ) -> list[TwitterQueryBuilder]:
        """
        Monitor for breach/leak announcements.
        Maps to CREDENTIAL_EXPOSURE claim type.
        """
        return [
            TwitterQueryBuilder()
            .any_word(company_or_domain)
            .any_word("breach", "leak", "dump", "exposed", "hacked", "pwned", "combolist")
            .exclude_retweets(),
            TwitterQueryBuilder()
            .url_contains(company_or_domain)
            .any_word("breach", "leak", "dump"),
            TwitterQueryBuilder()
            .exact_phrase(f"{company_or_domain} database")
            .any_word("leaked", "sold", "stolen", "download"),
        ]

    @staticmethod
    def account_network(
        handle: str,
        *,
        min_replies: int = 0,
        days_back: int = 90,
    ) -> list[TwitterQueryBuilder]:
        """
        Map interaction network around an account.
        Used for disinformation / coordination research.
        """
        from datetime import date, timedelta
        since = date.today() - timedelta(days=days_back)
        handle_clean = handle.lstrip("@")

        return [
            # Who the account interacts with (their replies)
            TwitterQueryBuilder().from_account(handle_clean).only_replies().since(since),
            # Who replies to the account
            TwitterQueryBuilder().to_account(handle_clean).since(since),
            # Who mentions the account (non-replies)
            TwitterQueryBuilder().mentions(handle_clean).exclude_replies().since(since),
        ]

    @staticmethod
    def disinformation_tracking(
        narrative: str,
        seed_url: str | None = None,
        *,
        min_retweets: int = 50,
    ) -> list[TwitterQueryBuilder]:
        """
        Track narrative spread — based on Bellingcat's disinformation methodology.
        Focus on high-retweet, link-sharing behaviour.
        """
        queries: list[TwitterQueryBuilder] = []

        q1 = (
            TwitterQueryBuilder()
            .exact_phrase(narrative)
            .has_links()
            .min_retweets(min_retweets)
        )
        queries.append(q1)

        if seed_url:
            q2 = TwitterQueryBuilder().url_contains(seed_url)
            queries.append(q2)

        # Find accounts amplifying the narrative
        q3 = (
            TwitterQueryBuilder()
            .exact_phrase(narrative)
            .min_retweets(min_retweets // 2)
            .only_verified()
        )
        queries.append(q3)

        return queries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _quote_if_needed(word: str) -> str:
    """Add quotes if word contains spaces; otherwise return as-is."""
    return f'"{word}"' if " " in word else word


def _format_date(dt: date | datetime | str) -> str:
    if isinstance(dt, str):
        return dt
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m-%d")
