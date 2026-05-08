"""
Evidence and Provenance models.

Design principles:
  - Every claim maps to evidence.
  - Every claim-evidence binding stores: URL, timestamp, extractor, raw snippet.
  - Confidence is a 4-component weighted sum — never a single magic number.
  - Conflicts between sources are preserved, never silently resolved.
  - High-risk outputs require human analyst review before publication.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Claim taxonomy
# ---------------------------------------------------------------------------


class ClaimType(StrEnum):
    OPEN_PORT = "open_port"
    SERVICE_BANNER = "service_banner"
    VULNERABILITY = "vulnerability"
    HOSTNAME = "hostname"
    ASN = "asn"
    GEOLOCATION = "geolocation"
    WEB_MENTION = "web_mention"
    SOCIAL_PROFILE = "social_profile"
    COMPANY_INFO = "company_info"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    WHOIS = "whois"
    TECH_STACK = "tech_stack"
    # Twitter / social media claims
    SOCIAL_POST = "social_post"              # a specific tweet mentioning the target
    HASHTAG_ACTIVITY = "hashtag_activity"    # a hashtag campaign or trending term linked to target
    ACCOUNT_NETWORK = "account_network"      # interaction graph between accounts
    MEDIA_MENTION = "media_mention"          # tweet containing image/video evidence
    SUBDOMAIN = "subdomain"                    # hostname/subdomain discovered (e.g. CT, search)
    EMAIL_DISCOVERY = "email_discovery"        # email harvested from public OSINT (PII-sensitive)
    HOST_DISCOVERY = "host_discovery"          # IP or host association from OSINT harvester
    FILE_METADATA = "file_metadata"  # uploaded artifact metadata (ExifTool / Exiv2)
    STEGANOGRAPHY = "steganography"  # hidden data detection (LSB, stego signatures, carving)
    STEGO_EMBEDDED = "stego_embedded"  # extracted embedded content (decoded payload)


class SourceTool(StrEnum):
    SHODAN = "shodan"
    NMAP = "nmap"
    NCRACK = "ncrack"
    TAVILY = "tavily"
    TWITTER = "twitter"   # X API v2 search (recent + full archive)
    THEHARVESTER = "theharvester"  # laramies/theHarvester CLI subprocess
    OSINTMAP = "osintmap"  # cipher387 worldwide OSINT resource map (GitHub README)
    EDGAR = "edgar"  # Bellingcat EDGAR tool — SEC EDGAR full-text search (edgar-tool)
    EXIFTOOL = "exiftool"  # Phil Harvey ExifTool — Metaforge-class metadata reports
    EXIV2 = "exiv2"  # https://github.com/Exiv2/exiv2 image Exif/IPTC/XMP CLI
    STEGOVERITAS = "stegoveritas"  # bannsec/stegoVeritas — multi-method stego analysis
    STEGO_LSB = "stego_lsb"  # pure-Python LSB extraction fallback
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# Source tiering — where the evidence came from
# ---------------------------------------------------------------------------


class SourceTier(StrEnum):
    """
    Reliability tier for the source that produced this evidence.

    Tier determines the `source_reliability` component of confidence.
    Analysts assign the tier at collection time; adapters set a default.

      OFFICIAL   — company's own website, official documentation, registry records
      REGULATOR  — SEC filings, OFAC SDN list, CISA advisories, government databases
      MEDIA      — established journalism (Reuters, Bloomberg, BBC, major trade press)
      COMMUNITY  — forums, social media, GitHub issues, verified community reports
      ANONYMOUS  — Pastebin, Telegram dumps, dark web posts, unverified tips
    """

    OFFICIAL = "official"
    REGULATOR = "regulator"
    MEDIA = "media"
    COMMUNITY = "community"
    ANONYMOUS = "anonymous"


# Default reliability score per tier (the `source_reliability` raw value)
TIER_RELIABILITY: dict[SourceTier, float] = {
    SourceTier.OFFICIAL: 1.00,
    SourceTier.REGULATOR: 0.95,
    SourceTier.MEDIA: 0.75,
    SourceTier.COMMUNITY: 0.55,
    SourceTier.ANONYMOUS: 0.25,
}

# Default tier assigned to each collection tool
TOOL_DEFAULT_TIER: dict[SourceTool, SourceTier] = {
    SourceTool.SHODAN: SourceTier.OFFICIAL,     # Shodan indexes public-facing data
    SourceTool.NMAP: SourceTier.OFFICIAL,        # active scan of the target itself
    SourceTool.NCRACK: SourceTier.OFFICIAL,
    SourceTool.TAVILY: SourceTier.MEDIA,         # web search — mix of tiers; default to media
    SourceTool.TWITTER: SourceTier.COMMUNITY,    # tweets are community-tier by default; override for verified/official accounts
    SourceTool.THEHARVESTER: SourceTier.COMMUNITY,  # mixed public sources; crtsh-only runs may set OFFICIAL in-provenance
    SourceTool.OSINTMAP: SourceTier.COMMUNITY,  # curated third-party link catalog
    SourceTool.EDGAR: SourceTier.REGULATOR,  # SEC filing index (official regulatory)
    SourceTool.EXIFTOOL: SourceTier.COMMUNITY,  # analyst-supplied file; may contain spoofed/stripped tags
    SourceTool.EXIV2: SourceTier.COMMUNITY,  # like ExifTool; image-focused CLI
    SourceTool.STEGOVERITAS: SourceTier.COMMUNITY,  # automated multi-method stego analysis
    SourceTool.STEGO_LSB: SourceTier.COMMUNITY,  # basic LSB extraction; lower confidence
    SourceTool.MANUAL: SourceTier.OFFICIAL,
}

# Expected value keys per claim type (used for evidence completeness scoring)
CLAIM_VALUE_KEYS: dict[ClaimType, list[str]] = {
    ClaimType.OPEN_PORT: ["ip", "port", "protocol"],
    ClaimType.SERVICE_BANNER: ["port", "product", "version"],
    ClaimType.VULNERABILITY: ["cve_id", "port"],
    ClaimType.WEB_MENTION: ["url", "title"],
    ClaimType.SOCIAL_PROFILE: ["url", "platform"],
    ClaimType.COMPANY_INFO: ["url", "title"],
    ClaimType.CREDENTIAL_EXPOSURE: ["source", "type"],
    ClaimType.TECH_STACK: ["technology", "evidence_url"],
    ClaimType.HOSTNAME: ["hostname"],
    ClaimType.ASN: ["asn", "org"],
    ClaimType.GEOLOCATION: ["country", "city"],
    ClaimType.CERTIFICATE: ["subject", "issuer"],
    ClaimType.DNS_RECORD: ["record_type", "value"],
    ClaimType.WHOIS: ["registrant", "registrar"],
    # Twitter claims
    ClaimType.SOCIAL_POST: ["tweet_id", "author_handle", "text", "url", "created_at"],
    ClaimType.HASHTAG_ACTIVITY: ["hashtag", "tweet_count", "date_range"],
    ClaimType.ACCOUNT_NETWORK: ["subject_handle", "interaction_type", "connected_handles"],
    ClaimType.MEDIA_MENTION: ["tweet_id", "author_handle", "media_url", "text"],
    ClaimType.SUBDOMAIN: ["hostname"],
    ClaimType.EMAIL_DISCOVERY: ["email"],
    ClaimType.HOST_DISCOVERY: ["ip"],
    ClaimType.FILE_METADATA: ["artifact_name", "format", "summary"],
    ClaimType.STEGANOGRAPHY: ["artifact_name", "method", "detection_confidence"],
    ClaimType.STEGO_EMBEDDED: ["artifact_name", "method", "payload_size", "payload_preview"],
}

# Claim types that require analyst review regardless of confidence
HIGH_RISK_CLAIM_TYPES: frozenset[ClaimType] = frozenset(
    {
        ClaimType.CREDENTIAL_EXPOSURE,
        ClaimType.EMAIL_DISCOVERY,
        ClaimType.FILE_METADATA,  # may embed GPS, device IDs, authorship — analyst review
        ClaimType.STEGANOGRAPHY,  # hidden content may contain illicit material
        ClaimType.STEGO_EMBEDDED,  # extracted payloads need human verification
    }
)


# ---------------------------------------------------------------------------
# Confidence components — the 4-factor breakdown
# ---------------------------------------------------------------------------


class ConfidenceComponents(BaseModel):
    """
    Structured breakdown of the confidence formula:

        Confidence = (w_s · source_reliability)
                   + (w_c · cross_source_agreement)
                   + (w_t · freshness)
                   + (w_e · evidence_completeness)

    All four raw sub-scores are in [0.0, 1.0].
    Weights must sum to 1.0 (validated by the Verifier, not the model).
    Stored on the Evidence item so analysts can inspect each driver.
    """

    source_reliability: float = Field(ge=0.0, le=1.0)
    cross_source_agreement: float = Field(ge=0.0, le=1.0)
    freshness: float = Field(ge=0.0, le=1.0)
    evidence_completeness: float = Field(ge=0.0, le=1.0)

    # Weights in effect at scoring time — stored for auditability
    w_s: float = Field(0.40, ge=0.0, le=1.0)
    w_c: float = Field(0.25, ge=0.0, le=1.0)
    w_t: float = Field(0.20, ge=0.0, le=1.0)
    w_e: float = Field(0.15, ge=0.0, le=1.0)

    @property
    def total(self) -> float:
        return round(
            min(
                self.w_s * self.source_reliability
                + self.w_c * self.cross_source_agreement
                + self.w_t * self.freshness
                + self.w_e * self.evidence_completeness,
                1.0,
            ),
            4,
        )

    def explain(self) -> str:
        """One-line breakdown suitable for analyst notes."""
        return (
            f"src={self.source_reliability:.2f}(×{self.w_s}) "
            f"corr={self.cross_source_agreement:.2f}(×{self.w_c}) "
            f"fresh={self.freshness:.2f}(×{self.w_t}) "
            f"complete={self.evidence_completeness:.2f}(×{self.w_e}) "
            f"→ {self.total:.4f}"
        )


# ---------------------------------------------------------------------------
# Provenance — the full citation trail
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    """
    Immutable record of exactly how and where evidence was collected.

    Claim-evidence binding rule: every Evidence item must have:
      ✓ source_tool  — which tool produced it
      ✓ source_tier  — reliability category of the source
      ✓ source_url   — direct URL to the page/API endpoint (if applicable)
      ✓ raw_snippet  — verbatim excerpt that supports the claim (≤500 chars)
      ✓ extractor    — function/parser that produced the structured value
      ✓ collection_query — exact search term, nmap flags, or API query
      ✓ collected_at — UTC timestamp
      ✓ raw_response — full unmodified API payload for deep audit
    """

    source_tool: SourceTool
    source_tier: SourceTier = SourceTier.COMMUNITY  # adapters should override

    # Direct evidence binding — the URL + snippet that proves the claim
    source_url: str | None = None
    raw_snippet: str | None = None          # ≤500 chars verbatim excerpt
    extractor: str = "unknown"              # e.g. "shodan.banner_parser"

    # Query / command that triggered this collection
    collection_query: str
    api_endpoint: str | None = None

    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analyst_id: str
    session_id: str

    # Full unmodified API payload — never trim; needed for audit trail
    raw_response: dict[str, Any]


# ---------------------------------------------------------------------------
# Evidence — a single verifiable claim
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    """
    One verifiable claim produced by a collection tool.

    Accuracy guarantees:
      - claim_type     : typed, not free text
      - value          : structured dict with known keys (see CLAIM_VALUE_KEYS)
      - provenance     : full citation trail including raw_snippet and source_url
      - confidence     : 4-component weighted score, never a guess
      - conflict_flag  : True if another source contradicts this claim
      - requires_review: True if this claim must not be published without human sign-off
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str

    # The claim
    claim: str            # human-readable: "Port 443/tcp open on 1.2.3.4"
    claim_type: ClaimType
    value: dict[str, Any]

    # Citation trail
    provenance: Provenance

    # Initial confidence — set by the collector based on tool defaults
    confidence: float = Field(ge=0.0, le=1.0)

    # 4-component breakdown — set by the Verifier
    confidence_components: ConfidenceComponents | None = None

    # Verification stage
    verified: bool = False
    verified_by: list[SourceTool] = Field(default_factory=list)
    verification_note: str | None = None

    # Conflict detection — set by Verifier when two sources disagree on the same claim
    conflict_flag: bool = False
    conflict_note: str | None = None  # describes what the conflict is

    # High-risk review gate — set by Verifier; must be cleared by human analyst
    requires_review: bool = False
    review_reason: str | None = None

    # Enrichment stage
    enrichments: dict[str, Any] = Field(default_factory=dict)

    # --------------------------------------------------------------------------
    # Computed helpers
    # --------------------------------------------------------------------------

    @property
    def age_days(self) -> float:
        """Elapsed days since collection — used for freshness scoring."""
        now = datetime.now(timezone.utc)
        collected = self.provenance.collected_at
        if collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        return max(0.0, (now - collected).total_seconds() / 86_400)

    @property
    def citation(self) -> str:
        """One-line citation suitable for report footnotes."""
        ts = self.provenance.collected_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        parts = [
            f"[{self.provenance.source_tool}|{self.provenance.source_tier}]",
            f'query="{self.provenance.collection_query}"',
            f"at={ts}",
        ]
        if self.provenance.source_url:
            parts.append(f"url={self.provenance.source_url}")
        if self.provenance.raw_snippet:
            snippet = self.provenance.raw_snippet[:120].replace("\n", " ")
            parts.append(f'snippet="{snippet}…"' if len(self.provenance.raw_snippet) > 120 else f'snippet="{snippet}"')
        return " ".join(parts)

    def evidence_completeness_score(self) -> float:
        """
        Fraction of expected evidence fields that are populated.

        Checks:
          - provenance.source_url present
          - provenance.raw_snippet present
          - provenance.extractor is not 'unknown'
          - value has all expected keys for this claim_type
        """
        prov_checks = [
            self.provenance.source_url is not None,
            self.provenance.raw_snippet is not None,
            self.provenance.extractor != "unknown",
        ]
        expected_keys = CLAIM_VALUE_KEYS.get(self.claim_type, [])
        value_checks = [
            bool(self.value.get(k)) for k in expected_keys
        ] if expected_keys else [True]

        all_checks = prov_checks + value_checks
        return sum(all_checks) / len(all_checks)
