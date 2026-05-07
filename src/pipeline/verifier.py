"""
Verification stage — deterministic accuracy pipeline.

Four operations applied to raw Evidence[]:

  1. Deduplication          — group items that make the same claim
  2. Cross-source agreement — mark verified=True when ≥2 independent sources confirm
  3. Conflict detection     — flag when sources disagree on the same claim
  4. Confidence scoring     — 4-component weighted formula (no LLM)
  5. Review lane            — flag high-risk items for analyst sign-off

Confidence formula:

    C = (w_s · source_reliability)
      + (w_c · cross_source_agreement)
      + (w_t · freshness)
      + (w_e · evidence_completeness)

  source_reliability    = TIER_RELIABILITY[tier] × tool_weight
  cross_source_agreement= 0.0 (unconfirmed) → 1.0 (≥2 independent sources)
  freshness             = e^(−λ × age_days)
  evidence_completeness = fraction of expected fields that are populated

High-risk review triggers:
  • claim_type == CREDENTIAL_EXPOSURE (always)
  • VULNERABILITY with CVSS ≥ 9.0 (critical)
  • Anonymous source (tier=ANONYMOUS) AND not corroborated
  • conflict_flag=True (contradictory sources)
"""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field

import structlog

from src.core.audit import AuditEvent, AuditLogger
from src.core.config import get_settings
from src.models.evidence import (
    HIGH_RISK_CLAIM_TYPES,
    TIER_RELIABILITY,
    ClaimType,
    ConfidenceComponents,
    Evidence,
    SourceTier,
)
from src.pipeline.domain_relevance import annotate_evidence_domain_relevance, extract_target_apex

log = structlog.get_logger("grond.pipeline.verifier")


# ---------------------------------------------------------------------------
# Claim key — defines "the same claim" for deduplication
# ---------------------------------------------------------------------------


def default_claim_key(ev: Evidence) -> str:
    """
    Normalised string key for deduplication.

    Two Evidence items with the same key represent the same real-world claim
    and will be merged into a single canonical item.
    """
    t = ev.claim_type
    v = ev.value
    if t == ClaimType.OPEN_PORT:
        return f"port|{ev.target}|{v.get('port')}|{v.get('protocol', 'tcp')}"
    if t == ClaimType.SERVICE_BANNER:
        return f"banner|{ev.target}|{v.get('port')}|{v.get('product', '')}".lower()
    if t == ClaimType.VULNERABILITY:
        return f"vuln|{ev.target}|{str(v.get('cve_id', '')).upper()}"
    if t in (ClaimType.WEB_MENTION, ClaimType.SOCIAL_PROFILE, ClaimType.COMPANY_INFO):
        return f"web|{v.get('url', ev.claim[:100])}"
    if t == ClaimType.SUBDOMAIN:
        return f"sub|{str(v.get('hostname', '')).lower()}"
    if t == ClaimType.EMAIL_DISCOVERY:
        return f"email|{str(v.get('email', '')).lower()}"
    if t == ClaimType.HOST_DISCOVERY:
        return f"host|{ev.target}|{v.get('ip', '')}"
    return f"other|{ev.target}|{t}|{ev.claim[:100]}"


# ---------------------------------------------------------------------------
# Component scorers
# ---------------------------------------------------------------------------


def score_source_reliability(ev: Evidence) -> float:
    """
    source_reliability = TIER_RELIABILITY[tier] × tool_weight

    Combines the inherent trustworthiness of the source *category* (official /
    regulator / media / community / anonymous) with the precision of the
    specific collection tool (nmap=0.95, shodan=0.85, tavily=0.70).
    """
    settings = get_settings()
    tier_score = TIER_RELIABILITY.get(ev.provenance.source_tier, 0.50)
    tool_score = settings.source_weight(ev.provenance.source_tool)
    return round(tier_score * tool_score, 4)


def score_cross_source_agreement(group: list[Evidence]) -> float:
    """
    cross_source_agreement = corroboration ratio.

    0.0 → single source (unconfirmed)
    0.5 → 2 independent sources
    0.75 → 3 sources
    1.0 → ≥4 sources

    Independent means distinct source tools — same tool called twice does not count.
    """
    distinct_tools = {e.provenance.source_tool for e in group}
    n = len(distinct_tools)
    if n == 1:
        return 0.0
    if n == 2:
        return 0.5
    if n == 3:
        return 0.75
    return 1.0


def score_freshness(ev: Evidence) -> float:
    """
    freshness = e^(−λ × age_days)

    Uses the temporal decay lambda from settings (default 0.02).
    At λ=0.02:
        0 days  → 1.00
        7 days  → 0.87
        30 days → 0.55
        90 days → 0.16
    """
    settings = get_settings()
    return round(math.exp(-settings.confidence_decay_lambda * ev.age_days), 4)


def score_evidence_completeness(ev: Evidence) -> float:
    """
    evidence_completeness = fraction of expected evidence fields that are filled.

    Checks:
      • provenance.source_url is present   (direct link to evidence)
      • provenance.raw_snippet is present  (verbatim excerpt)
      • provenance.extractor != 'unknown'  (parser is identified)
      • value has all expected keys for this claim_type
    """
    return round(ev.evidence_completeness_score(), 4)


def compute_confidence(ev: Evidence, group: list[Evidence]) -> ConfidenceComponents:
    """
    Compute all four confidence components and return the breakdown.

    The final confidence is accessed via `components.total`.
    """
    settings = get_settings()
    w_s, w_c, w_t, w_e = settings.confidence_weights

    return ConfidenceComponents(
        source_reliability=score_source_reliability(ev),
        cross_source_agreement=score_cross_source_agreement(group),
        freshness=score_freshness(ev),
        evidence_completeness=score_evidence_completeness(ev),
        w_s=w_s,
        w_c=w_c,
        w_t=w_t,
        w_e=w_e,
    )


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------


def detect_conflict(group: list[Evidence]) -> tuple[bool, str | None]:
    """
    Detect contradictions within a claim group.

    Conflict rules:
      • VULNERABILITY: same CVE but CVSS scores differ by ≥ settings.conflict_cvss_delta
      • SERVICE_BANNER: same port, same target, different product names
      • OPEN_PORT: one source says open, another says filtered/closed
      • WEB_MENTION/COMPANY_INFO: source_tier >= OFFICIAL contradicts source_tier ANONYMOUS

    Returns (conflict_flag, conflict_note).
    """
    if len(group) < 2:
        return False, None

    settings = get_settings()
    claim_type = group[0].claim_type

    if claim_type == ClaimType.VULNERABILITY:
        cvss_scores = [
            float(ev.value.get("cvss", 0) or 0)
            for ev in group
            if ev.value.get("cvss") is not None
        ]
        if len(cvss_scores) >= 2:
            delta = max(cvss_scores) - min(cvss_scores)
            if delta >= settings.conflict_cvss_delta:
                return True, (
                    f"CVSS score conflict: sources report values between "
                    f"{min(cvss_scores):.1f} and {max(cvss_scores):.1f} "
                    f"(delta={delta:.1f}). Both retained for analyst review."
                )

    if claim_type == ClaimType.SERVICE_BANNER:
        products = {str(ev.value.get("product", "")).lower() for ev in group if ev.value.get("product")}
        if len(products) > 1:
            return True, (
                f"Service product conflict: sources report different products "
                f"on same port: {', '.join(sorted(products))}. "
                "Analyst should verify which is current."
            )

    if claim_type == ClaimType.OPEN_PORT:
        states = {str(ev.value.get("state", "open")).lower() for ev in group}
        if len(states) > 1 and "open" in states:
            closed_states = states - {"open"}
            return True, (
                f"Port state conflict: one source reports 'open', "
                f"other(s) report {', '.join(closed_states)}. "
                "May indicate intermittent availability or firewall rules."
            )

    # Official/regulator source directly contradicts anonymous/community claim
    tiers_present = {ev.provenance.source_tier for ev in group}
    authoritative = {SourceTier.OFFICIAL, SourceTier.REGULATOR}
    low_trust = {SourceTier.ANONYMOUS}
    if authoritative & tiers_present and low_trust & tiers_present:
        # Check if their value fields differ meaningfully
        values = [ev.value for ev in group]
        if len({str(sorted(v.items())) for v in values}) > 1:
            return True, (
                "Source tier conflict: an official/regulator source and an anonymous "
                "source make different claims on the same key. "
                "Both are retained; anonymous claim requires extra scrutiny."
            )

    return False, None


# ---------------------------------------------------------------------------
# High-risk review lane
# ---------------------------------------------------------------------------


def should_require_review(ev: Evidence, conflict_flag: bool) -> tuple[bool, str | None]:
    """
    Return (requires_review, review_reason) for an evidence item.

    Review is required when:
      1. Claim type is inherently sensitive (credential exposure)
      2. Vulnerability is CVSS Critical (≥ 9.0)
      3. Anonymous and unverified (uncorroborated low-trust source)
      4. Conflicting sources — analyst must adjudicate
    """
    settings = get_settings()

    if ev.claim_type in HIGH_RISK_CLAIM_TYPES:
        return True, f"High-risk claim type: {ev.claim_type} always requires analyst review"

    if ev.claim_type == ClaimType.VULNERABILITY:
        cvss = float(ev.value.get("cvss", 0) or ev.enrichments.get("nvd", {}).get("cvss3_score", 0) or 0)
        if cvss >= settings.review_cvss_threshold:
            return True, f"Critical CVE: CVSS {cvss:.1f} ≥ {settings.review_cvss_threshold} threshold"

    if (
        ev.provenance.source_tier == SourceTier.ANONYMOUS
        and not ev.verified
        and ev.confidence < settings.review_anonymous_min_confidence
    ):
        return True, (
            f"Uncorroborated anonymous claim (tier=ANONYMOUS, verified=False, "
            f"confidence={ev.confidence:.2f} < {settings.review_anonymous_min_confidence})"
        )

    if conflict_flag:
        return True, "Conflicting sources — analyst must adjudicate before publication"

    return False, None


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    deduplicated: list[Evidence]
    original_count: int
    dedup_count: int            # items removed by dedup
    verified_count: int         # items corroborated by ≥2 independent sources
    conflict_count: int         # items with conflicting sources
    review_required_count: int  # items requiring analyst review
    confidence_breakdown: dict[str, float] = field(default_factory=dict)

    @property
    def avg_confidence(self) -> float:
        if not self.deduplicated:
            return 0.0
        return round(sum(e.confidence for e in self.deduplicated) / len(self.deduplicated), 4)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class Verifier:
    """
    Deterministic evidence verification pipeline.

    Steps:
    1. Group by claim key (deduplication)
    2. Per group: detect conflicts
    3. Merge group into canonical Evidence item
    4. Compute 4-component confidence
    5. Apply high-risk review lane
    """

    def __init__(
        self,
        audit: AuditLogger,
        claim_key_fn: Callable[[Evidence], str] = default_claim_key,
    ) -> None:
        self._audit = audit
        self._key_fn = claim_key_fn

    def verify(
        self,
        evidence: list[Evidence],
        *,
        investigation_target: str | None = None,
    ) -> VerificationResult:
        original_count = len(evidence)

        apex = extract_target_apex(investigation_target) if investigation_target else None
        gated = [
            annotate_evidence_domain_relevance(ev, apex) if investigation_target else ev
            for ev in evidence
        ]

        groups: dict[str, list[Evidence]] = {}
        for ev in gated:
            key = self._key_fn(ev)
            groups.setdefault(key, []).append(ev)

        deduplicated: list[Evidence] = []
        verified_count = 0
        conflict_count = 0
        review_required_count = 0

        for _key, group in groups.items():
            merged = self._process_group(group)
            if merged.verified:
                verified_count += 1
            if merged.conflict_flag:
                conflict_count += 1
            if merged.requires_review:
                review_required_count += 1
            deduplicated.append(merged)

        deduplicated.sort(key=lambda e: e.confidence, reverse=True)

        self._audit.record(
            AuditEvent.VERIFICATION_COMPLETE,
            original_count=original_count,
            dedup_count=original_count - len(deduplicated),
            verified_count=verified_count,
            conflict_count=conflict_count,
            review_required_count=review_required_count,
        )

        log.info(
            "verifier.complete",
            original=original_count,
            deduplicated=len(deduplicated),
            verified=verified_count,
            conflicts=conflict_count,
            review_required=review_required_count,
        )

        return VerificationResult(
            deduplicated=deduplicated,
            original_count=original_count,
            dedup_count=original_count - len(deduplicated),
            verified_count=verified_count,
            conflict_count=conflict_count,
            review_required_count=review_required_count,
        )

    def _process_group(self, group: list[Evidence]) -> Evidence:
        """
        Merge a claim group into a single canonical Evidence item.

        Preserves all provenance records in the enrichments block so no
        information is lost. The canonical item is the most confident one.
        """
        canonical = max(group, key=lambda e: e.confidence)

        # Cross-source validation
        distinct_tools = {e.provenance.source_tool for e in group}
        is_verified = len(distinct_tools) >= 2
        all_sources = list(distinct_tools)

        # Conflict detection
        conflict_flag, conflict_note = detect_conflict(group)

        # Preserve all corroborating provenances in enrichments
        corroborating = [
            {
                "source_tool": str(e.provenance.source_tool),
                "source_tier": str(e.provenance.source_tier),
                "source_url": e.provenance.source_url,
                "raw_snippet": e.provenance.raw_snippet,
                "extractor": e.provenance.extractor,
                "collection_query": e.provenance.collection_query,
                "collected_at": e.provenance.collected_at.isoformat(),
            }
            for e in group
            if e.id != canonical.id
        ]

        # Compute 4-component confidence
        components = compute_confidence(canonical, group)
        final_confidence = components.total

        # Review lane
        requires_review, review_reason = should_require_review(
            canonical.model_copy(update={
                "verified": is_verified,
                "confidence": final_confidence,
                "conflict_flag": conflict_flag,
            }),
            conflict_flag=conflict_flag,
        )

        return canonical.model_copy(
            update={
                "verified": is_verified,
                "verified_by": all_sources,
                "verification_note": (
                    f"Corroborated by {len(distinct_tools)} independent sources: "
                    f"{', '.join(str(s) for s in all_sources)}"
                    if is_verified
                    else f"Single source: {canonical.provenance.source_tool}"
                ),
                "confidence": final_confidence,
                "confidence_components": components,
                "conflict_flag": conflict_flag,
                "conflict_note": conflict_note,
                "requires_review": requires_review,
                "review_reason": review_reason,
                "enrichments": {
                    **canonical.enrichments,
                    "corroborating_provenances": corroborating,
                },
            }
        )
