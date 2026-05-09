"""
Intel report models.

Reports are produced deterministically from verified evidence.
The LLM contributes only narrative text — every factual statement links back
to one or more Evidence IDs.

Accuracy guarantees:
  - conflict_items     : contradicting evidence is shown, never suppressed
  - review_queue       : high-risk findings blocked until analyst sign-off
  - confidence_breakdown: every finding exposes its 4-component score
  - pending_review_count: report header shows how many items need attention
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from src.models.evidence import ClaimType, ConfidenceComponents, Evidence, SourceTier, SourceTool


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 1,
    RiskLevel.INFORMATIONAL: 0,
}


def highest_risk(levels: list[RiskLevel]) -> RiskLevel:
    if not levels:
        return RiskLevel.INFORMATIONAL
    return max(levels, key=lambda r: _RISK_ORDER[r])


# ---------------------------------------------------------------------------
# Conflict record — preserved when sources disagree
# ---------------------------------------------------------------------------


class ConflictRecord(BaseModel):
    """
    Describes a detected conflict between two or more sources on the same claim.

    Principle: conflicts are NEVER silently resolved by the system.
    Both sides are preserved so an analyst can adjudicate.
    """

    claim_key: str           # dedup key (e.g. "vuln|1.2.3.4|CVE-2024-1234")
    claim_type: ClaimType
    conflict_note: str       # plain-English description of the contradiction
    evidence_ids: list[str]  # all Evidence IDs involved in the conflict
    sources: list[SourceTool]
    source_tiers: list[SourceTier]
    analyst_adjudication: Literal["pending", "source_a_correct", "source_b_correct", "both_valid", "dismissed"] = "pending"
    analyst_note: str | None = None


# ---------------------------------------------------------------------------
# Report findings
# ---------------------------------------------------------------------------


class ReportFinding(BaseModel):
    """
    A single analyst-ready finding.

    Carries the full accuracy trail:
      - confidence_components  : 4-factor breakdown so analyst knows WHY this score
      - conflict_flag          : True if sources disagree on this claim
      - requires_review        : True if analyst must clear before publication
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str  # LLM-generated from structured evidence, never invented
    claim_type: ClaimType
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)

    # 4-component confidence breakdown — from the Verifier
    confidence_components: ConfidenceComponents | None = None

    # Evidence chain — analyst can follow IDs back to raw API responses
    evidence_ids: list[str] = Field(default_factory=list)
    sources_used: list[SourceTool] = Field(default_factory=list)
    source_tiers: list[SourceTier] = Field(default_factory=list)

    # Corroboration
    corroborated: bool = False

    # Accuracy flags
    conflict_flag: bool = False
    conflict_note: str | None = None

    # Human review gate
    requires_review: bool = False
    review_reason: str | None = None

    # Analyst fields — filled by human, never by agent
    analyst_status: Literal["pending", "confirmed", "disputed", "stale"] = "pending"
    analyst_note: str | None = None


class ReportSection(BaseModel):
    heading: str
    findings: list[ReportFinding] = Field(default_factory=list)
    summary: str = ""  # LLM-generated section summary

    @property
    def pending_review_count(self) -> int:
        return sum(1 for f in self.findings if f.requires_review and f.analyst_status == "pending")

    @property
    def conflict_count(self) -> int:
        return sum(1 for f in self.findings if f.conflict_flag)


# ---------------------------------------------------------------------------
# The full intel report
# ---------------------------------------------------------------------------


class IntelReport(BaseModel):
    """
    Complete OSINT intelligence report.

    Accuracy guarantees enforced by this model:
      ✓ Conflicts are listed explicitly in conflict_items — never merged
      ✓ pending_review_count shows how many items need analyst attention
      ✓ avg_confidence reflects the 4-component formula, not tool defaults
      ✓ Disclaimer is always included and non-removable
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    target: str
    goal: str
    analyst_id: str
    session_id: str

    # --- Deterministic header stats ---
    overall_risk: RiskLevel = RiskLevel.INFORMATIONAL
    avg_confidence: float = 0.0
    total_evidence_items: int = 0
    corroborated_findings: int = 0
    conflict_count: int = 0         # how many claim groups have conflicting sources
    pending_review_count: int = 0   # findings blocked pending analyst review

    sources_used: list[SourceTool] = Field(default_factory=list)

    # --- LLM-authored narrative ---
    # RULE: the LLM may only reference evidence IDs already in `evidence[]`.
    # It must not assert facts not present in the structured findings.
    executive_summary: str = ""

    key_takeaways: list[str] = Field(
        default_factory=list,
        description="Short bullets derived deterministically from primary (non-excluded) findings.",
    )

    critical_questions: list[str] = Field(
        default_factory=list,
        description="LLM-generated critical questions the analyst should investigate further.",
    )

    # --- Structured findings ---
    sections: list[ReportSection] = Field(default_factory=list)

    # --- Conflict register ---
    # All detected source conflicts, with both sides preserved for analyst review.
    # Removing items from this list requires explicit analyst adjudication.
    conflict_items: list[ConflictRecord] = Field(default_factory=list)

    # --- Full evidence appendix ---
    # Every collected item including those that were deduplicated.
    # Analyst may always drill down to the raw response.
    evidence: list[Evidence] = Field(default_factory=list)

    # --- Legal disclaimer (non-removable) ---
    disclaimer: str = (
        "This report contains intelligence derived solely from publicly available sources. "
        "Active scan findings were collected only against targets with explicit written "
        "authorization on record. "
        "Confidence scores are probabilistic (4-component formula: source reliability, "
        "cross-source agreement, temporal freshness, evidence completeness). "
        "All findings with requires_review=True MUST be reviewed by a qualified analyst "
        "before any action, publication, or further dissemination."
    )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def citation_for(self, evidence_id: str) -> str | None:
        for ev in self.evidence:
            if ev.id == evidence_id:
                return ev.citation
        return None

    def findings_requiring_review(self) -> list[ReportFinding]:
        """All findings that need analyst sign-off before publication."""
        return [
            f
            for section in self.sections
            for f in section.findings
            if f.requires_review and f.analyst_status == "pending"
        ]

    def is_publishable(self) -> bool:
        """
        Report is safe to publish only when all high-risk findings are reviewed.
        Analysts must resolve every requires_review=True item.
        """
        return len(self.findings_requiring_review()) == 0

    def accuracy_summary(self) -> dict[str, object]:
        """Machine-readable accuracy metrics for dashboards."""
        all_findings = [f for s in self.sections for f in s.findings]
        return {
            "total_evidence": self.total_evidence_items,
            "avg_confidence": self.avg_confidence,
            "corroborated_pct": (
                round(self.corroborated_findings / len(all_findings) * 100, 1)
                if all_findings else 0.0
            ),
            "conflict_count": self.conflict_count,
            "pending_review_count": self.pending_review_count,
            "is_publishable": self.is_publishable(),
        }
