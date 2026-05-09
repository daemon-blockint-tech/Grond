"""
Reporting stage.

Builds the final `IntelReport` from verified evidence.

Stage order (principle 4 — deterministic before LLM):
  1. Classify each finding → risk level (deterministic rules)
  2. Group findings into sections (deterministic)
  3. Build IntelReport skeleton with all metadata (deterministic)
  4. LLM synthesises section summaries and executive summary (LLM, last step)

The LLM receives only the structured evidence JSON — it cannot invent facts
not present in the evidence.  Section summaries are constrained by explicit
prompts that include the evidence payload.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlparse

import structlog

from src.core.audit import AuditEvent, AuditLogger
from src.core.config import get_settings
from src.models.evidence import ClaimType, Evidence
from src.models.report import (
    IntelReport,
    ReportFinding,
    ReportSection,
    RiskLevel,
    highest_risk,
)
from src.pipeline.domain_relevance import extract_target_apex

log = structlog.get_logger("grond.pipeline.reporter")

# ---------------------------------------------------------------------------
# Deterministic risk classification
# ---------------------------------------------------------------------------

_VULN_CVSS_THRESHOLDS: list[tuple[float, RiskLevel]] = [
    (9.0, RiskLevel.CRITICAL),
    (7.0, RiskLevel.HIGH),
    (4.0, RiskLevel.MEDIUM),
    (0.0, RiskLevel.LOW),
]


def classify_risk(ev: Evidence) -> RiskLevel:
    """
    Assign a risk level to an Evidence item using deterministic rules.
    No LLM involved.
    """
    if ev.claim_type == ClaimType.VULNERABILITY:
        cvss = ev.enrichments.get("nvd", {}).get("cvss3_score") or ev.value.get("cvss")
        if isinstance(cvss, (int, float)):
            for threshold, level in _VULN_CVSS_THRESHOLDS:
                if float(cvss) >= threshold:
                    return level
        return RiskLevel.MEDIUM  # unknown CVSS → default to medium

    if ev.claim_type == ClaimType.CREDENTIAL_EXPOSURE:
        return RiskLevel.HIGH

    if ev.claim_type == ClaimType.OPEN_PORT:
        port = ev.value.get("port", 0)
        if port in (21, 23, 2323, 512, 513, 514):  # FTP, Telnet, rsh, rlogin
            return RiskLevel.HIGH
        if port in (3306, 5432, 27017, 6379, 9200):  # databases exposed
            return RiskLevel.HIGH
        return RiskLevel.LOW

    if ev.claim_type == ClaimType.SERVICE_BANNER:
        # Outdated / EOL product → medium
        version = str(ev.value.get("version", "")).lower()
        if any(old in version for old in ("1.", "2.0", "2.1", "2.2", "2.3", "2.4")):
            return RiskLevel.MEDIUM
        return RiskLevel.INFORMATIONAL

    return RiskLevel.INFORMATIONAL


# ---------------------------------------------------------------------------
# Section grouping
# ---------------------------------------------------------------------------

_SECTION_MAP: dict[str, list[ClaimType]] = {
    "Network Exposure": [ClaimType.OPEN_PORT],
    "Services & Banners": [ClaimType.SERVICE_BANNER],
    "Vulnerabilities": [ClaimType.VULNERABILITY],
    "Web Intelligence": [
        ClaimType.WEB_MENTION,
        ClaimType.COMPANY_INFO,
        ClaimType.SOCIAL_PROFILE,
        ClaimType.TECH_STACK,
    ],
    "Credential & Data Exposure": [ClaimType.CREDENTIAL_EXPOSURE],
    "DNS & Certificates": [ClaimType.HOSTNAME, ClaimType.DNS_RECORD, ClaimType.CERTIFICATE],
}

_SECTION_ORDER: list[str] = list(_SECTION_MAP.keys()) + ["Other Findings"]


def _section_for(claim_type: ClaimType) -> str:
    for section_name, types in _SECTION_MAP.items():
        if claim_type in types:
            return section_name
    return "Other Findings"


def _exclude_from_report(ev: Evidence) -> bool:
    dr = ev.enrichments.get("domain_relevance")
    if not isinstance(dr, dict):
        return False
    return bool(dr.get("exclude_from_report"))


def _finding_title(ev: Evidence, max_len: int = 120) -> str:
    raw_title = str(ev.value.get("title") or "").strip()
    url = str(ev.value.get("url") or "").strip()
    title = raw_title
    if title and url:
        tail_full = f" — {url}"
        if title.endswith(tail_full):
            title = title[: -len(tail_full)].strip()
        netloc = urlparse(url).netloc
        if netloc:
            tail_host = f" — {netloc}"
            if title.endswith(tail_host):
                title = title[: -len(tail_host)].strip()
    if not title:
        title = str(ev.claim or "(untitled)")
    if len(title) > max_len:
        return title[: max_len - 1] + "…"
    return title


def _finding_description(ev: Evidence) -> str:
    snip = str(ev.value.get("snippet") or "").strip()
    if snip:
        return snip[:400]
    return (
        f"{ev.claim_type}: confidence {ev.confidence:.2f}, "
        f"corroborated={ev.verified}."
    )


def _deterministic_section_summary(section_heading: str, evs: list[Evidence]) -> str:
    if not evs:
        return f"No items in “{section_heading}” after filtering."
    titles = [_finding_title(e) for e in evs[:5]]
    more = len(evs) - len(titles)
    tail = f" (+{more} more)." if more > 0 else "."
    joined = "; ".join(titles)
    return f"{section_heading}: {joined}{tail}"


def _deterministic_executive_summary(
    target: str,
    goal: str,
    primary: list[Evidence],
    excluded_n: int,
) -> str:
    apex = extract_target_apex(target)
    apex_note = f" Apex inferred as {apex}." if apex else ""

    if not primary:
        base = (
            f"No domain-aligned primary findings for “{target}”.{apex_note} "
            f"Goal: {goal}."
        )
        if excluded_n:
            return (
                f"{base} {excluded_n} web hit(s) kept in the evidence appendix "
                "were excluded from risk rollup due to weak alignment or polysemy filters."
            )
        return base

    ordered = sorted(primary, key=lambda e: e.confidence, reverse=True)
    top = ordered[:3]
    parts = [
        f"Executive view — target “{target}” ({goal}): "
        f"{len(primary)} primary finding(s).{apex_note}",
    ]
    if excluded_n:
        parts.append(
            f"{excluded_n} item(s) omitted from scoring due to domain relevance / "
            "collision filters (still visible in evidence appendix)."
        )
    rh = highest_risk([classify_risk(e) for e in primary])
    parts.append(f"Rollup risk from primary findings: {rh}.")
    parts.append(
        "Top signals: "
        + "; ".join(
            f"{classify_risk(ev)} {_finding_title(ev)} ({ev.confidence:.2f})"
            for ev in top
        )
        + "."
    )
    corroborated = sum(1 for e in primary if e.verified)
    parts.append(
        f"Corroborated primary findings: {corroborated}/{len(primary)}."
    )
    return " ".join(parts)


def _build_key_takeaways(
    target: str,
    primary: list[Evidence],
    excluded_n: int,
    section_counts: Counter[str],
) -> list[str]:
    out: list[str] = []
    apex = extract_target_apex(target)
    if apex:
        out.append(f"Scoped relevance checks against apex domain {apex}.")
    if excluded_n:
        out.append(
            f"Filtered {excluded_n} likely off-topic web hit(s) from headline risk."
        )
    if not primary:
        out.append("No primary findings — validate target wording or widen sources.")
        return out[:8]

    top = sorted(primary, key=lambda e: e.confidence, reverse=True)[:3]
    for ev in top:
        out.append(f"{classify_risk(ev)} · {_finding_title(ev)}")
    if section_counts:
        busiest = section_counts.most_common(3)
        sec_bits = ", ".join(f"{n} ({c})" for n, c in busiest)
        out.append(f"Finding density by section: {sec_bits}.")
    return out[:8]


# ---------------------------------------------------------------------------
# LLM summary helpers
# ---------------------------------------------------------------------------

_SECTION_SUMMARY_PROMPT = """\
You are a senior intelligence analyst writing a section of a professional OSINT report (NKRI standard).
Write a 3–5 sentence ANALYTICAL summary of the "{section}" section for target "{target}".
Base the summary ONLY on the provided evidence. Do not speculate beyond the evidence.

Requirements:
- Be analytical, not merely descriptive. State WHAT the evidence MEANS, not just WHAT was found.
- Highlight anomalies, inconsistencies, or gaps in the data.
- If a claim appears in only one source, flag it as unverified.
- End with one critical question that the analyst should investigate further.
- Format: plain prose paragraphs, no bullet points.

Evidence (JSON):
{evidence_json}
"""

_EXECUTIVE_SUMMARY_PROMPT = """\
You are a senior intelligence analyst. Write a structured 6–8 sentence executive summary for an OSINT
report on target "{target}" at NKRI intelligence standard.

Structure your summary as follows:
1. **Overview**: What is the target and what was investigated?
2. **Most Significant Risk**: The single most important finding and why it matters.
3. **Attack Surface / Exposure**: Scale of the infrastructure or information exposure.
4. **Affiliations & Network**: Key persons, investors, backers, or hidden connections identified.
5. **Intent Assessment**: What appears to be the entity's actual intent/purpose? Does stated purpose match observed behavior?
6. **Corroboration Quality**: How well-corroborated are the findings? What remains unverified?
7. **Critical Questions**: 2–3 unresolved questions the analyst must follow up on.
8. **Recommended Immediate Action**: Specific, actionable next step for the analyst.

Base your summary ONLY on the findings provided. Do not invent facts. Be analytical and direct.

Top findings (JSON):
{top_findings_json}
"""

_CRITICAL_QUESTIONS_PROMPT = """\
You are an intelligence analyst reviewing OSINT findings on target "{target}".
Based on the evidence below, generate exactly 5 critical questions that remain unanswered.
These questions should challenge assumptions, probe hidden connections, and direct further investigation.

Focus on:
- Who really controls or benefits from the target entity?
- Does the stated purpose match observed behavior?
- What connections to other entities are suggested but unproven?
- What data or sources are conspicuously absent?
- What would change the risk assessment if discovered?

Format: numbered list, each question on its own line. Questions only — no answers.

Evidence summary (JSON):
{evidence_json}
"""


async def _anthropic_summary(prompt: str, max_tokens: int = 2048) -> str:
    import anthropic  # type: ignore[import]

    settings = get_settings()
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    msg = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text.strip()


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


@dataclass
class ReporterConfig:
    generate_llm_summaries: bool = True
    top_findings_for_exec_summary: int = 10
    min_confidence_for_report: float = 0.0  # include all by default


class Reporter:
    def __init__(self, audit: AuditLogger, config: ReporterConfig | None = None) -> None:
        self._audit = audit
        self._cfg = config or ReporterConfig()

    async def _llm_or_fallback(self, prompt: str, fallback: str, max_tokens: int = 2048) -> str:
        if not self._cfg.generate_llm_summaries:
            return fallback
        settings = get_settings()
        if not settings.anthropic_api_key.strip():
            return fallback
        try:
            return await _anthropic_summary(prompt, max_tokens=max_tokens)
        except Exception as exc:
            log.warning("LLM summary generation failed", error=str(exc))
            return fallback

    async def generate(
        self,
        evidence: list[Evidence],
        target: str,
        goal: str,
        analyst_id: str,
        session_id: str,
    ) -> IntelReport:
        # 1. Filter by minimum confidence
        filtered = [
            ev for ev in evidence
            if ev.confidence >= self._cfg.min_confidence_for_report
        ]

        primary = [ev for ev in filtered if not _exclude_from_report(ev)]
        excluded_n = len(filtered) - len(primary)

        # 2. Classify risk (deterministic) — primary only for surfaced findings
        classified: list[tuple[Evidence, RiskLevel]] = [
            (ev, classify_risk(ev)) for ev in primary
        ]

        section_counts: Counter[str] = Counter()
        for ev, _ in classified:
            section_counts[_section_for(ev.claim_type)] += 1

        # 3. Build ReportFinding objects (deterministic)
        report_findings: list[ReportFinding] = [
            ReportFinding(
                title=_finding_title(ev),
                description=_finding_description(ev),
                claim_type=ev.claim_type,
                risk_level=risk,
                confidence=ev.confidence,
                confidence_components=ev.confidence_components,
                evidence_ids=[ev.id],
                sources_used=(
                    list(ev.verified_by)
                    if ev.verified_by
                    else [ev.provenance.source_tool]
                ),
                source_tiers=[ev.provenance.source_tier],
                corroborated=ev.verified,
                conflict_flag=ev.conflict_flag,
                conflict_note=ev.conflict_note,
                requires_review=ev.requires_review,
                review_reason=ev.review_reason,
            )
            for ev, risk in classified
        ]

        # 4. Group into sections (deterministic)
        section_map: dict[str, list[tuple[ReportFinding, Evidence]]] = {}
        for rf, (ev, _) in zip(report_findings, classified, strict=True):
            sname = _section_for(ev.claim_type)
            section_map.setdefault(sname, []).append((rf, ev))

        sections: list[ReportSection] = []
        for sname, pairs in section_map.items():
            section_evidence = [ev for _, ev in pairs]
            section_findings = [rf for rf, _ in pairs]

            fallback_sum = _deterministic_section_summary(sname, section_evidence)
            summary = fallback_sum
            if section_findings:
                dumped = [
                    ev.model_dump(exclude={"provenance": {"raw_response"}})
                    for ev in section_evidence[:10]
                ]
                ev_json = json.dumps(dumped, default=str, indent=2)
                prompt = _SECTION_SUMMARY_PROMPT.format(
                    section=sname, target=target, evidence_json=ev_json
                )
                summary = await self._llm_or_fallback(prompt, fallback=fallback_sum)

            sections.append(
                ReportSection(
                    heading=sname,
                    findings=section_findings,
                    summary=summary,
                )
            )

        sections.sort(
            key=lambda sec: (
                _SECTION_ORDER.index(sec.heading)
                if sec.heading in _SECTION_ORDER
                else len(_SECTION_ORDER)
            )
        )

        # 5. Compute aggregated metrics from primary findings (rollup)
        all_risks = [risk for _, risk in classified]
        overall_risk = highest_risk(all_risks) if all_risks else RiskLevel.INFORMATIONAL
        avg_conf = (
            round(sum(ev.confidence for ev in primary) / len(primary), 3)
            if primary else 0.0
        )
        corroborated = sum(1 for ev in primary if ev.verified)
        sources_used = list({ev.provenance.source_tool for ev in primary})

        all_findings_flat = [f for s in sections for f in s.findings]
        pending_review_count = sum(
            1 for f in all_findings_flat
            if f.requires_review and f.analyst_status == "pending"
        )
        conflict_hdr_count = sum(1 for f in all_findings_flat if f.conflict_flag)

        exec_fallback = _deterministic_executive_summary(
            target, goal, primary, excluded_n
        )
        exec_summary = exec_fallback
        if primary:
            top_evs = sorted(primary, key=lambda e: e.confidence, reverse=True)[
                : self._cfg.top_findings_for_exec_summary
            ]
            top_json = json.dumps(
                [
                    {
                        "claim": ev.claim,
                        "claim_type": ev.claim_type,
                        "confidence": ev.confidence,
                        "verified": ev.verified,
                        "risk": classify_risk(ev),
                    }
                    for ev in top_evs
                ],
                default=str,
                indent=2,
            )
            prompt = _EXECUTIVE_SUMMARY_PROMPT.format(
                target=target, top_findings_json=top_json
            )
            exec_summary = await self._llm_or_fallback(prompt, fallback=exec_fallback)

        takeaways = _build_key_takeaways(target, primary, excluded_n, section_counts)

        # 6. Generate critical questions (LLM)
        critical_questions: list[str] = []
        if primary and self._cfg.generate_llm_summaries:
            cq_evs = sorted(primary, key=lambda e: e.confidence, reverse=True)[:15]
            cq_json = json.dumps(
                [
                    {
                        "claim": ev.claim,
                        "claim_type": ev.claim_type,
                        "confidence": ev.confidence,
                        "verified": ev.verified,
                        "value_snippet": str(ev.value.get("snippet", ""))[:200],
                    }
                    for ev in cq_evs
                ],
                default=str,
                indent=2,
            )
            cq_prompt = _CRITICAL_QUESTIONS_PROMPT.format(
                target=target, evidence_json=cq_json
            )
            cq_raw = await self._llm_or_fallback(cq_prompt, fallback="", max_tokens=1024)
            if cq_raw:
                # Parse numbered list lines
                lines = [ln.strip() for ln in cq_raw.splitlines() if ln.strip()]
                import re as _re
                parsed = []
                for line in lines:
                    stripped = _re.sub(r"^\d+[\.\)]\s*", "", line)
                    if stripped:
                        parsed.append(stripped)
                critical_questions = parsed[:5]

        report = IntelReport(
            target=target,
            goal=goal,
            analyst_id=analyst_id,
            session_id=session_id,
            overall_risk=overall_risk,
            avg_confidence=avg_conf,
            total_evidence_items=len(filtered),
            corroborated_findings=corroborated,
            conflict_count=conflict_hdr_count,
            pending_review_count=pending_review_count,
            sources_used=sources_used,
            executive_summary=exec_summary,
            key_takeaways=takeaways,
            critical_questions=critical_questions,
            sections=sections,
            evidence=filtered,
        )

        self._audit.record(
            AuditEvent.REPORT_GENERATED,
            target=target,
            session_id=session_id,
            overall_risk=overall_risk,
            evidence_count=len(filtered),
        )

        return report
