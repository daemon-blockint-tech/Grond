"""Tests for the reporter — deterministic classification and report building."""
from datetime import datetime, timezone

from src.core.audit import AuditLogger
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTool
from src.models.report import RiskLevel
from src.pipeline.reporter import Reporter, ReporterConfig, classify_risk


def _prov(tool: SourceTool = SourceTool.SHODAN) -> Provenance:
    return Provenance(
        source_tool=tool,
        collection_query="test",
        collected_at=datetime.now(timezone.utc),
        analyst_id="analyst-1",
        session_id="sess-1",
        raw_response={},
    )


def _ev(claim_type: ClaimType, value: dict, confidence: float = 0.8) -> Evidence:
    return Evidence(
        target="target.example.com",
        claim=f"{claim_type} on target",
        claim_type=claim_type,
        value=value,
        provenance=_prov(),
        confidence=confidence,
    )


class TestClassifyRisk:
    def test_critical_cvss(self):
        ev = _ev(ClaimType.VULNERABILITY, {"cve_id": "CVE-2021-44228"})
        ev.enrichments["nvd"] = {"cvss3_score": 10.0}
        assert classify_risk(ev) == RiskLevel.CRITICAL

    def test_high_cvss(self):
        ev = _ev(ClaimType.VULNERABILITY, {})
        ev.enrichments["nvd"] = {"cvss3_score": 8.5}
        assert classify_risk(ev) == RiskLevel.HIGH

    def test_medium_unknown_cvss(self):
        ev = _ev(ClaimType.VULNERABILITY, {"cve_id": "CVE-2020-0001"})
        # no nvd enrichment — default to medium
        assert classify_risk(ev) == RiskLevel.MEDIUM

    def test_telnet_port_is_high(self):
        ev = _ev(ClaimType.OPEN_PORT, {"port": 23, "protocol": "tcp"})
        assert classify_risk(ev) == RiskLevel.HIGH

    def test_credential_exposure_is_high(self):
        ev = _ev(ClaimType.CREDENTIAL_EXPOSURE, {"url": "https://pastebin.com/x"})
        assert classify_risk(ev) == RiskLevel.HIGH

    def test_normal_port_is_low(self):
        ev = _ev(ClaimType.OPEN_PORT, {"port": 443, "protocol": "tcp"})
        assert classify_risk(ev) == RiskLevel.LOW

    def test_web_mention_is_informational(self):
        ev = _ev(ClaimType.WEB_MENTION, {"url": "https://example.com"})
        assert classify_risk(ev) == RiskLevel.INFORMATIONAL


class TestReporter:
    async def test_report_contains_all_evidence(self):
        evidence = [
            _ev(ClaimType.OPEN_PORT, {"port": 80, "protocol": "tcp"}),
            _ev(ClaimType.VULNERABILITY, {"cve_id": "CVE-2020-0001"}),
            _ev(ClaimType.WEB_MENTION, {"url": "https://example.com", "title": "Test"}),
        ]
        audit = AuditLogger(analyst_id="analyst-1", session_id="sess-1")
        reporter = Reporter(audit=audit, config=ReporterConfig(generate_llm_summaries=False))

        report = await reporter.generate(
            evidence=evidence,
            target="target.example.com",
            goal="test",
            analyst_id="analyst-1",
            session_id="sess-1",
        )

        assert report.total_evidence_items == 3
        assert len(report.evidence) == 3

    async def test_report_risk_elevated_by_vuln(self):
        evidence = [
            _ev(ClaimType.VULNERABILITY, {"cve_id": "CVE-2021-44228"}),
        ]
        evidence[0].enrichments["nvd"] = {"cvss3_score": 10.0}

        audit = AuditLogger(analyst_id="analyst-1", session_id="sess-1")
        reporter = Reporter(audit=audit, config=ReporterConfig(generate_llm_summaries=False))

        report = await reporter.generate(
            evidence=evidence,
            target="target.example.com",
            goal="test",
            analyst_id="analyst-1",
            session_id="sess-1",
        )

        assert report.overall_risk == RiskLevel.CRITICAL

    async def test_disclaimer_always_present(self):
        audit = AuditLogger(analyst_id="analyst-1", session_id="sess-1")
        reporter = Reporter(audit=audit, config=ReporterConfig(generate_llm_summaries=False))

        report = await reporter.generate(
            evidence=[],
            target="example.com",
            goal="test",
            analyst_id="analyst-1",
            session_id="sess-1",
        )

        assert "publicly available sources" in report.disclaimer

    async def test_citation_lookup(self):
        ev = _ev(ClaimType.OPEN_PORT, {"port": 443})
        audit = AuditLogger(analyst_id="analyst-1", session_id="sess-1")
        reporter = Reporter(audit=audit, config=ReporterConfig(generate_llm_summaries=False))

        report = await reporter.generate(
            evidence=[ev],
            target="example.com",
            goal="test",
            analyst_id="analyst-1",
            session_id="sess-1",
        )

        citation = report.citation_for(ev.id)
        assert citation is not None
        assert "shodan" in citation.lower()

    async def test_excluded_domain_noise_not_in_rollup(self):
        """exclude_from_report evidence must not set overall_risk alone."""
        noise = Evidence(
            target="daemonprotocol.com",
            claim="paste dump — https://paste.example/x",
            claim_type=ClaimType.CREDENTIAL_EXPOSURE,
            value={
                "url": "https://paste.example/x",
                "title": "Leak compilation",
                "snippet": "credentials",
            },
            provenance=_prov(SourceTool.TAVILY),
            confidence=0.9,
            enrichments={
                "domain_relevance": {
                    "exclude_from_report": True,
                    "tier": "weak",
                }
            },
        )
        on_domain = Evidence(
            target="daemonprotocol.com",
            claim="Site — https://daemonprotocol.com/",
            claim_type=ClaimType.WEB_MENTION,
            value={
                "url": "https://daemonprotocol.com/",
                "title": "Daemon Protocol — official site",
                "snippet": "Welcome",
            },
            provenance=_prov(SourceTool.TAVILY),
            confidence=0.75,
            enrichments={
                "domain_relevance": {
                    "exclude_from_report": False,
                    "tier": "strong",
                }
            },
        )
        audit = AuditLogger(analyst_id="analyst-1", session_id="sess-1")
        reporter = Reporter(audit=audit, config=ReporterConfig(generate_llm_summaries=False))

        report = await reporter.generate(
            evidence=[noise, on_domain],
            target="daemonprotocol.com",
            goal="test",
            analyst_id="analyst-1",
            session_id="sess-1",
        )

        assert report.overall_risk == RiskLevel.INFORMATIONAL
        assert any(s.findings for s in report.sections)
        assert any(
            "filtered" in t.lower() or "omit" in t.lower()
            for t in report.key_takeaways
        )
