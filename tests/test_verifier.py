"""Tests for the verification stage — deduplication, cross-validation, confidence scoring."""
from datetime import datetime, timezone

from src.core.audit import AuditLogger
from src.models.evidence import ClaimType, Evidence, Provenance, SourceTool
from src.pipeline.verifier import Verifier, compute_confidence, default_claim_key


def _prov(tool: SourceTool, query: str = "test") -> Provenance:
    return Provenance(
        source_tool=tool,
        collection_query=query,
        collected_at=datetime.now(timezone.utc),
        analyst_id="analyst-test",
        session_id="sess-test",
        raw_response={},
    )


def _port_evidence(ip: str, port: int, tool: SourceTool, confidence: float = 0.85) -> Evidence:
    return Evidence(
        target=ip,
        claim=f"Port {port}/tcp open on {ip}",
        claim_type=ClaimType.OPEN_PORT,
        value={"ip": ip, "port": port, "protocol": "tcp"},
        provenance=_prov(tool),
        confidence=confidence,
    )


def _audit() -> AuditLogger:
    return AuditLogger(analyst_id="analyst-test", session_id="sess-test")


class TestClaimKey:
    def test_same_port_same_key(self):
        ev1 = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        ev2 = _port_evidence("1.2.3.4", 80, SourceTool.NMAP)
        assert default_claim_key(ev1) == default_claim_key(ev2)

    def test_different_port_different_key(self):
        ev1 = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        ev2 = _port_evidence("1.2.3.4", 443, SourceTool.SHODAN)
        assert default_claim_key(ev1) != default_claim_key(ev2)

    def test_different_ip_different_key(self):
        ev1 = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        ev2 = _port_evidence("5.6.7.8", 80, SourceTool.SHODAN)
        assert default_claim_key(ev1) != default_claim_key(ev2)


class TestVerifier:
    def test_deduplicates_same_port_two_sources(self):
        ev_shodan = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        ev_nmap = _port_evidence("1.2.3.4", 80, SourceTool.NMAP, confidence=0.95)

        v = Verifier(audit=_audit())
        result = v.verify([ev_shodan, ev_nmap])

        assert result.original_count == 2
        assert result.dedup_count == 1
        assert len(result.deduplicated) == 1

    def test_corroborated_when_two_sources(self):
        ev_shodan = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        ev_nmap = _port_evidence("1.2.3.4", 80, SourceTool.NMAP)

        v = Verifier(audit=_audit())
        result = v.verify([ev_shodan, ev_nmap])

        merged = result.deduplicated[0]
        assert merged.verified is True
        assert result.verified_count == 1

    def test_not_corroborated_single_source(self):
        ev = _port_evidence("1.2.3.4", 443, SourceTool.SHODAN)

        v = Verifier(audit=_audit())
        result = v.verify([ev])

        assert result.deduplicated[0].verified is False
        assert result.verified_count == 0

    def test_sorted_by_confidence_descending(self):
        items = [
            _port_evidence("1.1.1.1", 80, SourceTool.SHODAN, confidence=0.3),
            _port_evidence("2.2.2.2", 443, SourceTool.SHODAN, confidence=0.9),
            _port_evidence("3.3.3.3", 8080, SourceTool.SHODAN, confidence=0.6),
        ]
        v = Verifier(audit=_audit())
        result = v.verify(items)
        scores = [e.confidence for e in result.deduplicated]
        assert scores == sorted(scores, reverse=True)

    def test_empty_evidence_handled(self):
        v = Verifier(audit=_audit())
        result = v.verify([])
        assert result.deduplicated == []
        assert result.original_count == 0


class TestConfidence:
    def test_verified_gets_bonus(self):
        ev_shodan = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        ev_nmap = _port_evidence("1.2.3.4", 80, SourceTool.NMAP, confidence=0.95)
        group_multi = [ev_shodan, ev_nmap]
        group_single = [ev_shodan]

        multi_total = compute_confidence(ev_shodan, group_multi).total
        single_total = compute_confidence(ev_shodan, group_single).total
        assert multi_total > single_total

    def test_old_evidence_decays(self):
        from datetime import timedelta

        old_prov = _prov(SourceTool.SHODAN)
        old_date = datetime.now(timezone.utc) - timedelta(days=100)
        old_prov = old_prov.model_copy(update={"collected_at": old_date})

        fresh = _port_evidence("1.2.3.4", 80, SourceTool.SHODAN)
        old = fresh.model_copy(update={"provenance": old_prov})

        assert compute_confidence(fresh, [fresh]).total > compute_confidence(old, [old]).total


def _tavily_evidence(
    *,
    url: str,
    title: str,
    claim_type: ClaimType,
    snippet: str = "",
    confidence: float = 0.72,
) -> Evidence:
    return Evidence(
        target="daemonprotocol.com",
        claim=f"{title} — {url}",
        claim_type=claim_type,
        value={
            "url": url,
            "title": title,
            "snippet": snippet or title,
            "relevance_score": 0.42,
        },
        provenance=_prov(SourceTool.TAVILY, query='site:test "daemon"'),
        confidence=confidence,
    )


class TestDomainRelevanceGate:
    def test_polysemy_collision_weak_domain_excluded(self):
        ev = _tavily_evidence(
            url="https://daemon-tools.cc/news",
            title="DAEMON Tools security advisory",
            claim_type=ClaimType.WEB_MENTION,
            snippet="disk imaging product DAEMON Tools release notes",
        )
        v = Verifier(audit=_audit())
        result = v.verify([ev], investigation_target="daemonprotocol.com")
        dr = result.deduplicated[0].enrichments["domain_relevance"]
        assert dr["tier"] == "weak"
        assert dr["exclude_from_report"] is True

    def test_same_apex_kept(self):
        ev = _tavily_evidence(
            url="https://daemonprotocol.com/blog/post",
            title="Daemon Protocol quarterly update",
            claim_type=ClaimType.WEB_MENTION,
            snippet="engineering hires",
            confidence=0.8,
        )
        v = Verifier(audit=_audit())
        result = v.verify([ev], investigation_target="daemonprotocol.com")
        dr = result.deduplicated[0].enrichments["domain_relevance"]
        assert dr["tier"] == "strong"
        assert dr["exclude_from_report"] is False

    def test_off_domain_credential_excluded(self):
        ev = _tavily_evidence(
            url="https://example-breach-news.com/a",
            title="Anonymous breach compilation leak",
            claim_type=ClaimType.CREDENTIAL_EXPOSURE,
            snippet="paste references",
        )
        v = Verifier(audit=_audit())
        result = v.verify([ev], investigation_target="daemonprotocol.com")
        dr = result.deduplicated[0].enrichments["domain_relevance"]
        assert dr["exclude_from_report"] is True

    def test_without_investigation_target_skips_gate(self):
        ev = _tavily_evidence(
            url="https://daemon-tools.cc/news",
            title="DAEMON Tools",
            claim_type=ClaimType.WEB_MENTION,
        )
        v = Verifier(audit=_audit())
        result = v.verify([ev])
        assert "domain_relevance" not in result.deduplicated[0].enrichments
