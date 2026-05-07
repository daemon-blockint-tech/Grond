"""
Tests for tool adapters.

All tests mock the underlying API clients — no live network calls.
VCR cassettes can be added later for integration tests.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.audit import AuditLogger
from src.core.authorization import AuthorizationRecord, AuthorizationService
from src.core.exceptions import ToolAuthError, ToolError, UnauthorizedScanError
from src.models.evidence import ClaimType


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    from src.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _audit() -> AuditLogger:
    return AuditLogger(analyst_id="analyst-1", session_id="sess-1")


def _auth_service(target: str = "1.2.3.4") -> AuthorizationService:
    svc = AuthorizationService()
    svc.grant(
        AuthorizationRecord(
            target=target,
            analyst_id="analyst-1",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        )
    )
    return svc


# ---------------------------------------------------------------------------
# Shodan adapter
# ---------------------------------------------------------------------------

SHODAN_MOCK_MATCH = {
    "ip_str": "1.2.3.4",
    "port": 443,
    "transport": "tcp",
    "product": "Apache httpd",
    "version": "2.4.52",
    "org": "Example Corp",
    "asn": "AS12345",
    "location": {"country_code": "US"},
    "vulns": {
        "CVE-2022-22719": {"cvss": 7.5, "summary": "buffer overflow", "verified": True}
    },
    "cpe": ["cpe:/a:apache:http_server:2.4.52"],
    "data": "HTTP/1.1 200 OK",
}


class TestShodanAdapter:
    @patch.dict("os.environ", {
        "SHODAN_API_KEY": "test", "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test", "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    })
    async def test_parses_open_port(self):
        from src.tools.shodan_tool import ShodanAdapter, ShodanInput

        with patch("shodan.Shodan") as MockShodan:
            mock_client = MagicMock()
            mock_client.search.return_value = {"matches": [SHODAN_MOCK_MATCH]}
            MockShodan.return_value = mock_client

            adapter = ShodanAdapter(audit=_audit(), api_key="test-key")
            inp = ShodanInput(
                target="1.2.3.4",
                query="ip:1.2.3.4",
                analyst_id="analyst-1",
                session_id="sess-1",
            )
            evidence = await adapter.run(inp)

        port_claims = [e for e in evidence if e.claim_type == ClaimType.OPEN_PORT]
        assert len(port_claims) == 1
        assert port_claims[0].value["port"] == 443

    @patch.dict("os.environ", {
        "SHODAN_API_KEY": "test", "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test", "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    })
    async def test_parses_vulnerability(self):
        from src.tools.shodan_tool import ShodanAdapter, ShodanInput

        with patch("shodan.Shodan") as MockShodan:
            mock_client = MagicMock()
            mock_client.search.return_value = {"matches": [SHODAN_MOCK_MATCH]}
            MockShodan.return_value = mock_client

            adapter = ShodanAdapter(audit=_audit(), api_key="test-key")
            inp = ShodanInput(
                target="1.2.3.4",
                query="ip:1.2.3.4",
                analyst_id="analyst-1",
                session_id="sess-1",
            )
            evidence = await adapter.run(inp)

        vuln_claims = [e for e in evidence if e.claim_type == ClaimType.VULNERABILITY]
        assert len(vuln_claims) == 1
        assert vuln_claims[0].value["cve_id"] == "CVE-2022-22719"

    @patch.dict("os.environ", {
        "SHODAN_API_KEY": "test", "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test", "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    })
    async def test_raw_response_preserved_in_provenance(self):
        from src.tools.shodan_tool import ShodanAdapter, ShodanInput

        with patch("shodan.Shodan") as MockShodan:
            mock_client = MagicMock()
            mock_client.search.return_value = {"matches": [SHODAN_MOCK_MATCH]}
            MockShodan.return_value = mock_client

            adapter = ShodanAdapter(audit=_audit(), api_key="test-key")
            inp = ShodanInput(
                target="1.2.3.4",
                query="ip:1.2.3.4",
                analyst_id="analyst-1",
                session_id="sess-1",
            )
            evidence = await adapter.run(inp)

        # Every item must have the raw API payload preserved
        for ev in evidence:
            assert ev.provenance.raw_response != {}


# ---------------------------------------------------------------------------
# theHarvester JSON mapping
# ---------------------------------------------------------------------------

_HARVEST_JSON = {
    "cmd": "theHarvester -d example.com",
    "hosts": ["mail.example.com", "example.com"],
    "emails": ["a@example.com"],
    "ips": ["203.0.113.1"],
    "interesting_urls": ["https://example.com/admin"],
    "asns": ["AS64496"],
}


class TestHarvesterJsonMapping:
    @patch.dict("os.environ", {
        "SHODAN_API_KEY": "test",
        "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test",
        "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    })
    def test_harvest_json_to_evidence(self):
        from src.tools.harvester_tool import harvest_json_to_evidence
        from src.models.evidence import ClaimType, SourceTier

        items = harvest_json_to_evidence(
            _HARVEST_JSON,
            domain="example.com",
            analyst_id="analyst-1",
            session_id="sess-1",
            tier=SourceTier.COMMUNITY,
            source_label="duckduckgo,crtsh",
            cli_snippet="theHarvester -d example.com",
            stderr_text="",
            exit_code=0,
        )
        types = {e.claim_type for e in items}
        assert ClaimType.SUBDOMAIN in types
        assert ClaimType.HOSTNAME in types
        assert ClaimType.EMAIL_DISCOVERY in types
        assert ClaimType.HOST_DISCOVERY in types
        assert ClaimType.WEB_MENTION in types
        assert ClaimType.ASN in types
        assert any(e.requires_review for e in items if e.claim_type == ClaimType.EMAIL_DISCOVERY)

    @patch.dict("os.environ", {
        "SHODAN_API_KEY": "test",
        "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test",
        "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    })
    async def test_harvester_active_requires_allow_and_auth(self):
        from src.tools.harvester_tool import HarvesterAdapter, HarvesterInput

        svc = AuthorizationService()
        adapter = HarvesterAdapter(audit=_audit(), auth_service=svc)
        inp_no_flag = HarvesterInput(
            target="example.com",
            analyst_id="analyst-1",
            session_id="sess-1",
            allow_active_techniques=False,
            dns_brute=True,
        )
        with pytest.raises(ToolError):
            await adapter.run(inp_no_flag)

        inp_auth = HarvesterInput(
            target="example.com",
            analyst_id="analyst-1",
            session_id="sess-1",
            allow_active_techniques=True,
            dns_brute=True,
        )
        with pytest.raises(UnauthorizedScanError):
            await adapter.run(inp_auth)


class TestEdgarTextSearchAdapter:
    EDGAR_MOCK_ROW = {
        "entity_name": "Example Corp",
        "root_form": "10-K",
        "form_name": "Annual report",
        "filed_at": "2024-03-15",
        "filing_details_url": "https://www.sec.gov/Archives/edgar/data/123/filing.htm",
        "filing_document_url": "https://www.sec.gov/Archives/edgar/data/123/doc.htm",
        "company_cik_trimmed": "0000001234",
        "ticker": "EXMP",
    }

    @patch.dict("os.environ", {
        "SHODAN_API_KEY": "test",
        "TAVILY_API_KEY": "test",
        "ANTHROPIC_API_KEY": "test",
        "DATABASE_URL": "postgresql+asyncpg://x:y@h/db",
        "SECRET_KEY": "x" * 32,
    })
    def test_edgar_maps_rows_to_evidence(self):
        import asyncio

        from src.tools.sec_edgar_tool import EdgarTextSearchAdapter, EdgarTextSearchInput
        from src.models.evidence import ClaimType, SourceTool

        with patch("src.tools.sec_edgar_tool._sync_edgar_search", return_value=[self.EDGAR_MOCK_ROW]):
            adapter = EdgarTextSearchAdapter(audit=_audit())
            inp = EdgarTextSearchInput(
                target="Example Corp",
                analyst_id="analyst-1",
                session_id="sess-1",
                keywords=["risk factors"],
                entity="EXMP",
            )
            evidence = asyncio.run(adapter.run(inp))

        assert len(evidence) == 1
        ev = evidence[0]
        assert ev.claim_type == ClaimType.COMPANY_INFO
        assert ev.provenance.source_tool == SourceTool.EDGAR
        assert ev.value.get("ticker") == "EXMP"
        assert "Example Corp" in ev.claim
        assert ev.provenance.raw_response.get("entity_name") == "Example Corp"


class TestOsintmapParser:
    _SAMPLE = """| Country | Links |
| --- | --- |
| Belgium | <a href="https://kbopub.example/reg">Business registry</a> |
| France | <a href="https://fr.example/">Other</a> |
"""

    def test_matching_rows_belgium(self) -> None:
        from src.tools.osintmap_tool import _matching_rows

        rows = _matching_rows(self._SAMPLE, "belgium", 10)
        assert len(rows) == 1
        assert rows[0][0] == "Belgium"

    def test_extract_anchor_links(self) -> None:
        from src.tools.osintmap_tool import _extract_anchor_links

        cell = '<a href="https://a.example/">Alpha</a></br><a href="https://b.example/">Beta</a>'
        links = _extract_anchor_links(cell, 10)
        assert len(links) == 2
        assert links[0]["url"] == "https://a.example/"
        assert "Alpha" in links[0]["label"]


class TestAuthorization:
    def test_grants_matching_target(self):
        svc = _auth_service("1.2.3.4")
        assert svc.is_authorized("1.2.3.4", "analyst-1", "nmap") is True

    def test_denies_wrong_analyst(self):
        svc = _auth_service("1.2.3.4")
        assert svc.is_authorized("1.2.3.4", "other-analyst", "nmap") is False

    def test_grants_cidr_range(self):
        svc = AuthorizationService()
        svc.grant(AuthorizationRecord(
            target="10.0.0.0/8",
            analyst_id="analyst-1",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        ))
        assert svc.is_authorized("10.1.2.3", "analyst-1", "nmap") is True
        assert svc.is_authorized("192.168.1.1", "analyst-1", "nmap") is False

    def test_wildcard_tool(self):
        svc = AuthorizationService()
        svc.grant(AuthorizationRecord(
            target="1.2.3.4",
            analyst_id="analyst-1",
            tool="*",
            authorized_at=datetime.now(timezone.utc),
        ))
        assert svc.is_authorized("1.2.3.4", "analyst-1", "nmap") is True
        assert svc.is_authorized("1.2.3.4", "analyst-1", "ncrack") is True

    async def test_nmap_raises_without_authorization(self):
        from src.tools.nmap_tool import NmapAdapter, NmapInput

        svc = AuthorizationService()  # empty — no records
        adapter = NmapAdapter(audit=_audit(), auth_service=svc)
        inp = NmapInput(target="1.2.3.4", analyst_id="analyst-1", session_id="sess-1")

        with pytest.raises(UnauthorizedScanError):
            await adapter.run(inp)
