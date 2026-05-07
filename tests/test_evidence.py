"""Tests for the Evidence and Provenance models."""
from datetime import datetime, timezone, timedelta

import pytest

from src.models.evidence import ClaimType, Evidence, Provenance, SourceTool


def _make_prov(**kwargs) -> Provenance:
    defaults = dict(
        source_tool=SourceTool.SHODAN,
        collection_query="ip:1.2.3.4",
        collected_at=datetime.now(timezone.utc),
        analyst_id="analyst-1",
        session_id="sess-abc",
        raw_response={"ip_str": "1.2.3.4"},
    )
    return Provenance(**{**defaults, **kwargs})


def _make_evidence(**kwargs) -> Evidence:
    defaults = dict(
        target="1.2.3.4",
        claim="Port 80/tcp open on 1.2.3.4",
        claim_type=ClaimType.OPEN_PORT,
        value={"port": 80, "protocol": "tcp"},
        provenance=_make_prov(),
        confidence=0.85,
    )
    return Evidence(**{**defaults, **kwargs})


class TestEvidence:
    def test_creates_with_uuid(self):
        ev = _make_evidence()
        assert len(ev.id) == 36  # UUID4 format

    def test_age_days_is_zero_for_fresh_evidence(self):
        ev = _make_evidence(provenance=_make_prov(collected_at=datetime.now(timezone.utc)))
        assert ev.age_days < 0.01

    def test_age_days_for_old_evidence(self):
        old = datetime.now(timezone.utc) - timedelta(days=10)
        ev = _make_evidence(provenance=_make_prov(collected_at=old))
        assert 9.9 < ev.age_days < 10.1

    def test_citation_format(self):
        ev = _make_evidence()
        assert "[shodan" in ev.citation
        assert 'query="ip:1.2.3.4"' in ev.citation

    def test_confidence_bounds_enforced(self):
        with pytest.raises(Exception):
            _make_evidence(confidence=1.5)
        with pytest.raises(Exception):
            _make_evidence(confidence=-0.1)

    def test_verified_defaults_false(self):
        ev = _make_evidence()
        assert ev.verified is False

    def test_enrichments_start_empty(self):
        ev = _make_evidence()
        assert ev.enrichments == {}
