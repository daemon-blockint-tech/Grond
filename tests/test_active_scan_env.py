"""Authorization CSV grants + LangGraph HITL bypass helpers for synchronous scan."""

from datetime import datetime, timezone

from src.core.authorization import AuthorizationRecord, AuthorizationService
from src.core.config import Settings
from src.core.orchestrator import _initial_authorization_confirmed_for_nmap


def test_authorization_wildcard_analyst_matches_any_request() -> None:
    svc = AuthorizationService()
    svc.grant(
        AuthorizationRecord(
            target="10.0.0.5",
            analyst_id="*",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        )
    )
    assert svc.is_authorized("10.0.0.5", "alice", "nmap")
    assert svc.is_authorized("10.0.0.5", "bob", "nmap")
    assert not svc.is_authorized("10.0.0.6", "alice", "nmap")


def test_with_settings_grants_seeds_csv() -> None:
    settings = Settings.model_construct(grond_authorized_scan_targets=" 127.0.0.1 ,scanme.nmap.org ")
    svc = AuthorizationService.with_settings_grants(settings)
    assert svc.is_authorized("127.0.0.1", "analyst-x", "nmap")
    assert svc.is_authorized("scanme.nmap.org", "other", "nmap")


def test_hostname_parent_authorizes_subdomains() -> None:
    svc = AuthorizationService()
    svc.grant(
        AuthorizationRecord(
            target="customer.example",
            analyst_id="*",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        )
    )
    assert svc.is_authorized("customer.example", "a", "nmap")
    assert svc.is_authorized("api.customer.example", "a", "nmap")
    assert not svc.is_authorized("othercustomer.example", "a", "nmap")


def test_wildcard_subdomain_only_not_apex() -> None:
    svc = AuthorizationService()
    svc.grant(
        AuthorizationRecord(
            target="*.customer.example",
            analyst_id="*",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        )
    )
    assert svc.is_authorized("api.customer.example", "a", "nmap")
    assert not svc.is_authorized("customer.example", "a", "nmap")


def test_requested_ip_not_matched_by_hostname_suffix() -> None:
    svc = AuthorizationService()
    svc.grant(
        AuthorizationRecord(
            target="1.2.3.0/24",
            analyst_id="*",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        )
    )
    assert svc.is_authorized("1.2.3.4", "a", "nmap")
    svc2 = AuthorizationService()
    svc2.grant(
        AuthorizationRecord(
            target="evil.test",
            analyst_id="*",
            tool="nmap",
            authorized_at=datetime.now(timezone.utc),
        )
    )
    assert not svc2.is_authorized("1.2.3.4", "a", "nmap")


def test_hitl_bypass_requires_development_environment() -> None:
    prod_like = Settings.model_construct(
        grond_dev_bypass_nmap_hitl=True,
        environment="production",
    )
    assert _initial_authorization_confirmed_for_nmap(True, prod_like) is False

    dev = Settings.model_construct(
        grond_dev_bypass_nmap_hitl=True,
        environment="development",
    )
    assert _initial_authorization_confirmed_for_nmap(True, dev) is True
    assert _initial_authorization_confirmed_for_nmap(False, dev) is False
