"""
Domain-aware relevance for OSINT targets.

Reduces polysemy noise when the investigation target is domain-shaped (e.g.
daemonprotocol.com matching DAEMON Tools / Blockdaemon web hits).

Query construction (Tavily) and evidence annotation (Verifier → Reporter) share
apex-domain extraction so behavior stays consistent.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from src.models.evidence import ClaimType, Evidence, SourceTool
from src.tools.tavily_tool import COMPANY_INTEL_QUERIES

# Host suffixes where off-domain pages may still corroborate the target entity.
RELATED_CORROBORATION_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "linkedin.com",
    "twitter.com",
    "x.com",
    "crunchbase.com",
    "sec.gov",
    "bbc.co.uk",
)

# Snippets that usually refer to a different product/org than a daemon*-style domain target.
POLYSEMY_COLLISION_SUBSTRINGS: tuple[str, ...] = (
    "daemon tools",
    "disc soft",
    "disk imaging",
    "virtual drive",
    "blockdaemon",
    "block daemon",
)

_DOMAIN_TOKEN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)


def _looks_like_ipv4(host: str) -> bool:
    if not host or host.count(".") != 3:
        return False
    parts = host.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _looks_like_ipv6(host: str) -> bool:
    return ":" in host and host.count(":") >= 2


def registrable_apex(hostname: str) -> str | None:
    """
    Normalized registrable apex label (last two DNS labels), lowercased.

    Coarse heuristic — does not implement full PSL (e.g. co.uk). Good enough
    for aligning OSINT hits to a supplied corporate domain.
    """
    h = hostname.strip().lower().rstrip(".")
    if not h or _looks_like_ipv4(h) or _looks_like_ipv6(h):
        return None
    if h.startswith("www."):
        h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def host_from_evidence_url(ev: Evidence) -> str | None:
    url = ev.value.get("url") or ev.provenance.source_url
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname
        return host.lower().strip(".") if host else None
    except Exception:
        return None


def extract_target_apex(target: str) -> str | None:
    """
    Derive apex domain from an arbitrary target string (URL, bare domain, prose).

    Returns None for IPs or when no domain-like token is found.
    """
    t = target.strip()
    if not t:
        return None

    candidates: list[str] = []

    url_seed = t
    if "://" not in url_seed and "/" in t and "." in t.split("/", 1)[0]:
        url_seed = "https://" + t.split("/", 1)[0]
    if "://" in url_seed:
        host = urlparse(url_seed).hostname
        if host:
            candidates.append(host)

    if _DOMAIN_TOKEN_RE.fullmatch(t.strip()):
        candidates.append(t.strip())

    for m in _DOMAIN_TOKEN_RE.finditer(t):
        candidates.append(m.group(0))

    seen: set[str] = set()
    for cand in candidates:
        cand_norm = cand.strip().lower().rstrip(".")
        if cand_norm in seen:
            continue
        seen.add(cand_norm)
        apex = registrable_apex(cand_norm)
        if apex:
            return apex

    return None


def _is_subdomain_or_same(ev_apex: str | None, target_apex: str) -> bool:
    if not ev_apex:
        return False
    if ev_apex == target_apex:
        return True
    return ev_apex.endswith("." + target_apex)


def classify_host_tier(host_apex: str | None, target_apex: str) -> str:
    """Return strong | related | weak."""
    if host_apex and _is_subdomain_or_same(host_apex, target_apex):
        return "strong"
    if host_apex:
        for suf in RELATED_CORROBORATION_DOMAIN_SUFFIXES:
            if host_apex == suf or host_apex.endswith("." + suf):
                return "related"
    return "weak"


def text_blob(ev: Evidence) -> str:
    title = str(ev.value.get("title") or "")
    snippet = str(ev.value.get("snippet") or "")
    claim = str(ev.claim or "")
    return f"{title}\n{snippet}\n{claim}".lower()


def collision_noise(blob: str) -> bool:
    return any(s in blob for s in POLYSEMY_COLLISION_SUBSTRINGS)


def build_tavily_queries_for_target(target: str) -> list[str]:
    """
    Broad COMPANY_INTEL_QUERIES plus prioritized site:-scoped queries when the
    target yields an apex domain. IPs / non-domain targets keep legacy behavior.
    """
    broad = [t.format(target=target) for t in COMPANY_INTEL_QUERIES]
    apex = extract_target_apex(target)
    if not apex:
        return broad

    brand_guess = apex.rsplit(".", 1)[0]
    site_queries = [
        f"site:{apex} {brand_guess} company about",
        f"site:{apex} security careers engineering",
        f"site:{apex} news blog announcement",
        f'site:{apex} "{brand_guess}" breach leak incident',
    ]
    # Prioritized first so analysts see on-domain SERP context earlier in merged lists.
    return site_queries + broad


CLAIM_TYPES_DOMAIN_GATE: frozenset[ClaimType] = frozenset(
    {
        ClaimType.WEB_MENTION,
        ClaimType.COMPANY_INFO,
        ClaimType.SOCIAL_PROFILE,
        ClaimType.TECH_STACK,
        ClaimType.CREDENTIAL_EXPOSURE,
    }
)


def annotate_evidence_domain_relevance(ev: Evidence, target_apex: str | None) -> Evidence:
    """
    Attach domain_relevance enrichment and optional confidence downrank.

    Excludes obvious noise from primary reporting (Reporter reads exclude_from_report).
    """
    dr: dict[str, object] = {
        "tier": "unknown",
        "exclude_from_report": False,
        "reason": "",
        "target_apex": target_apex,
        "evidence_host_apex": None,
    }

    if not target_apex:
        dr["tier"] = "unknown"
        dr["reason"] = "non-domain target — gate skipped"
        return ev.model_copy(update={"enrichments": {**ev.enrichments, "domain_relevance": dr}})

    if ev.claim_type not in CLAIM_TYPES_DOMAIN_GATE:
        dr["tier"] = "not_applicable"
        dr["reason"] = "claim type not domain-gated"
        return ev.model_copy(update={"enrichments": {**ev.enrichments, "domain_relevance": dr}})

    # Tavily-driven WEBINT is the main noise source; still gate other tools with URLs.
    url = ev.value.get("url") or ev.provenance.source_url
    if not url:
        dr["tier"] = "unknown"
        dr["reason"] = "no URL on evidence — gate skipped"
        return ev.model_copy(update={"enrichments": {**ev.enrichments, "domain_relevance": dr}})

    raw_host = host_from_evidence_url(ev)
    host_ax = registrable_apex(raw_host) if raw_host else None
    dr["evidence_host_apex"] = host_ax

    tier = classify_host_tier(host_ax, target_apex)
    dr["tier"] = tier

    blob = text_blob(ev)
    rel_score = ev.value.get("relevance_score")
    low_relevance = isinstance(rel_score, (int, float)) and float(rel_score) < 0.45

    confidence_mult = 1.0
    exclude = False
    reason = ""

    if tier == "strong":
        reason = "URL host aligns with target apex"
    elif tier == "related":
        reason = "URL on configured related/corroboration domain"
    else:
        # weak
        if ev.claim_type == ClaimType.CREDENTIAL_EXPOSURE:
            exclude = True
            reason = "credential/breach-style claim from host not aligned with target apex"
        elif collision_noise(blob):
            exclude = True
            reason = "weak domain alignment and polysemy collision phrase in text"
        elif low_relevance and ev.provenance.source_tool == SourceTool.TAVILY:
            confidence_mult = 0.35
            reason = "weak alignment and low Tavily relevance_score"
        else:
            confidence_mult = 0.45
            reason = "weak domain alignment — downranked"

    dr["exclude_from_report"] = exclude
    dr["reason"] = reason

    new_conf = round(min(1.0, max(0.0, ev.confidence * confidence_mult)), 4)

    return ev.model_copy(
        update={
            "confidence": new_conf,
            "enrichments": {**ev.enrichments, "domain_relevance": dr},
        }
    )
