"""Application configuration — all secrets from environment, never hardcoded."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Tool keys ---------------------------------------------------------------
    shodan_api_key: str = Field(..., description="Shodan API key")
    tavily_api_key: str = Field(..., description="Tavily API key")
    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key — required for LLM section/executive summaries in Reporter; optional for tool-only runs",
    )
    twitter_bearer_token: str = Field(
        default="",
        description="X API v2 bearer token — required for Twitter OSINT",
    )
    twitter_max_results: int = Field(
        default=100,
        ge=10,
        le=500,
        description="Default max_results per Twitter search request",
    )

    # -- Infrastructure ----------------------------------------------------------
    database_url: str = Field(..., description="Async PostgreSQL DSN")
    redis_url: str = Field("redis://localhost:6379")
    neo4j_uri: str = Field("bolt://localhost:7687")
    neo4j_user: str = Field("neo4j")
    neo4j_password: str = Field("changeme")
    opensearch_url: str = Field("http://localhost:9200")

    # -- Vector store ------------------------------------------------------------
    embedding_backend: str = Field("pgvector", pattern="^(pgvector|qdrant)$")
    embedding_model: str = Field("sentence-transformers/all-MiniLM-L6-v2")
    qdrant_url: str = Field("http://localhost:6333")

    # -- S3 artifact store -------------------------------------------------------
    s3_bucket: str = Field("grond-artifacts")
    s3_endpoint: str | None = Field(None)
    s3_access_key: str = Field("")
    s3_secret_key: str = Field("")
    s3_region: str = Field("us-east-1")

    # -- Observability -----------------------------------------------------------
    otel_exporter_otlp_endpoint: str = Field("http://localhost:4318/v1/traces")
    sentry_dsn: str = Field("")
    sentry_traces_sample_rate: float = Field(0.1, ge=0.0, le=1.0)

    # -- Security / App ----------------------------------------------------------
    secret_key: str = Field(..., min_length=32)
    grond_api_url: str = Field("http://localhost:8000")
    environment: str = Field("development", pattern="^(development|staging|production)$")
    log_level: str = Field("INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    # Active scan (Nmap) — synchronous API cannot resume LangGraph HITL; see orchestrator + docs.
    grond_dev_bypass_nmap_hitl: bool = Field(
        default=False,
        description=(
            "Development only: when ENVIRONMENT=development and run_nmap=true, skip planner "
            "interrupt and pre-set authorization_confirmed for the graph (still requires "
            "GROND_AUTHORIZED_SCAN_TARGETS or explicit AuthorizationRecord for require_authorization)"
        ),
    )
    grond_authorized_scan_targets: str = Field(
        default="",
        description=(
            "Comma-separated IPs, CIDRs, hostnames, *.sub.example.com (subdomains only), or parent "
            "hostnames (parent matches subdomains). Pre-grants tool=nmap with analyst_id=* "
            "(AuthorizationService seed). Does not bypass LangGraph HITL unless GROND_DEV_BYPASS_NMAP_HITL"
        ),
    )
    grond_active_scan_auth_from_db: bool = Field(
        default=False,
        description=(
            "If true, merge non-expired rows from table grond_active_scan_authorization at API startup "
            "(and optional admin POST) into AuthorizationService."
        ),
    )
    grond_authorization_admin_key: str = Field(
        default="",
        description=(
            "If non-empty, POST /api/v1/admin/active-scan-authorizations requires header "
            "X-Grond-Authorization-Admin-Key with this value. Empty disables the route (HTTP 503)."
        ),
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, v: object) -> object:
        if isinstance(v, str):
            return v.upper()
        return v

    # -- Scan limits -------------------------------------------------------------
    shodan_rate_limit_rps: float = Field(1.0, gt=0, le=10)
    nmap_default_timeout_seconds: int = Field(300, ge=30, le=1800)
    tavily_max_results: int = Field(10, ge=1, le=20)
    theharvester_bin: str = Field(
        default="",
        description="Path to theHarvester executable; empty = PATH / python -m theHarvester",
    )
    theharvester_timeout_seconds: int = Field(600, ge=60, le=7200)
    osintmap_readme_url: str = Field(
        default="https://raw.githubusercontent.com/cipher387/osintmap/main/README.md",
        description="Raw README for cipher387/osintmap regional link table",
    )
    exiftool_bin: str = Field(
        default="exiftool",
        description="Path to ExifTool binary — same engine as github.com/chriswmorris/Metaforge",
    )
    exiftool_timeout_seconds: int = Field(120, ge=10, le=600)
    metadata_max_upload_bytes: int = Field(52_428_800, ge=1024, description="Max upload size ~50MB")
    exiv2_bin: str = Field(
        default="exiv2",
        description="Path to Exiv2 CLI — https://github.com/Exiv2/exiv2 / https://exiv2.org",
    )
    exiv2_timeout_seconds: int = Field(120, ge=10, le=600)
    metadata_engine: str = Field(
        default="exiftool",
        pattern="^(exiftool|exiv2|auto)$",
        description=(
            "Metadata CLI: exiftool (broad), exiv2 (images), auto = exiv2 then exiftool fallback"
        ),
    )
    stegoveritas_bin: str = Field(
        default="stegoveritas",
        description="Path to stegoVeritas CLI — https://github.com/bannsec/stegoVeritas. Set STEGOVERITAS_BIN to override (e.g. /opt/grond/.venv/bin/stegoveritas)",
    )
    stego_timeout_seconds: int = Field(300, ge=30, le=1800)
    stego_max_upload_bytes: int = Field(52_428_800, ge=1024, description="Max stego upload size ~50MB")
    stego_engine: str = Field(
        default="auto",
        pattern="^(stegoveritas|lsb|auto)$",
        description="Stego engine: stegoveritas (comprehensive), lsb (pure-Python fallback), auto",
    )
    # Confidence formula weights
    # Confidence = (w_s · source_reliability)
    #            + (w_c · cross_source_agreement)
    #            + (w_t · freshness)
    #            + (w_e · evidence_completeness)
    #
    # Weights must sum to 1.0 — validated below.
    # =========================================================================

    # w_s — source reliability weight (highest: provenance quality matters most)
    confidence_w_s: float = Field(
        0.40, ge=0.0, le=1.0, description="Weight for source reliability component"
    )

    # w_c — cross-source agreement weight
    confidence_w_c: float = Field(
        0.25, ge=0.0, le=1.0, description="Weight for cross-source corroboration component"
    )

    # w_t — temporal freshness weight
    confidence_w_t: float = Field(
        0.20, ge=0.0, le=1.0, description="Weight for temporal freshness component"
    )

    # w_e — evidence completeness weight
    confidence_w_e: float = Field(
        0.15, ge=0.0, le=1.0, description="Weight for evidence completeness component"
    )

    # Tool-level reliability within source_reliability score
    confidence_weight_nmap: float = Field(0.95, ge=0.0, le=1.0)
    confidence_weight_shodan: float = Field(0.85, ge=0.0, le=1.0)
    confidence_weight_tavily: float = Field(0.70, ge=0.0, le=1.0)
    confidence_weight_theharvester: float = Field(0.55, ge=0.0, le=1.0)
    confidence_weight_osintmap: float = Field(0.52, ge=0.0, le=1.0)
    confidence_weight_edgar: float = Field(0.88, ge=0.0, le=1.0)
    confidence_weight_exiftool: float = Field(0.72, ge=0.0, le=1.0)
    confidence_weight_exiv2: float = Field(0.72, ge=0.0, le=1.0)
    confidence_weight_stegoveritas: float = Field(0.78, ge=0.0, le=1.0)
    confidence_weight_stego_lsb: float = Field(0.55, ge=0.0, le=1.0)
    confidence_weight_manual: float = Field(1.00, ge=0.0, le=1.0)

    # Temporal decay λ — higher = findings go stale faster
    # Default 0.02 → at 7 days: freshness ≈ 0.87; at 30 days: ≈ 0.55
    confidence_decay_lambda: float = Field(0.02, ge=0.0, le=1.0)

    # =========================================================================
    # High-risk review thresholds
    # Evidence meeting any threshold gets requires_review=True
    # =========================================================================

    # CVE CVSS score threshold — CRITICAL (≥9.0 by CVSS v3 spec)
    review_cvss_threshold: float = Field(9.0, ge=0.0, le=10.0)

    # Confidence threshold — anonymous uncorroborated claims below this get flagged
    review_anonymous_min_confidence: float = Field(0.50, ge=0.0, le=1.0)

    # Cross-source conflict: CVSS difference to flag as conflicting
    conflict_cvss_delta: float = Field(2.0, ge=0.0, le=10.0)

    # =========================================================================
    # Validators
    # =========================================================================

    @model_validator(mode="after")
    def _validate_weight_sum(self) -> Settings:
        total = (
            self.confidence_w_s + self.confidence_w_c + self.confidence_w_t + self.confidence_w_e
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Confidence weights must sum to 1.0, got {total:.4f} "
                f"(w_s={self.confidence_w_s}, w_c={self.confidence_w_c}, "
                f"w_t={self.confidence_w_t}, w_e={self.confidence_w_e})"
            )
        return self

    @model_validator(mode="after")
    def _check_production_log_level(self) -> Settings:
        if self.environment == "production" and self.log_level == "DEBUG":
            raise ValueError("DEBUG log level is not allowed in production")
        return self

    # =========================================================================
    # Helpers
    # =========================================================================

    def source_weight(self, source: str) -> float:
        """Tool-level reliability multiplier (within source_reliability component)."""
        weights = {
            "nmap": self.confidence_weight_nmap,
            "ncrack": self.confidence_weight_nmap,
            "shodan": self.confidence_weight_shodan,
            "tavily": self.confidence_weight_tavily,
            "twitter": 0.50,
            "theharvester": self.confidence_weight_theharvester,
            "osintmap": self.confidence_weight_osintmap,
            "edgar": self.confidence_weight_edgar,
            "exiftool": self.confidence_weight_exiftool,
            "exiv2": self.confidence_weight_exiv2,
            "stegoveritas": self.confidence_weight_stegoveritas,
            "stego_lsb": self.confidence_weight_stego_lsb,
            "manual": self.confidence_weight_manual,
        }
        return weights.get(source, 0.5)

    @property
    def confidence_weights(self) -> tuple[float, float, float, float]:
        """Return (w_s, w_c, w_t, w_e) as a tuple."""
        return (self.confidence_w_s, self.confidence_w_c, self.confidence_w_t, self.confidence_w_e)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
