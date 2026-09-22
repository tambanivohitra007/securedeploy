"""Pydantic models for securedeploy.yaml project configuration."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


class Environment(str, Enum):
    LOCAL = "local"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Profile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class OutputFormat(str, Enum):
    TERMINAL = "terminal"
    HTML = "html"
    SARIF = "sarif"
    JSON = "json"
    JUNIT = "junit"


class PolicyAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    REPORT = "report"
    IGNORE = "ignore"


# ──────────────────────────────────────────────────────────────────────────────
# Sub-models
# ──────────────────────────────────────────────────────────────────────────────


class ProjectInfo(BaseModel):
    name: str
    id: str | None = None  # stable identifier for baseline tracking


class ScopeConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(
        default_factory=lambda: [
            "stripe.com",
            "paypal.com",
            "braintreepayments.com",
            "auth0.com",
            "okta.com",
            "google-analytics.com",
            "segment.com",
            "mixpanel.com",
            "cloudflare.com",
            "fastly.com",
            "akamai.net",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
        ]
    )
    max_depth: int = Field(default=3, ge=1, le=10)
    max_urls: int = Field(default=500, ge=1, le=10000)


class TargetConfig(BaseModel):
    url: str
    environment: Environment = Environment.STAGING
    api_base: str | None = None
    openapi_spec: str | None = None
    scope: ScopeConfig = Field(default_factory=ScopeConfig)

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("target.url must start with http:// or https://")
        return v.rstrip("/")

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).netloc


class SourceConfig(BaseModel):
    path: str = "./src"
    exclude: list[str] = Field(
        default_factory=lambda: [
            "node_modules/",
            "vendor/",
            ".git/",
            "**/*.min.js",
            "**/*.min.css",
        ]
    )
    languages: list[str] = Field(default_factory=list)  # auto-detect if empty


class TestingConfig(BaseModel):
    source_code: bool = True
    secrets: bool = True
    dependencies: bool = True
    containers: bool = True
    tls: bool = True
    headers: bool = True
    web: bool = True
    api: bool = True
    network: bool = False  # off by default — requires Nmap
    custom_tests: bool = True
    container_images: list[str] = Field(default_factory=list)
    iac_paths: list[str] = Field(default_factory=lambda: ["./infrastructure/", "./k8s/", "./terraform/"])


class CustomTestsConfig(BaseModel):
    paths: list[str] = Field(default_factory=lambda: ["./security-tests/**/*.yaml"])


class FindingPolicy(BaseModel):
    critical: PolicyAction = PolicyAction.BLOCK
    high: PolicyAction = PolicyAction.BLOCK
    medium: PolicyAction = PolicyAction.WARN
    low: PolicyAction = PolicyAction.REPORT
    informational: PolicyAction = PolicyAction.REPORT

    def action_for(self, severity: str) -> PolicyAction:
        return getattr(self, severity.lower(), PolicyAction.REPORT)


class ConfidenceAdjustment(BaseModel):
    enabled: bool = True
    # Minimum confidence required before applying BLOCK for each severity
    block_only_if_confidence: dict[str, str] = Field(
        default_factory=lambda: {"critical": "medium", "high": "high"}
    )


class PolicyThresholds(BaseModel):
    max_critical: int | None = 0
    max_high: int | None = 0
    max_medium: int | None = None
    max_low: int | None = None


class PolicyOverrides(BaseModel):
    block_cwe: list[str] = Field(default_factory=list)
    block_cve: list[str] = Field(default_factory=list)
    warn_cwe: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    on_finding: FindingPolicy = Field(default_factory=FindingPolicy)
    confidence_adjustment: ConfidenceAdjustment = Field(default_factory=ConfidenceAdjustment)
    on_tool_failure: PolicyAction = PolicyAction.WARN
    overrides: PolicyOverrides = Field(default_factory=PolicyOverrides)
    thresholds: PolicyThresholds = Field(default_factory=PolicyThresholds)


class AcceptedRisk(BaseModel):
    id: str
    title: str
    fingerprint: str | None = None
    rule_id: str | None = None
    tool: str | None = None
    reason: str = ""
    accepted_by: str = ""
    expires: str | None = None  # ISO 8601 date


class SafetyConfig(BaseModel):
    max_concurrency: int = Field(default=3, ge=1, le=10)
    default_timeout: int = Field(default=600, ge=30, le=7200)  # seconds
    max_requests_per_second: int = Field(default=10, ge=1, le=100)
    block_out_of_scope_redirects: bool = True
    deep_authorization_acknowledgement: str | None = None
    production_acknowledgement: str | None = None
    allow_private_ips: bool = False  # permit scanning RFC1918 ranges


class OutputConfig(BaseModel):
    directory: str = "./securedeploy-reports"
    formats: list[OutputFormat] = Field(
        default_factory=lambda: [
            OutputFormat.TERMINAL,
            OutputFormat.SARIF,
            OutputFormat.JSON,
        ]
    )
    fail_on_warn: bool = False


# Per-scanner option blocks

class NucleiOptions(BaseModel):
    timeout: int = 300
    tags_include: list[str] = Field(
        default_factory=lambda: ["cve", "misconfig", "headers", "tls", "exposure", "config"]
    )
    tags_exclude: list[str] = Field(
        default_factory=lambda: ["intrusive", "dos", "fuzzing", "exploit"]
    )
    rate_limit: int = 50  # requests/sec within Nuclei


class TrivyOptions(BaseModel):
    timeout: int = 300
    severity: list[str] = Field(
        default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )
    ignore_unfixed: bool = False


class SemgrepOptions(BaseModel):
    timeout: int = 300
    rulesets: list[str] = Field(
        default_factory=lambda: ["p/owasp-top-ten", "p/secrets", "p/security-audit"]
    )
    local_rules: str | None = None


class ZapOptions(BaseModel):
    timeout: int = 1200
    ajax_spider: bool = False


class ScannersConfig(BaseModel):
    nuclei: NucleiOptions = Field(default_factory=NucleiOptions)
    trivy: TrivyOptions = Field(default_factory=TrivyOptions)
    semgrep: SemgrepOptions = Field(default_factory=SemgrepOptions)
    zap: ZapOptions = Field(default_factory=ZapOptions)


# ──────────────────────────────────────────────────────────────────────────────
# Root config
# ──────────────────────────────────────────────────────────────────────────────


class ProjectConfig(BaseModel):
    version: str = "1"
    project: ProjectInfo
    target: TargetConfig
    source: SourceConfig = Field(default_factory=SourceConfig)
    testing: TestingConfig = Field(default_factory=TestingConfig)
    custom_tests: CustomTestsConfig = Field(default_factory=CustomTestsConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    accepted_risks: list[AcceptedRisk] = Field(default_factory=list)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)

    @model_validator(mode="after")
    def production_requires_acknowledgement(self) -> "ProjectConfig":
        if self.target.environment == Environment.PRODUCTION:
            ack = self.safety.production_acknowledgement
            if not ack:
                raise ValueError(
                    "Scanning a production environment requires "
                    "safety.production_acknowledgement to be set in config."
                )
        return self

    @model_validator(mode="after")
    def populate_scope_include(self) -> "ProjectConfig":
        """Auto-include the target host in scope if scope.include is empty."""
        if not self.target.scope.include:
            self.target.scope.include = [self.target.host]
        return self
