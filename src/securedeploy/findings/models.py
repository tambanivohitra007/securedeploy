"""Normalized finding models — the common internal currency of SecureDeploy."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def numeric(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}[self.value]

    def __lt__(self, other: "Severity") -> bool:
        return self.numeric < other.numeric

    def __le__(self, other: "Severity") -> bool:
        return self.numeric <= other.numeric

    def __gt__(self, other: "Severity") -> bool:
        return self.numeric > other.numeric

    def __ge__(self, other: "Severity") -> bool:
        return self.numeric >= other.numeric


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"

    @property
    def numeric(self) -> int:
        return {"confirmed": 4, "high": 3, "medium": 2, "low": 1, "speculative": 0}[self.value]


class LocationType(str, Enum):
    WEB = "web"
    SOURCE = "source"
    CONTAINER = "container"
    DEPENDENCY = "dependency"
    NETWORK = "network"
    TLS = "tls"
    SECRET = "secret"
    IaC = "iac"


class Disposition(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    REPORT = "report"
    ACCEPTED_RISK = "accepted_risk"
    EXPIRED_ACCEPTED_RISK = "expired_accepted_risk"
    SUPPRESSED = "suppressed"


class FindingLocation(BaseModel):
    type: LocationType
    # Web findings
    url: str | None = None
    endpoint: str | None = None  # normalized path with {id} placeholders
    method: str | None = None
    parameter: str | None = None
    # Source findings
    source_file: str | None = None
    line: int | None = None
    column: int | None = None
    # Dependency findings
    package_name: str | None = None
    package_version: str | None = None
    package_ecosystem: str | None = None


class Evidence(BaseModel):
    # HTTP evidence (web findings)
    request: str | None = None       # HTTP request — credentials must be redacted
    response_status: int | None = None
    response_excerpt: str | None = None
    # Generic
    description: str | None = None
    expected: str | None = None
    actual: str | None = None
    # Source evidence
    code_snippet: str | None = None
    # Raw tool output (truncated)
    raw: str | None = None


class SourceInfo(BaseModel):
    tool: str
    tool_version: str | None = None
    rule_id: str
    suite: str | None = None


class NormalizedFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = ""  # computed by fingerprint module after construction

    title: str
    description: str = ""

    severity: Severity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    confidence: Confidence = Confidence.MEDIUM

    category: str
    subcategory: str | None = None

    owasp_top10: list[str] = Field(default_factory=list)
    owasp_api_top10: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cve: str | None = None

    source: SourceInfo
    location: FindingLocation
    evidence: Evidence = Field(default_factory=Evidence)

    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    first_detected: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = ""

    suppression: str | None = None
    accepted_risk: str | None = None

    tags: list[str] = Field(default_factory=list)

    # Populated by policy engine
    disposition: Disposition | None = None

    model_config = {"use_enum_values": False}


class CorrelatedFinding(BaseModel):
    """One or more NormalizedFindings merged into a single deduplicated finding."""

    finding_id: str = Field(default_factory=lambda: f"corr-{uuid.uuid4()}")
    fingerprint: str

    title: str
    description: str
    severity: Severity
    confidence: Confidence

    category: str
    subcategory: str | None = None
    owasp_top10: list[str] = Field(default_factory=list)
    owasp_api_top10: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cve: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None

    location: FindingLocation
    remediation: str
    references: list[str] = Field(default_factory=list)

    # All source findings that were merged into this one
    sources: list[NormalizedFinding] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)

    first_detected: datetime
    scan_id: str = ""
    tags: list[str] = Field(default_factory=list)

    # Set by policy engine
    disposition: Disposition | None = None
    disposition_reason: str | None = None

    @classmethod
    def from_finding(cls, finding: NormalizedFinding) -> "CorrelatedFinding":
        return cls(
            fingerprint=finding.fingerprint,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=finding.confidence,
            category=finding.category,
            subcategory=finding.subcategory,
            owasp_top10=finding.owasp_top10,
            owasp_api_top10=finding.owasp_api_top10,
            cwe=finding.cwe,
            cve=finding.cve,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            location=finding.location,
            remediation=finding.remediation,
            references=finding.references,
            sources=[finding],
            source_tools=[finding.source.tool],
            first_detected=finding.first_detected,
            scan_id=finding.scan_id,
            tags=finding.tags,
        )

    def merge(self, finding: NormalizedFinding) -> None:
        """Merge an additional finding into this correlated finding."""
        self.sources.append(finding)
        if finding.source.tool not in self.source_tools:
            self.source_tools.append(finding.source.tool)
        # Escalate severity if higher
        if finding.severity > self.severity:
            self.severity = finding.severity
        # Escalate confidence if higher
        if finding.confidence.numeric > self.confidence.numeric:
            self.confidence = finding.confidence
        # Prefer richer CVE/CVSS data
        if finding.cve and not self.cve:
            self.cve = finding.cve
        if finding.cvss_score and (not self.cvss_score or finding.cvss_score > self.cvss_score):
            self.cvss_score = finding.cvss_score
            self.cvss_vector = finding.cvss_vector
        # Merge CWE, references, tags
        for cwe in finding.cwe:
            if cwe not in self.cwe:
                self.cwe.append(cwe)
        for ref in finding.references:
            if ref not in self.references:
                self.references.append(ref)
        for tag in finding.tags:
            if tag not in self.tags:
                self.tags.append(tag)


class ToolError(BaseModel):
    """Represents a scanner tool failure — distinct from a security finding."""

    tool: str
    tool_version: str | None = None
    reason: str  # TIMEOUT | CRASH | UNAVAILABLE | PARSE_ERROR
    message: str
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float = 0.0

    @property
    def display_reason(self) -> str:
        labels = {
            "TIMEOUT": "timed out",
            "CRASH": "crashed",
            "UNAVAILABLE": "not available",
            "PARSE_ERROR": "produced unparseable output",
        }
        return labels.get(self.reason, self.reason.lower())


class ScanSummary(BaseModel):
    scan_id: str
    project_name: str
    target_url: str
    profile: str
    started_at: datetime
    finished_at: datetime | None = None
    tool_errors: list[ToolError] = Field(default_factory=list)
    finding_counts: dict[str, int] = Field(default_factory=dict)
    verdict: str = "UNKNOWN"  # PASS | FAIL | ERROR

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def count_by_severity(self, findings: list[CorrelatedFinding]) -> None:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        self.finding_counts = counts

    model_config = {"arbitrary_types_allowed": True}
