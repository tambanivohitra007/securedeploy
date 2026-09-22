"""Policy evaluation result models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from securedeploy.findings.models import CorrelatedFinding, ToolError


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


PASS_DISCLAIMER = (
    "PASS means the application passed the configured security policy. "
    "It does not guarantee the absence of all security vulnerabilities."
)


class PolicyResult(BaseModel):
    verdict: Verdict
    scan_id: str
    block_reasons: list[str] = []

    # All correlated findings, each annotated with disposition
    findings: list[CorrelatedFinding] = []

    # Tool failures (separate channel from findings)
    tool_errors: list[ToolError] = []

    # Counts by severity (only unaccepted, unsuppressed findings)
    counts: dict[str, int] = {}

    disclaimer: str = PASS_DISCLAIMER

    @property
    def is_pass(self) -> bool:
        return self.verdict == Verdict.PASS

    @property
    def blocking_findings(self) -> list[CorrelatedFinding]:
        from securedeploy.findings.models import Disposition
        return [f for f in self.findings if f.disposition == Disposition.BLOCK]

    @property
    def warning_findings(self) -> list[CorrelatedFinding]:
        from securedeploy.findings.models import Disposition
        return [f for f in self.findings if f.disposition == Disposition.WARN]

    model_config = {"arbitrary_types_allowed": True}
