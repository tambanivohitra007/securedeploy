"""Tests for the policy engine — the core decision-maker."""

import pytest
from datetime import datetime, timezone

from securedeploy.config.models import PolicyConfig, PolicyAction
from securedeploy.findings.models import (
    CorrelatedFinding,
    Confidence,
    Disposition,
    Evidence,
    FindingLocation,
    LocationType,
    NormalizedFinding,
    Severity,
    SourceInfo,
)
from securedeploy.policy.engine import PolicyEngine
from securedeploy.policy.models import Verdict


def make_finding(
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    cwe: list[str] | None = None,
    cve: str | None = None,
) -> CorrelatedFinding:
    src = NormalizedFinding(
        title="Test finding",
        severity=severity,
        confidence=confidence,
        category="Test",
        cwe=cwe or [],
        cve=cve,
        source=SourceInfo(tool="test", rule_id="test-001"),
        location=FindingLocation(type=LocationType.WEB, endpoint="/test"),
        fingerprint="v1:sha256:abc",
        scan_id="test-scan",
        first_detected=datetime.now(timezone.utc),
    )
    cf = CorrelatedFinding.from_finding(src)
    return cf


def make_engine(
    critical: str = "block",
    high: str = "block",
    medium: str = "warn",
    low: str = "report",
    confidence_adjustment: bool = True,
) -> PolicyEngine:
    policy = PolicyConfig()
    policy.on_finding.critical = PolicyAction(critical)
    policy.on_finding.high = PolicyAction(high)
    policy.on_finding.medium = PolicyAction(medium)
    policy.on_finding.low = PolicyAction(low)
    policy.confidence_adjustment.enabled = confidence_adjustment
    return PolicyEngine(policy)


class TestBasicPolicy:
    def test_critical_blocks(self):
        engine = make_engine()
        finding = make_finding(Severity.CRITICAL, Confidence.HIGH)
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.FAIL
        assert any(f.disposition == Disposition.BLOCK for f in result.findings)

    def test_high_blocks(self):
        engine = make_engine()
        finding = make_finding(Severity.HIGH, Confidence.HIGH)
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.FAIL

    def test_medium_warns_not_blocks(self):
        engine = make_engine()
        finding = make_finding(Severity.MEDIUM, Confidence.HIGH)
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.PASS
        assert any(f.disposition == Disposition.WARN for f in result.findings)

    def test_low_reports_only(self):
        engine = make_engine()
        finding = make_finding(Severity.LOW, Confidence.HIGH)
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.PASS
        assert any(f.disposition == Disposition.REPORT for f in result.findings)

    def test_no_findings_is_pass(self):
        engine = make_engine()
        result = engine.evaluate([], [], scan_id="s1")
        assert result.verdict == Verdict.PASS


class TestConfidenceAdjustment:
    def test_critical_low_confidence_downgraded_to_high(self):
        engine = make_engine(confidence_adjustment=True)
        engine._policy.confidence_adjustment.block_only_if_confidence = {
            "critical": "medium",
            "high": "high",
        }
        # Critical with LOW confidence → downgraded to HIGH
        # HIGH with LOW confidence → downgraded to MEDIUM → WARN not BLOCK
        finding = make_finding(Severity.CRITICAL, Confidence.LOW)
        result = engine.evaluate([finding], [], scan_id="s1")
        # Downgraded critical→high, but high still requires HIGH confidence
        # LOW confidence finding should not block in this config
        assert finding.disposition != Disposition.BLOCK

    def test_critical_confirmed_always_blocks(self):
        engine = make_engine(confidence_adjustment=True)
        finding = make_finding(Severity.CRITICAL, Confidence.CONFIRMED)
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.FAIL


class TestCweOverrides:
    def test_block_cwe_overrides_severity(self):
        policy = PolicyConfig()
        policy.on_finding.medium = PolicyAction.WARN  # normally just warn
        policy.overrides.block_cwe = ["CWE-89"]
        engine = PolicyEngine(policy)
        finding = make_finding(Severity.MEDIUM, cwe=["CWE-89"])
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.FAIL

    def test_warn_cwe_downgrades_critical(self):
        policy = PolicyConfig()
        policy.overrides.warn_cwe = ["CWE-200"]
        engine = PolicyEngine(policy)
        finding = make_finding(Severity.CRITICAL, cwe=["CWE-200"])
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.PASS  # downgraded to WARN

    def test_block_cve_triggers_block(self):
        policy = PolicyConfig()
        policy.overrides.block_cve = ["CVE-2021-44228"]
        engine = PolicyEngine(policy)
        finding = make_finding(Severity.LOW, cve="CVE-2021-44228")
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.FAIL


class TestAcceptedRisks:
    def test_accepted_risk_does_not_block(self):
        engine = make_engine()
        finding = make_finding(Severity.CRITICAL)
        finding.fingerprint = "v1:sha256:known-risk"
        accepted = [{
            "id": "AR-001",
            "title": "Known risk",
            "fingerprint": "v1:sha256:known-risk",
            "reason": "Accepted for staging",
        }]
        result = engine.evaluate([finding], [], scan_id="s1", accepted_risks=accepted)
        assert result.verdict == Verdict.PASS
        assert any(f.disposition == Disposition.ACCEPTED_RISK for f in result.findings)

    def test_expired_accepted_risk_warns(self):
        engine = make_engine()
        finding = make_finding(Severity.CRITICAL)
        finding.fingerprint = "v1:sha256:expired-risk"
        accepted = [{
            "id": "AR-002",
            "title": "Expired risk",
            "fingerprint": "v1:sha256:expired-risk",
            "expires": "2020-01-01",  # expired
        }]
        result = engine.evaluate([finding], [], scan_id="s1", accepted_risks=accepted)
        # Expired → treated as WARN after re-evaluation
        assert any(
            f.disposition in (Disposition.WARN, Disposition.BLOCK)
            for f in result.findings
        )


class TestThresholds:
    def test_threshold_max_critical_zero_blocks(self):
        policy = PolicyConfig()
        policy.on_finding.critical = PolicyAction.BLOCK
        policy.thresholds.max_critical = 0
        engine = PolicyEngine(policy)
        finding = make_finding(Severity.CRITICAL, Confidence.CONFIRMED)
        result = engine.evaluate([finding], [], scan_id="s1")
        assert result.verdict == Verdict.FAIL

    def test_threshold_max_medium_exceeded_fails(self):
        policy = PolicyConfig()
        policy.on_finding.medium = PolicyAction.WARN
        policy.thresholds.max_medium = 2
        engine = PolicyEngine(policy)
        findings = [make_finding(Severity.MEDIUM) for _ in range(3)]
        result = engine.evaluate(findings, [], scan_id="s1")
        assert result.verdict == Verdict.FAIL
