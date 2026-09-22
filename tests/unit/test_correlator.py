"""Tests for finding deduplication and cross-tool correlation."""

import pytest
from datetime import datetime, timezone

from securedeploy.findings.correlator import correlate
from securedeploy.findings.models import (
    Confidence,
    Evidence,
    FindingLocation,
    LocationType,
    NormalizedFinding,
    Severity,
    SourceInfo,
)


def make_finding(
    tool: str,
    rule_id: str,
    endpoint: str,
    severity: Severity = Severity.HIGH,
    cwe: list[str] | None = None,
    title: str = "Test Finding",
    fingerprint: str | None = None,
) -> NormalizedFinding:
    f = NormalizedFinding(
        title=title,
        severity=severity,
        confidence=Confidence.HIGH,
        category="Test",
        cwe=cwe or [],
        source=SourceInfo(tool=tool, rule_id=rule_id),
        location=FindingLocation(
            type=LocationType.WEB,
            endpoint=endpoint,
            method="GET",
        ),
        first_detected=datetime.now(timezone.utc),
    )
    if fingerprint:
        f.fingerprint = fingerprint
    else:
        from securedeploy.findings.fingerprint import stamp_finding
        stamp_finding(f)
    return f


class TestExactDeduplication:
    def test_same_fingerprint_merges(self):
        fp = "v1:sha256:abc123"
        f1 = make_finding("zap", "xss-01", "/api/search", fingerprint=fp)
        f2 = make_finding("nuclei", "xss-reflected", "/api/search", fingerprint=fp)
        result = correlate([f1, f2])
        assert len(result) == 1
        assert len(result[0].sources) == 2
        assert set(result[0].source_tools) == {"zap", "nuclei"}

    def test_different_fingerprints_are_separate(self):
        f1 = make_finding("zap", "sqli-01", "/api/search")
        f2 = make_finding("nuclei", "xss-01", "/api/profile")
        result = correlate([f1, f2])
        assert len(result) == 2

    def test_single_finding_preserved(self):
        f = make_finding("trivy", "CVE-2024-1234", "/", title="Log4j vulnerability")
        result = correlate([f])
        assert len(result) == 1
        assert result[0].title == "Log4j vulnerability"


class TestSeverityEscalation:
    def test_merge_escalates_severity(self):
        fp = "v1:sha256:test-fp"
        f_medium = make_finding("nuclei", "test", "/api", Severity.MEDIUM, fingerprint=fp)
        f_high = make_finding("zap", "test2", "/api", Severity.HIGH, fingerprint=fp)
        result = correlate([f_medium, f_high])
        assert result[0].severity == Severity.HIGH


class TestSorting:
    def test_results_sorted_by_severity_desc(self):
        f_low = make_finding("t", "r1", "/a", Severity.LOW)
        f_critical = make_finding("t", "r2", "/b", Severity.CRITICAL)
        f_medium = make_finding("t", "r3", "/c", Severity.MEDIUM)
        result = correlate([f_low, f_critical, f_medium])
        assert result[0].severity == Severity.CRITICAL


class TestCweAndReferenceMerge:
    def test_cwes_merged_from_sources(self):
        fp = "v1:sha256:cwe-merge-test"
        f1 = make_finding("t1", "r1", "/api", cwe=["CWE-89"], fingerprint=fp)
        f2 = make_finding("t2", "r2", "/api", cwe=["CWE-564"], fingerprint=fp)
        result = correlate([f1, f2])
        assert "CWE-89" in result[0].cwe
        assert "CWE-564" in result[0].cwe
