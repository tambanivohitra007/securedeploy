"""Security policy engine.

Evaluates correlated findings against the project's security policy and
produces a PASS/FAIL verdict with annotated findings.

Policy evaluation is separate from scanning and reporting — this component
produces a PolicyResult that reporters consume.
"""

from __future__ import annotations

import logging

from securedeploy.config.models import PolicyAction, PolicyConfig
from securedeploy.findings.models import (
    Confidence,
    CorrelatedFinding,
    Disposition,
    Severity,
    ToolError,
)
from securedeploy.findings.suppression import apply_suppressions
from securedeploy.policy.models import PolicyResult, Verdict

log = logging.getLogger(__name__)

# Confidence level ordering for threshold checks
_CONFIDENCE_ORDER = {
    Confidence.SPECULATIVE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
    Confidence.CONFIRMED: 4,
}

# One severity level below (for confidence downgrade)
_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFORMATIONAL,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}


class PolicyEngine:
    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy

    def evaluate(
        self,
        findings: list[CorrelatedFinding],
        tool_errors: list[ToolError],
        scan_id: str,
        accepted_risks: list[dict] | None = None,
    ) -> PolicyResult:
        """
        Apply policy to correlated findings.
        Returns an annotated PolicyResult with PASS or FAIL verdict.
        """
        # Apply accepted risks and suppressions first
        findings = apply_suppressions(findings, accepted_risks or [])

        block_reasons: list[str] = []
        counts: dict[str, int] = {s.value: 0 for s in Severity}

        for finding in findings:
            # Skip already-annotated findings (accepted risk, suppressed)
            if finding.disposition in (
                Disposition.ACCEPTED_RISK,
                Disposition.SUPPRESSED,
            ):
                continue

            if finding.disposition == Disposition.EXPIRED_ACCEPTED_RISK:
                # Expired accepted risk — treat as warn + log
                finding.disposition = Disposition.WARN
                finding.disposition_reason = "Accepted risk has expired"
                counts[finding.severity.value] += 1
                continue

            disposition, reason = self._evaluate_finding(finding)
            finding.disposition = disposition
            finding.disposition_reason = reason

            if disposition in (Disposition.BLOCK, Disposition.WARN, Disposition.REPORT):
                counts[finding.severity.value] += 1

            if disposition == Disposition.BLOCK:
                block_reasons.append(
                    f"[{finding.severity.value.upper()}] {finding.title} "
                    f"(source: {', '.join(finding.source_tools)})"
                )

        # Note: threshold checks use only BLOCK-dispositioned findings so that
        # CWE/CVE overrides that downgrade to WARN are not double-penalised.

        # Check threshold maximums (applied after individual dispositions)
        threshold_violations = self._check_thresholds(findings)
        block_reasons.extend(threshold_violations)

        # Handle tool failures
        tool_failure_blocks: list[str] = []
        action = self._policy.on_tool_failure
        for err in tool_errors:
            if action == PolicyAction.BLOCK:
                tool_failure_blocks.append(
                    f"Tool failure: {err.tool} {err.display_reason}"
                )
            # WARN and REPORT do not block

        block_reasons.extend(tool_failure_blocks)

        verdict = Verdict.FAIL if block_reasons else Verdict.PASS

        return PolicyResult(
            verdict=verdict,
            scan_id=scan_id,
            block_reasons=block_reasons,
            findings=findings,
            tool_errors=tool_errors,
            counts=counts,
        )

    def _evaluate_finding(
        self, finding: CorrelatedFinding
    ) -> tuple[Disposition, str]:
        """Return (disposition, reason) for a single finding."""
        severity = finding.severity
        confidence = finding.confidence

        # CVE-specific override
        if finding.cve and finding.cve in self._policy.overrides.block_cve:
            return Disposition.BLOCK, f"CVE {finding.cve} is in policy block_cve list"

        # CWE downgrade override
        for cwe in finding.cwe:
            if cwe in self._policy.overrides.warn_cwe:
                return Disposition.WARN, f"CWE {cwe} is in policy warn_cwe list"

        # CWE block override
        for cwe in finding.cwe:
            if cwe in self._policy.overrides.block_cwe:
                return Disposition.BLOCK, f"CWE {cwe} is in policy block_cwe list"

        # Confidence adjustment (iterative downgrade until confidence threshold met).
        # Example: CRITICAL+LOW config{"critical":"medium","high":"high"}
        #   Step 1: CRITICAL needs MEDIUM, got LOW → downgrade to HIGH
        #   Step 2: HIGH needs HIGH, got LOW → downgrade to MEDIUM
        #   Result: MEDIUM → WARN (not BLOCK)
        effective_severity = severity
        if self._policy.confidence_adjustment.enabled:
            threshold_map = self._policy.confidence_adjustment.block_only_if_confidence
            for _ in range(len(Severity)):  # safety: at most N iterations
                min_conf_str = threshold_map.get(effective_severity.value)
                if not min_conf_str:
                    break
                min_conf = Confidence(min_conf_str)
                if _CONFIDENCE_ORDER.get(confidence, 2) >= _CONFIDENCE_ORDER.get(min_conf, 2):
                    break  # confidence meets the threshold — no more downgrade
                next_severity = _DOWNGRADE[effective_severity]
                if next_severity == effective_severity:
                    break  # already at minimum
                log.debug(
                    "Downgrading %s to %s due to low confidence (%s)",
                    effective_severity.value,
                    next_severity.value,
                    confidence.value,
                )
                effective_severity = next_severity

        # Map effective severity to policy action
        action = self._policy.on_finding.action_for(effective_severity.value)
        if action == PolicyAction.BLOCK:
            return Disposition.BLOCK, f"Severity {effective_severity.value} triggers BLOCK per policy"
        if action == PolicyAction.WARN:
            return Disposition.WARN, f"Severity {effective_severity.value} triggers WARN per policy"
        if action == PolicyAction.REPORT:
            return Disposition.REPORT, ""
        return Disposition.REPORT, ""  # IGNORE

    def _check_thresholds(
        self,
        findings: list[CorrelatedFinding],
    ) -> list[str]:
        """Threshold checks count BLOCK and WARN findings by severity.

        Findings downgraded to WARN by a warn_cwe override are excluded so
        that an intentional override is not simultaneously penalised by a
        max_critical threshold.  Normal WARN dispositions (e.g. medium=warn)
        do count because the threshold represents an aggregate attention limit.
        """
        violations: list[str] = []
        thresholds = self._policy.thresholds

        block_counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            if f.disposition in (Disposition.BLOCK, Disposition.WARN):
                # Exclude explicit CWE-override WARNs — they were intentionally handled
                if "warn_cwe list" in (f.disposition_reason or ""):
                    continue
                block_counts[f.severity.value] += 1

        if thresholds.max_critical is not None:
            n = block_counts.get(Severity.CRITICAL.value, 0)
            if n > thresholds.max_critical:
                violations.append(
                    f"{n} critical finding(s) exceed policy threshold of {thresholds.max_critical}"
                )
        if thresholds.max_high is not None:
            n = block_counts.get(Severity.HIGH.value, 0)
            if n > thresholds.max_high:
                violations.append(
                    f"{n} high finding(s) exceed policy threshold of {thresholds.max_high}"
                )
        if thresholds.max_medium is not None:
            n = block_counts.get(Severity.MEDIUM.value, 0)
            if n > thresholds.max_medium:
                violations.append(
                    f"{n} medium finding(s) exceed policy threshold of {thresholds.max_medium}"
                )
        if thresholds.max_low is not None:
            n = block_counts.get(Severity.LOW.value, 0)
            if n > thresholds.max_low:
                violations.append(
                    f"{n} low finding(s) exceed policy threshold of {thresholds.max_low}"
                )
        return violations
