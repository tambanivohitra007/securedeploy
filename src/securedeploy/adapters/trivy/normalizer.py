"""Trivy JSON output → NormalizedFinding."""

from __future__ import annotations

import logging
from typing import Any

from securedeploy.findings.models import (
    Confidence,
    Evidence,
    FindingLocation,
    LocationType,
    NormalizedFinding,
    Severity,
    SourceInfo,
)

log = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFORMATIONAL,
}


class TrivyNormalizer:
    def normalize(self, data: dict[str, Any], scan_id: str = "") -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result in data.get("Results", []):
            target = result.get("Target", "")
            result_class = result.get("Class", "")

            # Vulnerabilities (dependency CVEs)
            for vuln in result.get("Vulnerabilities") or []:
                f = self._normalize_vuln(vuln, target, result_class, scan_id)
                if f:
                    findings.append(f)

            # Secrets
            for secret in result.get("Secrets") or []:
                f = self._normalize_secret(secret, target, scan_id)
                if f:
                    findings.append(f)

            # Misconfigurations (IaC, container config)
            for misconfig in result.get("Misconfigurations") or []:
                f = self._normalize_misconfig(misconfig, target, scan_id)
                if f:
                    findings.append(f)

        return findings

    def _normalize_vuln(
        self, v: dict, target: str, result_class: str, scan_id: str
    ) -> NormalizedFinding | None:
        try:
            severity = _SEVERITY_MAP.get(v.get("Severity", "UNKNOWN"), Severity.INFORMATIONAL)
            vuln_id = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "")
            title = v.get("Title") or f"{vuln_id} in {pkg}"
            description = v.get("Description", "")

            cvss_score: float | None = None
            cvss_vector: str | None = None
            cvss_data = v.get("CVSS", {})
            for source_data in cvss_data.values():
                if isinstance(source_data, dict):
                    if "V3Score" in source_data:
                        cvss_score = float(source_data["V3Score"])
                        cvss_vector = source_data.get("V3Vector")
                        break
                    if "V2Score" in source_data and cvss_score is None:
                        cvss_score = float(source_data["V2Score"])

            cwe_ids = [str(c) for c in (v.get("CweIDs") or [])]
            references = v.get("References") or []

            loc_type = LocationType.CONTAINER if "image" in target.lower() else LocationType.DEPENDENCY
            remediation = f"Upgrade {pkg} from {installed} to {fixed}." if fixed else (
                f"No fixed version available for {pkg} {installed}. Monitor for updates."
            )

            return NormalizedFinding(
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                confidence=Confidence.HIGH,
                category="Vulnerable and Outdated Components",
                owasp_top10=["A06:2021-Vulnerable and Outdated Components"],
                cwe=cwe_ids,
                cve=vuln_id if vuln_id.startswith("CVE-") else None,
                source=SourceInfo(
                    tool="trivy",
                    rule_id=vuln_id,
                    suite="Dependency Vulnerabilities",
                ),
                location=FindingLocation(
                    type=loc_type,
                    source_file=target,
                    package_name=pkg,
                    package_version=installed,
                ),
                evidence=Evidence(
                    description=f"{pkg}@{installed} in {target}",
                    actual=f"Installed: {installed}",
                    expected=f"Fixed in: {fixed}" if fixed else "No fix available",
                ),
                remediation=remediation,
                references=references[:5],
                scan_id=scan_id,
            )
        except Exception as e:
            log.debug("Failed to normalize Trivy vuln: %s", e)
            return None

    def _normalize_secret(
        self, s: dict, target: str, scan_id: str
    ) -> NormalizedFinding | None:
        try:
            rule_id = s.get("RuleID", "unknown-secret")
            title = s.get("Title", "Secret detected")
            category = s.get("Category", "Generic")
            severity_raw = s.get("Severity", "HIGH")
            severity = _SEVERITY_MAP.get(severity_raw.upper(), Severity.HIGH)
            start_line = s.get("StartLine", 0)

            # Redact the matched secret before storing in evidence
            from securedeploy.utils.redact import redact
            match_text = redact(s.get("Match", ""))

            return NormalizedFinding(
                title=f"Hard-coded {title}",
                description=(
                    f"A {category} secret was detected in {target} at line {start_line}. "
                    "Hard-coded credentials can be extracted from the repository and "
                    "used to compromise the associated service."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                category="Security Misconfiguration",
                subcategory="Hard-coded Secret",
                owasp_top10=["A07:2021-Identification and Authentication Failures"],
                cwe=["CWE-798"],
                source=SourceInfo(
                    tool="trivy",
                    rule_id=rule_id,
                    suite="Secret Scanning",
                ),
                location=FindingLocation(
                    type=LocationType.SECRET,
                    source_file=target,
                    line=start_line,
                ),
                evidence=Evidence(
                    description=f"Matched pattern: {rule_id}",
                    code_snippet=match_text,
                ),
                remediation=(
                    "Remove the secret from the source code and rotate the credential immediately. "
                    "Use environment variables or a secrets manager instead."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                scan_id=scan_id,
            )
        except Exception as e:
            log.debug("Failed to normalize Trivy secret: %s", e)
            return None

    def _normalize_misconfig(
        self, m: dict, target: str, scan_id: str
    ) -> NormalizedFinding | None:
        try:
            rule_id = m.get("ID", "misconfig")
            title = m.get("Title", "Misconfiguration")
            description = m.get("Description", "")
            message = m.get("Message", "")
            severity_raw = m.get("Severity", "MEDIUM")
            severity = _SEVERITY_MAP.get(severity_raw.upper(), Severity.MEDIUM)
            resolution = m.get("Resolution", "")
            references = m.get("References") or []
            status = m.get("Status", "")
            if status.upper() in ("PASS", "EXCEPTION"):
                return None  # Only normalize failures

            return NormalizedFinding(
                title=title,
                description=description or message,
                severity=severity,
                confidence=Confidence.HIGH,
                category="Security Misconfiguration",
                owasp_top10=["A05:2021-Security Misconfiguration"],
                cwe=["CWE-16"],
                source=SourceInfo(
                    tool="trivy",
                    rule_id=rule_id,
                    suite="Misconfiguration Scanning",
                ),
                location=FindingLocation(
                    type=LocationType.IaC,
                    source_file=target,
                ),
                evidence=Evidence(description=message),
                remediation=resolution,
                references=references[:5],
                scan_id=scan_id,
            )
        except Exception as e:
            log.debug("Failed to normalize Trivy misconfig: %s", e)
            return None
