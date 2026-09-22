"""Semgrep JSON output → NormalizedFinding."""

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
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
}

_CONFIDENCE_MAP: dict[str, Confidence] = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}


class SemgrepNormalizer:
    def normalize(self, data: dict[str, Any]) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for result in data.get("results", []):
            f = self._normalize_result(result)
            if f:
                findings.append(f)
        return findings

    def _normalize_result(self, r: dict) -> NormalizedFinding | None:
        try:
            check_id = r.get("check_id", "semgrep-unknown")
            path = r.get("path", "")
            start = r.get("start", {})
            end = r.get("end", {})
            extra = r.get("extra", {})
            message = extra.get("message", "")
            severity_raw = extra.get("severity", "WARNING")
            severity = _SEVERITY_MAP.get(severity_raw.upper(), Severity.MEDIUM)
            lines = extra.get("lines", "")
            metadata = extra.get("metadata", {})

            # Extract CWE — Semgrep provides these as "CWE-798: ..." strings
            raw_cwes = metadata.get("cwe") or []
            if isinstance(raw_cwes, str):
                raw_cwes = [raw_cwes]
            cwe_ids = [self._extract_cwe_id(c) for c in raw_cwes if c]

            # Extract OWASP references
            owasp = metadata.get("owasp") or []
            if isinstance(owasp, str):
                owasp = [owasp]

            confidence_raw = metadata.get("confidence", "MEDIUM")
            confidence = _CONFIDENCE_MAP.get(str(confidence_raw).upper(), Confidence.MEDIUM)

            references = metadata.get("references") or []
            if isinstance(references, str):
                references = [references]

            # Override severity if metadata provides a more specific one
            meta_severity = metadata.get("severity") or metadata.get("impact")
            if meta_severity:
                mapped = _SEVERITY_MAP.get(str(meta_severity).upper())
                if mapped:
                    severity = mapped

            # Derive a clean title from the check_id (last segment, hyphen→space)
            title = self._id_to_title(check_id)

            # Category from OWASP tag or generic
            category = self._derive_category(owasp, cwe_ids, metadata)

            return NormalizedFinding(
                title=title,
                description=message,
                severity=severity,
                confidence=confidence,
                category=category,
                owasp_top10=[o for o in owasp if "2021" in o or "2017" in o],
                cwe=cwe_ids,
                source=SourceInfo(
                    tool="semgrep",
                    rule_id=check_id,
                    suite="SAST",
                ),
                location=FindingLocation(
                    type=LocationType.SOURCE,
                    source_file=path,
                    line=start.get("line"),
                    column=start.get("col"),
                ),
                evidence=Evidence(
                    code_snippet=lines,
                    description=message,
                ),
                remediation=metadata.get("fix") or metadata.get("fix-regex", {}).get("replacement") or "",
                references=[str(r) for r in references[:5]],
            )
        except Exception as e:
            log.debug("Failed to normalize Semgrep result: %s", e)
            return None

    def _extract_cwe_id(self, s: str) -> str:
        """Extract 'CWE-123' from 'CWE-123: Some description'."""
        if ":" in s:
            return s.split(":")[0].strip()
        return s.strip()

    def _id_to_title(self, check_id: str) -> str:
        """Convert 'python.django.security.audit.xss' to 'XSS'."""
        parts = check_id.split(".")
        # Take the last meaningful segment and humanize it
        slug = parts[-1] if parts else check_id
        return slug.replace("-", " ").replace("_", " ").title()

    def _derive_category(self, owasp: list, cwes: list, metadata: dict) -> str:
        """Derive a human-readable category from available metadata."""
        # Try OWASP first
        for o in owasp:
            o_lower = o.lower()
            if "injection" in o_lower:
                return "Injection"
            if "broken access" in o_lower or "authorization" in o_lower:
                return "Broken Access Control"
            if "cryptographic" in o_lower or "crypto" in o_lower:
                return "Cryptographic Failures"
            if "misconfiguration" in o_lower:
                return "Security Misconfiguration"
            if "authentication" in o_lower:
                return "Identification and Authentication Failures"
            if "xss" in o_lower or "cross-site" in o_lower:
                return "Injection"

        # Fall back to CWE
        for cwe in cwes:
            num_str = cwe.replace("CWE-", "")
            if num_str.isdigit():
                num = int(num_str)
                if num in (89, 564, 943):
                    return "SQL/NoSQL Injection"
                if num in (79, 80):
                    return "Cross-Site Scripting"
                if num in (78, 88):
                    return "Command Injection"
                if num in (284, 285, 639, 862):
                    return "Broken Access Control"
                if num in (798, 259, 321):
                    return "Hard-coded Secret"
                if num in (22, 23):
                    return "Path Traversal"
                if num in (918,):
                    return "SSRF"

        return "Security Misconfiguration"
