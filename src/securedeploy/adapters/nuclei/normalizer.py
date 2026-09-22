"""Nuclei JSONL output → NormalizedFinding.

Nuclei writes one JSON object per line (-json-export format).
"""

from __future__ import annotations

import json
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
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
}


class NucleiNormalizer:
    def normalize(self, jsonl_output: str) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for line in jsonl_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                f = self._normalize_result(data)
                if f:
                    findings.append(f)
            except (json.JSONDecodeError, Exception) as e:
                log.debug("Failed to parse Nuclei line: %s", e)
        return findings

    def _normalize_result(self, r: dict) -> NormalizedFinding | None:
        try:
            info = r.get("info", {})
            template_id = r.get("template-id", r.get("templateID", "nuclei-unknown"))
            name = info.get("name", template_id)
            severity_raw = info.get("severity", "info")
            severity = _SEVERITY_MAP.get(severity_raw.lower(), Severity.INFORMATIONAL)
            description = info.get("description", "")
            matched_at = r.get("matched-at", r.get("host", ""))
            method = r.get("type", "http").upper()
            if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                method = "GET"

            # Classification metadata
            classification = info.get("classification", {})
            metadata = info.get("metadata", {})

            cve_id = (
                classification.get("cve-id")
                or metadata.get("cve-id")
                or r.get("info", {}).get("cve-id")
            )
            if isinstance(cve_id, list):
                cve_id = cve_id[0] if cve_id else None

            raw_cwes = classification.get("cwe-id") or metadata.get("cwe-id") or []
            if isinstance(raw_cwes, str):
                raw_cwes = [raw_cwes]
            cwe_ids = [str(c).strip() for c in raw_cwes if c]

            cvss_score: float | None = None
            try:
                score_raw = classification.get("cvss-score") or metadata.get("cvss-score")
                if score_raw is not None:
                    cvss_score = float(score_raw)
            except (TypeError, ValueError):
                pass

            cvss_vector = classification.get("cvss-metrics") or metadata.get("cvss-metrics")

            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            # Evidence
            from securedeploy.utils.redact import redact
            request_raw = redact(r.get("request", "") or "")
            response_raw = r.get("response", "") or ""
            # Truncate long responses
            if len(response_raw) > 500:
                response_raw = response_raw[:500] + "...[truncated]"

            # Determine location type from tags
            if any(t in tags for t in ["ssl", "tls"]):
                loc_type = LocationType.TLS
            elif any(t in tags for t in ["network", "port"]):
                loc_type = LocationType.NETWORK
            else:
                loc_type = LocationType.WEB

            # Derive category
            category = self._derive_category(tags, cwe_ids, template_id)

            # Remediation from metadata
            remediation = (
                info.get("remediation")
                or metadata.get("remediation")
                or info.get("fix")
                or ""
            )

            references = info.get("reference") or []
            if isinstance(references, str):
                references = [references]

            return NormalizedFinding(
                title=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                confidence=Confidence.HIGH if cve_id else Confidence.MEDIUM,
                category=category,
                cwe=cwe_ids,
                cve=cve_id,
                source=SourceInfo(
                    tool="nuclei",
                    rule_id=template_id,
                    suite="DAST",
                ),
                location=FindingLocation(
                    type=loc_type,
                    url=matched_at,
                    endpoint=self._extract_path(matched_at),
                    method=method,
                ),
                evidence=Evidence(
                    request=request_raw,
                    response_excerpt=response_raw,
                    description=str(r.get("matcher-status", "")),
                ),
                remediation=remediation,
                references=[str(ref) for ref in references[:5]],
                tags=tags,
            )
        except Exception as e:
            log.debug("Failed to normalize Nuclei result: %s", e)
            return None

    def _extract_path(self, url: str) -> str:
        from urllib.parse import urlparse
        try:
            return urlparse(url).path or "/"
        except Exception:
            return "/"

    def _derive_category(self, tags: list, cwes: list, template_id: str) -> str:
        tag_set = {t.lower() for t in tags}

        if "cve" in tag_set:
            return "Known CVE"
        if any(t in tag_set for t in ["ssl", "tls"]):
            return "TLS/SSL Configuration"
        if "headers" in tag_set:
            return "HTTP Security Headers"
        if "cors" in tag_set:
            return "CORS Misconfiguration"
        if "misconfig" in tag_set or "config" in tag_set:
            return "Security Misconfiguration"
        if "exposure" in tag_set:
            return "Sensitive Information Exposure"
        if "sqli" in tag_set or "sql" in tag_set:
            return "SQL Injection"
        if "xss" in tag_set:
            return "Cross-Site Scripting"
        if "ssrf" in tag_set:
            return "SSRF"
        if "rce" in tag_set:
            return "Remote Code Execution"
        if "lfi" in tag_set or "path-traversal" in tag_set:
            return "Path Traversal"
        if "auth" in tag_set or "authentication" in tag_set:
            return "Authentication"

        return "Security Vulnerability"
