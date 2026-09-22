"""SARIF 2.1.0 report generator.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
consumed natively by GitHub Code Scanning, GitLab, Azure DevOps, and VS Code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securedeploy.findings.models import (
    CorrelatedFinding,
    Disposition,
    LocationType,
    Severity,
)
from securedeploy.policy.models import PolicyResult
from securedeploy.reporting.base import Reporter

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEVERITY_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}


class SarifReporter(Reporter):
    def write(self, result: PolicyResult, output_dir: Path, scan_meta: dict) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "results.sarif"
        sarif = self._build_sarif(result, scan_meta)
        output_path.write_text(json.dumps(sarif, indent=2, default=str), encoding="utf-8")
        return output_path

    def _build_sarif(self, result: PolicyResult, scan_meta: dict) -> dict[str, Any]:
        # Group findings by source tool to create one SARIF run per tool
        runs: list[dict] = []
        tools_seen: set[str] = set()

        # Group findings by tool
        by_tool: dict[str, list[CorrelatedFinding]] = {}
        for finding in result.findings:
            if finding.disposition in (Disposition.SUPPRESSED,):
                continue
            for tool in finding.source_tools:
                by_tool.setdefault(tool, []).append(finding)

        for tool_id, tool_findings in by_tool.items():
            rules = self._collect_rules(tool_findings)
            sarif_results = [self._finding_to_result(f) for f in tool_findings]

            runs.append({
                "tool": {
                    "driver": {
                        "name": tool_id,
                        "informationUri": f"https://github.com/securedeploy/securedeploy",
                        "version": scan_meta.get("version", "0.1.0"),
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            })

        if not runs:
            runs.append({
                "tool": {
                    "driver": {
                        "name": "securedeploy",
                        "version": scan_meta.get("version", "0.1.0"),
                        "rules": [],
                    }
                },
                "results": [],
            })

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": runs,
        }

    def _collect_rules(self, findings: list[CorrelatedFinding]) -> list[dict]:
        rules_seen: dict[str, dict] = {}
        for finding in findings:
            for src in finding.sources:
                rule_id = src.source.rule_id
                if rule_id not in rules_seen:
                    rules_seen[rule_id] = {
                        "id": rule_id,
                        "name": finding.title,
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {"text": finding.description[:1000] if finding.description else finding.title},
                        "helpUri": finding.references[0] if finding.references else "",
                        "properties": {
                            "tags": finding.tags,
                            "cwe": finding.cwe,
                            "precision": "high",
                            "problem.severity": finding.severity.value,
                        },
                        "defaultConfiguration": {
                            "level": _SEVERITY_LEVEL.get(finding.severity, "warning"),
                        },
                    }
        return list(rules_seen.values())

    def _finding_to_result(self, finding: CorrelatedFinding) -> dict[str, Any]:
        # Use the first source for primary location + rule
        primary = finding.sources[0] if finding.sources else None
        rule_id = primary.source.rule_id if primary else finding.fingerprint

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": finding.description or finding.title,
            },
            "fingerprints": {
                "securedeploy/v1": finding.fingerprint,
            },
            "locations": [],
        }

        # Add location
        loc = finding.location
        if loc.type in (LocationType.SOURCE, LocationType.SECRET):
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": loc.source_file or "",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": loc.line or 1,
                        "startColumn": loc.column or 1,
                    },
                }
            })
        elif loc.type in (LocationType.WEB, LocationType.TLS, LocationType.NETWORK):
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": loc.url or loc.endpoint or "",
                    },
                }
            })
        elif loc.type == LocationType.DEPENDENCY:
            result["locations"].append({
                "logicalLocations": [
                    {
                        "name": f"{loc.package_name}@{loc.package_version}",
                        "kind": "package",
                    }
                ]
            })

        # Remediation
        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation},
                }
            ]

        # Related OWASP/CWE tags as properties
        result["properties"] = {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "cwe": finding.cwe,
            "owasp": finding.owasp_top10,
            "sourceTools": finding.source_tools,
        }

        return result
