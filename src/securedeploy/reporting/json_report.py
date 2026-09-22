"""JSON report generator — structured machine-readable output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securedeploy.findings.models import CorrelatedFinding, Disposition
from securedeploy.policy.models import PolicyResult
from securedeploy.reporting.base import Reporter


class JsonReporter(Reporter):
    def write(self, result: PolicyResult, output_dir: Path, scan_meta: dict) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "results.json"

        report = {
            "securedeploy_version": scan_meta.get("version", "0.1.0"),
            "scan_id": result.scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project": scan_meta.get("project_name", ""),
            "target": scan_meta.get("target_url", ""),
            "profile": scan_meta.get("profile", ""),
            "verdict": result.verdict.value,
            "block_reasons": result.block_reasons,
            "disclaimer": result.disclaimer,
            "summary": {
                "counts": result.counts,
                "tool_errors": len(result.tool_errors),
            },
            "findings": [
                self._serialize_finding(f)
                for f in result.findings
                if f.disposition != Disposition.SUPPRESSED
            ],
            "tool_errors": [
                {
                    "tool": e.tool,
                    "reason": e.reason,
                    "message": e.message,
                }
                for e in result.tool_errors
            ],
        }

        output_path.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        return output_path

    def _serialize_finding(self, finding: CorrelatedFinding) -> dict[str, Any]:
        return {
            "finding_id": finding.finding_id,
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "category": finding.category,
            "subcategory": finding.subcategory,
            "owasp_top10": finding.owasp_top10,
            "owasp_api_top10": finding.owasp_api_top10,
            "cwe": finding.cwe,
            "cve": finding.cve,
            "cvss_score": finding.cvss_score,
            "source_tools": finding.source_tools,
            "location": {
                "type": finding.location.type.value,
                "url": finding.location.url,
                "endpoint": finding.location.endpoint,
                "method": finding.location.method,
                "source_file": finding.location.source_file,
                "line": finding.location.line,
                "package_name": finding.location.package_name,
                "package_version": finding.location.package_version,
            },
            "description": finding.description,
            "remediation": finding.remediation,
            "references": finding.references,
            "disposition": finding.disposition.value if finding.disposition else None,
            "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
            "tags": finding.tags,
        }
