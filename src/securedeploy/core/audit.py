"""Append-only structured audit log.

Writes one JSONL entry per scan run to securedeploy-audit.jsonl.
Suitable for shipping to a SIEM or object storage for compliance.
Credentials are never written to the audit log.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securedeploy.findings.models import ScanSummary
from securedeploy.utils.redact import redact_dict

_AUDIT_FILENAME = "securedeploy-audit.jsonl"


class AuditLogger:
    def __init__(self, output_dir: Path) -> None:
        self._path = output_dir / _AUDIT_FILENAME

    def log_scan_start(self, summary: ScanSummary, profile: str, config_path: str) -> None:
        entry: dict[str, Any] = {
            "event": "scan_start",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": summary.scan_id,
            "project": summary.project_name,
            "target": summary.target_url,
            "profile": profile,
            "config_path": config_path,
            "git_commit": _get_git_commit(),
            "git_branch": _get_git_branch(),
            "operator": os.environ.get("USER") or os.environ.get("CI_JOB_USER") or "unknown",
        }
        self._append(entry)

    def log_tool_invocation(
        self,
        scan_id: str,
        tool: str,
        version: str | None,
        exit_code: int,
        duration_s: float,
        error: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "event": "tool_invocation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            "tool": tool,
            "version": version,
            "exit_code": exit_code,
            "duration_seconds": round(duration_s, 2),
        }
        if error:
            entry["error"] = error
        self._append(entry)

    def log_scan_complete(self, summary: ScanSummary) -> None:
        entry: dict[str, Any] = {
            "event": "scan_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": summary.scan_id,
            "project": summary.project_name,
            "target": summary.target_url,
            "profile": summary.profile,
            "verdict": summary.verdict,
            "duration_seconds": round(summary.duration_seconds, 2),
            "finding_counts": summary.finding_counts,
            "tool_errors": [
                {
                    "tool": e.tool,
                    "reason": e.reason,
                    "message": e.message,
                }
                for e in summary.tool_errors
            ],
        }
        self._append(entry)

    def _append(self, entry: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(redact_dict(entry), default=str)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def _get_git_commit() -> str | None:
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3
        )
        return result.stdout.strip() or None
    except Exception:
        return None


def _get_git_branch() -> str | None:
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=3
        )
        return result.stdout.strip() or None
    except Exception:
        return None
