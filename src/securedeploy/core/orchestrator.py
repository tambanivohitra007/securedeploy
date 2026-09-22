"""Execution Coordinator — the core pipeline driver.

Runs all active scanner adapters concurrently (up to max_concurrency),
collects results, passes through the results pipeline, and returns a
PolicyResult ready for reporting.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from securedeploy.adapters.base import AdapterOptions, RawResult, ScannerAdapter, ToolError
from securedeploy.adapters.builtin import BuiltinAdapter
from securedeploy.adapters.nuclei import NucleiAdapter
from securedeploy.adapters.semgrep import SemgrepAdapter
from securedeploy.adapters.trivy import TrivyAdapter
from securedeploy.config.models import Profile, ProjectConfig
from securedeploy.core.audit import AuditLogger
from securedeploy.core.cancel import CancelToken
from securedeploy.core.profile import resolve_profile
from securedeploy.core.safety import SafetyController
from securedeploy.custom_tests.runner import CustomTestRunner
from securedeploy.findings.correlator import correlate
from securedeploy.findings.models import NormalizedFinding, ScanSummary
from securedeploy.policy.engine import PolicyEngine
from securedeploy.policy.models import PolicyResult

log = logging.getLogger(__name__)

# Registry of available adapter classes
_ADAPTER_REGISTRY: dict[str, type[ScannerAdapter]] = {
    "trivy": TrivyAdapter,
    "semgrep": SemgrepAdapter,
    "nuclei": NucleiAdapter,
    "builtin": BuiltinAdapter,
}


class Orchestrator:
    def __init__(self, config: ProjectConfig, output_dir: Path) -> None:
        self._config = config
        self._output_dir = output_dir
        self._audit = AuditLogger(output_dir)
        self._safety = SafetyController(config)

    async def run(
        self,
        profile: Profile,
        config_path: str = "securedeploy.yaml",
    ) -> PolicyResult:
        """
        Full pipeline: safety check → scan → normalize → correlate → policy.
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        summary = ScanSummary(
            scan_id=scan_id,
            project_name=self._config.project.name,
            target_url=self._config.target.url,
            profile=profile.value,
            started_at=started_at,
        )

        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._audit.log_scan_start(summary, profile.value, config_path)

        # ── Safety check ─────────────────────────────────────────────────
        self._safety.validate(profile)  # raises SafetyViolation on failure

        # ── Resolve active adapters for this profile ──────────────────────
        profile_cfg = resolve_profile(profile, self._config)

        adapters: list[ScannerAdapter] = []
        for adapter_id in profile_cfg.active_adapters:
            if adapter_id == "custom":
                continue  # handled separately
            cls = _ADAPTER_REGISTRY.get(adapter_id)
            if cls:
                adapters.append(cls())

        # ── Availability check ────────────────────────────────────────────
        avail_results = await asyncio.gather(
            *[adapter.check_available() for adapter in adapters],
            return_exceptions=False,
        )
        available_adapters = []
        tool_errors: list[ToolError] = []

        for adapter, avail in zip(adapters, avail_results):
            if avail.available:
                available_adapters.append(adapter)
                if avail.warning:
                    log.warning("[%s] %s", adapter.display_name, avail.warning)
            else:
                log.warning("[%s] Not available: %s", adapter.display_name, avail.warning)
                tool_errors.append(ToolError(
                    tool=adapter.tool_id,
                    reason=ToolError.UNAVAILABLE,
                    message=avail.warning or "Not available",
                ))

        # ── Run adapters concurrently ─────────────────────────────────────
        cancel_token = CancelToken()
        semaphore = asyncio.Semaphore(self._config.safety.max_concurrency)

        async def run_adapter(adapter: ScannerAdapter) -> tuple[str, RawResult]:
            async with semaphore:
                # Use tool-specific timeout if configured, else global default
                tool_cfg = getattr(self._config.scanners, adapter.tool_id, None)
                tool_timeout = getattr(tool_cfg, "timeout", None)
                timeout = float(tool_timeout or self._config.safety.default_timeout)
                options = AdapterOptions(
                    scan_id=scan_id,
                    timeout=int(timeout),
                )
                start = time.monotonic()
                try:
                    raw = await asyncio.wait_for(
                        adapter.run(self._config, profile, options, cancel_token),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    duration = time.monotonic() - start
                    raw = RawResult(
                        tool=adapter.tool_id,
                        error=ToolError(
                            tool=adapter.tool_id,
                            reason=ToolError.TIMEOUT,
                            message=f"Timed out after {timeout}s",
                            duration_seconds=duration,
                        ),
                        duration_seconds=duration,
                    )
                finally:
                    await adapter.cleanup()
                return adapter.tool_id, raw

        adapter_tasks = [run_adapter(a) for a in available_adapters]
        adapter_results: list[tuple[str, RawResult]] = await asyncio.gather(
            *adapter_tasks, return_exceptions=False
        )

        # ── Normalize and collect findings ────────────────────────────────
        all_findings: list[NormalizedFinding] = []

        for tool_id, raw in adapter_results:
            if raw.error:
                tool_errors.append(ToolError(
                    tool=raw.error.tool,
                    reason=raw.error.reason,
                    message=raw.error.message,
                    stderr=raw.error.stderr,
                    exit_code=raw.error.exit_code,
                    duration_seconds=raw.error.duration_seconds,
                    tool_version=raw.error.tool_version,
                ))
                self._audit.log_tool_invocation(
                    scan_id=scan_id,
                    tool=tool_id,
                    version=raw.tool_version,
                    exit_code=raw.exit_code or -1,
                    duration_s=raw.duration_seconds,
                    error=raw.error.message,
                )
                continue

            # Find the adapter to normalize
            adapter = next((a for a in available_adapters if a.tool_id == tool_id), None)
            if adapter:
                findings = adapter.normalize(raw)
                for f in findings:
                    f.scan_id = scan_id
                all_findings.extend(findings)

            self._audit.log_tool_invocation(
                scan_id=scan_id,
                tool=tool_id,
                version=raw.tool_version,
                exit_code=raw.exit_code,
                duration_s=raw.duration_seconds,
            )

        # ── Custom test runner ────────────────────────────────────────────
        if profile_cfg.has_adapter("custom") and self._config.testing.custom_tests:
            log.debug("Running custom security tests")
            try:
                custom_runner = CustomTestRunner(self._config)
                custom_findings = await custom_runner.run(scan_id=scan_id)
                all_findings.extend(custom_findings)
                self._audit.log_tool_invocation(
                    scan_id=scan_id,
                    tool="custom-test",
                    version="0.1.0",
                    exit_code=0,
                    duration_s=0.0,
                )
            except Exception as e:
                log.warning("Custom test runner failed: %s", e)
                tool_errors.append(ToolError(
                    tool="custom-test",
                    reason=ToolError.CRASH,
                    message=str(e),
                ))

        # ── Correlate and deduplicate ─────────────────────────────────────
        correlated = correlate(all_findings)

        # ── Policy evaluation ─────────────────────────────────────────────
        policy_engine = PolicyEngine(self._config.policy)
        accepted_risks = [ar.model_dump() for ar in self._config.accepted_risks]
        result = policy_engine.evaluate(
            findings=correlated,
            tool_errors=tool_errors,
            scan_id=scan_id,
            accepted_risks=accepted_risks,
        )

        # ── Finalize summary ──────────────────────────────────────────────
        summary.finished_at = datetime.now(timezone.utc)
        summary.verdict = result.verdict.value
        summary.tool_errors = [
            type("TE", (), {  # convert to models.ToolError for summary
                "tool": e.tool,
                "reason": e.reason,
                "message": e.message,
                "display_reason": e.message,
            })()  # type: ignore
            for e in tool_errors
        ]
        summary.count_by_severity(correlated)
        self._audit.log_scan_complete(summary)

        return result
