"""Semgrep CE adapter — static application security testing.

Uses --json output for reliable parsing.
Supports native invocation and Docker.

License note: Semgrep CE engine is LGPL-2.1. Community rules use
Semgrep Rules License v1.0 (internal/non-SaaS use). See NOTICE file.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from securedeploy.adapters.base import (
    AdapterOptions,
    AvailabilityResult,
    RawResult,
    ScannerAdapter,
    ToolError,
)
from securedeploy.adapters.semgrep.normalizer import SemgrepNormalizer
from securedeploy.config.models import Profile, ProjectConfig
from securedeploy.core.cancel import CancelToken
from securedeploy.findings.models import NormalizedFinding

SEMGREP_DOCKER_IMAGE = "semgrep/semgrep:1.85.0"


class SemgrepAdapter(ScannerAdapter):
    tool_id = "semgrep"
    display_name = "Semgrep CE"

    def __init__(self) -> None:
        self._normalizer = SemgrepNormalizer()

    async def check_available(self) -> AvailabilityResult:
        if self._is_native("semgrep"):
            try:
                _, stdout, _ = await self._run_subprocess(
                    ["semgrep", "--version"], timeout=10.0
                )
                version = stdout.strip().splitlines()[0] if stdout.strip() else None
                return AvailabilityResult(available=True, version=version, mode="native")
            except Exception:
                pass

        from securedeploy.utils.docker import is_docker_available
        if await is_docker_available():
            return AvailabilityResult(
                available=True,
                mode="docker",
                warning=f"Semgrep not found natively; will use Docker image {SEMGREP_DOCKER_IMAGE}",
            )

        return AvailabilityResult(
            available=False,
            warning="Semgrep not found. Install from https://semgrep.dev/docs/getting-started/ "
                    "or ensure Docker is running.",
        )

    async def run(
        self,
        config: ProjectConfig,
        profile: Profile,
        options: AdapterOptions,
        cancel_token: CancelToken,
    ) -> RawResult:
        import time
        start = time.monotonic()

        avail = await self.check_available()
        if not avail.available:
            return RawResult(
                tool=self.tool_id,
                error=ToolError(
                    tool=self.tool_id,
                    reason=ToolError.UNAVAILABLE,
                    message=avail.warning or "Semgrep not available",
                ),
            )

        timeout = options.timeout or config.scanners.semgrep.timeout
        source_path = str(Path(config.source.path).resolve())

        # Build ruleset args
        ruleset_args: list[str] = []
        if config.scanners.semgrep.local_rules:
            ruleset_args += ["--config", config.scanners.semgrep.local_rules]
        else:
            for ruleset in config.scanners.semgrep.rulesets:
                ruleset_args += ["--config", ruleset]

        # Build exclude args
        exclude_args: list[str] = []
        for pattern in config.source.exclude:
            exclude_args += ["--exclude", pattern]

        try:
            if avail.mode == "native":
                exit_code, stdout, stderr = await self._run_subprocess(
                    ["semgrep", "--json", "--quiet"] + ruleset_args + exclude_args + [source_path],
                    timeout=float(timeout),
                    cancel_token=cancel_token,
                )
            else:
                from securedeploy.utils.docker import run_container
                docker_args = (
                    ["semgrep", "--json", "--quiet"]
                    + ruleset_args
                    + exclude_args
                    + ["/src"]
                )
                result = await run_container(
                    SEMGREP_DOCKER_IMAGE,
                    docker_args,
                    volumes={source_path: "/src"},
                    timeout=float(timeout),
                )
                exit_code = result.exit_code
                stdout = result.stdout
                stderr = result.stderr

        except asyncio.TimeoutError:
            return RawResult(
                tool=self.tool_id,
                error=ToolError(
                    tool=self.tool_id,
                    reason=ToolError.TIMEOUT,
                    message=f"Semgrep timed out after {timeout}s",
                    duration_seconds=time.monotonic() - start,
                ),
                duration_seconds=time.monotonic() - start,
            )

        duration = time.monotonic() - start

        # Semgrep exits 1 when findings are found — this is not an error
        if exit_code not in (0, 1):
            return RawResult(
                tool=self.tool_id,
                raw_output=stdout,
                exit_code=exit_code,
                stderr=stderr,
                error=ToolError(
                    tool=self.tool_id,
                    reason=ToolError.CRASH,
                    message=f"Semgrep exited with code {exit_code}",
                    stderr=stderr,
                    exit_code=exit_code,
                    duration_seconds=duration,
                    tool_version=avail.version,
                ),
                duration_seconds=duration,
            )

        return RawResult(
            tool=self.tool_id,
            raw_output=stdout,
            exit_code=exit_code,
            stderr=stderr,
            duration_seconds=duration,
            tool_version=avail.version,
        )

    def normalize(self, raw: RawResult) -> list[NormalizedFinding]:
        if raw.error or not raw.raw_output:
            return []
        try:
            data = json.loads(raw.raw_output)
        except json.JSONDecodeError:
            return []
        findings = self._normalizer.normalize(data)
        from securedeploy.findings.fingerprint import stamp_finding
        return [stamp_finding(f) for f in findings]
