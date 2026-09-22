"""Nuclei adapter — CVEs, misconfigurations, web/API security checks.

Uses JSONL output (-json-export) for reliable streaming parse.
Template selection is profile-aware: QUICK uses a safe subset;
STANDARD adds broader coverage.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

from securedeploy.adapters.base import (
    AdapterOptions,
    AvailabilityResult,
    RawResult,
    ScannerAdapter,
    ToolError,
)
from securedeploy.adapters.nuclei.normalizer import NucleiNormalizer
from securedeploy.config.models import Profile, ProjectConfig
from securedeploy.core.cancel import CancelToken
from securedeploy.findings.models import NormalizedFinding

NUCLEI_DOCKER_IMAGE = "projectdiscovery/nuclei:v3.3.0"

# Tags that are safe to use in QUICK profile (non-intrusive)
QUICK_TAGS = ["headers", "ssl", "exposure", "config", "misconfig", "info"]

# Additional tags enabled in STANDARD profile
STANDARD_TAGS = QUICK_TAGS + ["cve", "cors", "takeover", "tech", "network"]


class NucleiAdapter(ScannerAdapter):
    tool_id = "nuclei"
    display_name = "Nuclei"

    def __init__(self) -> None:
        self._normalizer = NucleiNormalizer()
        self._tmp_dir: str | None = None

    async def check_available(self) -> AvailabilityResult:
        if self._is_native("nuclei"):
            try:
                _, stdout, stderr = await self._run_subprocess(
                    ["nuclei", "-version"], timeout=10.0
                )
                output = (stdout + stderr).strip()
                version = output.splitlines()[0] if output else None
                return AvailabilityResult(available=True, version=version, mode="native")
            except Exception:
                pass

        from securedeploy.utils.docker import is_docker_available
        if await is_docker_available():
            return AvailabilityResult(
                available=True,
                mode="docker",
                warning=f"Nuclei not found natively; will use Docker image {NUCLEI_DOCKER_IMAGE}",
            )

        return AvailabilityResult(
            available=False,
            warning="Nuclei not found. Install from https://github.com/projectdiscovery/nuclei "
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
                    message=avail.warning or "Nuclei not available",
                ),
            )

        self._tmp_dir = tempfile.mkdtemp(prefix="securedeploy-nuclei-")
        output_file = os.path.join(self._tmp_dir, "results.jsonl")
        # Prefer Nuclei-specific timeout over the global default — CVE scans need more time
        timeout = float(config.scanners.nuclei.timeout or options.timeout or 1800)

        # Determine tags for this profile
        nuclei_cfg = config.scanners.nuclei
        if profile == Profile.QUICK:
            tags = QUICK_TAGS
        else:
            tags = list(set(STANDARD_TAGS + nuclei_cfg.tags_include))

        # Always exclude dangerous tags
        exclude_tags = list(set(nuclei_cfg.tags_exclude))

        target_url = config.target.url
        rate_limit = str(nuclei_cfg.rate_limit)

        args = [
            "-u", target_url,
            "-tags", ",".join(tags),
            "-etags", ",".join(exclude_tags),
            "-json-export", output_file,
            "-rate-limit", rate_limit,
            "-silent",
            "-no-color",
            "-timeout", "10",          # per-request timeout (seconds)
        ]

        if config.target.openapi_spec:
            args += ["-api-spec", config.target.openapi_spec]

        try:
            if avail.mode == "native":
                exit_code, stdout, stderr = await self._run_subprocess(
                    ["nuclei"] + args,
                    timeout=timeout,
                    cancel_token=cancel_token,
                )
            else:
                from securedeploy.utils.docker import run_container
                # Persist templates across runs to avoid re-downloading every time
                templates_dir = os.path.expanduser("~/.securedeploy/nuclei-templates")
                os.makedirs(templates_dir, exist_ok=True)
                docker_args = [
                    "-u", target_url,
                    "-tags", ",".join(tags),
                    "-etags", ",".join(exclude_tags),
                    "-j",              # JSONL output to stdout (no file needed)
                    "-rate-limit", rate_limit,
                    "-silent",
                    "-no-color",
                    "-timeout", "10",
                ]
                result = await run_container(
                    NUCLEI_DOCKER_IMAGE,
                    docker_args,
                    volumes={templates_dir: "/root/nuclei-templates"},
                    timeout=timeout,
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
                    message=f"Nuclei timed out after {timeout}s",
                    duration_seconds=time.monotonic() - start,
                ),
                duration_seconds=time.monotonic() - start,
            )

        duration = time.monotonic() - start

        # Read results: file for native mode, stdout for Docker mode
        raw_output = ""
        if os.path.exists(output_file):
            raw_output = Path(output_file).read_text(encoding="utf-8")
        if not raw_output and stdout:
            raw_output = stdout

        return RawResult(
            tool=self.tool_id,
            raw_output=raw_output,
            exit_code=exit_code,
            stderr=stderr,
            duration_seconds=duration,
            tool_version=avail.version,
        )

    def normalize(self, raw: RawResult) -> list[NormalizedFinding]:
        if raw.error or not raw.raw_output:
            return []
        findings = self._normalizer.normalize(raw.raw_output)
        from securedeploy.findings.fingerprint import stamp_finding
        return [stamp_finding(f) for f in findings]

    async def cleanup(self) -> None:
        if self._tmp_dir:
            import shutil
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None
