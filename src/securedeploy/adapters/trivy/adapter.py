"""Trivy adapter — filesystem, secrets, dependencies, containers, IaC.

Invokes Trivy as a subprocess (native) or Docker container.
Uses --format json output for reliable machine-readable parsing.
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
from securedeploy.adapters.trivy.normalizer import TrivyNormalizer
from securedeploy.config.models import Profile, ProjectConfig
from securedeploy.core.cancel import CancelToken
from securedeploy.findings.models import NormalizedFinding

TRIVY_DOCKER_IMAGE = "aquasec/trivy:0.55.0"


class TrivyAdapter(ScannerAdapter):
    tool_id = "trivy"
    display_name = "Trivy"

    def __init__(self) -> None:
        self._normalizer = TrivyNormalizer()
        self._tmp_dir: str | None = None

    async def check_available(self) -> AvailabilityResult:
        # Try native first
        if self._is_native("trivy"):
            try:
                _, stdout, _ = await self._run_subprocess(
                    ["trivy", "--version"], timeout=10.0
                )
                version = self._parse_version(stdout)
                return AvailabilityResult(available=True, version=version, mode="native")
            except Exception:
                pass

        # Fall back to Docker
        from securedeploy.utils.docker import is_docker_available
        if await is_docker_available():
            return AvailabilityResult(
                available=True,
                version=None,
                mode="docker",
                warning=f"Trivy not found natively; will use Docker image {TRIVY_DOCKER_IMAGE}",
            )

        return AvailabilityResult(
            available=False,
            warning="Trivy not found. Install from https://aquasecurity.github.io/trivy/ "
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
                    message=avail.warning or "Trivy not available",
                ),
            )

        timeout = options.timeout or config.scanners.trivy.timeout
        self._tmp_dir = tempfile.mkdtemp(prefix="securedeploy-trivy-")
        output_file = os.path.join(self._tmp_dir, "results.json")
        all_results: list[dict] = []

        # Build scanners flag based on config
        scanners = []
        if config.testing.secrets:
            scanners.append("secret")
        if config.testing.dependencies:
            scanners.append("vuln")
        if not scanners:
            scanners = ["vuln", "secret"]
        scanners_flag = ",".join(scanners)

        severity_filter = ",".join(config.scanners.trivy.severity)

        try:
            # 1. Filesystem scan (source + deps + secrets)
            if config.testing.source_code or config.testing.secrets or config.testing.dependencies:
                if cancel_token.is_cancelled:
                    raise asyncio.CancelledError()

                source_path = str(Path(config.source.path).resolve())
                fs_results = await self._run_trivy_scan(
                    avail.mode,
                    ["fs", "--format", "json", "--scanners", scanners_flag,
                     "--severity", severity_filter,
                     "--exit-code", "0",  # don't fail on findings
                     source_path],
                    timeout=timeout,
                    cancel_token=cancel_token,
                    source_path=source_path,
                )
                if fs_results:
                    all_results.extend(fs_results.get("Results", []))

            # 2. Container image scan (if configured)
            if config.testing.containers and config.testing.container_images:
                for image in config.testing.container_images:
                    if cancel_token.is_cancelled:
                        raise asyncio.CancelledError()
                    img_results = await self._run_trivy_scan(
                        avail.mode,
                        ["image", "--format", "json", "--scanners", "vuln,secret",
                         "--severity", severity_filter,
                         "--exit-code", "0",
                         image],
                        timeout=timeout,
                        cancel_token=cancel_token,
                    )
                    if img_results:
                        all_results.extend(img_results.get("Results", []))

            # 3. IaC scan
            if config.testing.containers:
                for iac_path in config.testing.iac_paths:
                    resolved = Path(iac_path)
                    if not resolved.exists():
                        continue
                    if cancel_token.is_cancelled:
                        break
                    iac_results = await self._run_trivy_scan(
                        avail.mode,
                        ["config", "--format", "json",
                         "--severity", severity_filter,
                         "--exit-code", "0",
                         str(resolved.resolve())],
                        timeout=timeout,
                        cancel_token=cancel_token,
                        source_path=str(resolved.resolve()),
                    )
                    if iac_results:
                        all_results.extend(iac_results.get("Results", []))

        except asyncio.TimeoutError:
            return RawResult(
                tool=self.tool_id,
                error=ToolError(
                    tool=self.tool_id,
                    reason=ToolError.TIMEOUT,
                    message=f"Trivy scan timed out after {timeout}s",
                    duration_seconds=time.monotonic() - start,
                ),
                duration_seconds=time.monotonic() - start,
            )

        combined = {"Results": all_results}
        return RawResult(
            tool=self.tool_id,
            raw_output=json.dumps(combined),
            exit_code=0,
            duration_seconds=time.monotonic() - start,
            tool_version=avail.version,
        )

    async def _run_trivy_scan(
        self,
        mode: str,
        args: list[str],
        timeout: float,
        cancel_token: CancelToken,
        source_path: str | None = None,
    ) -> dict | None:
        try:
            if mode == "native":
                exit_code, stdout, stderr = await self._run_subprocess(
                    ["trivy"] + args,
                    timeout=timeout,
                    cancel_token=cancel_token,
                )
            else:
                from securedeploy.utils.docker import run_container
                volumes: dict[str, str] = {}
                docker_args = args.copy()
                if source_path:
                    volumes[source_path] = "/scan-target"
                    # Replace local path with container path in args
                    docker_args = [
                        "/scan-target" if a == source_path else a
                        for a in docker_args
                    ]
                result = await run_container(
                    TRIVY_DOCKER_IMAGE,
                    docker_args,
                    volumes=volumes,
                    timeout=timeout,
                )
                exit_code = result.exit_code
                stdout = result.stdout
                stderr = result.stderr

            if not stdout.strip():
                return None
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None
        except Exception:
            return None

    def normalize(self, raw: RawResult) -> list[NormalizedFinding]:
        if raw.error or not raw.raw_output:
            return []
        try:
            data = json.loads(raw.raw_output)
        except json.JSONDecodeError:
            return []
        findings = self._normalizer.normalize(data, scan_id=raw.tool_version or "")
        from securedeploy.findings.fingerprint import stamp_finding
        return [stamp_finding(f) for f in findings]

    async def cleanup(self) -> None:
        if self._tmp_dir:
            import shutil
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None

    def _parse_version(self, output: str) -> str | None:
        for line in output.splitlines():
            if "Version:" in line:
                return line.split("Version:")[-1].strip()
        return output.splitlines()[0] if output.strip() else None
