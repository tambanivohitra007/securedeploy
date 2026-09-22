"""Scanner adapter protocol and shared data types.

All scanner integrations implement ScannerAdapter. The core system only
interacts with this interface — never with adapter internals.
"""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from typing import Any

from securedeploy.config.models import Profile, ProjectConfig
from securedeploy.core.cancel import CancelToken
from securedeploy.findings.models import NormalizedFinding, ToolError


class AvailabilityResult:
    def __init__(
        self,
        available: bool,
        version: str | None = None,
        warning: str | None = None,
        mode: str = "native",  # "native" | "docker"
    ) -> None:
        self.available = available
        self.version = version
        self.warning = warning
        self.mode = mode  # how the tool will be invoked

    def __repr__(self) -> str:
        return (
            f"AvailabilityResult(available={self.available}, "
            f"version={self.version!r}, mode={self.mode!r})"
        )


class RawResult:
    """Raw output from a scanner tool — before normalization."""

    def __init__(
        self,
        tool: str,
        raw_output: str = "",
        exit_code: int = 0,
        stderr: str = "",
        error: "ToolError | None" = None,
        duration_seconds: float = 0.0,
        tool_version: str | None = None,
    ) -> None:
        self.tool = tool
        self.raw_output = raw_output
        self.exit_code = exit_code
        self.stderr = stderr
        self.error = error
        self.duration_seconds = duration_seconds
        self.tool_version = tool_version

    @property
    def succeeded(self) -> bool:
        return self.error is None


class AdapterOptions:
    """Runtime options passed to an adapter's run() method."""

    def __init__(
        self,
        scan_id: str = "",
        timeout: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.timeout = timeout
        self.extra = extra or {}


class ScannerAdapter(ABC):
    """
    Abstract base for all scanner adapters.

    Subclasses must implement check_available, run, and normalize.
    cleanup() is optional but called unconditionally in a finally block.
    """

    @property
    @abstractmethod
    def tool_id(self) -> str:
        """Stable lowercase identifier, e.g. 'trivy', 'nuclei'."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for reports and terminal output."""
        ...

    @abstractmethod
    async def check_available(self) -> AvailabilityResult:
        """
        Check whether the tool is installed and reachable.
        Must not raise — failures are captured in AvailabilityResult.
        """
        ...

    @abstractmethod
    async def run(
        self,
        config: ProjectConfig,
        profile: Profile,
        options: AdapterOptions,
        cancel_token: CancelToken,
    ) -> RawResult:
        """
        Execute the tool.
        Must not raise on tool errors — capture them in RawResult.error.
        Must respect cancel_token.is_cancelled.
        """
        ...

    @abstractmethod
    def normalize(self, raw: RawResult) -> list[NormalizedFinding]:
        """
        Convert raw tool output to NormalizedFinding objects.
        Must not raise — return [] and log a warning on parse errors.
        """
        ...

    async def cleanup(self) -> None:
        """Remove temp files, stop containers, close connections."""

    # ── Helpers available to all subclasses ──────────────────────────────

    async def _run_subprocess(
        self,
        args: list[str],
        *,
        timeout: float = 300.0,
        cancel_token: CancelToken | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> tuple[int, str, str]:
        """
        Run a subprocess, return (exit_code, stdout, stderr).
        Raises asyncio.TimeoutError on timeout.
        """
        import os
        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=proc_env,
            cwd=cwd,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise

        return (
            proc.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )

    def _is_native(self, binary: str) -> bool:
        return shutil.which(binary) is not None
