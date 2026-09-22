"""Docker execution utilities.

Runs security tool containers via `docker run` subprocesses rather than the
Docker SDK to keep I/O non-blocking in the async execution context.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import NamedTuple


class DockerRunResult(NamedTuple):
    exit_code: int
    stdout: str
    stderr: str


async def run_container(
    image: str,
    args: list[str],
    *,
    volumes: dict[str, str] | None = None,   # {host_path: container_path}
    env: dict[str, str] | None = None,
    workdir: str | None = None,
    timeout: float = 600.0,
    remove: bool = True,
) -> DockerRunResult:
    """
    Run a Docker container and return its stdout/stderr.

    Raises asyncio.TimeoutError if timeout is exceeded.
    Raises DockerNotAvailableError if Docker daemon is not running.
    """
    cmd = ["docker", "run", "--network", "host"]
    if remove:
        cmd.append("--rm")
    if workdir:
        cmd += ["-w", workdir]
    for host_path, container_path in (volumes or {}).items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd.append(image)
    cmd.extend(args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as e:
        raise DockerNotAvailableError("docker binary not found in PATH") from e

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise

    return DockerRunResult(
        exit_code=proc.returncode or 0,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
    )


async def is_docker_available() -> bool:
    """Return True if the Docker daemon is reachable."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "info",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)
        return proc.returncode == 0
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        return False


async def pull_image(image: str) -> bool:
    """Pull a Docker image. Returns True on success."""
    proc = await asyncio.create_subprocess_exec(
        "docker", "pull", image,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, _ = await proc.communicate()
    return proc.returncode == 0


def is_tool_in_path(name: str) -> bool:
    """Return True if `name` is a callable binary on PATH."""
    return shutil.which(name) is not None


async def get_tool_version(binary: str, version_flag: str = "--version") -> str | None:
    """Run `binary --version` and return the first line of stdout."""
    if not is_tool_in_path(binary):
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, version_flag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        output = (stdout or stderr).decode(errors="replace").strip()
        return output.splitlines()[0] if output else None
    except (asyncio.TimeoutError, OSError):
        return None


class DockerNotAvailableError(Exception):
    """Raised when Docker is required but not available."""
