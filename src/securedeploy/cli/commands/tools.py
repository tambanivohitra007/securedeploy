"""securedeploy tools — manage security tool availability."""

from __future__ import annotations

import asyncio

import typer

from securedeploy.adapters.builtin import BuiltinAdapter
from securedeploy.adapters.nuclei import NucleiAdapter
from securedeploy.adapters.semgrep import SemgrepAdapter
from securedeploy.adapters.trivy import TrivyAdapter
from securedeploy.cli.output.terminal import print_tool_availability

ALL_ADAPTERS = [
    TrivyAdapter(),
    SemgrepAdapter(),
    NucleiAdapter(),
    BuiltinAdapter(),
]


def tools_status_command() -> None:
    """Check availability and versions of security tools."""

    async def _check_all() -> list[dict]:
        results = []
        for adapter in ALL_ADAPTERS:
            avail = await adapter.check_available()
            results.append({
                "tool": adapter.display_name,
                "available": avail.available,
                "version": avail.version,
                "mode": avail.mode if avail.available else "-",
                "warning": avail.warning or "",
            })
        return results

    availabilities = asyncio.run(_check_all())
    print_tool_availability(availabilities)
