"""Rich-based terminal output for scan results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box
from rich.text import Text

from securedeploy.findings.models import (
    CorrelatedFinding,
    Disposition,
    LocationType,
    Severity,
)
from securedeploy.policy.models import PolicyResult, Verdict

console = Console(stderr=False)

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "dim white",
}

_VERDICT_COLOR = {
    Verdict.PASS: "bold green",
    Verdict.FAIL: "bold red",
    Verdict.ERROR: "bold yellow",
}


def print_scan_start(project: str, target: str, profile: str) -> None:
    console.print()
    console.rule("[bold blue]SECUREDEPLOY SECURITY GATE[/bold blue]")
    console.print()
    console.print(f"  Project  : [bold]{project}[/bold]")
    console.print(f"  Target   : [cyan]{target}[/cyan]")
    console.print(f"  Profile  : [yellow]{profile.upper()}[/yellow]")
    console.print()


def print_tool_status(tool: str, status: str, detail: str = "") -> None:
    symbol = "..." if status == "running" else ("✓" if status == "ok" else "✗")
    color = "green" if status == "ok" else ("red" if status == "error" else "dim")
    line = f"  [{color}]{symbol}[/{color}]  {tool:<30}"
    if detail:
        line += f" [dim]{detail}[/dim]"
    console.print(line)


def print_result(
    result: PolicyResult,
    scan_meta: dict,
    output_files: list[Path],
) -> None:
    console.print()
    console.rule()
    console.print()

    # Category summary table
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(width=35)
    table.add_column(width=10)
    table.add_column(width=20)

    categories: dict[str, list[CorrelatedFinding]] = {}
    for f in result.findings:
        if f.disposition == Disposition.SUPPRESSED:
            continue
        cat = f.category
        categories.setdefault(cat, []).append(f)

    # Print category rows
    for category, cat_findings in sorted(categories.items()):
        blocking = any(f.disposition == Disposition.BLOCK for f in cat_findings)
        warning = any(f.disposition == Disposition.WARN for f in cat_findings)
        if blocking:
            status_text = Text("FAIL", style="bold red")
        elif warning:
            status_text = Text("WARNING", style="yellow")
        else:
            status_text = Text("PASS", style="green")

        worst = max(cat_findings, key=lambda f: f.severity.numeric)
        count_str = f"({len(cat_findings)} finding{'s' if len(cat_findings) > 1 else ''})"
        table.add_row(
            f"  {category}",
            status_text,
            f"[dim]{count_str}[/dim]",
        )

    # Tool errors
    for err in result.tool_errors:
        table.add_row(
            f"  {err.tool} [tool error]",
            Text("WARNING", style="yellow"),
            f"[dim]{err.reason}[/dim]",
        )

    console.print(table)
    console.rule()
    console.print()

    # Severity counts
    counts_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    counts_table.add_column(width=20)
    counts_table.add_column(width=8, justify="right")
    counts_table.add_column(width=15)

    for severity_name, color in _SEVERITY_COLOR.items():
        count = result.counts.get(severity_name, 0)
        bar = "█" * min(count, 20)
        counts_table.add_row(
            f"  {severity_name.capitalize():<14}",
            f"[{color}]{count}[/{color}]",
            f"[dim]{bar}[/dim]",
        )

    console.print(counts_table)
    console.rule()
    console.print()

    # Blocking findings detail
    if result.blocking_findings:
        console.print("  [bold red]BLOCKING FINDINGS[/bold red]")
        console.print()
        for f in result.blocking_findings[:10]:  # show at most 10
            sev = f.severity.value.upper()
            color = _SEVERITY_COLOR.get(f.severity.value, "white")
            console.print(f"  [{color}][{sev}][/{color}] [bold]{f.title}[/bold]")
            if f.location.endpoint or f.location.url:
                endpoint = f.location.endpoint or f.location.url or ""
                method = f.location.method or ""
                console.print(f"         [dim]{method} {endpoint}[/dim]")
            if f.cve:
                console.print(f"         [dim]CVE: {f.cve}[/dim]")
            if f.cwe:
                console.print(f"         [dim]CWE: {', '.join(f.cwe[:3])}[/dim]")
            tools = ", ".join(f.source_tools)
            console.print(f"         [dim]Source: {tools}[/dim]")
            console.print()

        if len(result.blocking_findings) > 10:
            console.print(
                f"  [dim]... and {len(result.blocking_findings) - 10} more blocking findings[/dim]"
            )
            console.print()
        console.rule()
        console.print()

    # Verdict
    verdict_color = _VERDICT_COLOR.get(result.verdict, "white")
    verdict_symbol = "✓" if result.is_pass else "✗"
    console.print(
        f"  RESULT: [{verdict_color}]{verdict_symbol} {result.verdict.value}[/{verdict_color}]"
    )
    console.print()

    if result.block_reasons:
        for reason in result.block_reasons[:5]:
            console.print(f"  [red]• {reason}[/red]")
        console.print()

    # Disclaimer
    console.print(f"  [dim italic]{result.disclaimer}[/dim italic]")
    console.print()

    # Output files
    if output_files:
        for path in output_files:
            console.print(f"  Report: [blue]{path}[/blue]")
        console.print()

    console.rule()
    console.print()


def print_tool_availability(availabilities: list[dict]) -> None:
    """Print tool status table for `securedeploy tools status`."""
    table = Table(title="Security Tool Status", box=box.ROUNDED)
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Mode")
    table.add_column("Notes")

    for item in availabilities:
        available = item.get("available", False)
        status = Text("Available", style="green") if available else Text("Not found", style="red")
        table.add_row(
            item.get("tool", ""),
            status,
            item.get("version") or "-",
            item.get("mode") or "-",
            item.get("warning") or "",
        )
    console.print(table)


def print_error(message: str) -> None:
    console.print(f"\n[bold red]Error:[/bold red] {message}\n")


def print_warning(message: str) -> None:
    console.print(f"\n[yellow]Warning:[/yellow] {message}\n")


def print_info(message: str) -> None:
    console.print(f"  [dim]{message}[/dim]")
