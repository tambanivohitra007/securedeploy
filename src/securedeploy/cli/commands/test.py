"""securedeploy test — the main scan command."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console

from securedeploy.config.models import OutputFormat, Profile
from securedeploy.config.resolver import ConfigError, load_config
from securedeploy.core.orchestrator import Orchestrator
from securedeploy.core.safety import SafetyViolation
from securedeploy.cli.output.terminal import (
    print_error,
    print_result,
    print_scan_start,
    print_warning,
    print_info,
)

console = Console()

# Exit codes (public API — do not change without major version bump)
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_TOOL_ERROR = 3


def test_command(
    profile_name: str = typer.Option(
        "standard", "--profile", "-p",
        help="Scan profile: quick | standard | deep",
    ),
    target: str | None = typer.Option(
        None, "--target", "-t",
        help="Override target URL from config",
    ),
    config_path: str | None = typer.Option(
        None, "--config", "-c",
        help="Path to securedeploy.yaml",
    ),
    output_dir: str | None = typer.Option(
        None, "--output-dir", "-o",
        help="Override report output directory",
    ),
    formats: str | None = typer.Option(
        None, "--format",
        help="Comma-separated output formats: terminal,sarif,json",
    ),
    fail_on_warn: bool = typer.Option(
        False, "--fail-on-warn",
        help="Exit 1 on warnings (in addition to blocks)",
    ),
    no_fail: bool = typer.Option(
        False, "--no-fail",
        help="Always exit 0 (reporting-only mode)",
    ),
    confirm_deep: bool = typer.Option(
        False, "--confirm-deep",
        help="Non-interactive confirmation for DEEP profile (CI use)",
    ),
    only: str | None = typer.Option(
        None, "--only",
        help="Run only these scanners (comma-separated: trivy,semgrep,nuclei,builtin,custom)",
    ),
    skip: str | None = typer.Option(
        None, "--skip",
        help="Skip these scanners (comma-separated)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Show what would run without executing",
    ),
) -> None:
    """Run security tests and enforce the deployment gate."""
    # ── Parse profile ────────────────────────────────────────────────────
    try:
        profile = Profile(profile_name.lower())
    except ValueError:
        print_error(
            f"Unknown profile '{profile_name}'. Use: quick | standard | deep"
        )
        raise typer.Exit(EXIT_ERROR)

    # ── Load config ──────────────────────────────────────────────────────
    try:
        config = load_config(config_path)
    except ConfigError as e:
        print_error(str(e))
        raise typer.Exit(EXIT_ERROR)

    # ── Apply CLI overrides ──────────────────────────────────────────────
    if target:
        config.target.url = target.rstrip("/")

    resolved_output_dir = Path(output_dir or config.output.directory).resolve()

    # Determine formats
    active_formats = config.output.formats
    if formats:
        try:
            active_formats = [OutputFormat(f.strip()) for f in formats.split(",")]
        except ValueError as e:
            print_error(f"Invalid format: {e}")
            raise typer.Exit(EXIT_ERROR)

    # ── DEEP profile interactive confirmation ────────────────────────────
    if profile == Profile.DEEP and not confirm_deep:
        from securedeploy.config.models import Environment
        if config.target.environment != Environment.LOCAL:
            console.print()
            console.print(
                "[bold yellow]WARNING:[/bold yellow] DEEP profile runs intrusive security tests."
            )
            console.print(f"  Target: [cyan]{config.target.url}[/cyan]")
            console.print(
                "  Only use this against systems you are explicitly authorized to test."
            )
            console.print()
            confirmed = typer.confirm("  Proceed with DEEP scan?", default=False)
            if not confirmed:
                console.print("  [yellow]Aborted.[/yellow]")
                raise typer.Exit(EXIT_ERROR)

    # ── Dry run ──────────────────────────────────────────────────────────
    if dry_run:
        from securedeploy.core.profile import resolve_profile
        from securedeploy.core.safety import SafetyController
        profile_cfg = resolve_profile(profile, config)

        console.print(f"\n[bold]Dry run — profile: {profile.value.upper()}[/bold]")
        console.print(f"  Target: {config.target.url}")
        console.print(f"  Environment: {config.target.environment.value}")
        console.print(f"  Active adapters: {', '.join(profile_cfg.active_adapters)}")
        console.print(f"  Output: {resolved_output_dir}")
        console.print()
        raise typer.Exit(EXIT_PASS)

    # ── Print scan header ────────────────────────────────────────────────
    print_scan_start(
        project=config.project.name,
        target=config.target.url,
        profile=profile.value,
    )

    # ── Run the scan ─────────────────────────────────────────────────────
    try:
        orchestrator = Orchestrator(config, resolved_output_dir)
        result = asyncio.run(
            orchestrator.run(
                profile=profile,
                config_path=str(config_path or "securedeploy.yaml"),
            )
        )
    except SafetyViolation as e:
        print_error(f"Safety violation: {e}")
        raise typer.Exit(EXIT_ERROR)
    except KeyboardInterrupt:
        print_warning("Scan interrupted.")
        raise typer.Exit(EXIT_ERROR)
    except Exception as e:
        print_error(f"Unexpected error during scan: {e}")
        import traceback
        traceback.print_exc()
        raise typer.Exit(EXIT_ERROR)

    # ── Write reports ────────────────────────────────────────────────────
    scan_meta = {
        "version": "0.1.0",
        "project_name": config.project.name,
        "target_url": config.target.url,
        "profile": profile.value,
        "scan_id": result.scan_id,
    }

    output_files: list[Path] = []
    for fmt in active_formats:
        if fmt == OutputFormat.TERMINAL:
            continue
        try:
            file_path = _write_report(fmt, result, resolved_output_dir, scan_meta)
            if file_path:
                output_files.append(file_path)
        except Exception as e:
            print_warning(f"Failed to write {fmt.value} report: {e}")

    # ── Terminal output ──────────────────────────────────────────────────
    if OutputFormat.TERMINAL in active_formats:
        print_result(result, scan_meta, output_files)

    # ── Exit code ────────────────────────────────────────────────────────
    if no_fail:
        raise typer.Exit(EXIT_PASS)

    if result.tool_errors and not result.findings:
        raise typer.Exit(EXIT_TOOL_ERROR)

    if not result.is_pass:
        raise typer.Exit(EXIT_FAIL)

    if fail_on_warn and result.warning_findings:
        raise typer.Exit(EXIT_FAIL)

    raise typer.Exit(EXIT_PASS)


def _write_report(fmt, result, output_dir, scan_meta) -> Path | None:
    from securedeploy.config.models import OutputFormat
    if fmt == OutputFormat.SARIF:
        from securedeploy.reporting.sarif import SarifReporter
        return SarifReporter().write(result, output_dir, scan_meta)
    if fmt == OutputFormat.JSON:
        from securedeploy.reporting.json_report import JsonReporter
        return JsonReporter().write(result, output_dir, scan_meta)
    return None
