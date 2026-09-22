"""SecureDeploy CLI entry point."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="securedeploy",
    help=(
        "Pre-deployment security testing framework.\n\n"
        "Run 'securedeploy test' to execute security scans against your application.\n"
        "Run 'securedeploy init' to create a configuration file."
    ),
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

tools_app = typer.Typer(help="Manage security tool availability.")
app.add_typer(tools_app, name="tools")


@app.command("test")
def test(
    profile: str = typer.Option("standard", "--profile", "-p"),
    target: str | None = typer.Option(None, "--target", "-t"),
    config_path: str | None = typer.Option(None, "--config", "-c"),
    output_dir: str | None = typer.Option(None, "--output-dir", "-o"),
    formats: str | None = typer.Option(None, "--format"),
    fail_on_warn: bool = typer.Option(False, "--fail-on-warn"),
    no_fail: bool = typer.Option(False, "--no-fail"),
    confirm_deep: bool = typer.Option(False, "--confirm-deep"),
    only: str | None = typer.Option(None, "--only"),
    skip: str | None = typer.Option(None, "--skip"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Run security tests and enforce the deployment gate."""
    from securedeploy.cli.commands.test import test_command
    test_command(
        profile_name=profile,
        target=target,
        config_path=config_path,
        output_dir=output_dir,
        formats=formats,
        fail_on_warn=fail_on_warn,
        no_fail=no_fail,
        confirm_deep=confirm_deep,
        only=only,
        skip=skip,
        dry_run=dry_run,
    )


@app.command("init")
def init(
    output: str = typer.Option(".", "--output", "-o", help="Directory to create config in"),
) -> None:
    """Create a securedeploy.yaml configuration file."""
    from securedeploy.cli.commands.init import init_command
    init_command(output=output)


@app.command("validate")
def validate(
    config_path: str | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Validate securedeploy.yaml without running tests."""
    from securedeploy.config.resolver import load_config, ConfigError
    from rich.console import Console
    con = Console()
    try:
        config = load_config(config_path)
        con.print(f"\n  [green]✓[/green] Configuration valid")
        con.print(f"  Project: {config.project.name}")
        con.print(f"  Target:  {config.target.url}")
        con.print(f"  Environment: {config.target.environment.value}\n")
    except ConfigError as e:
        con.print(f"\n  [red]✗[/red] {e}\n")
        raise typer.Exit(2)


@tools_app.command("status")
def tools_status() -> None:
    """Check which security tools are available and their versions."""
    from securedeploy.cli.commands.tools import tools_status_command
    tools_status_command()


@tools_app.command("install")
def tools_install() -> None:
    """Pull Docker images for all configured tools."""
    import asyncio
    from rich.console import Console
    from securedeploy.utils.docker import pull_image, is_docker_available
    from securedeploy.adapters.trivy.adapter import TRIVY_DOCKER_IMAGE
    from securedeploy.adapters.semgrep.adapter import SEMGREP_DOCKER_IMAGE
    from securedeploy.adapters.nuclei.adapter import NUCLEI_DOCKER_IMAGE

    con = Console()

    async def _pull_all() -> None:
        if not await is_docker_available():
            con.print("[red]Docker is not running. Cannot pull images.[/red]")
            raise typer.Exit(2)

        images = [
            ("Trivy", TRIVY_DOCKER_IMAGE),
            ("Semgrep CE", SEMGREP_DOCKER_IMAGE),
            ("Nuclei", NUCLEI_DOCKER_IMAGE),
        ]
        for name, image in images:
            con.print(f"  Pulling {name} ({image})...")
            success = await pull_image(image)
            if success:
                con.print(f"  [green]✓[/green] {name}")
            else:
                con.print(f"  [red]✗[/red] {name} — pull failed")

    asyncio.run(_pull_all())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
