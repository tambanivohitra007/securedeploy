"""securedeploy init — generate starter configuration."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt

from securedeploy.config.defaults import (
    AUTHORIZATION_TEMPLATE,
    IDENTITIES_TEMPLATE,
    INIT_TEMPLATE,
)

console = Console()


def init_command(
    output: str = typer.Option(".", "--output", "-o", help="Directory to create config in"),
) -> None:
    """Create a securedeploy.yaml configuration file."""
    output_path = Path(output).resolve()
    config_file = output_path / "securedeploy.yaml"

    if config_file.exists():
        overwrite = typer.confirm(
            f"\n  securedeploy.yaml already exists in {output_path}. Overwrite?",
            default=False,
        )
        if not overwrite:
            console.print("  [yellow]Aborted.[/yellow]")
            raise typer.Exit(0)

    console.print("\n  [bold blue]SecureDeploy Configuration Setup[/bold blue]\n")

    project_name = Prompt.ask("  Project name", default=output_path.name)
    domain = Prompt.ask("  Staging domain", default=f"staging.{output_path.name.lower()}.com")

    # Write securedeploy.yaml
    config_content = INIT_TEMPLATE.format(
        project_name=project_name,
        domain=domain,
    )
    config_file.write_text(config_content, encoding="utf-8")
    console.print(f"\n  [green]✓[/green] Created {config_file}")

    # Create security-tests directory with starter files
    tests_dir = output_path / "security-tests"
    tests_dir.mkdir(exist_ok=True)

    identities_file = tests_dir / "identities.yaml"
    if not identities_file.exists():
        identities_file.write_text(IDENTITIES_TEMPLATE, encoding="utf-8")
        console.print(f"  [green]✓[/green] Created {identities_file}")

    auth_file = tests_dir / "authorization.yaml"
    if not auth_file.exists():
        auth_file.write_text(AUTHORIZATION_TEMPLATE, encoding="utf-8")
        console.print(f"  [green]✓[/green] Created {auth_file}")

    console.print()
    console.print("  Next steps:")
    console.print(f"  [dim]1. Edit securedeploy.yaml and set your target URL[/dim]")
    console.print(f"  [dim]2. Set test credentials as environment variables[/dim]")
    console.print(f"  [dim]3. Run: securedeploy test --profile quick[/dim]")
    console.print()
