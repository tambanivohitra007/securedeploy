"""Config loading: YAML file → env var substitution → Pydantic validation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from securedeploy.config.models import ProjectConfig

# Match ${VAR_NAME} or $VAR_NAME patterns
_ENV_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}|\$([A-Z_][A-Z0-9_]*)")

CONFIG_FILENAMES = [
    "securedeploy.yaml",
    "securedeploy.yml",
    ".securedeploy/config.yaml",
    ".securedeploy/config.yml",
]


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


def _substitute_env_vars(value: Any) -> Any:
    """Recursively substitute ${VAR} and $VAR patterns with environment variable values."""
    if isinstance(value, str):
        def replacer(m: re.Match) -> str:
            var_name = m.group(1) or m.group(2)
            env_value = os.environ.get(var_name)
            if env_value is None:
                # Leave unresolved vars as-is; they may be optional
                return m.group(0)
            return env_value
        return _ENV_VAR_RE.sub(replacer, value)
    if isinstance(value, dict):
        return {k: _substitute_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_env_vars(item) for item in value]
    return value


def _find_config_file(start_dir: Path) -> Path | None:
    """Walk up the directory tree looking for a config file."""
    current = start_dir.resolve()
    for _ in range(10):  # max 10 levels up
        for name in CONFIG_FILENAMES:
            candidate = current / name
            if candidate.exists():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_config(
    config_path: str | Path | None = None,
    working_dir: Path | None = None,
) -> ProjectConfig:
    """
    Load and validate project configuration.

    Search order:
    1. Explicit --config path (if provided)
    2. Walk up from working_dir (or cwd) for securedeploy.yaml
    3. Raise ConfigError if not found
    """
    if config_path is not None:
        path = Path(config_path).resolve()
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")
    else:
        search_dir = Path(working_dir) if working_dir else Path.cwd()
        path = _find_config_file(search_dir)
        if path is None:
            raise ConfigError(
                "No securedeploy.yaml found. Run `securedeploy init` to create one."
            )

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML parse error in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must be a YAML mapping, got {type(raw).__name__}")

    # Substitute environment variables throughout
    raw = _substitute_env_vars(raw)

    # Apply SECUREDEPLOY_* environment variable overrides
    raw = _apply_env_overrides(raw)

    try:
        return ProjectConfig.model_validate(raw)
    except ValidationError as e:
        lines = [f"Configuration error in {path}:"]
        for err in e.errors():
            loc = " → ".join(str(x) for x in err["loc"])
            lines.append(f"  {loc}: {err['msg']}")
        raise ConfigError("\n".join(lines)) from e


def _apply_env_overrides(config: dict) -> dict:
    """
    Apply SECUREDEPLOY_<SECTION>_<KEY>=value env var overrides.
    Example: SECUREDEPLOY_POLICY_ON_FINDING_CRITICAL=warn
    """
    prefix = "SECUREDEPLOY_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        parts = rest.lower().split("_")
        if not parts:
            continue
        _set_nested(config, parts, value)
    return config


def _set_nested(d: dict, keys: list[str], value: str) -> None:
    """Set a nested dict value by key path, creating intermediates as needed."""
    # Try progressively longer prefixes as section keys
    for split_at in range(1, len(keys)):
        section = "_".join(keys[:split_at])
        if section in d and isinstance(d[section], dict):
            _set_nested(d[section], keys[split_at:], value)
            return
    # Set at current level with the full remaining key
    leaf_key = "_".join(keys)
    d[leaf_key] = value
