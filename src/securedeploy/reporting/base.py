"""Reporter protocol."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from securedeploy.policy.models import PolicyResult


class Reporter(ABC):
    @abstractmethod
    def write(self, result: PolicyResult, output_dir: Path, scan_meta: dict) -> Path | None:
        """Write report to output_dir. Returns the output file path, or None for terminal."""
        ...
