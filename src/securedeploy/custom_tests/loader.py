"""Load and validate custom test definition files from YAML."""

from __future__ import annotations

import glob
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from securedeploy.custom_tests.models import (
    AuthorizationTestSuite,
    FixturesFile,
    IdentitiesFile,
)

log = logging.getLogger(__name__)


class TestLoader:
    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir or Path.cwd()

    def load_identities(self, patterns: list[str]) -> IdentitiesFile:
        """Load all identity definitions matching the given glob patterns."""
        all_identities: list = []
        for path in self._find_files(patterns, filename_hint="identities"):
            try:
                data = self._load_yaml(path)
                file_model = IdentitiesFile.model_validate(data)
                all_identities.extend(file_model.identities)
                log.debug("Loaded %d identities from %s", len(file_model.identities), path)
            except (ValidationError, Exception) as e:
                log.warning("Failed to load identities from %s: %s", path, e)
        return IdentitiesFile(identities=all_identities)

    def load_fixtures(self, patterns: list[str]) -> FixturesFile:
        """Load all fixture definitions matching the given glob patterns."""
        all_fixtures: list = []
        for path in self._find_files(patterns, filename_hint="fixtures"):
            try:
                data = self._load_yaml(path)
                file_model = FixturesFile.model_validate(data)
                all_fixtures.extend(file_model.fixtures)
                log.debug("Loaded %d fixtures from %s", len(file_model.fixtures), path)
            except (ValidationError, Exception) as e:
                log.warning("Failed to load fixtures from %s: %s", path, e)
        return FixturesFile(fixtures=all_fixtures)

    def load_test_suites(self, patterns: list[str]) -> list[AuthorizationTestSuite]:
        """Load all authorization test suite files matching the given glob patterns."""
        suites: list[AuthorizationTestSuite] = []
        for path in self._find_files(patterns):
            # Skip identity/fixture files
            name = Path(path).name.lower()
            if "identit" in name or "fixture" in name:
                continue
            try:
                data = self._load_yaml(path)
                if not isinstance(data, dict):
                    continue
                # Only parse files that have authorization_tests or header_tests
                if "authorization_tests" not in data and "header_tests" not in data:
                    continue
                suite = AuthorizationTestSuite.model_validate(data)
                suites.append(suite)
                total = len(suite.authorization_tests) + len(suite.header_tests)
                log.debug("Loaded %d tests from %s", total, path)
            except ValidationError as e:
                log.warning("Validation error in test suite %s: %s", path, e)
            except Exception as e:
                log.warning("Failed to load test suite %s: %s", path, e)
        return suites

    def _find_files(self, patterns: list[str], filename_hint: str | None = None) -> list[str]:
        """Expand glob patterns relative to base_dir."""
        found: list[str] = []
        for pattern in patterns:
            if not Path(pattern).is_absolute():
                full_pattern = str(self._base_dir / pattern)
            else:
                full_pattern = pattern
            matches = glob.glob(full_pattern, recursive=True)
            if filename_hint:
                matches = [m for m in matches if filename_hint in Path(m).name.lower()]
            found.extend(sorted(matches))
        return found

    def _load_yaml(self, path: str) -> dict:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
