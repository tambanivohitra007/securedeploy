"""Profile resolver — determines which adapters and options are active per profile."""

from __future__ import annotations

from securedeploy.config.models import Profile, ProjectConfig, TestingConfig


class ProfileConfig:
    """Resolved set of scanners and options for a given profile."""

    def __init__(self, profile: Profile, testing: TestingConfig) -> None:
        self.profile = profile
        # Which adapter IDs are active
        self.active_adapters: list[str] = []
        self._resolve(testing)

    def _resolve(self, testing: TestingConfig) -> None:
        active = []

        # QUICK and above
        if testing.source_code:
            active.append("semgrep")
        if testing.secrets or testing.dependencies or testing.containers:
            active.append("trivy")

        # STANDARD and above (includes QUICK)
        if self.profile in (Profile.STANDARD, Profile.DEEP):
            if testing.web or testing.api or testing.tls or testing.headers:
                active.append("nuclei")
            if testing.headers or testing.tls:
                active.append("builtin")
        else:
            # QUICK: built-in for headers + TLS basics
            if testing.headers or testing.tls:
                active.append("builtin")
            # QUICK: minimal nuclei (headers + ssl only)
            if testing.web:
                active.append("nuclei")

        # Always include custom tests if enabled
        if testing.custom_tests:
            active.append("custom")

        self.active_adapters = active

    def has_adapter(self, adapter_id: str) -> bool:
        return adapter_id in self.active_adapters


def resolve_profile(profile: Profile, config: ProjectConfig) -> ProfileConfig:
    return ProfileConfig(profile, config.testing)
