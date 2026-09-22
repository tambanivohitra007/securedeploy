"""Safety and scope controller.

Runs before any adapter is invoked. Cannot be bypassed by adapter code.
A failure here aborts the entire scan.
"""

from __future__ import annotations

from securedeploy.config.models import Environment, Profile, ProjectConfig
from securedeploy.utils.url import extract_host, is_in_scope, is_private_ip


class SafetyViolation(Exception):
    """Raised when a scan would violate safety constraints."""


class SafetyController:
    def __init__(self, config: ProjectConfig) -> None:
        self._config = config

    def validate(self, profile: Profile) -> None:
        """
        Validate that it is safe to proceed with the scan.
        Raises SafetyViolation with a descriptive message on any failure.
        """
        self._check_target_scheme()
        self._check_scope_populated()
        self._check_private_ip()
        self._check_production_acknowledgement()
        self._check_deep_acknowledgement(profile)

    def _check_target_scheme(self) -> None:
        url = self._config.target.url
        if not url.startswith(("http://", "https://")):
            raise SafetyViolation(
                f"Target URL '{url}' must use http:// or https:// scheme."
            )

    def _check_scope_populated(self) -> None:
        scope = self._config.target.scope
        if not scope.include:
            raise SafetyViolation(
                "target.scope.include is empty. Cannot determine safe scan scope."
            )

    def _check_private_ip(self) -> None:
        host = extract_host(self._config.target.url)
        env = self._config.target.environment

        if env in (Environment.LOCAL, Environment.DEVELOPMENT):
            return  # private IPs are expected in local/dev

        if self._config.safety.allow_private_ips:
            return

        if is_private_ip(host):
            raise SafetyViolation(
                f"Target host '{host}' resolves to a private IP address. "
                f"Set safety.allow_private_ips: true if this is intentional "
                f"(e.g., internal staging environment)."
            )

    def _check_production_acknowledgement(self) -> None:
        if self._config.target.environment != Environment.PRODUCTION:
            return
        ack = self._config.safety.production_acknowledgement
        if not ack:
            raise SafetyViolation(
                "Scanning a production environment requires "
                "safety.production_acknowledgement to be set in securedeploy.yaml."
            )

    def _check_deep_acknowledgement(self, profile: Profile) -> None:
        if profile != Profile.DEEP:
            return
        if self._config.target.environment == Environment.PRODUCTION:
            raise SafetyViolation(
                "DEEP profile cannot be used against a production environment."
            )
        ack = self._config.safety.deep_authorization_acknowledgement
        if not ack:
            raise SafetyViolation(
                "DEEP profile requires safety.deep_authorization_acknowledgement "
                "to be set in securedeploy.yaml. This must be an explicit statement "
                "confirming you are authorized to run intrusive tests against the target."
            )

    def check_url_in_scope(self, url: str) -> bool:
        """Return True if a URL is within the declared scan scope."""
        scope = self._config.target.scope
        return is_in_scope(url, scope.include, scope.exclude)
