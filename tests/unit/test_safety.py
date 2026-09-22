"""Tests for the safety controller — scope and environment validation."""

import pytest

from securedeploy.config.models import Environment, Profile, ProjectConfig, ProjectInfo, TargetConfig
from securedeploy.core.safety import SafetyController, SafetyViolation


def make_config(
    url: str = "https://staging.example.com",
    environment: Environment = Environment.STAGING,
    production_ack: str | None = None,
    deep_ack: str | None = None,
    allow_private: bool = False,
) -> ProjectConfig:
    from securedeploy.config.models import SafetyConfig
    target = TargetConfig(url=url, environment=environment)
    target.scope.include = ["staging.example.com"]
    safety = SafetyConfig(
        production_acknowledgement=production_ack,
        deep_authorization_acknowledgement=deep_ack,
        allow_private_ips=allow_private,
    )
    config = ProjectConfig(
        project=ProjectInfo(name="Test Project"),
        target=target,
        safety=safety,
    )
    return config


class TestTargetScheme:
    def test_https_passes(self):
        config = make_config("https://staging.example.com")
        ctrl = SafetyController(config)
        ctrl.validate(Profile.QUICK)  # no exception

    def test_http_passes(self):
        config = make_config("http://staging.example.com")
        config.target.environment = Environment.STAGING
        ctrl = SafetyController(config)
        ctrl.validate(Profile.QUICK)  # HTTP is allowed


class TestProductionProtection:
    def test_production_without_acknowledgement_fails(self):
        with pytest.raises(ValueError):
            # Pydantic validator should reject production without ack
            make_config(
                url="https://api.example.com",
                environment=Environment.PRODUCTION,
                production_ack=None,
            )

    def test_production_with_acknowledgement_passes(self):
        config = make_config(
            url="https://api.example.com",
            environment=Environment.PRODUCTION,
            production_ack="I confirm authorization to test api.example.com",
        )
        ctrl = SafetyController(config)
        ctrl.validate(Profile.QUICK)  # should not raise


class TestDeepProfileProtection:
    def test_deep_without_acknowledgement_raises(self):
        config = make_config(deep_ack=None)
        ctrl = SafetyController(config)
        with pytest.raises(SafetyViolation, match="deep_authorization_acknowledgement"):
            ctrl.validate(Profile.DEEP)

    def test_deep_with_acknowledgement_passes(self):
        config = make_config(
            deep_ack="I confirm authorization for deep testing against staging.example.com"
        )
        ctrl = SafetyController(config)
        ctrl.validate(Profile.DEEP)  # should not raise

    def test_deep_against_production_always_fails(self):
        config = make_config(
            url="https://api.example.com",
            environment=Environment.PRODUCTION,
            production_ack="I authorize production testing",
            deep_ack="I authorize deep testing",
        )
        ctrl = SafetyController(config)
        with pytest.raises(SafetyViolation, match="production"):
            ctrl.validate(Profile.DEEP)


class TestScopeValidation:
    def test_in_scope_url_passes(self):
        config = make_config()
        ctrl = SafetyController(config)
        assert ctrl.check_url_in_scope("https://staging.example.com/api/users") is True

    def test_out_of_scope_url_fails(self):
        config = make_config()
        ctrl = SafetyController(config)
        assert ctrl.check_url_in_scope("https://stripe.com/payment") is False

    def test_excluded_domain_is_out_of_scope(self):
        config = make_config()
        ctrl = SafetyController(config)
        assert ctrl.check_url_in_scope("https://auth0.com/authorize") is False
