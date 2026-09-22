"""Custom test runner — executes YAML-defined security assertions."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from jinja2 import Environment as JinjaEnv

from securedeploy.config.models import ProjectConfig
from securedeploy.custom_tests.assertions import evaluate_expectations
from securedeploy.custom_tests.auth import SessionManager
from securedeploy.custom_tests.fixtures import FixtureResolver
from securedeploy.custom_tests.loader import TestLoader
from securedeploy.custom_tests.models import (
    AuthorizationTest,
    AuthorizationTestSuite,
    ExpectSpec,
    RequestSpec,
    TestResult,
)
from securedeploy.findings.fingerprint import stamp_finding
from securedeploy.findings.models import (
    Confidence,
    Evidence,
    FindingLocation,
    LocationType,
    NormalizedFinding,
    Severity,
    SourceInfo,
)
from securedeploy.utils.redact import redact

log = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}


class CustomTestRunner:
    def __init__(self, config: ProjectConfig) -> None:
        self._config = config
        self._base_url = config.target.url.rstrip("/")
        self._session_manager: SessionManager | None = None
        self._fixture_resolver: FixtureResolver | None = None
        self._loader = TestLoader(base_dir=Path.cwd())

    async def run(self, scan_id: str = "") -> list[NormalizedFinding]:
        """
        Load, authenticate, resolve fixtures, and run all custom tests.
        Returns NormalizedFindings for all FAIL assertions.
        """
        patterns = self._config.custom_tests.paths
        if not patterns:
            return []

        # Load test definitions
        identities_file = self._loader.load_identities(patterns)
        fixtures_file = self._loader.load_fixtures(patterns)
        suites = self._loader.load_test_suites(patterns)

        if not suites:
            log.debug("No custom test suites found")
            return []

        # Set up auth
        self._session_manager = SessionManager(self._base_url)
        for identity in identities_file.identities:
            self._session_manager.register(identity)

        auth_errors = await self._session_manager.authenticate_all()
        if auth_errors:
            for iid, err in auth_errors.items():
                log.warning("Identity '%s' authentication failed: %s", iid, err)

        # Set up fixtures
        self._fixture_resolver = FixtureResolver(
            self._base_url, self._session_manager
        )
        fixture_errors = await self._fixture_resolver.resolve_all(fixtures_file.fixtures)
        if fixture_errors:
            for fid, err in fixture_errors.items():
                log.warning("Fixture '%s' resolution failed: %s", fid, err)

        # Run all tests
        all_findings: list[NormalizedFinding] = []
        semaphore = asyncio.Semaphore(self._config.safety.max_concurrency)

        async def run_suite_test(
            suite: AuthorizationTestSuite, test: AuthorizationTest
        ) -> list[NormalizedFinding]:
            async with semaphore:
                return await self._run_test(suite, test, scan_id)

        tasks = []
        for suite in suites:
            for test in suite.authorization_tests + suite.header_tests:
                if test.skip:
                    continue
                tasks.append(run_suite_test(suite, test))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                log.debug("Custom test error: %s", result)

        try:
            await self._session_manager.close()
            await self._fixture_resolver.close()
        except Exception:
            pass

        return all_findings

    async def _run_test(
        self,
        suite: AuthorizationTestSuite,
        test: AuthorizationTest,
        scan_id: str,
    ) -> list[NormalizedFinding]:
        """Execute a single test and return findings for assertion failures."""
        assert self._session_manager is not None
        assert self._fixture_resolver is not None

        identity_id = test.identity

        # Get auth headers
        try:
            auth_headers = await self._session_manager.get_headers(identity_id)
        except Exception as e:
            log.warning("Test '%s' skipped — cannot authenticate '%s': %s",
                        test.name, identity_id, e)
            return []

        # Render path template with fixtures
        try:
            path = self._fixture_resolver.render_template(test.request.path)
        except Exception as e:
            log.warning("Test '%s' skipped — template render error: %s", test.name, e)
            return []

        # Build URL
        protocol = test.request.protocol or urlparse(self._base_url).scheme
        host = urlparse(self._base_url).netloc
        url = f"{protocol}://{host}{path}"

        # Merge headers
        req_headers = {**auth_headers, **test.request.headers}

        # Execute request
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=False,
                verify=False,
            ) as client:
                resp = await client.request(
                    test.request.method.upper(),
                    url,
                    headers=req_headers,
                    json=test.request.body if test.request.body else None,
                )
        except Exception as e:
            log.warning("Test '%s' HTTP error: %s", test.name, e)
            return []

        # Evaluate assertions
        assertion_results = evaluate_expectations(resp, test.expect)
        failures = [ar for ar in assertion_results if not ar.passed]

        findings: list[NormalizedFinding] = []

        if failures:
            severity = _SEVERITY_MAP.get(test.severity.lower(), Severity.HIGH)

            # For positive assertions (expect 200), a FAIL means the feature is broken
            # For security assertions (expect 403), a FAIL means access control is broken
            is_positive_test = (
                isinstance(test.expect.status, int) and test.expect.status == 200
            ) or (
                isinstance(test.expect.status, list) and test.expect.status == [200]
            )

            if is_positive_test:
                severity = Severity.INFORMATIONAL

            failure_messages = "; ".join(f.message for f in failures)
            request_summary = redact(
                f"{test.request.method.upper()} {path}\n"
                + "\n".join(f"{k}: {'<redacted>' if k.lower() in ('authorization', 'cookie') else v}"
                            for k, v in req_headers.items())
            )

            body_excerpt = ""
            try:
                body_excerpt = resp.text[:300]
            except Exception:
                pass

            finding = NormalizedFinding(
                title=test.name,
                description=failure_messages,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                category=suite.category,
                owasp_top10=[suite.owasp] if suite.owasp and "WSTG" not in suite.owasp else [],
                owasp_api_top10=["API1:2023-Broken Object Level Authorization"]
                if "idor" in test.name.lower() or "bola" in test.name.lower()
                else [],
                cwe=[suite.cwe] if suite.cwe else [],
                source=SourceInfo(
                    tool="custom-test",
                    tool_version="securedeploy/0.1.0",
                    rule_id=f"{suite.suite}/{test.name}".lower().replace(" ", "-"),
                    suite=suite.suite,
                ),
                location=FindingLocation(
                    type=LocationType.WEB,
                    url=url,
                    endpoint=path,
                    method=test.request.method.upper(),
                ),
                evidence=Evidence(
                    request=request_summary,
                    response_status=resp.status_code,
                    response_excerpt=body_excerpt,
                    expected=str(test.expect.status),
                    actual=str(resp.status_code),
                ),
                remediation=(
                    "Review and enforce server-side access control for this endpoint. "
                    "Ensure ownership and role checks are applied before returning data."
                ),
                scan_id=scan_id,
                first_detected=datetime.now(timezone.utc),
                tags=["custom-test", "authorization"],
            )
            stamp_finding(finding)
            findings.append(finding)

            # Execute follow-up request if defined
            if test.expect.follow_up:
                fu_findings = await self._run_follow_up(
                    test, suite, resp, scan_id, auth_headers
                )
                findings.extend(fu_findings)

        return findings

    async def _run_follow_up(
        self,
        test: AuthorizationTest,
        suite: AuthorizationTestSuite,
        original_resp: httpx.Response,
        scan_id: str,
        auth_headers: dict[str, str],
    ) -> list[NormalizedFinding]:
        """Execute a follow-up request to verify server state after the main request."""
        assert self._fixture_resolver is not None
        follow_up = test.expect.follow_up
        if not follow_up:
            return []

        try:
            path = self._fixture_resolver.render_template(follow_up.request.path)
        except Exception:
            return []

        url = f"{self._base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as c:
                resp = await c.request(
                    follow_up.request.method.upper(),
                    url,
                    headers=auth_headers,
                )
        except Exception:
            return []

        results = evaluate_expectations(resp, follow_up.expect)
        failures = [r for r in results if not r.passed]
        if failures:
            finding = NormalizedFinding(
                title=f"{test.name} (follow-up state verification)",
                description="; ".join(f.message for f in failures),
                severity=_SEVERITY_MAP.get(test.severity.lower(), Severity.HIGH),
                confidence=Confidence.CONFIRMED,
                category=suite.category,
                cwe=[suite.cwe] if suite.cwe else [],
                source=SourceInfo(
                    tool="custom-test",
                    rule_id=f"{suite.suite}/{test.name}-follow-up".lower().replace(" ", "-"),
                    suite=suite.suite,
                ),
                location=FindingLocation(
                    type=LocationType.WEB,
                    url=url,
                    endpoint=path,
                    method=follow_up.request.method.upper(),
                ),
                evidence=Evidence(
                    response_status=resp.status_code,
                    response_excerpt=resp.text[:300],
                ),
                remediation="Verify server-side state was not modified by the unauthorized request.",
                scan_id=scan_id,
            )
            stamp_finding(finding)
            return [finding]
        return []
