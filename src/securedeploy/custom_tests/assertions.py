"""Assertion evaluators for custom security tests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx

from securedeploy.custom_tests.models import ExpectSpec, HeaderAssertion


@dataclass
class AssertionResult:
    passed: bool
    message: str  # human-readable description of what was expected vs. actual


def evaluate_expectations(
    response: httpx.Response,
    expect: ExpectSpec,
) -> list[AssertionResult]:
    """
    Evaluate all assertions in an ExpectSpec against an HTTP response.
    Returns a list of AssertionResult objects — failed assertions describe the violation.
    """
    results: list[AssertionResult] = []

    # Status code assertion
    if expect.status is not None:
        results.append(_check_status(response.status_code, expect.status))

    # Body must contain
    body_text = ""
    try:
        body_text = response.text
    except Exception:
        pass

    for pattern in expect.body_must_contain:
        if pattern in body_text:
            results.append(AssertionResult(
                passed=True,
                message=f"Response body contains expected pattern '{pattern}'",
            ))
        else:
            results.append(AssertionResult(
                passed=False,
                message=f"Response body missing expected pattern '{pattern}'",
            ))

    # Body must NOT contain
    for pattern in expect.body_must_not_contain:
        if pattern in body_text:
            results.append(AssertionResult(
                passed=False,
                message=(
                    f"Response body contains forbidden pattern '{pattern}' — "
                    "possible information disclosure or authorization bypass"
                ),
            ))
        else:
            results.append(AssertionResult(
                passed=True,
                message=f"Response body does not contain forbidden pattern (OK)",
            ))

    # Header assertions
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    for header_name, assertion in expect.headers.items():
        actual = resp_headers.get(header_name.lower())
        results.append(_check_header(header_name, actual, assertion))

    # Set-Cookie assertions
    if expect.set_cookie:
        results.extend(_check_set_cookie(response, expect.set_cookie))

    return results


def _check_status(
    actual: int,
    expected: int | list[int],
) -> AssertionResult:
    if isinstance(expected, int):
        expected = [expected]
    if actual in expected:
        return AssertionResult(
            passed=True,
            message=f"Status code {actual} matches expected {expected}",
        )
    return AssertionResult(
        passed=False,
        message=(
            f"Expected status {expected}, got {actual}. "
            "This may indicate a broken access control check."
        ),
    )


def _check_header(
    name: str,
    actual_value: str | None,
    assertion: HeaderAssertion,
) -> AssertionResult:
    if assertion.present is True and actual_value is None:
        return AssertionResult(
            passed=False,
            message=f"Expected header '{name}' to be present, but it was absent",
        )
    if assertion.present is False and actual_value is not None:
        return AssertionResult(
            passed=False,
            message=f"Expected header '{name}' to be absent, but found: '{actual_value}'",
        )
    if actual_value is None:
        return AssertionResult(passed=True, message=f"Header '{name}' assertion passed (absent)")

    if assertion.contains and assertion.contains not in actual_value:
        return AssertionResult(
            passed=False,
            message=f"Header '{name}: {actual_value}' does not contain '{assertion.contains}'",
        )

    if assertion.starts_with and not actual_value.startswith(assertion.starts_with):
        return AssertionResult(
            passed=False,
            message=f"Header '{name}: {actual_value}' does not start with '{assertion.starts_with}'",
        )

    if assertion.must_not_contain and assertion.must_not_contain in actual_value:
        return AssertionResult(
            passed=False,
            message=f"Header '{name}: {actual_value}' contains forbidden value '{assertion.must_not_contain}'",
        )

    if assertion.min_max_age is not None:
        m = re.search(r"max-age=(\d+)", actual_value, re.IGNORECASE)
        if m:
            age = int(m.group(1))
            if age < assertion.min_max_age:
                return AssertionResult(
                    passed=False,
                    message=f"Header '{name}' max-age={age} is less than required {assertion.min_max_age}",
                )

    return AssertionResult(passed=True, message=f"Header '{name}' assertion passed")


def _check_set_cookie(
    response: httpx.Response,
    assertion: Any,
) -> list[AssertionResult]:
    results = []
    raw_cookies = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]

    if not raw_cookies:
        return results

    for raw in raw_cookies:
        parts = {p.strip().lower() for p in raw.split(";")}
        if assertion.all:
            flags = assertion.all
            required_flags = flags.get("has_flag", [])
            if isinstance(required_flags, str):
                required_flags = [required_flags]
            for flag in required_flags:
                if flag.lower() not in parts:
                    name = raw.split("=")[0].strip()
                    results.append(AssertionResult(
                        passed=False,
                        message=f"Cookie '{name}' is missing the '{flag}' flag",
                    ))
                else:
                    results.append(AssertionResult(passed=True, message=f"Cookie has {flag} flag"))

    return results
