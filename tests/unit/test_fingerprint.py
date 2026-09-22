"""Tests for fingerprint stability and URL normalization."""

import pytest

from securedeploy.findings.fingerprint import (
    normalize_path,
    normalize_url_for_fingerprint,
    compute_fingerprint,
)
from securedeploy.findings.models import FindingLocation, LocationType


def test_numeric_id_normalization():
    assert normalize_path("/api/students/42/grades") == "/api/students/{id}/grades"
    assert normalize_path("/api/users/99") == "/api/users/{id}"
    assert normalize_path("/api/classes/1/students") == "/api/classes/{id}/students"


def test_uuid_normalization():
    uuid = "a3b4c5d6-e7f8-1234-5678-abcdef012345"
    assert normalize_path(f"/api/users/{uuid}") == "/api/users/{uuid}"


def test_static_path_unchanged():
    assert normalize_path("/api/auth/login") == "/api/auth/login"
    assert normalize_path("/api/admin/users") == "/api/admin/users"


def test_url_normalization_strips_host():
    result = normalize_url_for_fingerprint("https://staging.example.com/api/students/42")
    assert "staging.example.com" not in result
    assert "{id}" in result


def test_url_normalization_query_keys_kept():
    result = normalize_url_for_fingerprint("https://example.com/search?q=foo&page=2")
    assert "q=?" in result
    assert "page=?" in result
    assert "foo" not in result


def test_fingerprint_stability():
    """Same vulnerability = same fingerprint across multiple calls."""
    loc = FindingLocation(
        type=LocationType.WEB,
        url="https://staging.example.com/api/students/42/grades",
        endpoint="/api/students/{id}/grades",
        method="GET",
    )
    fp1 = compute_fingerprint("nuclei", "sqli-01", loc)
    fp2 = compute_fingerprint("nuclei", "sqli-01", loc)
    assert fp1 == fp2


def test_fingerprint_different_endpoints():
    loc_a = FindingLocation(type=LocationType.WEB, endpoint="/api/grades", method="GET")
    loc_b = FindingLocation(type=LocationType.WEB, endpoint="/api/users", method="GET")
    fp_a = compute_fingerprint("nuclei", "sqli-01", loc_a)
    fp_b = compute_fingerprint("nuclei", "sqli-01", loc_b)
    assert fp_a != fp_b


def test_fingerprint_same_endpoint_different_id():
    """Two different numeric IDs in path should produce same fingerprint."""
    loc_42 = FindingLocation(
        type=LocationType.WEB,
        url="https://example.com/api/students/42/grades",
        endpoint="/api/students/42/grades",
        method="GET",
    )
    loc_99 = FindingLocation(
        type=LocationType.WEB,
        url="https://example.com/api/students/99/grades",
        endpoint="/api/students/99/grades",
        method="GET",
    )
    fp_42 = compute_fingerprint("custom-test", "authorization/test", loc_42)
    fp_99 = compute_fingerprint("custom-test", "authorization/test", loc_99)
    assert fp_42 == fp_99


def test_fingerprint_format():
    loc = FindingLocation(type=LocationType.SOURCE, source_file="app.py")
    fp = compute_fingerprint("semgrep", "python.hardcoded-secret", loc)
    assert fp.startswith("v1:sha256:")
    assert len(fp) == len("v1:sha256:") + 64
