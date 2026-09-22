"""Deterministic fingerprint computation for normalized findings.

The fingerprint identifies the *vulnerability class* at a *location*, not a
specific instance. Two findings with the same fingerprint represent the same
underlying issue — even if found by different tools on different scan runs.

Algorithm version: v1
  SHA-256 of: tool_id | rule_id | normalized_endpoint | parameter | location_type

URL normalization removes dynamic segments so that
  /api/students/42/grades  →  /api/students/{id}/grades
  /api/users/<uuid>/profile  →  /api/users/{uuid}/profile
producing identical fingerprints for the same endpoint pattern.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from securedeploy.findings.models import FindingLocation, LocationType, NormalizedFinding

# Patterns replaced in URL paths during normalization
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NUMERIC_SEGMENT_RE = re.compile(r"(?<=/)\d+(?=/|$)")
_HEX_SEGMENT_RE = re.compile(r"(?<=/)[0-9a-fA-F]{16,}(?=/|$)")

FINGERPRINT_VERSION = "v1"


def normalize_path(path: str) -> str:
    """Replace dynamic path segments with placeholders."""
    path = _UUID_RE.sub("{uuid}", path)
    path = _NUMERIC_SEGMENT_RE.sub("{id}", path)
    path = _HEX_SEGMENT_RE.sub("{hash}", path)
    return path


def normalize_url_for_fingerprint(url: str) -> str:
    """Extract and normalize the path portion of a URL."""
    try:
        parsed = urlparse(url)
        path = normalize_path(parsed.path)
        if parsed.query:
            # Keep query parameter names but discard values
            keys = [part.split("=")[0] for part in parsed.query.split("&") if part]
            path = path + "?" + "&".join(f"{k}=?" for k in sorted(keys))
        return path
    except Exception:
        return normalize_path(url)


def compute_fingerprint(
    tool_id: str,
    rule_id: str,
    location: FindingLocation,
) -> str:
    """Compute a stable fingerprint for a finding's vulnerability class + location."""
    if location.type in (LocationType.WEB, LocationType.TLS, LocationType.NETWORK):
        loc_key = normalize_url_for_fingerprint(location.endpoint or location.url or "")
    elif location.type in (LocationType.SOURCE, LocationType.SECRET):
        # For source findings, normalize the file path (remove line numbers)
        loc_key = location.source_file or ""
    elif location.type == LocationType.DEPENDENCY:
        loc_key = f"{location.package_ecosystem or ''}:{location.package_name or ''}"
    elif location.type == LocationType.CONTAINER:
        loc_key = location.package_name or ""
    else:
        loc_key = ""

    parts = [
        tool_id,
        rule_id,
        loc_key,
        location.parameter or "",
        location.method or "",
        location.type.value,
    ]
    data = "|".join(parts)
    digest = hashlib.sha256(data.encode()).hexdigest()
    return f"{FINGERPRINT_VERSION}:sha256:{digest}"


def stamp_finding(finding: NormalizedFinding) -> NormalizedFinding:
    """Compute and assign fingerprint in place, return the finding."""
    finding.fingerprint = compute_fingerprint(
        tool_id=finding.source.tool,
        rule_id=finding.source.rule_id,
        location=finding.location,
    )
    return finding
