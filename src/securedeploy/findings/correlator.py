"""Finding deduplication and correlation.

Stage 1 — Exact fingerprint grouping:
  Findings with the same fingerprint are always merged into one CorrelatedFinding.

Stage 2 — Fuzzy correlation (same-rule, same-endpoint, different tools):
  Findings from different tools on the same normalized endpoint with overlapping
  CWEs are merged if their similarity score exceeds FUZZY_THRESHOLD.
  This handles cases where ZAP and Nuclei both report the same XSS.
"""

from __future__ import annotations

from securedeploy.findings.fingerprint import normalize_url_for_fingerprint
from securedeploy.findings.models import (
    CorrelatedFinding,
    FindingLocation,
    LocationType,
    NormalizedFinding,
    Severity,
)

FUZZY_THRESHOLD = 0.75


def _endpoint_key(loc: FindingLocation) -> str:
    if loc.type in (LocationType.WEB, LocationType.TLS, LocationType.NETWORK):
        return normalize_url_for_fingerprint(loc.endpoint or loc.url or "")
    if loc.type in (LocationType.SOURCE, LocationType.SECRET):
        return loc.source_file or ""
    if loc.type == LocationType.DEPENDENCY:
        return f"{loc.package_ecosystem or ''}:{loc.package_name or ''}"
    return ""


def _cwe_overlap(a: list[str], b: list[str]) -> float:
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb)


def _title_similarity(a: str, b: str) -> float:
    """Simple word-level Jaccard similarity between two titles."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    return len(words_a & words_b) / len(words_a | words_b)


def _fuzzy_score(a: NormalizedFinding, b: NormalizedFinding) -> float:
    """Return similarity score [0, 1] between two findings from different tools."""
    if a.source.tool == b.source.tool:
        return 0.0  # same tool — handled by fingerprint match
    if a.location.type != b.location.type:
        return 0.0

    endpoint_match = 1.0 if _endpoint_key(a.location) == _endpoint_key(b.location) else 0.0
    if endpoint_match == 0.0:
        return 0.0  # endpoints must match for cross-tool correlation

    method_match = 1.0 if (a.location.method or "") == (b.location.method or "") else 0.5
    cwe_sim = _cwe_overlap(a.cwe, b.cwe)
    title_sim = _title_similarity(a.title, b.title)

    score = (
        0.50 * endpoint_match
        + 0.25 * cwe_sim
        + 0.15 * title_sim
        + 0.10 * method_match
    )
    return score


def correlate(findings: list[NormalizedFinding]) -> list[CorrelatedFinding]:
    """Deduplicate and correlate findings. Returns one CorrelatedFinding per issue."""
    # Stage 1: exact fingerprint grouping
    by_fingerprint: dict[str, CorrelatedFinding] = {}
    for finding in findings:
        fp = finding.fingerprint
        if fp in by_fingerprint:
            by_fingerprint[fp].merge(finding)
        else:
            by_fingerprint[fp] = CorrelatedFinding.from_finding(finding)

    correlated = list(by_fingerprint.values())

    # Stage 2: fuzzy cross-tool correlation on remaining distinct fingerprints
    merged: set[str] = set()
    final: list[CorrelatedFinding] = []

    for i, cf_a in enumerate(correlated):
        if cf_a.fingerprint in merged:
            continue
        for cf_b in correlated[i + 1 :]:
            if cf_b.fingerprint in merged:
                continue
            # Only attempt fuzzy merge if one source each (not already multi-source)
            if len(cf_a.sources) > 2 or len(cf_b.sources) > 2:
                continue
            # Score using the primary source findings
            score = _fuzzy_score(cf_a.sources[0], cf_b.sources[0])
            if score >= FUZZY_THRESHOLD:
                for src in cf_b.sources:
                    cf_a.merge(src)
                merged.add(cf_b.fingerprint)
        final.append(cf_a)

    # Sort: critical first, then by title for deterministic output
    final.sort(key=lambda f: (-f.severity.numeric, f.title))
    return final
