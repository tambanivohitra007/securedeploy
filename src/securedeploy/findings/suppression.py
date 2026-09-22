"""Apply accepted-risk and suppression annotations to correlated findings."""

from __future__ import annotations

from datetime import datetime, timezone

from securedeploy.findings.models import CorrelatedFinding, Disposition


def apply_suppressions(
    findings: list[CorrelatedFinding],
    accepted_risks: list[dict],  # from config — list of AcceptedRisk dicts
) -> list[CorrelatedFinding]:
    """
    Mark findings that match accepted_risk entries.
    Findings are NOT removed; they are annotated with disposition = ACCEPTED_RISK
    or EXPIRED_ACCEPTED_RISK so they still appear in reports.
    """
    now = datetime.now(timezone.utc)

    for finding in findings:
        for ar in accepted_risks:
            if _matches_accepted_risk(finding, ar):
                expires_raw = ar.get("expires")
                if expires_raw:
                    try:
                        expires = datetime.fromisoformat(expires_raw).replace(tzinfo=timezone.utc)
                        if expires < now:
                            finding.disposition = Disposition.EXPIRED_ACCEPTED_RISK
                            finding.disposition_reason = (
                                f"Accepted risk '{ar.get('id', '')}' expired {expires_raw}"
                            )
                            break
                    except ValueError:
                        pass
                finding.disposition = Disposition.ACCEPTED_RISK
                finding.disposition_reason = ar.get("reason", "")
                break

    return findings


def _matches_accepted_risk(finding: CorrelatedFinding, ar: dict) -> bool:
    # Match by fingerprint (most precise)
    fp = ar.get("fingerprint")
    if fp and finding.fingerprint == fp:
        return True

    # Match by rule_id + tool combination
    rule_id = ar.get("rule_id")
    tool = ar.get("tool")
    if rule_id:
        for src in finding.sources:
            if src.source.rule_id == rule_id:
                if not tool or src.source.tool == tool:
                    return True

    return False
