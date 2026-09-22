"""HTML report generator — human-readable security assessment report."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from securedeploy.policy.models import PolicyResult
from securedeploy.findings.models import Disposition, Severity


_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#65a30d",
    "informational": "#6b7280",
}

_DISPOSITION_BADGE = {
    Disposition.BLOCK:               ('<span class="badge badge-block">BLOCK</span>', "#fee2e2"),
    Disposition.WARN:                ('<span class="badge badge-warn">WARN</span>',  "#fef9c3"),
    Disposition.REPORT:              ('<span class="badge badge-info">INFO</span>',  "#f0f9ff"),
    Disposition.ACCEPTED_RISK:       ('<span class="badge badge-ok">ACCEPTED</span>', "#f0fdf4"),
    Disposition.SUPPRESSED:          ('<span class="badge badge-ok">SUPPRESSED</span>', "#f0fdf4"),
    Disposition.EXPIRED_ACCEPTED_RISK: ('<span class="badge badge-warn">EXPIRED ACK</span>', "#fef9c3"),
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f8fafc; color: #1e293b; line-height: 1.6; }
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }

/* Header */
.header { background: #1e293b; color: white; padding: 32px 0; margin-bottom: 32px; }
.header .container { display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 1.6rem; font-weight: 700; }
.header .meta { font-size: 0.85rem; color: #94a3b8; margin-top: 4px; }

/* Verdict banner */
.verdict { border-radius: 10px; padding: 20px 28px; margin-bottom: 28px;
           display: flex; align-items: center; gap: 16px; font-size: 1.1rem; font-weight: 600; }
.verdict-pass { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
.verdict-fail { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
.verdict-icon { font-size: 2rem; }
.verdict-detail { font-size: 0.875rem; font-weight: 400; color: inherit; opacity: 0.8; margin-top: 2px; }

/* Summary grid */
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 28px; }
.sev-card { background: white; border-radius: 8px; padding: 16px; text-align: center;
            border-top: 4px solid; box-shadow: 0 1px 3px rgba(0,0,0,.07); }
.sev-card .count { font-size: 2.2rem; font-weight: 800; }
.sev-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: .06em; color: #64748b; }

/* Section */
.section { background: white; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.07);
           margin-bottom: 24px; overflow: hidden; }
.section-header { padding: 16px 24px; background: #f1f5f9; border-bottom: 1px solid #e2e8f0;
                  font-weight: 600; font-size: 0.95rem; display: flex; justify-content: space-between; }
.section-count { background: #e2e8f0; border-radius: 999px; padding: 2px 10px;
                 font-size: 0.78rem; font-weight: 500; color: #475569; }

/* Finding table */
table { width: 100%; border-collapse: collapse; }
th { padding: 10px 16px; background: #f8fafc; font-size: 0.78rem; text-transform: uppercase;
     letter-spacing: .05em; color: #64748b; text-align: left; border-bottom: 1px solid #e2e8f0; }
td { padding: 14px 16px; border-bottom: 1px solid #f1f5f9; vertical-align: top; font-size: 0.875rem; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafafa; }

.sev-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
           margin-right: 6px; vertical-align: middle; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem;
         font-weight: 600; letter-spacing: .04em; }
.badge-block { background: #fee2e2; color: #991b1b; }
.badge-warn  { background: #fef9c3; color: #854d0e; }
.badge-info  { background: #e0f2fe; color: #075985; }
.badge-ok    { background: #dcfce7; color: #166534; }

.finding-title { font-weight: 600; color: #0f172a; }
.finding-desc  { color: #64748b; font-size: 0.82rem; margin-top: 3px; }
.finding-loc   { font-family: monospace; font-size: 0.78rem; color: #475569; margin-top: 4px;
                 background: #f1f5f9; padding: 2px 6px; border-radius: 4px; display: inline-block; }
.cwe-tag  { display: inline-block; background: #f1f5f9; color: #475569; border-radius: 4px;
            padding: 1px 6px; font-size: 0.72rem; margin: 2px 2px 0 0; }

/* Tool errors */
.tool-error { background: #fffbeb; border-left: 3px solid #f59e0b; padding: 12px 16px;
              margin: 0; font-size: 0.875rem; }
.tool-error strong { color: #92400e; }

/* Remediation */
.remediation { background: #f0fdf4; border-radius: 6px; padding: 10px 14px; margin-top: 8px;
               font-size: 0.82rem; color: #166534; }
.remediation-label { font-weight: 600; margin-bottom: 2px; }

/* Footer */
.footer { text-align: center; color: #94a3b8; font-size: 0.8rem; margin-top: 40px; padding-top: 24px;
          border-top: 1px solid #e2e8f0; }

/* Responsive */
@media (max-width: 700px) {
  .summary-grid { grid-template-columns: repeat(3, 1fr); }
  .header .container { flex-direction: column; gap: 8px; }
}
"""


def _sev_dot(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#6b7280")
    return f'<span class="sev-dot" style="background:{color}"></span>'


def _render_finding_row(f) -> str:
    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    color = _SEVERITY_COLOR.get(sev, "#6b7280")
    badge_html, _ = _DISPOSITION_BADGE.get(
        f.disposition, ('<span class="badge badge-info">INFO</span>', "#f0f9ff")
    )

    loc_parts = []
    if f.location.url:
        loc_parts.append(html.escape(f.location.url))
    elif f.location.endpoint:
        loc_parts.append(html.escape(f.location.endpoint))
    if f.location.source_file:
        loc = f.location.source_file
        if f.location.line:
            loc += f":{f.location.line}"
        loc_parts.append(html.escape(loc))
    if f.location.package_name:
        loc_parts.append(html.escape(f"{f.location.package_name}@{f.location.package_version or '?'}"))
    loc_html = "".join(f'<span class="finding-loc">{p}</span>' for p in loc_parts)

    cwe_html = "".join(
        f'<span class="cwe-tag">{html.escape(c)}</span>' for c in (f.cwe or [])
    )

    remediation_html = ""
    if f.remediation:
        remediation_html = f"""
        <div class="remediation">
            <div class="remediation-label">Remediation</div>
            {html.escape(f.remediation[:300])}{"…" if len(f.remediation) > 300 else ""}
        </div>"""

    tools = ", ".join(f.source_tools) if hasattr(f, "source_tools") else ""

    return f"""
    <tr>
      <td>
        {_sev_dot(sev)}
        <span style="font-weight:600;color:{color};text-transform:capitalize">{sev}</span>
      </td>
      <td>
        <div class="finding-title">{html.escape(f.title)}</div>
        <div class="finding-desc">{html.escape((f.description or "")[:180])}{"…" if len(f.description or "") > 180 else ""}</div>
        {loc_html}
        {cwe_html}
        {remediation_html}
      </td>
      <td>{html.escape(f.category or "")}</td>
      <td><code style="font-size:0.75rem;color:#64748b">{html.escape(tools)}</code></td>
      <td>{badge_html}</td>
    </tr>"""


def _severity_order(f) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    return order.get(sev, 5)


class HtmlReporter:
    def write(self, result: PolicyResult, output_dir: Path, meta: dict) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "report.html"
        path.write_text(self._render(result, meta), encoding="utf-8")
        return path

    def _render(self, result: PolicyResult, meta: dict) -> str:
        project = html.escape(meta.get("project_name", "Security Assessment"))
        target  = html.escape(meta.get("target_url", ""))
        profile = html.escape(meta.get("profile", "").upper())
        scan_id = html.escape(meta.get("scan_id", ""))
        now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        version = html.escape(meta.get("version", ""))

        is_pass  = result.verdict.value == "PASS"
        verdict_cls  = "verdict-pass" if is_pass else "verdict-fail"
        verdict_icon = "✅" if is_pass else "❌"
        verdict_text = "PASS — No blocking findings" if is_pass else "FAIL — Policy violations detected"

        # Severity counts
        counts = {s.value: 0 for s in Severity}
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        sev_cards = ""
        for sev, label in [
            ("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
            ("low", "Low"), ("informational", "Info"),
        ]:
            color = _SEVERITY_COLOR[sev]
            sev_cards += f"""
            <div class="sev-card" style="border-color:{color}">
                <div class="count" style="color:{color}">{counts.get(sev, 0)}</div>
                <div class="label">{label}</div>
            </div>"""

        # Group findings by category
        from collections import defaultdict
        by_category: dict[str, list] = defaultdict(list)
        for f in sorted(result.findings, key=_severity_order):
            by_category[f.category or "Uncategorized"].append(f)

        findings_html = ""
        for category, findings in sorted(by_category.items()):
            rows = "".join(_render_finding_row(f) for f in findings)
            findings_html += f"""
            <div class="section">
              <div class="section-header">
                {html.escape(category)}
                <span class="section-count">{len(findings)} finding{"s" if len(findings) != 1 else ""}</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th style="width:100px">Severity</th>
                    <th>Finding</th>
                    <th style="width:180px">Category</th>
                    <th style="width:120px">Source</th>
                    <th style="width:100px">Status</th>
                  </tr>
                </thead>
                <tbody>{rows}</tbody>
              </table>
            </div>"""

        # Tool errors
        tool_errors_html = ""
        if result.tool_errors:
            errors = "".join(
                f'<div class="tool-error"><strong>{html.escape(e.tool)}</strong>: '
                f'{html.escape(e.display_reason)} — {html.escape(e.message or "")}</div>'
                for e in result.tool_errors
            )
            tool_errors_html = f"""
            <div class="section">
              <div class="section-header">Tool Warnings</div>
              {errors}
            </div>"""

        # Block reasons
        block_html = ""
        if result.block_reasons:
            items = "".join(
                f'<li style="margin-bottom:6px">{html.escape(r)}</li>'
                for r in result.block_reasons
            )
            block_html = f"""
            <div class="section">
              <div class="section-header" style="color:#991b1b">Blocking Reasons</div>
              <ul style="padding:16px 24px 16px 40px;color:#7f1d1d">{items}</ul>
            </div>"""

        disclaimer = html.escape(
            "PASS means the application passed the configured security policy. "
            "It does not guarantee the absence of all security vulnerabilities."
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureDeploy Report — {project}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="header">
    <div class="container">
      <div>
        <h1>SecureDeploy Security Report</h1>
        <div class="meta">{project} &nbsp;·&nbsp; {target} &nbsp;·&nbsp; Profile: {profile}</div>
        <div class="meta">Scan ID: {scan_id} &nbsp;·&nbsp; Generated: {now} &nbsp;·&nbsp; v{version}</div>
      </div>
    </div>
  </div>

  <div class="container">
    <div class="verdict {verdict_cls}">
      <span class="verdict-icon">{verdict_icon}</span>
      <div>
        {verdict_text}
        <div class="verdict-detail">{disclaimer}</div>
      </div>
    </div>

    <div class="summary-grid">{sev_cards}</div>

    {block_html}
    {findings_html}
    {tool_errors_html}

    <div class="footer">
      Generated by <strong>SecureDeploy {version}</strong> &nbsp;·&nbsp;
      This report is confidential and intended for authorized recipients only.
    </div>
  </div>
</body>
</html>"""
