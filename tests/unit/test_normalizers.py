"""Normalizer golden-dataset tests — verify parsing of known tool outputs."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestTrivyNormalizer:
    def test_parses_vulnerability(self):
        from securedeploy.adapters.trivy.normalizer import TrivyNormalizer
        data = json.loads((FIXTURES / "trivy_output.json").read_text())
        findings = TrivyNormalizer().normalize(data)
        assert len(findings) >= 1
        # Check CVE finding
        cve_findings = [f for f in findings if f.cve == "CVE-2022-42969"]
        assert len(cve_findings) == 1
        f = cve_findings[0]
        assert f.severity.value == "high"
        assert f.location.package_name == "py"
        assert f.location.package_version == "1.11.0"

    def test_parses_secret(self):
        from securedeploy.adapters.trivy.normalizer import TrivyNormalizer
        data = json.loads((FIXTURES / "trivy_output.json").read_text())
        findings = TrivyNormalizer().normalize(data)
        secret_findings = [
            f for f in findings
            if (f.subcategory and "Secret" in f.subcategory)
            or "secret" in f.source.rule_id.lower()
            or "aws" in f.source.rule_id.lower()
        ]
        assert len(secret_findings) >= 1
        s = secret_findings[0]
        assert s.severity.value == "critical"
        assert "CWE-798" in s.cwe
        # Secret value must be redacted — the raw match containing AKIA should not appear
        assert "AKIA" not in (s.evidence.code_snippet or "")

    def test_empty_results_returns_empty_list(self):
        from securedeploy.adapters.trivy.normalizer import TrivyNormalizer
        findings = TrivyNormalizer().normalize({"Results": []})
        assert findings == []


class TestNucleiNormalizer:
    def test_parses_jsonl(self):
        from securedeploy.adapters.nuclei.normalizer import NucleiNormalizer
        jsonl = (FIXTURES / "nuclei_output.jsonl").read_text()
        findings = NucleiNormalizer().normalize(jsonl)
        assert len(findings) == 2

    def test_cve_finding_has_correct_fields(self):
        from securedeploy.adapters.nuclei.normalizer import NucleiNormalizer
        jsonl = (FIXTURES / "nuclei_output.jsonl").read_text()
        findings = NucleiNormalizer().normalize(jsonl)
        cve = next(f for f in findings if f.cve == "CVE-2021-41773")
        assert cve.severity.value == "critical"
        assert cve.cvss_score == 9.8
        assert "CWE-22" in cve.cwe
        assert cve.confidence.value == "high"

    def test_empty_jsonl_returns_empty(self):
        from securedeploy.adapters.nuclei.normalizer import NucleiNormalizer
        assert NucleiNormalizer().normalize("") == []
        assert NucleiNormalizer().normalize("   \n  ") == []

    def test_malformed_line_skipped(self):
        from securedeploy.adapters.nuclei.normalizer import NucleiNormalizer
        jsonl = '{"valid": true, "info": {"name": "test", "severity": "info"}, "matched-at": "https://example.com"}\nnot-json\n'
        # Should not raise, just skip bad lines
        findings = NucleiNormalizer().normalize(jsonl)
        assert len(findings) <= 1  # malformed line skipped


class TestSemgrepNormalizer:
    def test_parses_sql_injection(self):
        from securedeploy.adapters.semgrep.normalizer import SemgrepNormalizer
        data = json.loads((FIXTURES / "semgrep_output.json").read_text())
        findings = SemgrepNormalizer().normalize(data)
        sqli = [f for f in findings if "sql" in f.source.rule_id.lower() or "injection" in f.title.lower()]
        assert len(sqli) >= 1
        f = sqli[0]
        assert f.severity.value in ("high", "critical")
        assert "CWE-89" in f.cwe

    def test_parses_hardcoded_password(self):
        from securedeploy.adapters.semgrep.normalizer import SemgrepNormalizer
        data = json.loads((FIXTURES / "semgrep_output.json").read_text())
        findings = SemgrepNormalizer().normalize(data)
        secret = [f for f in findings if "CWE-798" in f.cwe]
        assert len(secret) >= 1

    def test_location_has_line_number(self):
        from securedeploy.adapters.semgrep.normalizer import SemgrepNormalizer
        data = json.loads((FIXTURES / "semgrep_output.json").read_text())
        findings = SemgrepNormalizer().normalize(data)
        for f in findings:
            assert f.location.line is not None
            assert f.location.source_file != ""
