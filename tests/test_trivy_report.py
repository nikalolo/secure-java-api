"""Unit tests for scripts/trivy_report.py (run with: python -m pytest tests)."""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "trivy-sample.json"

spec = importlib.util.spec_from_file_location("trivy_report", ROOT / "scripts" / "trivy_report.py")
tr = importlib.util.module_from_spec(spec)
sys.modules["trivy_report"] = tr  # dataclasses look up their module here
spec.loader.exec_module(tr)


def sample():
    return json.loads(FIXTURE.read_text())


def test_flattens_all_targets_and_skips_targets_without_vulns():
    findings = tr.load_findings(sample())
    assert len(findings) == 6
    assert {f.target for f in findings} == {"secure-java-api:baseline (oracle 8.5)", "app.jar"}


def test_severity_counts_normalise_case_and_unknown_values():
    counts = tr.count_by_severity(tr.load_findings(sample()))
    assert counts == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 1}


def test_fixable_counts_only_findings_with_fixed_version():
    assert tr.fixable(tr.load_findings(sample())) == 3


def test_empty_report_gives_zero_counts():
    assert tr.count_by_severity(tr.load_findings({"Results": None})) == {
        s: 0 for s in tr.SEVERITIES
    }


def test_single_report_lists_critical_before_high_and_marks_no_fix():
    md = tr.single_report("baseline", sample(), top=10)
    assert md.index("CVE-0000-0001") < md.index("CVE-0000-0002")
    assert "no fix yet" in md
    assert "| **Total** | **6** |" in md
    assert "CVE-0000-0003" not in md  # MEDIUM is counted but not listed


def test_top_limits_listed_rows():
    md = tr.single_report("baseline", sample(), top=1)
    assert "CVE-0000-0001" in md and "CVE-0000-0005" not in md


def test_comparison_table_has_one_column_per_report(tmp_path, capsys):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"ArtifactName": "hardened", "Results": []}))
    rc = tr.main([f"baseline={FIXTURE}", f"hardened={empty}"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "| Severity | baseline | hardened |" in out
    assert "| CRITICAL | 1 | 0 |" in out


def test_diff_lists_findings_with_a_different_installed_version(tmp_path, capsys):
    other = sample()
    vulns = other["Results"][1]["Vulnerabilities"]
    vulns[0]["InstalledVersion"] = "9.9.9"  # same CVE and package, other version
    path = tmp_path / "other.json"
    path.write_text(json.dumps(other))
    rc = tr.main(["--diff", "--title", "Repo vs JAR", f"repo={FIXTURE}", f"jar={path}"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "## Repo vs JAR" in out
    vuln = vulns[0]
    assert f"| jar | {vuln['VulnerabilityID']} |" in out and "| 9.9.9 |" in out
    assert f"| repo | {vuln['VulnerabilityID']} |" in out


def test_diff_of_identical_reports_says_none(capsys):
    rc = tr.main(["--diff", f"a={FIXTURE}", f"b={FIXTURE}"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "None: a and b report the same findings." in out
    assert tr.main(["--diff", f"a={FIXTURE}"]) == 2


def test_bad_argument_returns_error_code(capsys):
    assert tr.main(["no-equals-sign"]) == 2
    assert tr.main([f"x={FIXTURE.parent / 'missing.json'}"]) == 2
