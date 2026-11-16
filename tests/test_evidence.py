import csv
import json
from datetime import date
from pathlib import Path

import pytest

from evidence.cli import main
from evidence.controls import normalize_severity, severity_rank
from evidence.parsers import (
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_trivy,
)
from evidence.report import build_rows, dedupe, finding_id

FIX = Path(__file__).parent / "fixtures"
AS_OF = date(2026, 11, 16)
SLA = {"critical": 15, "high": 30, "medium": 90, "low": 180, "info": 365}


def load(name):
    return json.loads((FIX / name).read_text())


# ---- severity helpers -------------------------------------------------------

def test_normalize_severity():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("Moderate") == "medium"
    assert normalize_severity("UNKNOWN") == "low"
    assert normalize_severity("") == "low"


def test_severity_rank_orders_levels():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("low")


# ---- parsers ----------------------------------------------------------------

def test_bandit_mapping_and_fallback():
    findings = {f.rule_id: f for f in parse_bandit(load("bandit.json"))}
    assert findings["B105"].controls == ["IA-5"]
    assert findings["B608"].controls == ["SI-10"]
    assert findings["B602"].severity == "high"
    assert findings["B999"].controls == ["SA-11"]  # unmapped -> default


def test_pip_audit_default_severity_and_fix():
    findings = parse_pip_audit(load("pip_audit.json"))
    assert len(findings) == 2  # flask has no vulns
    requests = next(f for f in findings if "requests" in f.location)
    assert requests.severity == "high"
    assert requests.controls == ["RA-5", "SI-2"]
    assert requests.fix == "Upgrade to 2.20.0"
    pyyaml = next(f for f in findings if "pyyaml" in f.location)
    assert pyyaml.fix is None  # no fixed version published


def test_pip_audit_severity_override():
    findings = parse_pip_audit(load("pip_audit.json"), default_severity="medium")
    assert {f.severity for f in findings} == {"medium"}


def test_trivy_vulns_and_misconfigs():
    findings = parse_trivy(load("trivy.json"))
    by_id = {f.rule_id: f for f in findings}
    assert by_id["CVE-2024-0001"].severity == "critical"
    assert by_id["CVE-2024-0002"].severity == "low"  # UNKNOWN
    assert by_id["DS002"].controls == ["CM-6"]
    assert by_id["DS002"].fix.startswith("Add a USER")
    assert len(findings) == 3  # the clean layer adds nothing


def test_gitleaks_never_keeps_secret_value():
    findings = parse_gitleaks(load("gitleaks.json"))
    assert len(findings) == 1
    blob = json.dumps(findings[0].__dict__)
    assert "EXAMPLE_SECRET" not in blob


def test_parsers_tolerate_empty_input():
    assert parse_bandit({}) == []
    assert parse_pip_audit({}) == []
    assert parse_trivy({"Results": None}) == []
    assert parse_gitleaks(None) == []


# ---- report building --------------------------------------------------------

def test_finding_id_is_stable_and_dedupe_works():
    findings = parse_bandit(load("bandit.json"))
    assert finding_id(findings[0]) == finding_id(findings[0])
    assert len(dedupe(findings + findings)) == len(findings)


def test_rows_sorted_worst_first_with_due_dates():
    findings = (
        parse_bandit(load("bandit.json"))
        + parse_trivy(load("trivy.json"))
    )
    rows = build_rows(findings, AS_OF, SLA)
    severities = [r["Severity"] for r in rows]
    assert severities[0] == "critical"
    ranks = [severity_rank(s) for s in severities]
    assert ranks == sorted(ranks, reverse=True)
    critical = rows[0]
    assert critical["Scheduled Completion"] == "2026-12-01"  # +15 days
    assert critical["Status"] == "Open"


# ---- CLI --------------------------------------------------------------------

def run_cli(tmp_path, *extra):
    argv = [
        "--bandit", str(FIX / "bandit.json"),
        "--pip-audit", str(FIX / "pip_audit.json"),
        "--trivy", str(FIX / "trivy.json"),
        "--gitleaks", str(FIX / "gitleaks.json"),
        "--out", str(tmp_path),
        "--as-of", "2026-11-16",
        *extra,
    ]
    return main(argv)


def test_cli_writes_all_outputs(tmp_path):
    assert run_cli(tmp_path) == 0
    assert (tmp_path / "poam.csv").is_file()
    assert (tmp_path / "summary.md").is_file()
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["count"] == len(data["findings"]) > 0
    with open(tmp_path / "poam.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == data["count"]
    assert "EXAMPLE_SECRET" not in (tmp_path / "poam.csv").read_text()
    assert "EXAMPLE_SECRET" not in (tmp_path / "summary.md").read_text()


def test_cli_gate_fails_on_threshold(tmp_path):
    assert run_cli(tmp_path, "--fail-on", "critical") == 1  # trivy critical present
    assert run_cli(tmp_path) == 0  # no gate -> pass


def test_cli_gate_passes_when_nothing_blocks(tmp_path):
    rc = main([
        "--bandit", str(FIX / "bandit.json"),
        "--out", str(tmp_path),
        "--as-of", "2026-11-16",
        "--fail-on", "critical",
    ])
    assert rc == 0  # bandit fixture tops out at high


def test_cli_errors(tmp_path, capsys):
    assert main(["--out", str(tmp_path)]) == 2  # no inputs
    assert main(["--bandit", str(tmp_path / "nope.json"), "--out", str(tmp_path)]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["--bandit", str(bad), "--out", str(tmp_path)]) == 2
    assert main(["--bandit", str(FIX / "bandit.json"), "--as-of", "11/16/2026"]) == 2
