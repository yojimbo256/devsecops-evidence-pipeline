"""Build POA&M rows and write the evidence outputs.

Outputs (all written to the chosen directory):
    poam.csv       one row per finding, in a POA&M-style column layout
    summary.md     human-readable roll-up by control and severity
    findings.json  machine-readable copy of everything above
"""

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List

from .controls import (
    CONTROL_TITLES,
    DEFAULT_SLA_DAYS,
    SEVERITY_ORDER,
    severity_rank,
)
from .parsers import Finding

POAM_COLUMNS = [
    "POAM ID",
    "Controls",
    "Weakness Name",
    "Weakness Description",
    "Source",
    "Severity",
    "Resource / Location",
    "Detected",
    "Scheduled Completion",
    "Milestone",
    "Status",
]


def finding_id(f: Finding) -> str:
    """Stable id: the same finding always gets the same POAM ID across runs."""
    key = f"{f.source}|{f.rule_id}|{f.location}"
    return "POAM-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()


def dedupe(findings: List[Finding]) -> List[Finding]:
    seen = {}
    for f in findings:
        seen.setdefault(finding_id(f), f)
    return list(seen.values())


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.source, f.rule_id, f.location),
    )


def build_rows(findings: List[Finding], as_of: date, sla_days: Dict[str, int]) -> List[dict]:
    rows = []
    for f in sort_findings(dedupe(findings)):
        due = as_of + timedelta(days=sla_days[f.severity])
        rows.append(
            {
                "POAM ID": finding_id(f),
                "Controls": "; ".join(f.controls),
                "Weakness Name": f.title,
                "Weakness Description": f.description,
                "Source": f.source,
                "Severity": f.severity,
                "Resource / Location": f.location,
                "Detected": as_of.isoformat(),
                "Scheduled Completion": due.isoformat(),
                "Milestone": f.fix or "Triage and remediate",
                "Status": "Open",
            }
        )
    return rows


def write_csv(rows: List[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=POAM_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows: List[dict], as_of: date, path: Path) -> None:
    payload = {"generated": as_of.isoformat(), "count": len(rows), "findings": rows}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_summary(rows: List[dict], as_of: date, path: Path) -> None:
    by_sev = Counter(r["Severity"] for r in rows)
    by_control = defaultdict(Counter)
    for r in rows:
        for control in r["Controls"].split("; "):
            if control:
                by_control[control][r["Severity"]] += 1

    lines = [
        "# Security Evidence Summary",
        "",
        f"Generated: {as_of.isoformat()}  ",
        f"Total open findings: {len(rows)}",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in reversed(SEVERITY_ORDER):
        lines.append(f"| {sev} | {by_sev.get(sev, 0)} |")

    lines += ["", "## Findings by NIST SP 800-53 control", ""]
    if not by_control:
        lines.append("No findings. No controls affected.")
    else:
        lines += ["| Control | Title | Findings | Worst severity |", "|---|---|---|---|"]
        for control in sorted(by_control):
            counts = by_control[control]
            worst = max(counts, key=severity_rank)
            title = CONTROL_TITLES.get(control, "")
            lines.append(f"| {control} | {title} | {sum(counts.values())} | {worst} |")

    lines += [
        "",
        "## Notes",
        "",
        "- Control mappings are judgment-based, not an official crosswalk. See `evidence/controls.py`.",
        "- pip-audit reports no severity; its findings use the configured default.",
        "- Secret values are never written to this report.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_all(findings: List[Finding], out_dir: Path, as_of: date, sla_days=None) -> List[dict]:
    sla = dict(DEFAULT_SLA_DAYS)
    if sla_days:
        sla.update(sla_days)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = build_rows(findings, as_of, sla)
    write_csv(rows, out_dir / "poam.csv")
    write_json(rows, as_of, out_dir / "findings.json")
    write_summary(rows, as_of, out_dir / "summary.md")
    return rows
