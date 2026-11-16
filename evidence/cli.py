"""Command-line entry point: python -m evidence ..."""

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import List, Optional

from . import __version__
from .controls import SEVERITY_ORDER, severity_rank
from .parsers import (
    Finding,
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_trivy,
)
from .report import write_all


def _load(path: str) -> object:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"input file not found: {path}")
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evidence",
        description="Map security-scan output to NIST 800-53 controls and build a POA&M.",
    )
    p.add_argument("--bandit", help="bandit JSON report")
    p.add_argument("--pip-audit", dest="pip_audit", help="pip-audit JSON report")
    p.add_argument("--trivy", help="trivy JSON report")
    p.add_argument("--gitleaks", help="gitleaks JSON report")
    p.add_argument("--out", default="evidence-out", help="output directory (default: evidence-out)")
    p.add_argument("--as-of", help="report date, YYYY-MM-DD (default: today)")
    p.add_argument(
        "--pip-audit-severity",
        default="high",
        choices=SEVERITY_ORDER,
        help="severity assigned to pip-audit findings (it reports none; default: high)",
    )
    p.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        help="exit 1 if any finding is at or above this severity (use as a CI gate)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not any([args.bandit, args.pip_audit, args.trivy, args.gitleaks]):
        print("error: give at least one input report", file=sys.stderr)
        return 2

    try:
        as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
    except ValueError:
        print(f"error: --as-of must be YYYY-MM-DD, got {args.as_of!r}", file=sys.stderr)
        return 2

    findings: List[Finding] = []
    try:
        if args.bandit:
            findings += parse_bandit(_load(args.bandit))
        if args.pip_audit:
            findings += parse_pip_audit(_load(args.pip_audit), args.pip_audit_severity)
        if args.trivy:
            findings += parse_trivy(_load(args.trivy))
        if args.gitleaks:
            findings += parse_gitleaks(_load(args.gitleaks))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rows = write_all(findings, Path(args.out), as_of)
    print(f"{len(rows)} finding(s) written to {args.out}/ (poam.csv, summary.md, findings.json)")

    if args.fail_on:
        threshold = severity_rank(args.fail_on)
        blocking = [r for r in rows if severity_rank(r["Severity"]) >= threshold]
        if blocking:
            print(
                f"gate failed: {len(blocking)} finding(s) at or above '{args.fail_on}'",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
