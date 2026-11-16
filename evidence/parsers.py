"""Parsers that turn scanner JSON into a common Finding record.

Supported inputs:
    bandit      bandit -r <dir> -f json
    pip-audit   pip-audit -r requirements.txt -f json
    trivy       trivy image --format json
    gitleaks    gitleaks detect --report-format json

Secret values are never copied into a Finding. Only the rule and location are
kept, so the evidence report cannot leak what it reports.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .controls import (
    BANDIT_CONTROLS,
    DEFAULT_BANDIT_CONTROLS,
    DEPENDENCY_VULN_CONTROLS,
    MISCONFIG_CONTROLS,
    SECRET_CONTROLS,
    normalize_severity,
)


@dataclass
class Finding:
    source: str
    rule_id: str
    title: str
    description: str
    severity: str
    location: str
    controls: List[str] = field(default_factory=list)
    fix: Optional[str] = None


def parse_bandit(data: dict) -> List[Finding]:
    findings = []
    for item in data.get("results", []):
        test_id = item.get("test_id", "B000")
        findings.append(
            Finding(
                source="bandit",
                rule_id=test_id,
                title=f"{item.get('test_name', 'unknown')} ({test_id})",
                description=item.get("issue_text", ""),
                severity=normalize_severity(item.get("issue_severity", "")),
                location=f"{item.get('filename', '?')}:{item.get('line_number', '?')}",
                controls=list(BANDIT_CONTROLS.get(test_id, DEFAULT_BANDIT_CONTROLS)),
            )
        )
    return findings


def parse_pip_audit(data: dict, default_severity: str = "high") -> List[Finding]:
    """pip-audit reports no severity, so every vulnerability gets default_severity.

    High is the conservative choice; pass a lower value if you triage separately.
    """
    findings = []
    severity = normalize_severity(default_severity)
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            fixes = vuln.get("fix_versions") or []
            findings.append(
                Finding(
                    source="pip-audit",
                    rule_id=vuln.get("id", "UNKNOWN"),
                    title=f"{dep.get('name', '?')} {dep.get('version', '?')}: {vuln.get('id', 'UNKNOWN')}",
                    description=vuln.get("description", ""),
                    severity=severity,
                    location=f"{dep.get('name', '?')}=={dep.get('version', '?')}",
                    controls=list(DEPENDENCY_VULN_CONTROLS),
                    fix=("Upgrade to " + ", ".join(fixes)) if fixes else None,
                )
            )
    return findings


def parse_trivy(data: dict) -> List[Finding]:
    findings = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "?")
        for vuln in result.get("Vulnerabilities", []) or []:
            fixed = vuln.get("FixedVersion")
            findings.append(
                Finding(
                    source="trivy",
                    rule_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    title=f"{vuln.get('PkgName', '?')} {vuln.get('InstalledVersion', '?')}: {vuln.get('VulnerabilityID', 'UNKNOWN')}",
                    description=vuln.get("Title") or vuln.get("Description", ""),
                    severity=normalize_severity(vuln.get("Severity", "")),
                    location=f"{target} ({vuln.get('PkgName', '?')})",
                    controls=list(DEPENDENCY_VULN_CONTROLS),
                    fix=f"Upgrade to {fixed}" if fixed else None,
                )
            )
        for mis in result.get("Misconfigurations", []) or []:
            findings.append(
                Finding(
                    source="trivy",
                    rule_id=mis.get("ID", "UNKNOWN"),
                    title=mis.get("Title", "Misconfiguration"),
                    description=mis.get("Description", ""),
                    severity=normalize_severity(mis.get("Severity", "")),
                    location=target,
                    controls=list(MISCONFIG_CONTROLS),
                    fix=mis.get("Resolution"),
                )
            )
    return findings


def parse_gitleaks(data: Iterable[dict]) -> List[Finding]:
    findings = []
    for item in data or []:
        findings.append(
            Finding(
                source="gitleaks",
                rule_id=item.get("RuleID", "UNKNOWN"),
                title=f"Possible secret: {item.get('RuleID', 'UNKNOWN')}",
                description=item.get("Description", "Possible hard-coded secret"),
                severity="high",
                location=f"{item.get('File', '?')}:{item.get('StartLine', '?')}",
                controls=list(SECRET_CONTROLS),
                fix="Rotate the credential, remove it from history, and load it from a secret store.",
            )
        )
    return findings
