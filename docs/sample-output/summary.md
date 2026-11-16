# Security Evidence Summary

Generated: 2026-11-16  
Total open findings: 10

## Findings by severity

| Severity | Count |
|---|---|
| critical | 1 |
| high | 5 |
| medium | 1 |
| low | 3 |
| info | 0 |

## Findings by NIST SP 800-53 control

| Control | Title | Findings | Worst severity |
|---|---|---|---|
| CM-6 | Configuration Settings | 1 | high |
| IA-5 | Authenticator Management | 2 | high |
| RA-5 | Vulnerability Monitoring and Scanning | 4 | critical |
| SA-11 | Developer Testing and Evaluation | 2 | high |
| SI-10 | Information Input Validation | 2 | high |
| SI-2 | Flaw Remediation | 4 | critical |

## Notes

- Control mappings are judgment-based, not an official crosswalk. See `evidence/controls.py`.
- pip-audit reports no severity; its findings use the configured default.
- Secret values are never written to this report.
