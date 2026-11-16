"""Severity handling and the finding -> NIST SP 800-53 Rev. 5 control mapping.

The mappings are a judgment call, not an official crosswalk. They are kept in
plain dictionaries so a reviewer can read and change them without touching
code logic.
"""

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Days allowed to remediate, by severity. Common continuous-monitoring
# practice; override with --sla if your authorizing official says otherwise.
DEFAULT_SLA_DAYS = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}

CONTROL_TITLES = {
    "CM-6": "Configuration Settings",
    "IA-5": "Authenticator Management",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SA-11": "Developer Testing and Evaluation",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-23": "Session Authenticity",
    "SI-2": "Flaw Remediation",
    "SI-10": "Information Input Validation",
    "SI-11": "Error Handling",
}

# Bandit test id -> controls. Anything not listed falls back to SA-11.
BANDIT_CONTROLS = {
    # hard-coded credentials
    "B105": ["IA-5"],
    "B106": ["IA-5"],
    "B107": ["IA-5"],
    # injection / unsafe input handling
    "B102": ["SI-10"],
    "B301": ["SI-10"],
    "B307": ["SI-10"],
    "B310": ["SI-10"],
    "B506": ["SI-10"],
    "B602": ["SI-10"],
    "B603": ["SI-10"],
    "B604": ["SI-10"],
    "B605": ["SI-10"],
    "B606": ["SI-10"],
    "B607": ["SI-10"],
    "B608": ["SI-10"],
    # network exposure
    "B104": ["SC-7"],
    # debug / error handling
    "B201": ["CM-6", "SI-11"],
    # weak or misused cryptography
    "B303": ["SC-13"],
    "B304": ["SC-13"],
    "B305": ["SC-13"],
    "B324": ["SC-13"],
    "B505": ["SC-12", "SC-13"],
    # TLS / transport
    "B501": ["SC-8", "SC-23"],
    "B502": ["SC-8"],
    "B503": ["SC-8"],
    "B504": ["SC-8"],
}
DEFAULT_BANDIT_CONTROLS = ["SA-11"]

DEPENDENCY_VULN_CONTROLS = ["RA-5", "SI-2"]
MISCONFIG_CONTROLS = ["CM-6"]
SECRET_CONTROLS = ["IA-5", "SA-11"]


def severity_rank(severity: str) -> int:
    """Position of a severity in SEVERITY_ORDER; unknown values rank as 'low'."""
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return SEVERITY_ORDER.index("low")


def normalize_severity(raw: str) -> str:
    """Map a scanner's severity label onto our five levels."""
    value = (raw or "").strip().lower()
    if value in SEVERITY_ORDER:
        return value
    if value in ("moderate",):
        return "medium"
    return "low"  # UNKNOWN and anything unexpected
