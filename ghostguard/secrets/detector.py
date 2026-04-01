"""
Secrets Detector - Detect sensitive keys, passwords, and tokens in code
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class SecretType(str, Enum):
    """Types of secrets that can be detected"""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CREDENTIAL = "credential"
    AWS_KEY = "aws_key"
    GITHUB_TOKEN = "github_token"
    STRIPE_KEY = "stripe_key"
    DATABASE_URL = "database_url"
    JWT_SECRET = "jwt_secret"
    ENCRYPTION_KEY = "encryption_key"
    OAUTH_CLIENT_SECRET = "oauth_client_secret"


class Severity(str, Enum):
    """Severity levels for detected secrets"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecretFinding:
    """A detected secret finding"""

    secret_type: SecretType
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    start_col: int
    end_col: int
    rule_id: str
    message: str
    false_positive: bool = False


# Rule definitions
SECRET_RULES = [
    # AWS Keys
    {
        "id": "AWS_ACCESS_KEY",
        "type": SecretType.AWS_KEY,
        "severity": Severity.CRITICAL,
        "pattern": r"(?:^|[^A-Za-z0-9/+=])(A[BGR]IA[IS][A-Z0-9]{16})(?:[^A-Za-z0-9/+=]|$)",
        "message": "AWS Access Key detected",
    },
    {
        "id": "AWS_SECRET_KEY",
        "type": SecretType.AWS_KEY,
        "severity": Severity.CRITICAL,
        "pattern": r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        "message": "AWS Secret Key detected",
    },
    # GitHub
    {
        "id": "GITHUB_TOKEN",
        "type": SecretType.GITHUB_TOKEN,
        "severity": Severity.HIGH,
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "message": "GitHub Personal Access Token detected",
    },
    {
        "id": "GITHUB_OAUTH",
        "type": SecretType.TOKEN,
        "severity": Severity.HIGH,
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "message": "GitHub OAuth Token detected",
    },
    # Stripe
    {
        "id": "STRIPE_KEY",
        "type": SecretType.STRIPE_KEY,
        "severity": Severity.CRITICAL,
        "pattern": r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}",
        "message": "Stripe API Key detected",
    },
    # Google API
    {
        "id": "GOOGLE_API_KEY",
        "type": SecretType.API_KEY,
        "severity": Severity.HIGH,
        "pattern": r"AIza[A-Za-z0-9_\-]{35}",
        "message": "Google API Key detected",
    },
    # Private Keys
    {
        "id": "RSA_PRIVATE_KEY",
        "type": SecretType.PRIVATE_KEY,
        "severity": Severity.CRITICAL,
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "message": "Private key file detected",
    },
    # JWT
    {
        "id": "JWT_TOKEN",
        "type": SecretType.TOKEN,
        "severity": Severity.HIGH,
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "message": "JWT token detected",
    },
    # Generic patterns (more prone to false positives)
    {
        "id": "GENERIC_API_KEY",
        "type": SecretType.API_KEY,
        "severity": Severity.MEDIUM,
        "pattern": r"""(?:api[_-]?key|apikey)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?""",
        "message": "Potential API key assignment",
    },
    {
        "id": "GENERIC_SECRET",
        "type": SecretType.CREDENTIAL,
        "severity": Severity.MEDIUM,
        "pattern": r"""(?:secret|password|passwd|pwd)\s*[=:]\s*['"]?([^\s'\"]{8,})['"]?""",
        "message": "Potential secret/password assignment",
        "skip_in_strings": True,
    },
    {
        "id": "GENERIC_TOKEN",
        "type": SecretType.TOKEN,
        "severity": Severity.MEDIUM,
        "pattern": r"""(?:auth[_-]?token|access[_-]?token)\s*[=:]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?""",
        "message": "Potential authentication token",
    },
    # Database URLs
    {
        "id": "DATABASE_URL",
        "type": SecretType.DATABASE_URL,
        "severity": Severity.HIGH,
        "pattern": r"(?:mysql|postgresql|postgres|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+",
        "message": "Database connection string with credentials",
    },
    # Slack
    {
        "id": "SLACK_TOKEN",
        "type": SecretType.TOKEN,
        "severity": Severity.HIGH,
        "pattern": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "message": "Slack token detected",
    },
    # Twilio
    {
        "id": "TWILIO_KEY",
        "type": SecretType.API_KEY,
        "severity": Severity.HIGH,
        "pattern": r"SK[0-9a-fA-F]{32}",
        "message": "Twilio API Key detected",
    },
    # SendGrid
    {
        "id": "SENDGRID_KEY",
        "type": SecretType.API_KEY,
        "severity": Severity.HIGH,
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "message": "SendGrid API Key detected",
    },
    # Private IP (lower severity, informational)
    {
        "id": "HARDCODED_PRIVATE_IP",
        "type": SecretType.CREDENTIAL,
        "severity": Severity.LOW,
        "pattern": r"""(?:host|server|ip)\s*[=:]\s*['"]?(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})['"]?""",
        "message": "Hardcoded private IP address",
    },
]

# Patterns that indicate comments or strings (to reduce false positives)
COMMENT_PATTERNS = [
    r"^\s*#",  # Python/Ruby comments
    r"^\s*//",  # C-style comments
    r"^\s*\*",  # Block comment continuation
    r"^\s*/\*",  # Block comment start
    r"^\s*\*",  # Block comment continuation
]

STRING_PATTERNS = [
    r"^\s*(?:assert|expect|test|it|describe)\s*\(",  # Test files
    r"console\.log\(",  # Console logs
    r"print\(",  # Print statements
    r"example",  # Example values
    r"dummy",  # Dummy values
    r"placeholder",  # Placeholders
    r"xxx",  # Common placeholder
    r"changeme",  # Common placeholder
]


class SecretsDetector:
    """
    Detect secrets and sensitive information in code.

    Usage:
        detector = SecretsDetector()
        findings = detector.scan_file("config.py")
        findings = detector.scan_text(code_content, "myfile.py")
    """

    def __init__(
        self,
        rules: Optional[List[dict]] = None,
        severity_threshold: Severity = Severity.LOW,
        ignore_rules: Optional[Set[str]] = None,
        custom_rules: Optional[List[dict]] = None,
    ):
        self.rules = rules or SECRET_RULES
        self.severity_threshold = severity_threshold
        self.ignore_rules = ignore_rules or set()

        # Add custom rules
        if custom_rules:
            self.rules = self.rules + custom_rules

        # Compile patterns
        self._compiled_rules = []
        for rule in self.rules:
            if rule["id"] in self.ignore_rules:
                continue
            try:
                pattern = re.compile(rule["pattern"], re.IGNORECASE)
                self._compiled_rules.append(
                    {
                        **rule,
                        "compiled": pattern,
                    }
                )
            except re.error as e:
                print(f"Warning: Invalid pattern for rule {rule['id']}: {e}")

    def scan_file(self, file_path: str) -> List[SecretFinding]:
        """Scan a file for secrets"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, file_path)
        except Exception as e:
            return []

    def scan_text(self, text: str, file_path: str = "<text>") -> List[SecretFinding]:
        """Scan text content for secrets"""
        findings = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Skip comments and obvious false positives
            if self._is_likely_false_positive(line):
                continue

            for rule in self._compiled_rules:
                for match in rule["compiled"].finditer(line):
                    finding = SecretFinding(
                        secret_type=rule["type"],
                        severity=rule["severity"],
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip(),
                        matched_text=match.group(0),
                        start_col=match.start(),
                        end_col=match.end(),
                        rule_id=rule["id"],
                        message=rule["message"],
                    )

                    # Check for additional false positive indicators
                    if self._check_false_positive(finding):
                        finding.false_positive = True

                    findings.append(finding)

        return findings

    def scan_lines(
        self, lines: List[str], file_path: str = "<text>"
    ) -> List[SecretFinding]:
        """Scan a list of lines for secrets"""
        return self.scan_text("\n".join(lines), file_path)

    def _is_likely_false_positive(self, line: str) -> bool:
        """Check if line is likely a false positive"""
        # Check for comments
        for pattern in COMMENT_PATTERNS:
            if re.match(pattern, line):
                return True

        # Check for test/example patterns
        line_lower = line.lower()
        for pattern in STRING_PATTERNS:
            if pattern.lower() in line_lower:
                return True

        return False

    def _check_false_positive(self, finding: SecretFinding) -> bool:
        """Additional false positive checks"""
        line_lower = finding.line_content.lower()

        # Test files
        if any(
            x in finding.file_path.lower()
            for x in ["test", "spec", "mock", "fake", "example"]
        ):
            return True

        # Documentation
        if any(
            x in finding.file_path.lower()
            for x in [".md", ".rst", ".txt", "doc", "readme"]
        ):
            return True

        # Obvious placeholders
        placeholders = [
            "xxx",
            "changeme",
            "your_key",
            "your_api_key",
            "replace_me",
            "yourtokenhere",
            "insert_here",
            "placeholder",
            "example",
        ]
        if any(p in line_lower for p in placeholders):
            return True

        # Empty or very short values
        if finding.secret_type in [SecretType.PASSWORD, SecretType.API_KEY]:
            match = re.search(r"""['"]([^'"]+)['"]""", finding.matched_text)
            if match:
                value = match.group(1)
                if len(value) < 8 or value.lower() in ["true", "false", "null", "none"]:
                    return True

        return False

    def get_findings_summary(self, findings: List[SecretFinding]) -> Dict:
        """Get a summary of findings"""
        summary = {
            "total": len(findings),
            "real_findings": len([f for f in findings if not f.false_positive]),
            "false_positives": len([f for f in findings if f.false_positive]),
            "by_severity": {},
            "by_type": {},
            "by_file": {},
        }

        for finding in findings:
            if finding.false_positive:
                continue

            # By severity
            severity = finding.severity.value
            summary["by_severity"][severity] = (
                summary["by_severity"].get(severity, 0) + 1
            )

            # By type
            secret_type = finding.secret_type.value
            summary["by_type"][secret_type] = summary["by_type"].get(secret_type, 0) + 1

            # By file
            file_path = finding.file_path
            summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1

        return summary

    def get_real_findings(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Filter out false positives"""
        return [f for f in findings if not f.false_positive]

    def filter_by_severity(
        self, findings: List[SecretFinding], min_severity: Severity
    ) -> List[SecretFinding]:
        """Filter findings by minimum severity"""
        severity_order = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        min_idx = severity_order.index(min_severity)

        return [f for f in findings if severity_order.index(f.severity) >= min_idx]
