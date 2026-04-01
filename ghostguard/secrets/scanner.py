"""
File and Repository Scanners for secrets detection
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ghostguard.secrets.detector import (
    SecretsDetector,
    SecretFinding,
    Severity,
)


# Default file extensions to scan
DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".swift",
    ".kt",
    ".scala",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".properties",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".sql",
    ".graphql",
    ".gql",
    ".tf",
    ".hcl",  # Terraform
    ".pem",
    ".key",  # Key files
}

# Files/directories to always skip
SKIP_PATTERNS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "target",
    ".lock",
    ".sum",  # Lock files often have hashes that trigger false positives
}

# Files to always scan regardless of extension
ALWAYS_SCAN = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "secrets",
}


class FileScanner:
    """
    Scan individual files for secrets.

    Usage:
        scanner = FileScanner()
        findings = scanner.scan("config.py")
        findings = scanner.scan_directory("./src")
    """

    def __init__(
        self,
        detector: Optional[SecretsDetector] = None,
        extensions: Optional[Set[str]] = None,
        skip_patterns: Optional[Set[str]] = None,
        max_file_size: int = 1024 * 1024,  # 1MB
    ):
        self.detector = detector or SecretsDetector()
        self.extensions = extensions or DEFAULT_EXTENSIONS
        self.skip_patterns = skip_patterns or SKIP_PATTERNS
        self.max_file_size = max_file_size

    def scan(self, path: str) -> List[SecretFinding]:
        """Scan a file or directory"""
        path = Path(path)

        if path.is_file():
            return self._scan_file(path)
        elif path.is_dir():
            return self._scan_directory(path)
        else:
            return []

    def _scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file"""
        # Check file extension
        if file_path.suffix.lower() not in self.extensions:
            # Check if it's in ALWAYS_SCAN
            if file_path.name not in ALWAYS_SCAN:
                return []

        # Check file size
        try:
            if file_path.stat().st_size > self.max_file_size:
                return []
        except OSError:
            return []

        # Check filename patterns
        if any(pattern in file_path.name for pattern in self.skip_patterns):
            return []

        return self.detector.scan_file(str(file_path))

    def _scan_directory(self, dir_path: Path) -> List[SecretFinding]:
        """Scan all files in a directory"""
        all_findings = []

        for file_path in self._walk_directory(dir_path):
            findings = self._scan_file(file_path)
            all_findings.extend(findings)

        return all_findings

    def _walk_directory(self, dir_path: Path):
        """Walk directory, skipping ignored patterns"""
        for item in dir_path.rglob("*"):
            # Skip directories that match ignore patterns
            if item.is_dir():
                if item.name in self.skip_patterns:
                    continue
                # Also check parent directories
                if any(parent.name in self.skip_patterns for parent in item.parents):
                    continue

            if item.is_file():
                yield item

    def scan_staged_files(self) -> List[SecretFinding]:
        """Scan git staged files"""
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return []

            files = result.stdout.strip().split("\n")
            all_findings = []

            for file in files:
                if file and os.path.exists(file):
                    findings = self.detector.scan_file(file)
                    all_findings.extend(findings)

            return all_findings

        except (subprocess.SubprocessError, FileNotFoundError):
            return []


class RepoScanner:
    """
    Scan an entire git repository for secrets.

    Usage:
        scanner = RepoScanner()
        report = scanner.scan_repo("./myproject")
        report = scanner.scan_current_repo()
    """

    def __init__(
        self,
        detector: Optional[SecretsDetector] = None,
        file_scanner: Optional[FileScanner] = None,
        include_history: bool = False,
    ):
        self.detector = detector or SecretsDetector()
        self.file_scanner = file_scanner or FileScanner(self.detector)
        self.include_history = include_history

    def scan_current_repo(self) -> Dict:
        """Scan the current git repository"""
        return self.scan_repo(".")

    def scan_repo(self, repo_path: str) -> Dict:
        """Scan a git repository"""
        repo_path = Path(repo_path).resolve()

        report = {
            "repo_path": str(repo_path),
            "files_scanned": 0,
            "findings": [],
            "summary": {},
        }

        # Scan current files
        findings = self.file_scanner.scan(str(repo_path))
        report["findings"].extend(findings)

        # Scan git history if enabled
        if self.include_history:
            history_findings = self._scan_git_history(repo_path)
            report["findings"].extend(history_findings)

        # Generate summary
        report["files_scanned"] = len(set(f.file_path for f in report["findings"]))
        report["summary"] = self.detector.get_findings_summary(report["findings"])

        return report

    def _scan_git_history(self, repo_path: Path) -> List[SecretFinding]:
        """Scan git commit history for secrets"""
        findings = []

        try:
            # Get list of all commits
            result = subprocess.run(
                ["git", "log", "--all", "--oneline", "--format=%H"],
                capture_output=True,
                text=True,
                cwd=repo_path,
            )

            if result.returncode != 0:
                return findings

            commits = result.stdout.strip().split("\n")[:100]  # Limit to 100 commits

            for commit in commits:
                if not commit:
                    continue

                # Get files changed in this commit
                files_result = subprocess.run(
                    ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                    capture_output=True,
                    text=True,
                    cwd=repo_path,
                )

                for file in files_result.stdout.strip().split("\n"):
                    if not file:
                        continue

                    # Get file content at this commit
                    content_result = subprocess.run(
                        ["git", "show", f"{commit}:{file}"],
                        capture_output=True,
                        text=True,
                        cwd=repo_path,
                    )

                    if content_result.returncode == 0:
                        file_findings = self.detector.scan_text(
                            content_result.stdout, f"{file} (commit {commit[:8]})"
                        )
                        findings.extend(file_findings)

        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return findings

    def generate_report(
        self, findings: List[SecretFinding], format: str = "text"
    ) -> str:
        """Generate a report from findings"""
        if format == "json":
            import json

            return json.dumps(
                [
                    {
                        "type": f.secret_type.value,
                        "severity": f.severity.value,
                        "file": f.file_path,
                        "line": f.line_number,
                        "message": f.message,
                        "false_positive": f.false_positive,
                    }
                    for f in findings
                ],
                indent=2,
            )

        # Text format
        lines = []
        real_findings = self.detector.get_real_findings(findings)

        if not real_findings:
            return "No secrets detected."

        lines.append(f"Found {len(real_findings)} potential secret(s):\n")

        for f in real_findings:
            severity_icon = {
                Severity.LOW: "ℹ️",
                Severity.MEDIUM: "⚠️",
                Severity.HIGH: "🔶",
                Severity.CRITICAL: "🚨",
            }.get(f.severity, "❓")

            lines.append(
                f"{severity_icon} [{f.severity.value.upper()}] {f.file_path}:{f.line_number}"
            )
            lines.append(f"   {f.message}")
            lines.append(f"   {f.line_content[:100]}")
            lines.append("")

        return "\n".join(lines)
