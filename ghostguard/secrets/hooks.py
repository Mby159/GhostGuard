"""
Git Hooks - Pre-commit hook for secrets detection
"""

import os
import stat
import subprocess
from pathlib import Path
from typing import Optional

from ghostguard.secrets.detector import SecretsDetector, Severity
from ghostguard.secrets.scanner import FileScanner


# Pre-commit hook template
PRE_COMMIT_HOOK = """#!/bin/sh
#
# GhostGuard pre-commit hook
# Prevents committing secrets and sensitive information
#

# Check if ghostguard is installed
if ! command -v ghostguard &> /dev/null; then
    echo "GhostGuard is not installed. Install with: pip install ghostguard"
    exit 1
fi

# Run secrets check on staged files
ghostguard secrets check-staged --format text --fail-on high

# Capture exit code
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "==========================================="
    echo "❌ Commit blocked by GhostGuard"
    echo "==========================================="
    echo ""
    echo "Your commit contains potential secrets."
    echo "Review the findings above and:"
    echo "  1. Remove the secrets"
    echo "  2. Use environment variables instead"
    echo "  3. Add to .ghostguard-ignore if false positive"
    echo ""
    echo "To bypass this check (not recommended):"
    echo "  git commit --no-verify"
    echo ""
    exit 1
fi

exit 0
"""


class GitHooks:
    """
    Manage git hooks for secrets detection.

    Usage:
        hooks = GitHooks()
        hooks.install()  # Install pre-commit hook
        hooks.uninstall()  # Remove hook
        hooks.is_installed()  # Check if installed
    """

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).resolve()
        self.git_dir = self.repo_path / ".git"
        self.hooks_dir = self.git_dir / "hooks"
        self.hook_file = self.hooks_dir / "pre-commit"

    def install(self) -> dict:
        """Install the pre-commit hook"""
        # Check if it's a git repo
        if not self.git_dir.exists():
            return {"success": False, "error": "Not a git repository"}

        # Create hooks directory if needed
        self.hooks_dir.mkdir(parents=True, exist_ok=True)

        # Backup existing hook if present
        if self.hook_file.exists():
            backup = self.hook_file.with_suffix(".pre-ghostguard")
            self.hook_file.rename(backup)

        # Write new hook
        self.hook_file.write_text(PRE_COMMIT_HOOK)

        # Make executable
        self.hook_file.chmod(
            self.hook_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )

        return {"success": True, "message": "Pre-commit hook installed"}

    def uninstall(self) -> dict:
        """Remove the pre-commit hook"""
        if not self.hook_file.exists():
            return {"success": False, "error": "Hook not installed"}

        # Check if it's our hook
        content = self.hook_file.read_text()
        if "GhostGuard" not in content:
            return {"success": False, "error": "Hook is not a GhostGuard hook"}

        # Remove hook
        self.hook_file.unlink()

        # Restore backup if exists
        backup = self.hook_file.with_suffix(".pre-ghostguard")
        if backup.exists():
            backup.rename(self.hook_file)

        return {"success": True, "message": "Pre-commit hook removed"}

    def is_installed(self) -> bool:
        """Check if GhostGuard hook is installed"""
        if not self.hook_file.exists():
            return False

        try:
            content = self.hook_file.read_text()
            return "GhostGuard" in content
        except Exception:
            return False

    def check_staged_files(self, min_severity: Severity = Severity.HIGH) -> dict:
        """Manually check staged files (same as the hook would)"""
        scanner = FileScanner()
        findings = scanner.scan_staged_files()

        # Filter by severity
        detector = SecretsDetector()
        real_findings = detector.get_real_findings(findings)
        critical_findings = detector.filter_by_severity(real_findings, min_severity)

        return {
            "has_findings": len(critical_findings) > 0,
            "findings": critical_findings,
            "count": len(critical_findings),
        }
