"""
GhostGuard Secrets - Code secrets detection and prevention

Detect and prevent accidental commits of sensitive information like
API keys, passwords, tokens, and other secrets in code.
"""

from ghostguard.secrets.detector import SecretsDetector
from ghostguard.secrets.scanner import FileScanner, RepoScanner
from ghostguard.secrets.hooks import GitHooks

__all__ = [
    "SecretsDetector",
    "FileScanner",
    "RepoScanner",
    "GitHooks",
]
