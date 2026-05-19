"""Dependency vulnerability scanner: npm audit + pip-audit + CVE lookup."""
from pathlib import Path

from zeroclaw.models import Finding


def scan_python_deps(target_dir: Path) -> list[Finding]:
    """Run pip-audit on requirements.txt / pyproject.toml."""
    raise NotImplementedError("Phase 2 task: Sania implements this")


def scan_node_deps(target_dir: Path) -> list[Finding]:
    """Run npm audit on package.json."""
    raise NotImplementedError("Phase 2 task: Sania implements this")


def scan_dependencies(target_dir: Path) -> list[Finding]:
    """Auto-detect project type and scan dependencies."""
    raise NotImplementedError("Phase 2 task: Sania implements this")
