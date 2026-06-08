"""Code pattern scanner: SQLi, XSS, unsafe patterns."""
import logging
import re
from pathlib import Path

from zeroclaw.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

DANGEROUS_PATTERNS = [
    (
        r"\.execute\s*\(\s*f['\"]",
        "Possible SQL injection (f-string in execute)",
        Severity.HIGH,
    ),
    (
        r"\.execute\s*\(\s*['\"].*\+",
        "Possible SQL injection (string concat in execute)",
        Severity.HIGH,
    ),
    (
        r"dangerouslySetInnerHTML",
        "XSS risk: dangerouslySetInnerHTML",
        Severity.HIGH,
    ),
    (
        r"\.innerHTML\s*=(?!\s*\"\")",
        "XSS risk: innerHTML assignment",
        Severity.HIGH,
    ),
    (
        r"document\.write\s*\(",
        "XSS risk: document.write",
        Severity.MEDIUM,
    ),
    (
        r"subprocess\.(call|run|Popen).*shell\s*=\s*True",
        "Command injection: shell=True",
        Severity.HIGH,
    ),
]

SAFE_PATTERNS = [
    r"\.execute\s*\(\s*['\"][^'\"]*['\"],\s*\(",  # parameterized query
    r"\.textContent\s*=",                          # safe DOM assignment
    r"\.innerText\s*=",                            # safe DOM assignment
]

EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".vue", ".svelte",
}


def _is_safe(line: str) -> bool:
    """Return True if the line matches a known safe pattern."""
    return any(re.search(p, line) for p in SAFE_PATTERNS)


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()

    for file_path in target_dir.rglob("*"):
        # Fix 1: skip symbolic links to prevent reading files outside workspace
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        if file_path.suffix not in EXTENSIONS:
            continue

        try:
            # Fix 2: stat() moved inside try-except to handle crashes gracefully
            if file_path.stat().st_size > 5 * 1024 * 1024:  # skip files larger than 5MB
                continue

            # Extra safety: verify file is inside target directory
            if not file_path.resolve().is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    if _is_safe(line):
                        continue
                    for pattern, message, severity in DANGEROUS_PATTERNS:
                        if re.search(pattern, line):
                            findings.append(
                                Finding(
                                    id=f"PATTERN-{len(findings)+1:04d}",
                                    severity=severity,
                                    category=Category.CODE_PATTERN,
                                    title=message,
                                    description=f"{message} at line {line_number}: {line.strip()}",
                                    file_path=str(file_path),
                                    line_number=line_number,
                                    remediation="Use parameterized queries or safe DOM APIs.",
                                )
                            )
                            break  # one finding per line
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Could not read file %s: %s", file_path, e)

    return findings
