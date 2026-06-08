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
        r"\.execute\s*\(\s*['\"][^'\n]*\+",
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
        r"subprocess\.(call|run|Popen)\s*\([^'\n]*shell\s*=\s*True",
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

MAX_LINE_LENGTH = 2048  # Fix: ReDoS protection


def _is_safe(line: str) -> bool:
    """Return True if the line matches a known safe pattern."""
    return any(re.search(p, line) for p in SAFE_PATTERNS)


def _has_dangerous_pattern(line: str) -> tuple[bool, str, Severity] | tuple[bool, None, None]:
    """Check line against dangerous patterns only."""
    for pattern, message, severity in DANGEROUS_PATTERNS:
        if re.search(pattern, line):
            return True, message, severity
    return False, None, None


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()

    for file_path in target_dir.rglob("*"):
        # Fix 1: skip symlinks
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        # Fix 2: only process regular files (blocks named pipes/FIFOs)
        if not file_path.is_file():
            continue

        if file_path.suffix not in EXTENSIONS:
            continue

        try:
            # Fix 3: boundary check BEFORE stat() call
            if not file_path.resolve().is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            if file_path.stat().st_size > 5 * 1024 * 1024:  # skip files larger than 5MB
                continue

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    # Fix 4: skip extremely long lines to prevent ReDoS
                    if len(line) > MAX_LINE_LENGTH:
                        continue

                    # Fix 5: only skip line if safe pattern matches BUT no dangerous pattern exists
                    found, message, severity = _has_dangerous_pattern(line)
                    if not found:
                        continue
                    if _is_safe(line) and not found:
                        continue

                    if found and message and severity:
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

        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Could not read file %s: %s", file_path, e)

    return findings
