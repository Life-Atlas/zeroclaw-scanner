"""Code pattern scanner: SQLi, XSS, unsafe patterns."""
import logging
import os
import re
from collections import deque
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
        r"\.execute\s*\(\s*['\"][^'\"]*\+",
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
        r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True",
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

MAX_LINE_LENGTH = 2048
WINDOW_SIZE = 3


def _is_safe(line: str) -> bool:
    """Return True if the line matches a known safe pattern."""
    return any(re.search(p, line) for p in SAFE_PATTERNS)


def _has_dangerous_pattern(text: str) -> tuple[bool, str, Severity] | tuple[bool, None, None]:
    """Check text against dangerous patterns."""
    for pattern, message, severity in DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            return True, message, severity
    return False, None, None


def _open_safe(file_path: Path, resolved_target: Path):
    """Open file safely, preventing symlink attacks. Returns file object or None."""
    if hasattr(os, "O_NOFOLLOW"):
        try:
            fd = os.open(str(file_path), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            logger.warning("Skipping file due to O_NOFOLLOW rejection: %s", file_path)
            return None
        # Fix TOCTOU: post-open verify real path is still inside target
        try:
            real_path = Path(f"/proc/self/fd/{fd}").resolve()
        except OSError:
            real_path = file_path.resolve()
        if not real_path.is_relative_to(resolved_target):
            os.close(fd)
            logger.warning("Skipping file outside target after open: %s", file_path)
            return None
        return os.fdopen(fd, "r", encoding="utf-8", errors="ignore")
    else:
        # Windows fallback
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            return None
        return open(file_path, "r", encoding="utf-8", errors="ignore")


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()

    for file_path in target_dir.rglob("*"):
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        if not file_path.is_file():
            continue

        if file_path.suffix not in EXTENSIONS:
            continue

        try:
            if not file_path.resolve().is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            if file_path.stat().st_size > 5 * 1024 * 1024:
                continue

            f = _open_safe(file_path, resolved_target)
            if f is None:
                continue

            with f:
                window: deque[str] = deque(maxlen=WINDOW_SIZE)
                line_number = 0

                for line in f:
                    line_number += 1

                    # Fix: clear window on long lines, don't append
                    if len(line) > MAX_LINE_LENGTH:
                        window.clear()
                        continue

                    # Fix ARCH-BYPASS-001: check safe pattern on current line only
                    # not across entire window
                    if _is_safe(line):
                        window.append(line)
                        continue

                    window.append(line)
                    context = "".join(window)

                    found, message, severity = _has_dangerous_pattern(context)
                    if not found:
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
