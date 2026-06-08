"""Code pattern scanner: SQLi, XSS, unsafe patterns."""
import logging
import os
import re
import stat
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
        r"subprocess\.(call|run|Popen)\s*\([\s\S]*?shell\s*=\s*True",
        "Command injection: shell=True",
        Severity.HIGH,
    ),
]

EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".vue", ".svelte",
}

MAX_LINE_LENGTH = 2048
WINDOW_SIZE = 3


def _has_dangerous_pattern(text: str) -> tuple[str, Severity] | None:
    """Check text against dangerous patterns."""
    for pattern, message, severity in DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            return message, severity
    return None


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    findings: list[Finding] = []
    resolved_target = target_dir.resolve()

    for file_path in target_dir.rglob("*"):
        # skip symlinks
        if file_path.is_symlink():
            logger.warning("Skipping symbolic link: %s", file_path)
            continue

        # only process regular files
        if not file_path.is_file():
            continue

        if file_path.suffix not in EXTENSIONS:
            continue

        fd = None
        try:
            # Boundary check using Path.resolve() before open
            resolved_file = file_path.resolve()
            if not resolved_file.is_relative_to(resolved_target):
                logger.warning("Skipping file outside target directory: %s", file_path)
                continue

            # Open file descriptor securely (O_NOFOLLOW prevents following trailing symlinks)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(resolved_file, flags)

            # Inspect metadata securely on the opened descriptor (TOCTOU fix)
            fstat_info = os.fstat(fd)
            if not stat.S_ISREG(fstat_info.st_mode):
                logger.warning("Skipping non-regular file: %s", file_path)
                os.close(fd)
                fd = None
                continue

            # Limit file size to 5MB
            if fstat_info.st_size > 5 * 1024 * 1024:
                os.close(fd)
                fd = None
                continue

            # Read securely using the file descriptor
            with os.fdopen(fd, "r", encoding="utf-8", errors="ignore") as f:
                fd = None  # os.fdopen takes ownership of the descriptor
                window: deque[str] = deque(maxlen=WINDOW_SIZE)

                for line_number, line in enumerate(f, start=1):
                    if len(line) > MAX_LINE_LENGTH:
                        line = line[:MAX_LINE_LENGTH]

                    window.append(line)
                    context = "".join(window)

                    res = _has_dangerous_pattern(context)
                    if res is None:
                        continue

                    message, severity = res

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
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.warning("Could not read file %s: %s", file_path, e)
        except Exception as e:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            logger.error("Unexpected error processing file %s: %s", file_path, e)

    return findings
