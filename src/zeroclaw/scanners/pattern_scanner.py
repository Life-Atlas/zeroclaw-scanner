"""Code pattern scanner: SQLi, XSS, unsafe patterns."""
import re
from pathlib import Path

from zeroclaw.models import Category, Finding, Severity

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

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}


def _is_safe(line: str) -> bool:
    """Return True if the line matches a known safe pattern."""
    return any(re.search(p, line) for p in SAFE_PATTERNS)


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    findings = []

    for file_path in target_dir.rglob("*"):
        if file_path.suffix not in EXTENSIONS:
            continue
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue

        for line_number, line in enumerate(lines, start=1):
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

    return findings