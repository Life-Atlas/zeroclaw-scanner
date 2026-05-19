"""Code pattern scanner: SQLi, XSS, unsafe patterns."""
from pathlib import Path

from zeroclaw.models import Finding

DANGEROUS_PATTERNS = [
    (r"execute\s*\(\s*f['\"]", "Possible SQL injection (f-string in execute)"),
    (r"\.format\s*\(.*\).*execute", "Possible SQL injection (format in execute)"),
    (r"dangerouslySetInnerHTML", "XSS risk: dangerouslySetInnerHTML"),
    (r"innerHTML\s*=", "XSS risk: innerHTML assignment"),
    (r"eval\s*\(", "Code injection: eval()"),
    (r"document\.write\s*\(", "XSS risk: document.write"),
    (r"subprocess\.call\s*\(.*shell\s*=\s*True", "Command injection: shell=True"),
]


def scan_patterns(target_dir: Path) -> list[Finding]:
    """Scan for dangerous code patterns."""
    raise NotImplementedError("Phase 2 task: Varshit implements this")
