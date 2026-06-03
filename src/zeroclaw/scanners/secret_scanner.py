import re
from pathlib import Path

from zeroclaw.models import Finding, Severity, Category

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "API key"),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Password/Secret"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API key"),
    (r"sk-ant-[A-Za-z0-9\-]{20,}", "Anthropic API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub token"),
    (r"xoxb-[A-Za-z0-9\-]+", "Slack bot token"),
    (r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}", "Bearer token"),
]

IGNORE_PATHS = {".git", "node_modules", "__pycache__", ".env.example", "*.md"}


def scan_secrets(target_dir: Path) -> list[Finding]:
    """Scan directory for hardcoded secrets. Returns list of findings."""
    findings: list[Finding] = []

    def is_ignored(path: Path) -> bool:
        try:
            rel_path = path.relative_to(target_dir)
        except ValueError:
            return False

        for part in rel_path.parts:
            if part in IGNORE_PATHS:
                return True
        if path.suffix == ".md":
            return True
        return False

    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue

        if is_ignored(path):
            continue

        # Check if the file is a committed .env file
        if path.name == ".env":
            findings.append(Finding(
                id=f"SEC-ENV-{len(findings) + 1:03d}",
                severity=Severity.CRITICAL,
                category=Category.SECRET,
                title="Committed Environment File",
                description="Committed .env file containing sensitive database credentials or environment variables.",
                file_path=str(path.relative_to(target_dir)),
                line_number=1,
                remediation="Remove .env from the repository, add it to .gitignore, and rotate all exposed secrets."
            ))
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            # Avoid false positives on environment variable lookups
            if any(keyword in line for keyword in ["environ", "getenv", "os.env", "process.env", "env.get"]):
                continue

            for pattern, name in SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        id=f"SEC-KEY-{len(findings) + 1:03d}",
                        severity=Severity.HIGH,
                        category=Category.SECRET,
                        title=f"Hardcoded {name}",
                        description=f"A hardcoded {name.lower()} was detected in the source code.",
                        file_path=str(path.relative_to(target_dir)),
                        line_number=idx,
                        remediation="Remove the hardcoded secret and replace it with environment variable injection or a secret vault lookup."
                    ))
                    break

    return findings

