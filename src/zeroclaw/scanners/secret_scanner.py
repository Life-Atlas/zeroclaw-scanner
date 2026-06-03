import re
import tempfile
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


def validate_path(path: Path, base_dir: Path) -> Path:
    """Validate that path is resolved and contained within safe workspace or temp bounds."""
    resolved_path = path.resolve()
    resolved_base = base_dir.resolve()
    temp_dir = Path(tempfile.gettempdir()).resolve()

    is_under_base = False
    try:
        resolved_path.relative_to(resolved_base)
        is_under_base = True
    except ValueError:
        pass

    is_under_temp = False
    try:
        resolved_path.relative_to(temp_dir)
        is_under_temp = True
    except ValueError:
        pass

    if not (is_under_base or is_under_temp):
        raise ValueError(f"Path traversal detected: {path} is outside the allowed directories.")
    return resolved_path


def scan_secrets(target_dir: Path) -> list[Finding]:
    """Scan directory for hardcoded secrets. Returns list of findings."""
    # Resolve and validate target_dir path limits (SEC-PATH-TRAVERSAL)
    try:
        target_abs = validate_path(target_dir, Path.cwd())
    except ValueError as e:
        raise ValueError(str(e))

    findings: list[Finding] = []

    def is_ignored(path: Path) -> bool:
        try:
            rel_path = path.relative_to(target_abs)
        except ValueError:
            return False

        for part in rel_path.parts:
            if part in IGNORE_PATHS:
                return True
        if path.suffix == ".md":
            return True
        return False

    for path in target_abs.rglob("*"):
        if not path.is_file():
            continue

        if is_ignored(path):
            continue

        # Prevent symlink directory escapes (SEC-PATH-TRAVERSAL)
        try:
            resolved_file = path.resolve()
            resolved_file.relative_to(target_abs)
        except ValueError:
            continue

        # Check if the file is a committed .env file
        if path.name == ".env":
            findings.append(Finding(
                id=f"SEC-ENV-{len(findings) + 1:03d}",
                severity=Severity.CRITICAL,
                category=Category.SECRET,
                title="Committed Environment File",
                description="Committed .env file containing sensitive database credentials or environment variables.",
                file_path=str(path.relative_to(target_abs)),
                line_number=1,
                remediation="Remove .env from the repository, add it to .gitignore, and rotate all exposed secrets."
            ))
            continue

        # Avoid Memory Exhaustion / OOM (SEC-DOS-OOM & ZC-SEC-001)
        # Skip files exceeding 5MB threshold
        try:
            if path.stat().st_size > 5 * 1024 * 1024:
                continue
        except Exception:
            continue

        # Read files line-by-line using buffered streaming to prevent OOM
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, start=1):
                    # Strip comments to prevent naive exclusion bypasses (ZC-SEC-002)
                    clean_line = line.split("#")[0].split("//")[0].split("--")[0].strip()
                    
                    is_env_lookup = any(keyword in clean_line for keyword in ["environ", "getenv", "os.env", "process.env", "env.get"])

                    for pattern, name in SECRET_PATTERNS:
                        if re.search(pattern, line):
                            # Skip if it is a legitimate env lookup, unless it is a high-confidence token
                            if is_env_lookup and name not in [
                                "OpenAI API key",
                                "Anthropic API key",
                                "GitHub token",
                                "Slack bot token",
                                "Bearer token",
                            ]:
                                continue

                            findings.append(Finding(
                                id=f"SEC-KEY-{len(findings) + 1:03d}",
                                severity=Severity.HIGH,
                                category=Category.SECRET,
                                title=f"Hardcoded {name}",
                                description=f"A hardcoded {name.lower()} was detected in the source code.",
                                file_path=str(path.relative_to(target_abs)),
                                line_number=idx,
                                remediation="Remove the hardcoded secret and replace it with environment variable injection or a secret vault lookup."
                            ))
                            break
        except Exception:
            continue

    return findings

