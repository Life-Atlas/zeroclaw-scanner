"""Secret scanner: detect hardcoded API keys, tokens, passwords."""
from pathlib import Path

from zeroclaw.models import Finding

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
    raise NotImplementedError("Phase 2 task: Kailash implements this")
