from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CODE_PATTERN = "code_pattern"
    AUTH = "auth"
    INJECTION = "injection"
    CONFIG = "config"


class Finding(BaseModel):
    id: str
    severity: Severity
    category: Category
    title: str
    description: str
    file_path: str
    line_number: int | None = None
    remediation: str
    stream: str = ""
    false_positive: bool = False


class ScanResult(BaseModel):
    stream: str
    repo_url: str
    scanned_at: datetime
    findings: list[Finding]
    stats: dict[str, int] = {}


class StreamScore(BaseModel):
    stream: str
    score: float  # 0-10
    findings_by_severity: dict[str, int]
    top_issues: list[str]
