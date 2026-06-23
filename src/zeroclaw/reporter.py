"""Report generation: terminal, JSON, PDF."""
from __future__ import annotations
from datetime import datetime
import json
from collections import defaultdict

from zeroclaw.models import ScanResult, StreamScore, Finding, Severity, Category


def calculate_stream_score(result: ScanResult) -> StreamScore:
    """Calculate 0-10 security score for a stream.

    Formula:
    Base score is 10.0.
    For each finding:
      - Critical: -2.5
      - High: -1.5
      - Medium: -0.75
      - Low: -0.25
      - Info: -0.0
    The score is bounded to [0.0, 10.0] and rounded to 1 decimal place.
    """
    severity_deductions = {
        Severity.CRITICAL: 2.5,
        Severity.HIGH: 1.5,
        Severity.MEDIUM: 0.75,
        Severity.LOW: 0.25,
        Severity.INFO: 0.0,
    }

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    # Count findings by severity, ignoring false positives
    for finding in result.findings:
        if finding.false_positive:
            continue
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    # Calculate score
    deductions = sum(counts[sev] * severity_deductions[Severity(sev)] for sev in counts)
    score_val = max(0.0, 10.0 - deductions)
    score_val = round(score_val, 1)

    # Prioritize and identify top issues
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    real_findings = [f for f in result.findings if not f.false_positive]
    real_findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.title))

    top_issues = []
    seen_titles = set()
    for f in real_findings:
        if f.title not in seen_titles:
            seen_titles.add(f.title)
            top_issues.append(f"{f.severity.value.upper()}: {f.title}")
            if len(top_issues) == 5:
                break

    return StreamScore(
        stream=result.stream,
        score=score_val,
        findings_by_severity=counts,
        top_issues=top_issues,
    )


def generate_json_report(result: ScanResult) -> dict:
    """JSON report for dashboard consumption."""
    scorecard = calculate_stream_score(result)
    
    # Calculate stats
    stats = {}
    for f in result.findings:
        if f.false_positive:
            continue
        stats[f.category.value] = stats.get(f.category.value, 0) + 1
        stats[f.severity.value] = stats.get(f.severity.value, 0) + 1
    
    result.stats = stats

    if hasattr(result, "model_dump_json"):
        serialized = json.loads(result.model_dump_json())
    else:
        serialized = json.loads(result.json())
        
    scorecard_dict = scorecard.model_dump() if hasattr(scorecard, "model_dump") else scorecard.dict()
    serialized["scorecard"] = scorecard_dict
    return serialized


REMEDIATIONS_GUIDES = {
    Category.SECRET: {
        "guideline": "API keys, passwords, and sensitive tokens should never be hardcoded in source files or committed to Git. Instead, load them from environment variables or a secret manager.",
        "bad": 'API_KEY = "sk-ant-api03-exampleKeyValHere1234567890"',
        "good": 'import os\nAPI_KEY = os.environ.get("API_KEY")'
    },
    Category.DEPENDENCY: {
        "guideline": "Vulnerable dependencies expose applications to known exploits. Floating/unpinned dependencies risk supply chain compromise. Pin versions and use cryptographic hashes.",
        "bad": 'requests>=2.25.0',
        "good": 'requests==2.31.0 --hash=sha256:7486c32d... # or use lockfiles'
    },
    Category.CODE_PATTERN: {
        "guideline": "Avoid dynamic SQL query building and direct innerHTML assignments. Use parameterized queries or secure DOM APIs.",
        "bad": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n# Or in frontend:\nelement.innerHTML = user_input',
        "good": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n# Or in frontend:\nelement.textContent = user_input'
    },
    Category.AUTH: {
        "guideline": "Endpoints that handle user data must enforce access control via authentication dependencies or Supabase row-level security (RLS) policies.",
        "bad": '@app.get("/data")\ndef get_data(): ...',
        "good": '@app.get("/data")\ndef get_data(user: User = Depends(get_current_user)): ...\n# SQL RLS:\nALTER TABLE profiles ENABLE ROW LEVEL SECURITY;'
    }
}


def generate_terminal_report(result: ScanResult) -> str:
    """Rich terminal output of scan results."""
    scorecard = calculate_stream_score(result)
    
    # Calculate stats
    stats = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in result.findings:
        if f.false_positive:
            continue
        stats[f.severity.value] = stats.get(f.severity.value, 0) + 1

    lines = []
    lines.append("=" * 80)
    lines.append(f" ZEROCLAW SECURITY REPORT — {result.stream.upper()}")
    lines.append(f" Scanned At: {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    lines.append("")
    
    # Score details
    lines.append(f" GLASS Security Score: {scorecard.score}/10.0")
    lines.append(f" Findings by Severity: CRITICAL: {stats['critical']} | HIGH: {stats['high']} | MEDIUM: {stats['medium']} | LOW: {stats['low']} | INFO: {stats['info']}")
    lines.append("")

    if not result.findings:
        lines.append(" ✅ No security findings detected! The repository is clean.")
        lines.append("-" * 80)
        return "\n".join(lines)

    # Group findings by category
    grouped: dict[Category, list[Finding]] = defaultdict(list)
    for f in result.findings:
        grouped[f.category].append(f)

    # Print Findings grouped by Category
    lines.append("DETAILED FINDINGS")
    lines.append("-" * 80)

    for cat in Category:
        cat_findings = grouped.get(cat, [])
        if not cat_findings:
            continue
        
        lines.append(f"## {cat.value.upper()} SCANNER — {len(cat_findings)} findings")
        lines.append("")
        
        for idx, f in enumerate(cat_findings, start=1):
            fp_flag = " [FALSE POSITIVE]" if f.false_positive else ""
            lines.append(f"  {idx}. [{f.severity.value.upper()}]{fp_flag} {f.title}")
            lines.append(f"     File: {f.file_path}:{f.line_number or 'N/A'}")
            lines.append(f"     ID: {f.id}")
            lines.append(f"     Description: {f.description}")
            lines.append(f"     Remediation: {f.remediation}")
            
            # Print ZeroClaw Reasoning and Fixed Code if present
            if getattr(f, "reasoning_chain", None):
                lines.append("")
                lines.append("     🧠 ZeroClaw Reasoning:")
                for chain_line in f.reasoning_chain.splitlines():
                    lines.append(f"       {chain_line}")
            if getattr(f, "fixed_code", None):
                lines.append("")
                lines.append("     🔧 ZeroClaw Fixed Code:")
                lines.append("       ┌" + "─" * 56 + "┐")
                for code_line in f.fixed_code.splitlines():
                    lines.append(f"       │ {code_line}")
                lines.append("       └" + "─" * 56 + "┘")
            lines.append("")

        # Add remediation guidance + code examples
        guide = REMEDIATIONS_GUIDES.get(cat)
        if guide:
            lines.append("  Remediation Guidance:")
            lines.append(f"     {guide['guideline']}")
            lines.append("     [BAD EXAMPLES]")
            for bad_line in guide["bad"].splitlines():
                lines.append(f"     - {bad_line}")
            lines.append("     [GOOD EXAMPLES]")
            for good_line in guide["good"].splitlines():
                lines.append(f"     + {good_line}")
            lines.append("")
        lines.append("-" * 80)

    return "\n".join(lines)

