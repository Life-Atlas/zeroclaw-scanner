"""Report generation: terminal, JSON, PDF."""
from __future__ import annotations

from zeroclaw.models import ScanResult, StreamScore


def generate_terminal_report(result: ScanResult) -> str:
    """Rich terminal output of scan results with ZeroClaw enrichment data."""
    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────
    lines.append("")
    lines.append("=" * 72)
    lines.append("  ZEROCLAW SECURITY SCAN REPORT")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"  Repository:  {result.repo_url}")
    if result.stream:
        lines.append(f"  Stream:      {result.stream}")
    lines.append(f"  Scanned at:  {result.scanned_at.isoformat()}")
    lines.append("")

    # ── Executive Summary ───────────────────────────────────────────────
    total = len(result.findings)
    lines.append("─" * 72)
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("─" * 72)
    lines.append("")

    if total == 0:
        lines.append("  ✅ No vulnerabilities detected.")
        lines.append("")
        lines.append("=" * 72)
        return "\n".join(lines)

    lines.append(f"  Total Findings: {total}")
    lines.append("")

    # Severity breakdown
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    for sev in severity_order:
        count = result.stats.get(sev, 0)
        if count > 0:
            icon = severity_icons.get(sev, "  ")
            lines.append(f"    {icon} {sev.upper():10s}  {count}")

    lines.append("")

    # Security posture
    critical = result.stats.get("critical", 0)
    high = result.stats.get("high", 0)
    if critical > 0:
        lines.append("  ⛔ Security Posture: CRITICAL — Immediate remediation required.")
    elif high > 0:
        lines.append("  ⚠️  Security Posture: AT RISK — High-severity issues must be addressed.")
    else:
        lines.append("  📋 Security Posture: MODERATE — Review findings before production.")

    lines.append("")

    # ── Detailed Findings ───────────────────────────────────────────────
    lines.append("─" * 72)
    lines.append("  DETAILED FINDINGS")
    lines.append("─" * 72)

    for i, finding in enumerate(result.findings, 1):
        sev = finding.severity.value.upper()
        icon = severity_icons.get(finding.severity.value, "  ")

        lines.append("")
        lines.append(f"  {icon} [{i}/{total}] {finding.id}")
        lines.append(f"  {'─' * 60}")
        lines.append(f"  Severity:    {sev}")
        lines.append(f"  Category:    {finding.category.value}")
        lines.append(f"  Title:       {finding.title}")
        lines.append(f"  File:        {finding.file_path}")
        if finding.line_number is not None:
            lines.append(f"  Line:        {finding.line_number}")
        lines.append("")
        lines.append(f"  Description:")
        for desc_line in finding.description.split("\n"):
            lines.append(f"    {desc_line}")
        lines.append("")
        lines.append(f"  Remediation:")
        for rem_line in finding.remediation.split("\n"):
            lines.append(f"    {rem_line}")

        # ── ZeroClaw Enrichment (if available) ──────────────────────────
        if finding.reasoning_chain:
            lines.append("")
            lines.append(f"  🧠 ZeroClaw Reasoning:")
            for chain_line in finding.reasoning_chain.split("\n"):
                lines.append(f"    {chain_line}")

        if finding.fixed_code:
            lines.append("")
            lines.append(f"  🔧 ZeroClaw Fixed Code:")
            lines.append(f"    ┌{'─' * 56}┐")
            for code_line in finding.fixed_code.split("\n"):
                lines.append(f"    │ {code_line}")
            lines.append(f"    └{'─' * 56}┘")

        lines.append("")

    # ── Footer ──────────────────────────────────────────────────────────
    enriched_count = sum(1 for f in result.findings if f.reasoning_chain is not None)
    lines.append("=" * 72)
    lines.append(f"  {total} findings | {enriched_count} AI-enriched | powered by ZeroClaw")
    lines.append("=" * 72)
    lines.append("")

    return "\n".join(lines)


def generate_json_report(result: ScanResult) -> dict:
    """JSON report formatted precisely to the LifeAtlasEcosystemSecurityFindingSchema."""
    
    findings_array = []
    for f in result.findings:
        # Default stride based on category
        stride = "Tampering"
        if f.category.value == "auth":
            stride = "Elevation of Privilege"
        elif f.category.value == "secret":
            stride = "Information Disclosure"
        elif f.category.value == "dependency":
            stride = "Tampering"
        elif f.category.value == "injection":
            stride = "Tampering"
            
        steps = f.remediation
        if f.fixed_code:
            steps += f"\n\nFixed Code:\n```\n{f.fixed_code}\n```"
            
        findings_array.append({
            "id": f.id,
            "reasoning_chain": f.reasoning_chain or "Static analysis identified the vulnerability; AI enrichment skipped or unavailable.",
            "severity": f.severity.value.upper(),
            "stride_classification": stride,
            "owasp_alignment": "LA-01",
            "affected_component": f.file_path,
            "description": f.description,
            "remediation": {
                "steps": steps
            }
        })
        
    stream_id = 1
    try:
        import re
        if result.stream:
            match = re.search(r'\d+', result.stream)
            if match:
                stream_id = int(match.group(0))
    except Exception:
        pass
        
    # Extract base name from repo_url or target path
    import os
    repo_name = os.path.basename(os.path.normpath(result.repo_url)) or "unknown-repo"

    return {
        "scan_metadata": {
            "timestamp": result.scanned_at.isoformat(),
            "scanner_tool": "custom-regex",
            "execution_environment": "local-dev-env"
        },
        "target_scope": {
            "stream_id": stream_id,
            "repository_name": repo_name,
            "commit_sha": "0000000000000000000000000000000000000000"
        },
        "summary": {
            "total_findings": len(result.findings),
            "critical_count": result.stats.get("critical", 0),
            "high_count": result.stats.get("high", 0),
            "medium_count": result.stats.get("medium", 0),
            "low_count": result.stats.get("low", 0)
        },
        "findings": findings_array
    }


def calculate_stream_score(result: ScanResult) -> StreamScore:
    """Calculate 0-10 security score for a stream."""
    # Severity weights for scoring
    weights = {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 0.5,
        "info": 0.0,
    }

    total_penalty = 0.0
    findings_by_severity: dict[str, int] = {}

    for finding in result.findings:
        sev = finding.severity.value
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
        total_penalty += weights.get(sev, 0)

    # Score: 10.0 (perfect) minus penalties, floored at 0.0
    raw_score = max(0.0, 10.0 - total_penalty)
    score = round(raw_score, 1)

    # Top issues: up to 5 highest-severity finding titles
    sorted_findings = sorted(
        result.findings,
        key=lambda f: list(weights.keys()).index(f.severity.value)
        if f.severity.value in weights
        else 999,
    )
    top_issues = [f.title for f in sorted_findings[:5]]

    return StreamScore(
        stream=result.stream,
        score=score,
        findings_by_severity=findings_by_severity,
        top_issues=top_issues,
    )
