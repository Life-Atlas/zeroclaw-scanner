"""CLI entrypoint — zeroclaw scan / report commands."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from zeroclaw.models import ScanResult


def main() -> None:
    parser = argparse.ArgumentParser(prog="zeroclaw", description="ZeroClaw security scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_cmd = subparsers.add_parser("scan", help="Scan a target directory")
    scan_cmd.add_argument("--target", default=".", help="Directory to scan")
    scan_cmd.add_argument("--stream", default="", help="Intern stream label")
    scan_cmd.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip ZeroClaw AI enrichment (raw scanner output only)",
    )
    scan_cmd.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format for scan results",
    )

    report_cmd = subparsers.add_parser("report", help="Generate a report from a saved scan")
    report_cmd.add_argument("--format", choices=["terminal", "json"], default="terminal")
    report_cmd.add_argument("--input", default="reports/latest_scan.json", help="Input JSON scan file")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        _run_scan(args)

    elif args.command == "report":
        _run_report(args)


def _run_scan(args: argparse.Namespace) -> None:
    """Execute the 3-phase scan pipeline: Gather → Enrich → Report."""
    from zeroclaw.scanners.pattern_scanner import scan_patterns
    from zeroclaw.scanners.dependency_scanner import scan_dependencies
    from zeroclaw.scanners.secret_scanner import scan_secrets
    from zeroclaw.scanners.auth_scanner import scan_fastapi_auth, scan_supabase_rls

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target directory {target} does not exist")
        sys.exit(1)

    stream = args.stream if args.stream else target.name

    # ── Phase 1: Gathering ──────────────────────────────────────────────
    print(f"[ZeroClaw] Phase 1/3 — Static analysis on {target}")
    raw_findings = []

    print("  ├─ Pattern scanner ...", end=" ", flush=True)
    patterns = scan_patterns(target)
    print(f"{len(patterns)} finding(s)")
    raw_findings.extend(patterns)

    print("  ├─ Dependency scanner ...", end=" ", flush=True)
    deps = scan_dependencies(target)
    print(f"{len(deps)} finding(s)")
    raw_findings.extend(deps)

    print("  ├─ Secret scanner ...", end=" ", flush=True)
    secrets = scan_secrets(target, allowed_base=target)
    print(f"{len(secrets)} finding(s)")
    raw_findings.extend(secrets)

    print("  ├─ Auth scanner (FastAPI) ...", end=" ", flush=True)
    auth = scan_fastapi_auth(target)
    print(f"{len(auth)} finding(s)")
    raw_findings.extend(auth)

    print("  └─ Auth scanner (Supabase RLS) ...", end=" ", flush=True)
    rls = scan_supabase_rls(target)
    print(f"{len(rls)} finding(s)")
    raw_findings.extend(rls)

    # Tag findings with stream label
    for f in raw_findings:
        f.stream = stream

    print(f"\n[ZeroClaw] Total raw findings: {len(raw_findings)}")

    # ── Phase 2: Enrichment ─────────────────────────────────────────────
    if args.no_enrich:
        print("[ZeroClaw] Phase 2/3 — Enrichment SKIPPED (--no-enrich)")
        enriched_findings = raw_findings
    else:
        enrichable = [
            f for f in raw_findings
            if f.severity.value in ("critical", "high", "medium")
        ]
        skipped = len(raw_findings) - len(enrichable)
        print(
            f"[ZeroClaw] Phase 2/3 — Enriching {len(enrichable)} findings "
            f"(skipping {skipped} low/info severity)"
        )

        if enrichable:
            from zeroclaw.agent_client import ZeroClawClient

            client = ZeroClawClient()

            # Warn early if the binary wasn't found
            if not client.is_available:
                print(
                    "  ⚠  ZeroClaw binary not found! Enrichment will use fallback messages.\n"
                    "     Install: curl -fsSL https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw/master/install.sh | bash\n"
                    "     Then ensure ~/.cargo/bin is in your PATH.\n"
                )

            _fallback_keywords = (
                "not found", "not installed", "timed out",
                "unavailable", "non-zero exit", "Error",
            )

            for i, finding in enumerate(enrichable, 1):
                print(f"  [{i}/{len(enrichable)}] Enriching {finding.id} ...", end=" ", flush=True)
                target_file = target / finding.file_path
                client.enrich_finding(finding, target_file)
                rc = finding.reasoning_chain or ""
                is_real = bool(rc) and not any(kw in rc for kw in _fallback_keywords)
                print("✓ enriched" if is_real else "⚠ fallback")

                # Rate limiting prevention: sleep 60 seconds after every 10 enrichments
                if i % 10 == 0 and i < len(enrichable):
                    print(f"  [Rate Limit] Sleeping for 60 seconds to prevent API blocks...")
                    time.sleep(60)

        enriched_findings = raw_findings  # enrichable items are mutated in-place

    # ── Phase 3: Reporting ──────────────────────────────────────────────
    print(f"[ZeroClaw] Phase 3/3 — Generating {args.format} report")

    # Build the ScanResult
    stats = {}
    for f in enriched_findings:
        if f.false_positive:
            continue
        stats[f.severity.value] = stats.get(f.severity.value, 0) + 1
        stats[f.category.value] = stats.get(f.category.value, 0) + 1

    result = ScanResult(
        stream=stream,
        repo_url=f"https://github.com/lifeatlas/{stream}",
        scanned_at=datetime.now(timezone.utc),
        findings=enriched_findings,
        stats=stats,
    )

    from zeroclaw.reporter import generate_terminal_report, generate_json_report

    # Ensure reports directory exists
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Save to reports/latest_scan.json and reports/{stream}_scan.json
    json_data = generate_json_report(result)
    latest_file = reports_dir / "latest_scan.json"
    stream_file = reports_dir / f"{stream}_scan.json"

    # Datetime serializer for JSON
    def dt_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError("Type not serializable")

    with open(latest_file, "w", encoding="utf-8") as fh:
        json.dump(json_data, fh, indent=2, default=dt_serializer)
    with open(stream_file, "w", encoding="utf-8") as fh:
        json.dump(json_data, fh, indent=2, default=dt_serializer)

    if args.format == "json":
        print(json.dumps(json_data, indent=2, default=dt_serializer))
    else:
        output = generate_terminal_report(result)
        print(output)

    print(f"\n[ZeroClaw] Scan complete. {len(enriched_findings)} total findings.")


def _run_report(args: argparse.Namespace) -> None:
    """Re-generate a report from a previously saved JSON scan."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file {input_path} does not exist")
        sys.exit(1)

    try:
        with open(input_path, encoding="utf-8") as fh:
            data = json.load(fh)
        
        # Parse back to ScanResult model (Pydantic resolves datetime strings)
        result = ScanResult(**data)
    except Exception as e:
        print(f"Error reading or parsing scan results: {e}")
        sys.exit(1)

    from zeroclaw.reporter import generate_terminal_report, generate_json_report

    if args.format == "json":
        report = generate_json_report(result)
        print(json.dumps(report, indent=2, default=str))
    else:
        output = generate_terminal_report(result)
        print(output)


if __name__ == "__main__":
    main()
