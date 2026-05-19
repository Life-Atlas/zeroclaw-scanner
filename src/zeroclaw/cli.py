"""CLI entrypoint — zeroclaw scan / report commands."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(prog="zeroclaw", description="ZeroClaw security scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_cmd = subparsers.add_parser("scan", help="Scan a target directory")
    scan_cmd.add_argument("--target", default=".", help="Directory to scan")
    scan_cmd.add_argument("--stream", default="", help="Intern stream label")

    report_cmd = subparsers.add_parser("report", help="Generate a report")
    report_cmd.add_argument("--format", choices=["terminal", "json"], default="terminal")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        target = Path(args.target).resolve()
        if not target.exists():
            print(f"Error: target directory {target} does not exist")
            sys.exit(1)
        print(f"[ZeroClaw] Scanning {target} ...")
        print("[ZeroClaw] Scanners not yet implemented — run 'make test' to see TDD gates")

    elif args.command == "report":
        print("[ZeroClaw] Reporter not yet implemented — Phase 4 task")


if __name__ == "__main__":
    main()
