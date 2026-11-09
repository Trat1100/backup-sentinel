from __future__ import annotations

import argparse
import json
import sys

from backup_sentinel.audit import ConfigError, SEVERITY_ORDER, audit_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backup-sentinel", description="Read-only freshness and checksum checks for backup directories.")
    parser.add_argument("config", help="Path to a Backup Sentinel JSON configuration")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format")
    parser.add_argument("--fail-on", choices=("none", "warning", "error"), default="error", help="Exit with status 1 when a finding at this severity or above is present")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = audit_config(args.config)
    except ConfigError as exc:
        print(f"backup-sentinel: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        counts = report.counts()
        print(f"Backup Sentinel report: {report.source}")
        print(f"Findings: {counts['error']} error, {counts['warning']} warning, {counts['info']} info")
        for finding in report.findings:
            path = f" ({finding.path})" if finding.path else ""
            print(f"[{finding.severity.upper()}] {finding.rule_id} — {finding.backup_set}{path}: {finding.message}")
        if not report.findings:
            print("All configured backup checks passed.")

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return int(any(SEVERITY_ORDER[item.severity] >= threshold for item in report.findings))


if __name__ == "__main__":
    raise SystemExit(main())
