"""Command line entry point.

Exit codes are part of the contract, because this tool's main use is a CI step:

    0  no findings at or above --fail-on
    1  findings at or above --fail-on
    2  usage error / unreadable input

`2` exists so a typo in a log path fails a security job instead of passing it.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .detectors import run_all
from .models import SEVERITIES, AuthEvent, Finding
from .parse import in_window, parse_lines, read_file, sort_events
from .report import to_json, to_markdown, to_sarif, to_text

FAIL_ON_CHOICES = ("critical", "high", "medium", "low")
FORMATS = ("text", "json", "sarif", "markdown")


def _severity_at_least(finding: Finding, threshold: str) -> bool:
    """True when `finding` is at least as severe as `threshold`."""
    if finding.severity not in SEVERITIES or threshold not in SEVERITIES:
        return False
    return SEVERITIES.index(finding.severity) <= SEVERITIES.index(threshold)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sshwatch",
        description=(
            "Detect SSH brute force, credential spraying and post-failure logins "
            "in auth logs. Offline: reads files, never connects to a host."
        ),
        epilog=(
            "examples:\n"
            "  sshwatch /var/log/auth.log\n"
            "  sshwatch auth.log --hours 168 --fail-on high\n"
            "  sshwatch auth.log -f sarif -o ssh.sarif\n"
            "  journalctl -u sshd --since '24 hours ago' | sshwatch -\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "logs",
        nargs="+",
        metavar="LOG",
        help="auth log file(s) to read, or '-' for stdin",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="write the report to PATH")
    parser.add_argument(
        "--hours",
        type=int,
        metavar="N",
        help=(
            "only consider the last N hours of the log's own newest timestamp; "
            "default is the whole file"
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        metavar="LEVEL",
        help="exit 1 when a finding at or above LEVEL exists (critical/high/medium/low)",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=2026,
        metavar="YYYY",
        help="year to assume for classic syslog timestamps, which omit it (default: 2026)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the report on stdout; only the exit code matters",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sshwatch {__version__}",
    )
    return parser


def _read_inputs(paths: Sequence[str], year: int) -> List[AuthEvent]:
    events: List[AuthEvent] = []
    for path in paths:
        if path == "-":
            events.extend(parse_lines(sys.stdin, year))
        else:
            events.extend(read_file(path, year))
    return sort_events(events)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        events = _read_inputs(args.logs, args.year)
    except OSError as exc:
        print(f"sshwatch: cannot read input: {exc}", file=sys.stderr)
        return 2

    if args.hours is not None:
        if args.hours <= 0:
            print("sshwatch: --hours must be a positive number", file=sys.stderr)
            return 2
        events = in_window(events, args.hours)

    if not events:
        print(
            "sshwatch: no auth events parsed - check the path, the log format, "
            "or whether the file is compressed",
            file=sys.stderr,
        )
        return 2

    findings = run_all(events)

    label = ", ".join(args.logs)
    if args.format == "text":
        report = to_text(findings, events, label)
    elif args.format == "json":
        report = to_json(findings, events)
    elif args.format == "sarif":
        report = to_sarif(findings)
    else:
        report = to_markdown(findings, events)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as exc:
            print(f"sshwatch: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2

    if not args.quiet and not args.output:
        print(report)

    if args.fail_on and any(_severity_at_least(f, args.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
