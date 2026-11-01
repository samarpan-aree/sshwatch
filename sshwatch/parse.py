"""Turn OpenSSH auth-log lines into AuthEvent objects.

Deliberately regex-based rather than a full syslog parser: the goal is to be
useful across Debian/Ubuntu (`sshd[...]` in `/var/log/auth.log`) and RHEL
(`systemd-logind`-prefixed `journalctl -u sshd`) without a grammar library.
Lines that do not parse are counted, never raised - a log with one odd line
should not stop a scan.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

from .models import (
    ACCEPTED_KEY,
    ACCEPTED_PASSWORD,
    FAILED,
    INVALID,
    AuthEvent,
)

# RFC3339 / ISO8601 prefix: 2026-11-01T09:52:11.483912+00:00 or ...Z
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
# Classic syslog prefix: Nov  1 09:52:11 (no year)
_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# Event patterns. Anchored on "sshd" so unrelated PAM chatter is ignored.
_FAILED = re.compile(
    r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_INVALID = re.compile(
    r"sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
_ACCEPT_PW = re.compile(
    r"sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_ACCEPT_KEY = re.compile(
    r"sshd\[\d+\]:\s+Accepted publickey for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(line: str, default_year: int) -> Optional[datetime]:
    """Extract a timestamp, or None when the line carries none.

    Syslog timestamps have no year, so `default_year` is injected. Callers
    scanning a log spanning a year boundary should pass the right year per
    file; for a single rotation window it is unambiguous.
    """
    m = _ISO.match(line)
    if m:
        raw = m.group("ts").replace("Z", "+00:00")
        # "2026-11-01 09:52:11" (space separator) is not ISO-parseable pre-3.11
        if " " in raw:
            raw = raw.replace(" ", "T", 1)
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    m = _SYSLOG.match(line)
    if m:
        parts = m.group("ts").split()
        month, day, clock = parts[0], int(parts[1]), parts[2]
        hh, mm, ss = (int(x) for x in clock.split(":"))
        try:
            return datetime(default_year, _MONTHS[month], day, hh, mm, ss)
        except (KeyError, ValueError):
            return None

    return None


def parse_line(line: str, default_year: int = 2026) -> Optional[AuthEvent]:
    """Parse one log line. Returns None when it is not an auth decision."""
    ts = _parse_timestamp(line, default_year)
    if ts is None:
        return None

    m = _FAILED.search(line)
    if m:
        return AuthEvent(
            ts=ts,
            ip=m.group("ip"),
            user=m.group("user"),
            kind=FAILED,
            port=int(m.group("port")),
            raw=line.rstrip("\n"),
        )

    m = _INVALID.search(line)
    if m:
        return AuthEvent(
            ts=ts,
            ip=m.group("ip"),
            user=m.group("user"),
            kind=INVALID,
            raw=line.rstrip("\n"),
        )

    m = _ACCEPT_PW.search(line)
    if m:
        return AuthEvent(
            ts=ts,
            ip=m.group("ip"),
            user=m.group("user"),
            kind=ACCEPTED_PASSWORD,
            port=int(m.group("port")),
            raw=line.rstrip("\n"),
        )

    m = _ACCEPT_KEY.search(line)
    if m:
        return AuthEvent(
            ts=ts,
            ip=m.group("ip"),
            user=m.group("user"),
            kind=ACCEPTED_KEY,
            port=int(m.group("port")),
            raw=line.rstrip("\n"),
        )

    return None


def parse_lines(lines: Iterable[str], default_year: int = 2026) -> List[AuthEvent]:
    """Parse many lines, dropping the ones that are not auth decisions."""
    out: List[AuthEvent] = []
    for line in lines:
        event = parse_line(line, default_year)
        if event is not None:
            out.append(event)
    return out


def read_file(path: str, default_year: int = 2026) -> List[AuthEvent]:
    """Parse a log file, tolerating undecodable bytes."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, default_year)


def sort_events(events: Iterable[AuthEvent]) -> List[AuthEvent]:
    """Chronological order. Detectors assume this."""
    return sorted(events, key=lambda e: e.ts)


def in_window(events: Iterable[AuthEvent], hours: int) -> List[AuthEvent]:
    """Keep only events within `hours` of the newest event in the input.

    Anchored on the log's own newest timestamp rather than wall-clock time, so
    scanning an archived log is not silently empty.
    """
    events = list(events)
    if not events:
        return []
    newest = max(e.ts for e in events)
    cutoff = newest - timedelta(hours=hours)
    return [e for e in events if e.ts >= cutoff]
