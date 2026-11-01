"""Tests for log parsing.

Fixture lines are built from fragments rather than pasted literals so the file
stays readable and mixes both timestamp dialects the tool supports.
"""

from __future__ import annotations

import pytest

from sshwatch.models import ACCEPTED_KEY, ACCEPTED_PASSWORD, FAILED, INVALID
from sshwatch.parse import (
    in_window,
    parse_line,
    parse_lines,
    read_file,
    sort_events,
)

HOST = "web-01"


def syslog(clock: str, body: str) -> str:
    """Classic `auth.log` line: no year, month + day + time."""
    return f"Nov  1 {clock} {HOST} sshd[3141]: {body}"


def failed(user: str, ip: str, port: int = 50022) -> str:
    return f"Failed password for {user} from {ip} port {port} ssh2"


def invalid(user: str, ip: str) -> str:
    return f"Invalid user {user} from {ip}"


class TestTimestamps:
    def test_classic_syslog_timestamp(self):
        event = parse_line(syslog("10:04:11", failed("root", "203.0.113.9")), 2026)
        assert event is not None
        assert (event.ts.year, event.ts.month, event.ts.day) == (2026, 11, 1)
        assert (event.ts.hour, event.ts.minute, event.ts.second) == (10, 4, 11)

    def test_iso_timestamp_with_offset(self):
        line = (
            "2026-11-01T09:52:11.483912+00:00 web-01 sshd[22]: "
            + failed("admin", "198.51.100.7")
        )
        event = parse_line(line, 2026)
        assert event is not None
        assert event.ts.hour == 9

    def test_iso_timestamp_with_zulu(self):
        line = "2026-11-01T09:52:11Z web-01 sshd[22]: " + failed("admin", "198.51.100.7")
        event = parse_line(line, 2026)
        assert event is not None
        assert event.ts.tzinfo is not None

    def test_year_is_injected_not_guessed(self):
        line = syslog("23:59:59", failed("root", "203.0.113.9"))
        assert parse_line(line, 2019).ts.year == 2019
        assert parse_line(line, 2026).ts.year == 2026


class TestEventKinds:
    def test_failed_password(self):
        event = parse_line(syslog("10:00:00", failed("deploy", "203.0.113.9", 60000)))
        assert event.kind == FAILED
        assert event.user == "deploy"
        assert event.ip == "203.0.113.9"
        assert event.port == 60000
        assert event.failed and not event.accepted

    def test_invalid_user(self):
        event = parse_line(syslog("10:00:00", invalid("oracle", "203.0.113.9")))
        assert event.kind == INVALID
        assert event.user == "oracle"
        assert event.failed

    def test_accepted_password(self):
        body = "Accepted password for sam from 192.0.2.10 port 51000 ssh2"
        event = parse_line(syslog("10:00:00", body))
        assert event.kind == ACCEPTED_PASSWORD
        assert event.accepted and not event.failed

    def test_accepted_publickey(self):
        body = "Accepted publickey for sam from 192.0.2.10 port 51000 ssh2: ED25519"
        event = parse_line(syslog("10:00:00", body))
        assert event.kind == ACCEPTED_KEY
        assert event.accepted

    def test_ipv6_address(self):
        event = parse_line(syslog("10:00:00", failed("root", "2001:db8::1")))
        assert event.ip == "2001:db8::1"

    def test_two_word_usernames_are_not_split(self):
        body = "Failed password for DOMAIN\\svc from 203.0.113.9 port 1 ssh2"
        event = parse_line(syslog("10:00:00", body))
        assert event.user == "DOMAIN\\svc"


class TestNonEvents:
    @pytest.mark.parametrize(
        "line",
        [
            "",
            "Nov  1 10:00:00 web-01 sshd[1]: Server listening on 0.0.0.0 port 22.",
            "Nov  1 10:00:00 web-01 CRON[9]: pam_unix(cron:session): session opened",
            "Nov  1 10:00:00 web-01 sshd[1]: Connection closed by 203.0.113.9 port 1",
            "no timestamp at all sshd[1]: Failed password for root from 1.2.3.4 port 1",
            "Nov  1 10:00:00 web-01 sshd[1]: Received disconnect from 203.0.113.9",
        ],
    )
    def test_ignored(self, line):
        assert parse_line(line) is None

    def test_parse_lines_drops_non_events(self):
        lines = [
            syslog("10:00:00", failed("root", "203.0.113.9")),
            syslog("10:00:01", "Server listening on 0.0.0.0 port 22."),
            syslog("10:00:02", invalid("test", "203.0.113.9")),
        ]
        assert len(parse_lines(lines)) == 2


class TestOrdering:
    def test_sort_events_is_chronological(self):
        lines = [
            syslog("10:00:09", failed("root", "203.0.113.9")),
            syslog("10:00:01", failed("root", "203.0.113.9")),
            syslog("10:00:05", failed("root", "203.0.113.9")),
        ]
        events = sort_events(parse_lines(lines))
        assert [e.ts.second for e in events] == [1, 5, 9]

    def test_in_window_anchors_on_newest_event(self):
        lines = [
            syslog("08:00:00", failed("root", "203.0.113.9")),
            syslog("09:30:00", failed("root", "203.0.113.9")),
            syslog("10:00:00", failed("root", "203.0.113.9")),
        ]
        events = sort_events(parse_lines(lines))
        assert len(in_window(events, 1)) == 2
        assert len(in_window(events, 3)) == 3

    def test_in_window_of_empty_is_empty(self):
        assert in_window([], 24) == []


class TestReadFile:
    def test_reads_and_parses(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "\n".join(
                [
                    syslog("10:00:00", failed("root", "203.0.113.9")),
                    syslog("10:00:05", failed("admin", "203.0.113.9")),
                ]
            ),
            encoding="utf-8",
        )
        assert len(read_file(str(log))) == 2

    def test_undecodable_bytes_do_not_raise(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_bytes(
            b"Nov  1 10:00:00 web-01 sshd[1]: Failed password for root "
            b"from 203.0.113.9 port 5 ssh2\n\xff\xfe binary garbage\n"
        )
        assert len(read_file(str(log))) == 1
