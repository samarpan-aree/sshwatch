"""Tests for the four detectors.

Each test builds the smallest event sequence that should (or should not) fire,
because the threshold itself is the thing under test - a big captured log would
hide which condition actually tripped.

Two classes of test matter more than the rest, and both are about the failure
mode that kills security tools:

- the silent tests, which pin down what must NOT be reported
- the separation tests, which prove one real attack is not reported twice
  under two names
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List

from sshwatch.detectors import (
    detect_brute_force,
    detect_compromise,
    detect_distributed,
    detect_spray,
    run_all,
)
from sshwatch.models import (
    ACCEPTED_KEY,
    ACCEPTED_PASSWORD,
    FAILED,
    INVALID,
    AuthEvent,
    Finding,
)

BASE = datetime(2026, 11, 1, 10, 0, 0)


def ev(
    minute: int = 0,
    ip: str = "203.0.113.9",
    user: str = "root",
    kind: str = FAILED,
    second: int = 0,
) -> AuthEvent:
    return AuthEvent(
        ts=BASE + timedelta(minutes=minute, seconds=second),
        ip=ip,
        user=user,
        kind=kind,
    )


def failures(
    count: int,
    ip: str = "203.0.113.9",
    user: str = "root",
    step: int = 1,
) -> List[AuthEvent]:
    """`count` failures `step` seconds apart, starting at minute 0."""
    return [ev(0, ip, user, FAILED, second=i * step) for i in range(count)]


def by_detector(findings: List[Finding], name: str) -> List[Finding]:
    return [f for f in findings if f.detector == name]


class TestBruteForce:
    def test_fires_at_threshold(self):
        assert len(detect_brute_force(failures(10))) == 1

    def test_silent_below_threshold(self):
        assert detect_brute_force(failures(9)) == []

    def test_severity_is_high(self):
        assert detect_brute_force(failures(12))[0].severity == "high"

    def test_attempts_spread_beyond_window_do_not_accumulate(self):
        # 20 failures, one every 2 minutes => never 10 inside a 10-minute window
        spread = [ev(0, second=i * 120) for i in range(20)]
        assert detect_brute_force(spread) == []

    def test_one_ip_does_not_hide_another(self):
        noisy = failures(12, ip="203.0.113.9")
        quiet = failures(2, ip="198.51.100.4")
        found = detect_brute_force(noisy + quiet)
        assert len(found) == 1
        assert found[0].ip == "203.0.113.9"

    def test_invalid_user_counts_as_a_failure(self):
        events = failures(9) + [ev(0, kind=INVALID, user="root", second=30)]
        assert len(detect_brute_force(events)) == 1

    def test_accepted_logins_do_not_count(self):
        events = failures(9) + [ev(0, kind=ACCEPTED_PASSWORD, user="sam")]
        assert detect_brute_force(events) == []

    def test_each_account_is_counted_separately(self):
        # 5 attempts on each of two accounts is not 10 on either.
        events = failures(5, user="root") + failures(5, user="admin")
        assert detect_brute_force(events) == []

    def test_two_hammered_accounts_are_one_finding(self):
        events = failures(10, user="root") + failures(10, user="admin")
        found = detect_brute_force(events)
        assert len(found) == 1
        assert found[0].users == ("admin", "root")
        assert found[0].count == 20

    def test_a_spray_is_not_reported_as_brute_force(self):
        # 22 attempts over 22 accounts: a spray, never a brute force.
        events = [ev(0, user=f"svc{i}", second=i) for i in range(22)]
        assert detect_brute_force(events) == []

    def test_finding_carries_remediation(self):
        assert "fail2ban" in detect_brute_force(failures(10))[0].remediation

    def test_rate_appears_in_detail(self):
        finding = detect_brute_force(failures(10, step=30))[0]
        assert "attempts/minute" in finding.detail

    def test_per_account_breakdown_in_detail(self):
        events = failures(10, user="root") + failures(11, user="admin")
        detail = detect_brute_force(events)[0].detail
        assert "root (10)" in detail and "admin (11)" in detail


class TestSpray:
    def test_fires_on_many_distinct_users(self):
        events = [ev(0, user=f"user{i}", second=i) for i in range(6)]
        assert len(detect_spray(events)) == 1

    def test_silent_when_few_users(self):
        events = [ev(0, user=f"user{i}", second=i) for i in range(5)]
        assert detect_spray(events) == []

    def test_hammering_one_user_is_not_a_spray(self):
        assert detect_spray(failures(30, user="root")) == []

    def test_reports_distinct_user_count(self):
        events = [ev(0, user=f"user{i}", second=i) for i in range(9)]
        assert len(detect_spray(events)[0].users) == 9

    def test_spread_beyond_window_does_not_count(self):
        events = [ev(0, user=f"user{i}", second=i * 400) for i in range(6)]
        assert detect_spray(events) == []

    def test_a_brute_force_is_not_a_spray(self):
        assert detect_spray(failures(40, user="root")) == []

    def test_message_explains_why_lockout_fails(self):
        events = [ev(0, user=f"user{i}", second=i) for i in range(7)]
        assert "lockout" in detect_spray(events)[0].remediation


class TestCompromise:
    def test_success_after_failures_is_critical(self):
        events = failures(4, step=60) + [ev(5, kind=ACCEPTED_PASSWORD)]
        found = detect_compromise(events)
        assert len(found) == 1
        assert found[0].severity == "critical"
        assert found[0].count == 4

    def test_success_from_a_clean_ip_is_ignored(self):
        events = [ev(2, ip="192.0.2.10", user="sam", kind=ACCEPTED_PASSWORD)]
        assert detect_compromise(events) == []

    def test_success_long_after_failures_is_ignored(self):
        events = failures(4, step=60) + [ev(90, kind=ACCEPTED_PASSWORD)]
        assert detect_compromise(events) == []

    def test_success_before_failures_is_ignored(self):
        # Login at minute 0, every failure strictly after: a legit session that
        # is later probed must not be read as a compromise.
        events = [ev(0, kind=ACCEPTED_PASSWORD)] + [ev(5 + i) for i in range(4)]
        assert detect_compromise(events) == []

    def test_one_success_reported_even_with_many_failures(self):
        events = failures(50) + [ev(3, kind=ACCEPTED_PASSWORD)]
        assert len(detect_compromise(events)) == 1

    def test_publickey_login_also_triggers(self):
        events = failures(2) + [ev(1, kind=ACCEPTED_KEY, user="root", second=30)]
        assert detect_compromise(events)[0].severity == "critical"

    def test_success_from_a_different_ip_is_ignored(self):
        events = failures(5) + [
            ev(1, ip="192.0.2.10", user="root", kind=ACCEPTED_PASSWORD)
        ]
        assert detect_compromise(events) == []

    def test_remediation_mentions_persistence_checks(self):
        events = failures(2) + [ev(1, kind=ACCEPTED_PASSWORD, second=30)]
        assert "authorized_keys" in detect_compromise(events)[0].remediation


class TestDistributed:
    def _persistent(self, ips: int, per_ip: int = 2, user: str = "deploy") -> List[AuthEvent]:
        """`ips` distinct sources, each trying `per_ip` times, all inside window."""
        events: List[AuthEvent] = []
        for i in range(ips):
            for j in range(per_ip):
                events.append(ev(0, ip=f"203.0.113.{i}", user=user, second=i * 10 + j))
        return events

    def test_fires_when_many_persistent_sources_hit_one_account(self):
        assert len(detect_distributed(self._persistent(5))) == 1

    def test_silent_on_one_shot_scanners(self):
        # Six unrelated scanners that try once and leave: background noise, not
        # an attack. This is the assertion that keeps the report quiet on a
        # normal internet-facing host.
        events = [ev(0, ip=f"203.0.113.{i}", user="admin", second=i) for i in range(6)]
        assert detect_distributed(events) == []

    def test_silent_on_one_ip(self):
        events = [ev(0, ip="203.0.113.9", user="deploy", second=i) for i in range(40)]
        assert detect_distributed(events) == []

    def test_silent_when_sources_are_spread_beyond_window(self):
        events = [
            ev(0, ip=f"203.0.113.{i}", user="deploy", second=i * 900)
            for i in range(5)
        ]
        events += [ev(0, ip=f"203.0.113.{i}", user="deploy", second=i * 900 + 5) for i in range(5)]
        assert detect_distributed(events) == []

    def test_scoped_per_account(self):
        # Four persistent IPs on one account and four on another: five nowhere.
        assert detect_distributed(
            self._persistent(4, user="alpha") + self._persistent(4, user="beta")
        ) == []

    def test_mixed_sources_need_five_persistent_ones(self):
        # Four persistent + ten one-shot = not an attack, just four and noise.
        persistent = self._persistent(4)
        noise = [ev(0, ip=f"198.51.100.{i}", user="deploy", second=i) for i in range(10)]
        assert detect_distributed(persistent + noise) == []

    def test_severity_is_medium(self):
        assert detect_distributed(self._persistent(6))[0].severity == "medium"

    def test_reported_ip_is_a_placeholder_not_blockable(self):
        assert detect_distributed(self._persistent(5))[0].ip == "(distributed)"


class TestRunAll:
    def test_returns_worst_first(self):
        events = (
            failures(12)
            + [ev(0, ip="198.51.100.4", user=f"u{i}", second=i) for i in range(6)]
            + [ev(0, ip=f"203.0.113.{i}", user="deploy", second=i) for i in range(5)]
            + [ev(1, kind=ACCEPTED_PASSWORD, second=30)]
        )
        ranks = [f.rank for f in run_all(events)]
        assert ranks == sorted(ranks)

    def test_clean_log_is_silent(self):
        assert run_all([]) == []

    def test_normal_admin_session_is_silent(self):
        events = [
            ev(0, ip="10.0.0.14", user="sam", kind=ACCEPTED_KEY, second=0),
            ev(37, ip="10.0.0.14", user="sam", kind=ACCEPTED_KEY, second=0),
        ]
        assert run_all(events) == []

    def test_a_real_incident_produces_all_four(self):
        events = (
            failures(12)
            + [ev(0, ip="198.51.100.4", user=f"svc{i}", second=i) for i in range(6)]
            + [
                ev(5, ip=f"203.0.113.{i}", user="deploy", second=i * 10 + j)
                for i in range(5)
                for j in range(2)
            ]
            + [ev(6, kind=ACCEPTED_PASSWORD, second=30)]
        )
        names = {f.detector for f in run_all(events)}
        assert names == {
            "brute-force",
            "credential-spray",
            "distributed-attack",
            "success-after-failures",
        }

    def test_no_duplicate_findings(self):
        events = failures(12) + [ev(1, kind=ACCEPTED_PASSWORD, second=30)]
        found = run_all(events)
        keys = [(f.detector, f.title) for f in found]
        assert len(keys) == len(set(keys))

    def test_every_finding_has_remediation(self):
        events = failures(12) + [ev(1, kind=ACCEPTED_PASSWORD, second=30)]
        assert all(f.remediation for f in run_all(events))

    def test_every_finding_has_a_valid_severity(self):
        events = failures(12) + [ev(1, kind=ACCEPTED_PASSWORD, second=30)]
        assert all(
            f.severity in ("critical", "high", "medium", "low", "info") for f in run_all(events)
        )
