"""Several sources persistently working one account.

Requiring persistence (more than one attempt per source) is what keeps this
quiet on a normal internet-facing host. Hundreds of unrelated scanners try
`admin` once each every day and leave; that is background radiation, and
reporting it as a coordinated attack trains the reader to ignore the report.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Sequence, Set, Tuple

from .models import AuthEvent, Finding

# One address, one account, this many failures inside this window.
BRUTE_FAILURES = 10
BRUTE_WINDOW_MIN = 10

# One address, this many distinct usernames, inside this window.
SPRAY_USERS = 6
SPRAY_WINDOW_MIN = 15

# A success this soon after a failure from the same address is an incident.
COMPROMISE_LOOKBACK_MIN = 60

# This many separate sources, each retrying, against a single account.
DISTRIBUTED_IPS = 5
DISTRIBUTED_MIN_PER_IP = 2
DISTRIBUTED_WINDOW_MIN = 30


def _best_window(
    events: Sequence[AuthEvent], window: timedelta, key=lambda e: e.ip
) -> Tuple[List[AuthEvent], List[AuthEvent]]:
    """Return the densest `window`-sized run, plus the most diverse one.

    Counting over the whole log answers "how many failures ever", which is
    useless: a host up for a year accumulates thousands from scanners that gave
    up in an hour. The window is what makes a count mean "attack in progress".

    Two different runs are worth reporting, and they are usually not the same
    run: the one with the most events (brute force) and the one covering the
    most distinct `key` values (a spray, where 22 attempts over 22 accounts
    beats 30 attempts over one). `key` selects which diversity matters.

    Returns (densest by count, densest by distinct key).
    """
    if not events:
        return [], []

    best_by_count: List[AuthEvent] = []
    best_by_key: List[AuthEvent] = []
    best_key_count = 0

    # events arrive sorted, so a two-pointer sweep is enough.
    start = 0
    for end, event in enumerate(events):
        while event.ts - events[start].ts > window:
            start += 1
        run = events[start : end + 1]
        if len(run) > len(best_by_count):
            best_by_count = list(run)
        distinct = len({key(e) for e in run})
        if distinct > best_key_count:
            best_key_count = distinct
            best_by_key = list(run)

    return best_by_count, best_by_key


def _persistent_window(
    events: Sequence[AuthEvent],
    window: timedelta,
    key,
    min_per_key: int,
) -> List[AuthEvent]:
    """The `window` run containing the most keys seen at least `min_per_key` times.

    Distinct-key counting is not enough here: a run can contain six addresses
    while only four of them retried, and "six sources attacking" would then be
    a lie about four. This scores the run the way the finding is worded - how
    many sources actually persisted - so the number in the title is the number
    the evidence supports.
    """
    if not events:
        return []

    best: List[AuthEvent] = []
    best_score = 0
    counts: Dict[str, int] = {}
    start = 0

    for end, event in enumerate(events):
        counts[key(event)] = counts.get(key(event), 0) + 1
        while event.ts - events[start].ts > window:
            dropped = key(events[start])
            counts[dropped] -= 1
            if counts[dropped] == 0:
                del counts[dropped]
            start += 1

        score = sum(1 for count in counts.values() if count >= min_per_key)
        if score > best_score:
            best_score = score
            best = list(events[start : end + 1])

    return best


def _by(events: Sequence[AuthEvent], key) -> Dict[str, List[AuthEvent]]:
    grouped: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in events:
        grouped[key(event)].append(event)
    return grouped


def detect_brute_force(events: Sequence[AuthEvent]) -> List[Finding]:
    """One IP hammering one account inside the window.

    Scoped per (IP, account) rather than per IP. An address that fails once
    against 22 different usernames has not brute-forced anything - that is a
    spray, reported by `detect_spray`, and it needs a different mitigation.
    """
    findings: List[Finding] = []
    window = timedelta(minutes=BRUTE_WINDOW_MIN)

    failures = [e for e in events if e.failed]
    for ip, ip_events in _by(failures, lambda e: e.ip).items():
        per_account: List[Tuple[str, List[AuthEvent]]] = []
        for user, user_events in _by(ip_events, lambda e: e.user).items():
            densest, _ = _best_window(user_events, window)
            if len(densest) >= BRUTE_FAILURES:
                per_account.append((user, densest))

        if not per_account:
            continue

        all_seen = [e for _, run in per_account for e in run]
        first = min(e.ts for e in all_seen)
        last = max(e.ts for e in all_seen)
        span = max(1.0, (last - first).total_seconds())
        rate = len(all_seen) / (span / 60.0) if span > 60 else float(len(all_seen))
        accounts = ", ".join(f"{u} ({len(r)})" for u, r in sorted(per_account))

        findings.append(
            Finding(
                detector="brute-force",
                severity="high",
                title=f"{len(all_seen)} failed logins from {ip} in {BRUTE_WINDOW_MIN}m",
                ip=ip,
                count=len(all_seen),
                first_seen=first,
                last_seen=last,
                detail=(
                    f"{len(all_seen)} failures against {len(per_account)} account(s): "
                    f"{accounts}. Sustained at {rate:.0f} attempts/minute."
                ),
                remediation=(
                    "Block the source with fail2ban or an nftables rule, and confirm "
                    "PasswordAuthentication is off in sshd_config. A password-only SSH "
                    "daemon reachable from the internet will always see this."
                ),
                users=tuple(sorted(u for u, _ in per_account)),
            )
        )
    return findings


def detect_spray(events: Sequence[AuthEvent]) -> List[Finding]:
    """One IP, many distinct usernames, low rate per username.

    Reported separately from brute force because the mitigation differs: a
    per-account lockout does nothing against a spray, so the correct response is
    to block the source and disable password auth entirely.
    """
    findings: List[Finding] = []
    window = timedelta(minutes=SPRAY_WINDOW_MIN)

    failures = [e for e in events if e.failed]
    for ip, ip_events in _by(failures, lambda e: e.ip).items():
        _, densest = _best_window(ip_events, window, key=lambda e: e.user)
        users = sorted({e.user for e in densest})
        if len(users) < SPRAY_USERS:
            continue

        findings.append(
            Finding(
                detector="credential-spray",
                severity="high",
                title=f"Credential spray from {ip}: {len(users)} accounts in {SPRAY_WINDOW_MIN}m",
                ip=ip,
                count=len(densest),
                first_seen=densest[0].ts,
                last_seen=densest[-1].ts,
                detail=(
                    f"{len(densest)} attempts spread over {len(users)} distinct "
                    "usernames - a low rate per account, which defeats per-account "
                    "lockout and per-account rate limiting."
                ),
                remediation=(
                    "Block the source and disable PasswordAuthentication. Because no "
                    "single account sees enough attempts, per-account lockout cannot "
                    "catch this - only a network-level block or key-only auth will."
                ),
                users=tuple(users),
            )
        )
    return findings


def detect_compromise(events: Sequence[AuthEvent]) -> List[Finding]:
    """An accepted login from an address that was failing shortly before.

    Scanning 40,000 failed attempts is noise; one success from the same address
    minutes later is an incident. This is the finding worth waking up for.
    """
    findings: List[Finding] = []
    lookback = timedelta(minutes=COMPROMISE_LOOKBACK_MIN)

    failures_by_ip: Dict[str, List[AuthEvent]] = _by(
        [e for e in events if e.failed], lambda e: e.ip
    )

    for event in events:
        if not event.accepted:
            continue
        prior = [
            f
            for f in failures_by_ip.get(event.ip, ())
            if timedelta(0) <= event.ts - f.ts <= lookback
        ]
        if not prior:
            continue

        findings.append(
            Finding(
                detector="success-after-failures",
                severity="critical",
                title=(
                    f"Successful login as '{event.user}' from {event.ip} "
                    f"after {len(prior)} failures"
                ),
                ip=event.ip,
                count=len(prior),
                first_seen=prior[0].ts,
                last_seen=event.ts,
                detail=(
                    f"{event.kind.replace('_', ' ')} for user '{event.user}' at "
                    f"{event.ts:%Y-%m-%d %H:%M:%S}, preceded by {len(prior)} failure(s) "
                    f"from the same address within {COMPROMISE_LOOKBACK_MIN} minutes."
                ),
                remediation=(
                    f"Treat account '{event.user}' as compromised. Assume persistence: "
                    "check ~/.ssh/authorized_keys for added keys, review sudoers and "
                    "cron, look for new UID 0 accounts, then rotate credentials and "
                    "rebuild if anything is unexplained."
                ),
                users=(event.user,),
            )
        )
    return findings


def detect_distributed(events: Sequence[AuthEvent]) -> List[Finding]:
    """Several sources persistently working one account.

    Requiring persistence (more than one attempt per source) is what keeps this
    quiet on a normal internet-facing host. Hundreds of unrelated scanners try
    `admin` once each every day and leave; that is background radiation, and
    reporting it as a coordinated attack trains the reader to ignore the report.
    """
    findings: List[Finding] = []
    window = timedelta(minutes=DISTRIBUTED_WINDOW_MIN)

    failures = [e for e in events if e.failed]
    if not failures:
        return findings

    for user, user_events in _by(failures, lambda e: e.user).items():
        densest = _persistent_window(
            user_events, window, key=lambda e: e.ip, min_per_key=DISTRIBUTED_MIN_PER_IP
        )
        per_ip = _by(densest, lambda e: e.ip)
        persistent = {ip: run for ip, run in per_ip.items() if len(run) >= DISTRIBUTED_MIN_PER_IP}

        if len(persistent) < DISTRIBUTED_IPS:
            continue

        sources = sorted(persistent)
        attempts = sum(len(r) for r in persistent.values())

        findings.append(
            Finding(
                detector="distributed-attack",
                severity="medium",
                title=f"{len(sources)} sources attacking '{user}' within {DISTRIBUTED_WINDOW_MIN}m",
                ip="(distributed)",
                count=attempts,
                first_seen=min(r[0].ts for r in persistent.values()),
                last_seen=max(r[-1].ts for r in persistent.values()),
                detail=(
                    f"{attempts} failures against '{user}' from {len(sources)} distinct "
                    f"addresses, each retrying at least {DISTRIBUTED_MIN_PER_IP} times. "
                    "Every source stays under the per-IP threshold, so per-IP rate "
                    "limiting alone will not stop it."
                ),
                remediation=(
                    "Rotate this account's password and require public-key auth. "
                    "Consider an nftables rule limiting new inbound SSH connections per "
                    "subnet rather than per IP."
                ),
                users=(user,),
            )
        )
    return findings


DETECTORS = (
    detect_compromise,
    detect_brute_force,
    detect_spray,
    detect_distributed,
)


def run_all(events: Sequence[AuthEvent]) -> List[Finding]:
    """Run every detector and return findings worst-first, newest-first."""
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(events))
    findings.sort(key=lambda f: (f.rank, -f.last_seen.timestamp()))
    return findings


def attackers(findings: Sequence[Finding]) -> Set[str]:
    """Every real address that produced a finding, for a blocklist."""
    return {f.ip for f in findings if f.ip and not f.ip.startswith("(")}
