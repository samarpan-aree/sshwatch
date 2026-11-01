# Architecture

## The two constraints

**Noise is the failure mode.** A security scanner that cries wolf is disabled,
and a disabled tool detects nothing. Every threshold here is set so that a human
mistyping a password never produces a finding, even at the cost of missing a
very slow, very quiet attacker.

**The report is read under pressure.** At 2am somebody opens this output to
answer one question: *is anything wrong, and which account is it?* That drives
the ordering (critical first), the density (one screen for a normal attack), and
the fact that every finding ends with a specific action rather than advice.

## Module graph

```
cli.py
  +-- parse.py       log lines -> AuthEvent
  +-- detectors.py   AuthEvent[] -> Finding[]
  +-- report.py      Finding[] -> text / json / sarif / markdown
```

Strictly one-directional and acyclic. `report.py` never calls back into parsing,
and no module outside `cli.py` reads a file or touches stdin. That is what makes
`sshwatch` offline as a structural property rather than a promise.

## Why detectors are pure functions

Each detector takes an already-parsed, chronologically sorted `AuthEvent` list
and returns `Finding` objects. No detector opens a file, reads the clock, or
touches a socket.

The payoff is the test suite: 99 tests, under 100 ms, no fixture files. Each
threshold is asserted with the smallest event sequence that should trip it — six
lines — because a captured log hides *which* condition actually fired. A test
that passes against a 5,000-line real log tells you almost nothing about whether
the boundary at 10 failures is correct.

## Windowing, and why it is anchored on log time

Counting failures over a whole file answers "how many ever", which is useless: a
host up for a year accumulates tens of thousands from scanners that gave up in
an hour. A window is what makes a count mean "attack in progress".

Windows are anchored on the **newest timestamp in the log**, not on wall-clock
time. Analysing `auth.log.3` from last week must not return an empty report just
because that file is old.

Two sweeps are implemented, because two different questions are being asked:

- `_best_window` finds the densest run by count, and the run richest in a chosen
  key. Used by brute force (count) and spray (distinct usernames).
- `_persistent_window` finds the run containing the most keys that appear at
  least *N* times. Used by `distributed-attack`.

The second exists because distinct-counting lies in a specific way: a window can
hold six addresses while only four of them retried. Reporting "6 sources" there
would overstate the evidence by two. Scoring the window the way the finding is
worded — how many sources actually persisted — keeps the number in the title
equal to the number the data supports.

## Why brute force is scoped per account

The obvious implementation is one counter per IP. It is wrong, and the first
realistic log I scanned proved it: 22 failures spread across 22 usernames
tripped it, producing a finding titled "brute force" on what was actually a
credential spray. Two misleading findings, one real attack.

Scoping the count to `(IP, account)` fixed the label. An address that fails once
against 22 usernames has not brute-forced anything, and the mitigation differs
entirely: per-account lockout cannot help against a spray.

`test_a_spray_is_not_reported_as_brute_force` exists to keep that fixed.

## Why "distributed" requires persistence

Six unrelated addresses probing `admin` once each is the normal state of the
public internet. The first version of this detector fired on it six times per
scan — technically true, practically noise, and exactly the kind of output that
teaches a reader to skim past the one finding that matters.

A source now has to *retry* before it counts. Persistence is what separates a
campaign from coincidence, and it is the only cheap signal available offline.

## The compromise check

The highest-value detector is also the simplest: for each accepted login, look
for any failure from the same address in the preceding hour.

This is the check log summarisers miss, because it is not a count — it is a
join. Scanning 40,000 failures is background noise; one success from an address
that just failed 5 times is an incident. It is `critical` and it sorts first.

The failure must be *before* the success. A legitimate session that is later
probed from the same address would otherwise read as a compromise, which is why
`test_success_before_failures_is_ignored` pins the direction.

## Output formats

| Format | Purpose | Contract |
| --- | --- | --- |
| `text` | Terminal | One screen for a normal attack; verdict first |
| `json` | Automation | Counts under `events`, findings with ISO timestamps |
| `sarif` | GitHub code scanning | 2.1.0; `security-severity` aligned with the text severity so a finding is not "high" in CI and "medium" on the Security tab |
| `markdown` | Tickets and wikis | One table row per finding, then detail |

SARIF locations point at a synthetic `sshd:auth` artefact with the address as a
logical location. SSH findings are not about a line of source code, and GitHub
groups alerts sensibly when the logical location is the address.

## Exit codes

`0` clean · `1` findings at or above `--fail-on` · `2` usage or unreadable input.

A gate needs to distinguish "nothing found" from "could not check" — otherwise a
typo in the path turns a security job green. `2` exists for exactly that.

## Known limitations

- **Fixed, unlearned thresholds.** A low-and-slow attacker staying under all four
  will be missed. Deliberate: the alternative is a baseline that needs weeks of
  clean data before it is useful.
- **OpenSSH's default format only.** Custom `LogFormat`, or sshd behind a proxy
  that rewrites source addresses, will not parse as expected.
- **No journald reader.** Piping `journalctl` in keeps the tool a pure file
  reader and lets it work on archived logs. A direct reader would add a
  privileged dependency for no analytical gain.
- **Whole-file parsing.** Streaming is on the roadmap; parsing 100 MB currently
  holds every event in memory.
- **No GeoIP/ASN.** Enrichment would help triage but requires a database shipped
  with the tool or a network call, and the latter is off the table.

## Testing approach

```
tests/test_parse.py        timestamp dialects, event kinds, IPv6, ignored lines
tests/test_detectors.py    every threshold, both directions; silence cases
tests/test_report_cli.py   all four formats, SARIF shape, exit codes
```

The silent tests carry as much weight as the firing ones. Each detector has a
test asserting what it must *not* report — one-shot scanners, a spray against a
brute-force rule, a legit session with no prior failures — because the false
positive is the bug that gets a scanner uninstalled.

CI adds one integration assertion unit tests cannot make: the CLI runs
end-to-end against `demo/auth.log`, must exit non-zero on a critical gate, and
must emit valid SARIF. A broken entry point fails the build rather than the user.
