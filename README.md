# sshwatch

**Turns an SSH auth log into three sentences you can act on — and tells you which account is already compromised.**

[![CI](https://github.com/samarpan-aree/sshwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/samarpan-aree/sshwatch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-99%20passing-brightgreen)](tests/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-success)](pyproject.toml)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](docs/ARCHITECTURE.md)

An internet-facing SSH daemon produces hundreds of failed logins a day. Reading
that by eye is hopeless, and `grep -c "Failed password"` is worse than useless —
it returns one number with no idea whether any of it worked. The line that
matters is the one where somebody **succeeded**.

`sshwatch` reads the log, separates real attacks from background scanner noise,
and says so in one screen.

```
$ sshwatch demo/auth.log

sshwatch - demo/auth.log

Read 258 auth events from 184 address(es): 253 failures, 5 successes.

3 finding(s): 1 critical, 2 high

  [CRITICAL] Successful login as 'deploy' from 192.0.2.77 after 5 failures
             accepted password for user 'deploy' at 2026-10-31 06:41:00, preceded by 5 failure(s) from the same address within 60 minutes.
             2026-10-31 06:40:11 -> 2026-10-31 06:41:00  (detector: success-after-failures)
             fix: Treat account 'deploy' as compromised. Assume persistence:
                  check ~/.ssh/authorized_keys for added keys, review sudoers
                  and cron, look for new UID 0 accounts, then rotate credentials
                  and rebuild if anything is unexplained.

  [HIGH    ] Credential spray from 198.51.100.23: 22 accounts in 15m
             22 attempts spread over 22 distinct usernames - a low rate per account, which defeats per-account lockout and per-account rate limiting.
             2026-10-31 06:05:18 -> 2026-10-31 06:08:55  (detector: credential-spray)
             fix: Block the source and disable PasswordAuthentication. Because
                  no single account sees enough attempts, per-account lockout
                  cannot catch this - only a network-level block or key-only
                  auth will.

  [HIGH    ] 46 failed logins from 203.0.113.66 in 10m
             46 failures against 1 account(s): root (46). Sustained at 7 attempts/minute.
             2026-10-31 04:51:12 -> 2026-10-31 04:57:28  (detector: brute-force)
             fix: Block the source with fail2ban or an nftables rule, and
                  confirm PasswordAuthentication is off in sshd_config. A
                  password-only SSH daemon reachable from the internet will
                  always see this.

Addresses worth blocking (3):
  192.0.2.77
  198.51.100.23
  203.0.113.66
```

Real output from `demo/auth.log` in this repository — 258 lines containing 253
failures from 184 addresses, and exactly three things worth doing. Not a mock-up.

## What it detects

| Detector | Fires on | Why it is separate |
| --- | --- | --- |
| **success-after-failures** | An accepted login from an address that failed within the last hour | **Critical.** The only finding that means "someone got in". Merely counting failures cannot tell you this. |
| **brute-force** | One address, one account, 10+ failures inside 10 minutes | Scoped **per account**, so a spray is not mislabelled as a brute force |
| **credential-spray** | One address, 6+ distinct usernames inside 15 minutes | Defeats per-account lockout, so it needs a different fix: block at the network layer |
| **distributed-attack** | 5+ sources *each retrying* against one account inside 30 minutes | Per-IP rate limiting cannot stop it; requires a subnet-level rule |

## The two design decisions that matter

**Noise is the enemy, not missed detections.** A scanner that reports everything
gets turned off within a week, and a scanner that is off catches nothing. Two
rules carry most of that weight:

- **Background radiation is not an attack.** Hundreds of unrelated addresses try
  `admin` once each every day on any public host. `distributed-attack` requires
  each source to *retry* — persistence is what makes it a campaign rather than
  coincidence.
- **One attack is one finding.** 22 failures across 22 usernames is a spray, not
  a brute force. Reporting it twice under two names pads the report and makes
  the real critical finding harder to see.

**Reports are read under pressure, so every finding carries its own fix.** Each
one ends with the concrete action: *which* account to treat as compromised,
*what* persistence to check, *which* rule to add. There is no generic "review
your security posture" line, because at 2am that is not an instruction.

## Install

```bash
pip install git+https://github.com/samarpan-aree/sshwatch.git
```

Zero runtime dependencies — standard library only. A security tool you drop onto
a locked-down host should not drag in a dependency tree you then have to audit.

## Usage

```bash
sshwatch /var/log/auth.log                      # human-readable report
sshwatch /var/log/auth.log --hours 24           # last 24h of the log
sshwatch auth.log auth.log.1 -f json            # merge rotated files
sshwatch auth.log -f sarif -o ssh.sarif         # GitHub code scanning
sshwatch auth.log -f markdown -o report.md      # ticket / wiki
sshwatch auth.log --fail-on high                # CI gate
journalctl -u sshd --since '24 hours ago' | sshwatch -
```

Works with both dialects out of the box: classic syslog (`Oct 31 04:51:12
web-01 sshd[3141]: ...`) and journalctl's RFC3339 (`2026-10-31T04:51:12.483+00:00
...`). `--year` sets the year for syslog lines, which omit it.

### As a CI or cron gate

Exit codes are the contract: `0` clean, `1` findings at or above `--fail-on`,
`2` usage or unreadable input.

```yaml
- name: SSH auth review
  run: |
    pip install git+https://github.com/samarpan-aree/sshwatch.git
    sshwatch /var/log/auth.log --hours 24 --fail-on critical
```

### Findings in GitHub code scanning

```yaml
- run: sshwatch auth.log -f sarif -o ssh.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ssh.sarif
```

## Architecture

```
cli.py          argparse, exit codes, format dispatch
  └── parse.py       log lines -> AuthEvent (naive, no network)
  └── detectors.py   AuthEvent[] -> Finding[] (pure functions)
  └── report.py      Finding[] -> text / json / sarif / markdown
```

The rule that makes this testable: **every detector is a pure function.** It
receives an already-parsed, chronologically sorted event list and returns
findings. No detector opens a file, reads the clock, or touches a socket. That
is why 99 tests run in under 100 ms with no fixtures to maintain — each threshold
is asserted with a six-line event sequence rather than a captured log that hides
which condition actually tripped.

Time windows are anchored on the **log's own newest timestamp**, not wall-clock
time, so analysing an archived log does not silently return nothing.

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety

`sshwatch` is **defensive and offline**. It reads files you point at, and does
nothing else: no connections, no scanning, no credential use, no telemetry.

Only analyse logs from hosts you own or have written authorisation to examine.
Report vulnerabilities in sshwatch privately — see [SECURITY.md](SECURITY.md).

## Limits worth knowing

- **It does not read journald directly.** Pipe it in (`journalctl -u sshd | sshwatch -`),
  so it stays a pure file reader and works on archived logs.
- **No live blocking.** It prints a blocklist; applying it is your call. A tool
  that edits firewall rules from a log parser is a worse idea than it sounds.
- **Only OpenSSH's default log format.** Custom `LogFormat`, or sshd behind a
  proxy that rewrites source addresses, will not parse as expected.
- **Thresholds are fixed, not learned.** They are conservative by design; a
  determined low-and-slow attacker staying under all four will be missed. That
  trade-off is deliberate and documented, not hidden.

## Roadmap

- [x] Four detectors with per-finding remediation
- [x] SARIF 2.1.0 for GitHub code scanning
- [x] Windowed analysis anchored on log time, not wall clock
- [ ] `--baseline` to report only findings new since a stored snapshot
- [ ] GeoIP/ASN enrichment for triage, offline database only
- [ ] `--block-cmd` to emit ready-made `nft`/`fail2ban` commands
- [ ] Streaming mode for very large logs (currently whole-file)

## License

MIT — see [LICENSE](LICENSE).
