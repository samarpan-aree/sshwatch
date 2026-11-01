# sshwatch

**Turns an SSH auth log into three sentences you can act on — and tells you which account is already compromised.**

[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-99%20passing-brightgreen)](tests/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-success)](pyproject.toml)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](docs/ARCHITECTURE.md)

An internet-facing SSH daemon produces hundreds of failed logins a day. Reading
that by eye is hopeless, and `grep -c "Failed password"` is worse than useless —
it returns one number with no idea whether any of it worked. The line that
matters is the one where somebody **succeeded**.

```
$ sshwatch demo/auth.log

Read 29 auth events from 4 address(es): 26 failures, 3 successes.

3 finding(s): 1 critical, 2 high

  [CRITICAL] Successful login as 'deploy' from 192.0.2.77 after 5 failures
             accepted password for user 'deploy' at 2026-10-31 06:41:00, preceded
             by 5 failure(s) from the same address within 60 minutes.
             fix: Treat account 'deploy' as compromised. Assume persistence:
                  check ~/.ssh/authorized_keys for added keys, review sudoers
                  and cron, then rotate credentials and rebuild.

  [HIGH    ] Credential spray from 198.51.100.23: 8 accounts in 15m
             8 attempts spread over 8 distinct usernames - a low rate per account.
             fix: Block the source and disable PasswordAuthentication. Per-account
                  lockout cannot catch this - only key-only auth will.

  [HIGH    ] 13 failed logins from 203.0.113.66 in 10m
             13 failures against 1 account(s): root (13). Sustained at 10 attempts/minute.
             fix: Block the source with fail2ban or an nftables rule.

Addresses worth blocking (3): 192.0.2.77, 198.51.100.23, 203.0.113.66
```

Real output from `demo/auth.log` in this repository — 29 lines of one host's
afternoon, 26 failures from four addresses, and exactly three things worth
doing. Run the command above and you get this.

## What it detects

| Detector | Fires on | Why separate |
| --- | --- | --- |
| **success-after-failures** | An accepted login from an address that failed within the hour | **Critical.** The only finding that means "someone got in". No count can tell you this. |
| **brute-force** | One address, one account, 10+ failures in 10 minutes | Scoped **per account**, so a spray is not mislabelled |
| **credential-spray** | One address, 6+ distinct usernames in 15 minutes | Defeats per-account lockout; needs a network-level block |
| **distributed-attack** | 5+ sources *each retrying* against one account in 30 minutes | Adds nothing per-IP limiting could catch on its own |

## Design decisions that matter

**Noise is the enemy, not missed detections.** A scanner that reports everything
gets switched off, and one that is off catches nothing. So a source must *retry*
before it counts as part of a distributed attack — hundreds of unrelated
addresses probe `admin` once a day and leave, and reporting that trains the
reader to skim past the finding that matters.

**One attack is one finding.** 22 failures across 22 usernames is a spray, not a
brute force. My first implementation reported both, on one real attack. The
per-account scoping in `detect_brute_force` exists because that happened.

**Every finding carries its own fix** — which account, what persistence to
check, which rule to add. At 2am "review your security posture" is not an
instruction.

## Install

```bash
pip install git+https://github.com/samarpan-aree/sshwatch.git
```

Zero runtime dependencies — standard library only. A security tool you drop onto
a locked-down host should not drag in a tree you then have to audit.

## Usage

```bash
sshwatch /var/log/auth.log                 # human-readable report
sshwatch auth.log --hours 24               # last 24h of the log
sshwatch auth.log auth.log.1 -f json       # merge rotated files
sshwatch auth.log -f sarif -o ssh.sarif    # GitHub code scanning
sshwatch auth.log -f markdown -o out.md    # ticket / wiki
sshwatch auth.log --fail-on high           # CI gate
journalctl -u sshd --since '24 hours ago' | sshwatch -
```

Both dialects work out of the box: classic syslog (`Oct 31 04:51:12 web-01
sshd[3141]: ...`) and journalctl's RFC3339. `--year` sets the year for syslog
lines, which omit it.

Exit codes are the contract: `0` clean, `1` findings at or above `--fail-on`,
`2` usage or unreadable input. `2` exists so a typo in a path fails a security
job rather than passing it.

```yaml
- run: sshwatch auth.log -f sarif -o ssh.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: ssh.sarif }
```

## Architecture

```
cli.py          argparse, exit codes, format dispatch
  └── parse.py       log lines -> AuthEvent
  └── detectors.py   AuthEvent[] -> Finding[]   (pure functions)
  └── report.py      Finding[] -> text/json/sarif/markdown
```

Every detector is a pure function over an already-parsed, sorted event list. None
opens a file, reads the clock, or touches a socket — which is what makes
`sshwatch` offline as a structural property, and why 99 tests run in under 100 ms
with no fixtures. Windows are anchored on the log's own newest timestamp, so
analysing an archived log does not silently return nothing.

Deeper rationale, thresholds and trade-offs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety

**Defensive and offline.** It reads files you point at: no connections, no
scanning, no credential use, no telemetry. Only analyse logs from hosts you own
or have written authorisation to examine. See [SECURITY.md](SECURITY.md).

## Limits worth knowing

- **No live blocking.** It prints a blocklist; applying it is your call.
- **OpenSSH's default log format only.** A custom `LogFormat` or a proxy that
  rewrites source addresses will not parse as expected.
- **Thresholds are fixed, not learned.** A low-and-slow attacker staying under
  all four is missed. Deliberate, and documented rather than hidden.

## Roadmap

- [ ] `--baseline` to report only findings new since a stored snapshot
- [ ] `--block-cmd` to emit ready-made `nft`/`fail2ban` commands
- [ ] Streaming mode for very large logs (currently whole-file)

## License

MIT — see [LICENSE](LICENSE).
