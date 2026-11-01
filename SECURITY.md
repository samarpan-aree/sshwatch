# Ethical use and responsible disclosure

## Intended use

`sshwatch` is a **defensive**, **offline** tool. It reads auth log files you
point it at, on disk, and reports attack patterns. It makes no network
connections, performs no authentication attempts, and sends no telemetry.

Read the logs of:

- hosts you own or administer
- systems you have written authorisation to review (client engagements, audits)

Do **not** read logs from systems you are not authorised to examine. Log data
contains usernames, source addresses and session timings; analysing someone
else's is often unauthorised access in itself, regardless of how the file was
obtained.

## By design

- **No network calls.** There is no HTTP, socket or DNS client anywhere in the
  codebase. Nothing is validated against a service, nothing is reported home.
- **Read-only.** `sshwatch` never edits a log, never writes outside the `-o`
  path you name, and never modifies firewall or SSH configuration.
- **No credential use.** It never attempts to authenticate with anything it
  finds. It has no way to.
- **Safe to attach to a ticket.** Output contains usernames and source
  addresses — never passwords or keys.

## If sshwatch reports `success-after-failures`

That finding is `critical` because it means an account was probably taken over.
Treat it as an active incident:

1. **Isolate first.** Do not begin forensics on a host you have not contained;
   assume the attacker still has access.
2. **Rotate that account's credentials** and revoke its SSH keys.
3. **Look for persistence**, in this order:
   - `~/.ssh/authorized_keys`, for both the account and root
   - `crontab -l`, `/etc/cron.*`, and the account's systemd user units
   - `/etc/sudoers` and `/etc/sudoers.d/`
   - new UID 0 accounts, and recently modified `/etc/passwd`
   - shell rc files and `LD_PRELOAD` entries in `/etc/ld.so.preload`
4. **Check what the account could reach** before you trust the rotation.
5. **Rebuild** if anything is unexplained. A cleaned host you are not sure about
   is a host you will be compromised on again.

Then fix the entry point: `PasswordAuthentication no`, and optionally
`AllowUsers` / `AllowGroups` to shrink the surface.

## Reporting a vulnerability in sshwatch

If you find a way to make `sshwatch` execute code, write outside the named
output path, read files outside the given targets, or crash on hostile input,
report it privately via GitHub's
[private vulnerability reporting](https://github.com/samarpan-aree/sshwatch/security/advisories/new)
with the affected version, a minimal reproduction, and the impact.

Acknowledgement within 72 hours; fix or mitigation within 30 days for confirmed
issues. Credit in the release notes unless you prefer otherwise.

A parser crash on hostile log input is treated as medium severity — logs are
attacker-influenced data, since an attacker controls the username they try.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |
