"""Tests for the report formats and the CLI contract.

The SARIF assertions matter most: a malformed SARIF file fails silently in
GitHub code scanning (nothing appears on the Security tab), so the shape is
asserted rather than eyeballed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from sshwatch.cli import _severity_at_least, main
from sshwatch.models import ACCEPTED_PASSWORD, FAILED, AuthEvent, Finding
from sshwatch.report import (
    SARIF_SCORE,
    summary_counts,
    to_json,
    to_markdown,
    to_sarif,
    to_text,
)

BASE = datetime(2026, 11, 1, 10, 0, 0)


def ev(minute: int = 0, ip: str = "203.0.113.9", user: str = "root", kind: str = FAILED) -> AuthEvent:
    return AuthEvent(ts=BASE + timedelta(minutes=minute), ip=ip, user=user, kind=kind)


def finding(**kwargs) -> Finding:
    defaults = dict(
        detector="brute-force",
        severity="high",
        title="12 failed logins from 203.0.113.9 in 10m",
        ip="203.0.113.9",
        count=12,
        first_seen=BASE,
        last_seen=BASE + timedelta(minutes=9),
        detail="12 failures across 1 account(s) (root), peaking at 1 attempts/minute.",
        remediation="Block the source with fail2ban.",
        users=("root",),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestText:
    def test_clean_report_says_so_without_claiming_safety(self):
        out = to_text([], [ev(0)], "auth.log")
        assert "No attack patterns detected" in out
        assert "not that the log is clean" in out

    def test_summary_counts_events(self):
        events = [ev(0), ev(1), ev(2, kind=ACCEPTED_PASSWORD, user="sam")]
        out = to_text([], events, "auth.log")
        assert "3 auth events" in out
        assert "2 failures" in out
        assert "1 successes" in out

    def test_findings_render_with_fix(self):
        out = to_text([finding()], [ev(0)], "auth.log")
        assert "[HIGH    ] 12 failed logins" in out
        assert "fail2ban" in out

    def test_blocklist_lists_offenders(self):
        found = [finding(), finding(ip="198.51.100.4", count=3)]
        out = to_text(found, [ev(0)], "auth.log")
        assert "Addresses worth blocking (2)" in out
        assert "203.0.113.9" in out and "198.51.100.4" in out

    def test_distributed_pseudo_ip_is_not_in_blocklist(self):
        found = [finding(ip="(distributed)", detector="distributed-attack")]
        out = to_text(found, [ev(0)], "auth.log")
        assert "worth blocking" not in out


class TestJson:
    def test_is_valid_json_with_expected_keys(self):
        payload = json.loads(to_json([finding()], [ev(0)]))
        assert payload["tool"] == "sshwatch"
        assert payload["events"]["total"] == 1
        assert payload["summary"] == {"high": 1}
        assert payload["findings"][0]["users"] == ["root"]

    def test_timestamps_are_iso(self):
        payload = json.loads(to_json([finding()], []))
        assert payload["findings"][0]["first_seen"] == BASE.isoformat()

    def test_empty_findings_is_empty_list_not_null(self):
        payload = json.loads(to_json([], [ev(0)]))
        assert payload["findings"] == []


class TestSarif:
    def test_version_and_schema(self):
        doc = json.loads(to_sarif([finding()]))
        assert doc["version"] == "2.1.0"
        assert "sarif" in doc["$schema"]

    def test_high_maps_to_error_level(self):
        doc = json.loads(to_sarif([finding()]))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_security_severity_matches_table(self):
        doc = json.loads(to_sarif([finding()]))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == SARIF_SCORE["high"]

    def test_rules_are_deduplicated(self):
        found = [finding(), finding(title="same rule twice")]
        doc = json.loads(to_sarif(found))
        assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(doc["runs"][0]["results"]) == 2

    def test_result_has_location(self):
        result = json.loads(to_sarif([finding()]))["runs"][0]["results"][0]
        loc = result["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "sshd:auth"
        assert loc["logicalLocations"][0]["name"] == "203.0.113.9"

    def test_empty_findings_still_valid(self):
        doc = json.loads(to_sarif([]))
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []


class TestMarkdown:
    def test_table_row_per_finding(self):
        out = to_markdown([finding()], [ev(0)])
        assert "| high | brute-force | `203.0.113.9` | 12 |" in out

    def test_detail_section_present(self):
        out = to_markdown([finding()], [ev(0)])
        assert "## Detail" in out
        assert "**Fix:**" in out

    def test_clean_log(self):
        assert "No attack patterns detected." in to_markdown([], [ev(0)])


class TestSummaryCounts:
    def test_counts_each_severity(self):
        found = [finding(), finding(severity="critical"), finding(severity="critical")]
        assert summary_counts(found) == {"high": 1, "critical": 2}


class TestSeverityGate:
    @pytest.mark.parametrize(
        "severity,threshold,expected",
        [
            ("critical", "high", True),
            ("high", "high", True),
            ("medium", "high", False),
            ("low", "critical", False),
            ("critical", "low", True),
        ],
    )
    def test_ordering(self, severity, threshold, expected):
        assert _severity_at_least(finding(severity=severity), threshold) is expected


LOG = (
    "Nov  1 10:00:00 web-01 sshd[9]: Failed password for root "
    "from 203.0.113.9 port 50022 ssh2\n"
) * 12


@pytest.fixture()
def logfile(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(LOG, encoding="utf-8")
    return str(path)


class TestCli:
    def test_text_exit_zero_without_fail_on(self, logfile, capsys):
        assert main([logfile]) == 0
        assert "failed logins" in capsys.readouterr().out

    def test_fail_on_high_exits_one(self, logfile, capsys):
        assert main([logfile, "--fail-on", "high"]) == 1

    def test_fail_on_critical_exits_zero_for_high_findings(self, logfile, capsys):
        assert main([logfile, "--fail-on", "critical"]) == 0

    def test_output_file_written_and_stdout_silent(self, logfile, tmp_path, capsys):
        out = tmp_path / "report.json"
        assert main([logfile, "-f", "json", "-o", str(out)]) == 0
        assert capsys.readouterr().out == ""
        assert json.loads(out.read_text())["tool"] == "sshwatch"

    def test_json_format_to_stdout(self, logfile, capsys):
        main([logfile, "-f", "json"])
        assert json.loads(capsys.readouterr().out)["summary"]["high"] == 1

    def test_quiet_suppresses_report(self, logfile, capsys):
        main([logfile, "--quiet"])
        assert capsys.readouterr().out == ""

    def test_missing_file_exits_two(self, tmp_path, capsys):
        assert main([str(tmp_path / "nope.log")]) == 2
        assert "cannot read input" in capsys.readouterr().err

    def test_unparseable_log_exits_two(self, tmp_path, capsys):
        path = tmp_path / "empty.log"
        path.write_text("nothing here\n", encoding="utf-8")
        assert main([str(path)]) == 2
        assert "no auth events parsed" in capsys.readouterr().err

    def test_zero_hours_is_a_usage_error(self, logfile, capsys):
        assert main([logfile, "--hours", "0"]) == 2

    def test_multiple_files_are_merged(self, tmp_path, capsys):
        a = tmp_path / "a.log"
        b = tmp_path / "b.log"
        a.write_text(LOG, encoding="utf-8")
        b.write_text(LOG.replace("web-01", "web-02"), encoding="utf-8")
        main([str(a), str(b), "-f", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["events"]["total"] == 24

    def test_sarif_format_from_cli(self, logfile, capsys):
        main([logfile, "-f", "sarif"])
        assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"
