"""Rendering findings as text, JSON, SARIF or Markdown.

Nothing here reads files or re-derives data - it formats what detectors
returned. That keeps the report layer trivially testable and means a new output
format is a pure addition.
"""

from __future__ import annotations

import json
from typing import Dict, List, Sequence

from .models import AuthEvent, Finding

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

#: SARIF security-severity scores, the convention GitHub code scanning uses to
#: bucket an alert. Keeping them aligned with the text severities means the
#: same finding is not "high" in CI and "medium" on the Security tab.
SARIF_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def summary_counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def to_text(
    findings: Sequence[Finding],
    events: Sequence[AuthEvent],
    scanned_label: str,
) -> str:
    """The human report. Shape: verdict first, evidence second."""
    failures = sum(1 for e in events if e.failed)
    accepts = sum(1 for e in events if e.accepted)
    ips = len({e.ip for e in events})

    lines: List[str] = []
    lines.append(f"sshwatch - {scanned_label}")
    lines.append("")
    lines.append(
        f"Read {len(events):,} auth events from {ips:,} address(es): "
        f"{failures:,} failures, {accepts:,} successes."
    )
    lines.append("")

    if not findings:
        lines.append("No attack patterns detected.")
        lines.append("")
        lines.append(
            "This means nothing met the thresholds - not that the log is clean. "
            "A slow, low-volume attempt can stay under every one of them."
        )
        return "\n".join(lines)

    counts = summary_counts(findings)
    ordered = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
    )
    lines.append(f"{len(findings)} finding(s): {ordered}")
    lines.append("")

    for finding in findings:
        lines.append(f"  [{finding.severity.upper():8}] {finding.title}")
        lines.append(f"             {finding.detail}")
        lines.append(
            f"             {finding.first_seen:%Y-%m-%d %H:%M:%S} -> "
            f"{finding.last_seen:%Y-%m-%d %H:%M:%S}  (detector: {finding.detector})"
        )
        if finding.remediation:
            for i, chunk in enumerate(_wrap(finding.remediation, 62)):
                prefix = "             fix: " if i == 0 else "                  "
                lines.append(prefix + chunk)
        lines.append("")

    blocked = sorted({f.ip for f in findings if f.ip and not f.ip.startswith("(")})
    if blocked:
        lines.append(f"Addresses worth blocking ({len(blocked)}):")
        for ip in blocked[:40]:
            lines.append(f"  {ip}")
        if len(blocked) > 40:
            lines.append(f"  ... and {len(blocked) - 40} more")
    return "\n".join(lines)


def to_json(findings: Sequence[Finding], events: Sequence[AuthEvent]) -> str:
    payload = {
        "tool": "sshwatch",
        "version": "1.0.0",
        "events": {
            "total": len(events),
            "failures": sum(1 for e in events if e.failed),
            "accepted": sum(1 for e in events if e.accepted),
            "addresses": len({e.ip for e in events}),
        },
        "summary": summary_counts(findings),
        "findings": [
            {
                "detector": f.detector,
                "severity": f.severity,
                "title": f.title,
                "ip": f.ip,
                "count": f.count,
                "first_seen": f.first_seen.isoformat(),
                "last_seen": f.last_seen.isoformat(),
                "detail": f.detail,
                "remediation": f.remediation,
                "users": list(f.users),
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def to_sarif(findings: Sequence[Finding]) -> str:
    """SARIF 2.1.0 for GitHub code scanning.

    SSH findings are not about a line of source code, so results point at a
    synthetic `sshd:auth` location carrying the IP as a logical location. That
    is enough for GitHub to group alerts by address instead of by line.
    """
    rule_ids = sorted({f.detector for f in findings})
    rules = []
    for rule_id in rule_ids:
        sample = next(f for f in findings if f.detector == rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", " ").title(),
                "shortDescription": {"text": sample.title},
                "help": {"text": sample.remediation or sample.detail},
                "properties": {
                    "security-severity": SARIF_SCORE.get(sample.severity, "0.0"),
                    "tags": ["security", "ssh"],
                },
            }
        )

    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.detector,
                "level": SARIF_LEVEL.get(finding.severity, "note"),
                "message": {"text": f"{finding.title}. {finding.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "sshd:auth"},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"name": finding.ip, "kind": "address"}],
                    }
                ],
                "properties": {"severity": finding.severity, "count": finding.count},
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sshwatch",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/samarpan-aree/sshwatch",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def to_markdown(findings: Sequence[Finding], events: Sequence[AuthEvent]) -> str:
    lines = [
        "# SSH auth log report",
        "",
        f"- Events parsed: **{len(events):,}**",
        f"- Failures: **{sum(1 for e in events if e.failed):,}**",
        f"- Successful logins: **{sum(1 for e in events if e.accepted):,}**",
        f"- Distinct addresses: **{len({e.ip for e in events}):,}**",
        f"- Findings: **{len(findings)}**",
        "",
    ]
    if not findings:
        lines.append("No attack patterns detected.")
        return "\n".join(lines)

    lines.append("| Severity | Detector | Source | Count | Window |")
    lines.append("| --- | --- | --- | --- | --- |")
    for f in findings:
        window = f"{f.first_seen:%m-%d %H:%M} → {f.last_seen:%m-%d %H:%M}"
        lines.append(
            f"| {f.severity} | {f.detector} | `{f.ip}` | {f.count} | {window} |"
        )
    lines.append("")
    lines.append("## Detail")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.title}")
        lines.append("")
        lines.append(f.detail)
        lines.append("")
        if f.remediation:
            lines.append(f"**Fix:** {f.remediation}")
            lines.append("")
    return "\n".join(lines)
