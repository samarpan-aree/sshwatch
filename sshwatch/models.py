"""The two data structures the whole tool is built around."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Tuple

# Event kinds. OpenSSH writes several distinct lines per authentication
# attempt; these are the only ones that carry a decision.
FAILED = "failed"
INVALID = "invalid_user"
ACCEPTED_PASSWORD = "accepted_password"
ACCEPTED_KEY = "accepted_publickey"

ACCEPTED = frozenset({ACCEPTED_PASSWORD, ACCEPTED_KEY})

#: Severities, ordered worst first. Used for sorting and for --fail-on.
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class AuthEvent:
    """One authentication decision lifted from one log line."""

    ts: datetime
    ip: str
    user: str
    kind: str
    port: Optional[int] = None
    raw: str = ""

    @property
    def failed(self) -> bool:
        return self.kind in (FAILED, INVALID)

    @property
    def accepted(self) -> bool:
        return self.kind in ACCEPTED


@dataclass(frozen=True)
class Finding:
    """One pattern worth a human's attention."""

    detector: str
    severity: str
    title: str
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    detail: str
    remediation: str = ""
    users: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def rank(self) -> int:
        return SEVERITIES.index(self.severity) if self.severity in SEVERITIES else len(SEVERITIES)
