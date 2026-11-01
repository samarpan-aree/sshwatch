"""sshwatch - SSH auth log attack detection.

    >>> from sshwatch import parse_lines, run_all
    >>> events = parse_lines([
    ...     "Nov  1 10:00:00 host sshd[1]: Failed password for root from "
    ...     "203.0.113.9 port 5000 ssh2",
    ... ])
    >>> len(events)
    1
"""

from __future__ import annotations

__version__ = "1.0.0"

from .detectors import run_all  # noqa: E402
from .models import AuthEvent, Finding  # noqa: E402
from .parse import parse_line, parse_lines, read_file, sort_events  # noqa: E402
from .report import to_json, to_markdown, to_sarif, to_text  # noqa: E402

__all__ = [
    "__version__",
    "AuthEvent",
    "Finding",
    "parse_line",
    "parse_lines",
    "read_file",
    "sort_events",
    "run_all",
    "to_text",
    "to_json",
    "to_sarif",
    "to_markdown",
]
