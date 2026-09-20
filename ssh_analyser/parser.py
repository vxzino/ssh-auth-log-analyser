"""Turn raw auth.log lines into structured events.

An auth.log line from OpenSSH looks like this:

    Sep 20 14:10:01 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 52344 ssh2
    |-------------| |---| |--------|  |------------------------------------------------------|
      timestamp     host   process                        message

We split that into two steps:

1. SYSLOG_LINE matches the common prefix (timestamp, host, process name).
2. The message is then matched against the few sshd messages we care about.

Splitting it this way keeps each regex short enough to read, and means we
can ignore non-sshd lines (sudo, cron, systemd...) cheaply.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import List, NamedTuple, Optional

# Event types. Using constants instead of bare strings means a typo is a
# NameError (loud) rather than a silently non-matching string (quiet).
EVENT_FAILED_PASSWORD = "failed_password"
EVENT_INVALID_USER = "invalid_user"
EVENT_ACCEPTED = "accepted"

# The two event types that represent a failed authentication attempt.
FAILURE_EVENTS = (EVENT_FAILED_PASSWORD, EVENT_INVALID_USER)

# Month names are mapped by hand rather than using strptime("%b"), because
# %b depends on the machine's locale. A hard-coded table gives identical
# results on macOS, Linux and Windows, in any language setting.
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"      # Sep
    r"(?P<day>\d{1,2})\s+"               # 20   (single digits are space padded)
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"    # 14:10:01
    r"(?P<host>\S+)\s+"                  # web01
    r"(?P<process>[\w\-/]+)"             # sshd
    r"(?:\[\d+\])?:\s+"                  # [1234]:   (the pid is optional)
    r"(?P<message>.*)$"                  # Failed password for root from ...
)

# "Failed password for root from 203.0.113.45 port 52344 ssh2"
# "Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2"
FAILED_PASSWORD = re.compile(
    r"^Failed password for (?P<invalid>invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+) port \d+"
)

# "Accepted password for alice from 192.0.2.10 port 51000 ssh2"
# "Accepted publickey for alice from 192.0.2.10 port 51000 ssh2: RSA SHA256:..."
ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?P<username>\S+) from (?P<ip>\S+) port \d+"
)


class LogEvent(NamedTuple):
    """One authentication event we care about.

    A NamedTuple is used rather than a plain dict because the fields are
    fixed and known in advance: it is immutable, it reads like a record
    (event.source_ip), and ._asdict() gives us a dict for free when it is
    time to write CSV or JSON.
    """

    timestamp: datetime
    event_type: str
    username: str
    source_ip: str
    line_number: int


class ParseResult(NamedTuple):
    """Everything parse_file() found, including what it had to skip."""

    events: List[LogEvent]
    total_lines: int
    skipped_lines: int


def parse_line(line: str, year: int, line_number: int = 0) -> Optional[LogEvent]:
    """Parse a single log line. Return None if it is not an sshd auth event.

    Returning None (rather than raising) is deliberate: a real auth.log is
    full of lines we do not care about, so "not interesting" is the normal
    case, not an error.
    """
    # Strip whitespace and any trailing carriage return, so a log copied
    # from a Windows machine (CRLF line endings) parses the same as one
    # read on Linux.
    line = line.strip()
    if not line:
        return None

    prefix = SYSLOG_LINE.match(line)
    if prefix is None:
        return None

    # Only sshd writes the messages we understand. This also covers names
    # like "sshd-session" used by newer OpenSSH builds.
    if not prefix.group("process").startswith("sshd"):
        return None

    message = prefix.group("message")

    match = FAILED_PASSWORD.match(message)
    if match is not None:
        # sshd says "invalid user bob" when the account does not exist at
        # all, and just "bob" when the account exists but the password was
        # wrong. Both are failures; the distinction is useful to an analyst.
        event_type = EVENT_INVALID_USER if match.group("invalid") else EVENT_FAILED_PASSWORD
    else:
        match = ACCEPTED.match(message)
        if match is None:
            return None
        event_type = EVENT_ACCEPTED

    timestamp = _build_timestamp(prefix, year)
    if timestamp is None:
        return None

    return LogEvent(
        timestamp=timestamp,
        event_type=event_type,
        username=match.group("username"),
        source_ip=match.group("ip"),
        line_number=line_number,
    )


def _build_timestamp(prefix: "re.Match", year: int) -> Optional[datetime]:
    """Combine the syslog date parts and the given year into a datetime.

    Classic syslog timestamps have no year in them, which is why the year
    has to be supplied by the caller (see the --year flag).
    """
    month = MONTHS.get(prefix.group("month"))
    if month is None:
        return None

    hour, minute, second = (int(part) for part in prefix.group("time").split(":"))
    try:
        return datetime(year, month, int(prefix.group("day")), hour, minute, second)
    except ValueError:
        # e.g. "Feb 30", or 29 February in a non-leap year.
        return None


def parse_file(path: Path, year: int) -> ParseResult:
    """Read a log file and return every sshd auth event in it.

    The file is opened with an explicit UTF-8 encoding so behaviour does
    not change with the machine's default encoding (Windows in particular
    does not default to UTF-8 on older Python versions). errors="replace"
    means a single corrupt byte cannot crash a whole analysis run.
    """
    events: List[LogEvent] = []
    total_lines = 0
    skipped_lines = 0

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            total_lines += 1
            event = parse_line(line, year, line_number)
            if event is None:
                skipped_lines += 1
            else:
                events.append(event)

    # Sort by time: the detection logic below assumes events are in order,
    # and concatenated or merged log files are not always sorted.
    events.sort(key=lambda event: event.timestamp)
    return ParseResult(events=events, total_lines=total_lines, skipped_lines=skipped_lines)
