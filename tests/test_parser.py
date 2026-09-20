"""Tests for turning raw log lines into LogEvent records."""

from datetime import datetime

import pytest

from ssh_analyser.parser import (
    EVENT_ACCEPTED,
    EVENT_FAILED_PASSWORD,
    EVENT_INVALID_USER,
    parse_file,
    parse_line,
)

YEAR = 2026


def test_parses_failed_password():
    line = "Sep 20 14:10:01 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 52344 ssh2"
    event = parse_line(line, YEAR)

    assert event.event_type == EVENT_FAILED_PASSWORD
    assert event.username == "root"
    assert event.source_ip == "203.0.113.45"
    assert event.timestamp == datetime(2026, 9, 20, 14, 10, 1)


def test_parses_invalid_user_as_its_own_event_type():
    """sshd says 'invalid user' when the account does not exist at all.
    That is still a failure, but worth telling apart from a wrong password."""
    line = ("Sep 20 14:10:02 web01 sshd[1234]: Failed password for invalid user "
            "admin from 203.0.113.45 port 40134 ssh2")
    event = parse_line(line, YEAR)

    assert event.event_type == EVENT_INVALID_USER
    assert event.username == "admin"


def test_parses_accepted_password():
    line = "Sep 20 14:10:05 web01 sshd[1299]: Accepted password for alice from 192.0.2.10 port 51000 ssh2"
    event = parse_line(line, YEAR)

    assert event.event_type == EVENT_ACCEPTED
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"


def test_parses_accepted_publickey_with_key_fingerprint():
    """The publickey variant has a trailing fingerprint that must not break
    the match or leak into the username."""
    line = ("Sep 20 14:10:05 web01 sshd[1299]: Accepted publickey for alice from "
            "192.0.2.10 port 51000 ssh2: RSA SHA256:7h2Qp1kXcO9vEr4m0LzYbN6s")
    event = parse_line(line, YEAR)

    assert event.event_type == EVENT_ACCEPTED
    assert event.username == "alice"


def test_handles_windows_line_endings():
    """A log copied from a Linux server to Windows may gain a trailing \\r."""
    line = "Sep 20 14:10:01 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 52344 ssh2\r\n"
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.source_ip == "203.0.113.45"


def test_accepts_sshd_session_process_name():
    """Newer OpenSSH builds log as 'sshd-session' rather than 'sshd'."""
    line = ("Sep 20 14:10:01 web01 sshd-session[1234]: Failed password for root "
            "from 203.0.113.45 port 52344 ssh2")
    assert parse_line(line, YEAR) is not None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "this is not a log line",
        "Sep 20 14:10:06 web01 sudo[99]: pam_unix(sudo:session): session opened",
        "Sep 20 14:10:01 web01 sshd[1234]: Failed password for",          # truncated
        "Sep 20 14:10:01 web01 sshd[1234]: Connection closed [preauth]",  # not an auth result
        "Sep 20 14:10:01 web01 sshd[1234]: Server listening on 0.0.0.0 port 22.",
    ],
)
def test_ignores_lines_that_are_not_ssh_auth_events(line):
    """Anything we do not understand returns None rather than raising: a
    real auth.log is mostly lines this tool does not care about."""
    assert parse_line(line, YEAR) is None


@pytest.mark.parametrize(
    "line",
    [
        "Foo 20 14:10:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
        "Feb 30 14:10:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2",
    ],
)
def test_rejects_impossible_dates(line):
    """A month that does not exist, and 30 February, must not crash."""
    assert parse_line(line, YEAR) is None


def test_missing_pid_is_allowed():
    """The [1234] process id is optional in syslog output."""
    line = "Sep 20 14:10:01 web01 sshd: Failed password for root from 203.0.113.45 port 52344 ssh2"
    assert parse_line(line, YEAR) is not None


def test_year_is_taken_from_the_caller():
    """Classic syslog timestamps carry no year, so the caller supplies it."""
    line = "Jan 01 00:00:00 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
    assert parse_line(line, 1999).timestamp.year == 1999


def test_parse_file_counts_and_sorts(tmp_path):
    """parse_file reports what it skipped, and returns events in time order
    even when the file itself is out of order."""
    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 20 14:10:09 web01 sshd[2]: Failed password for bob from 203.0.113.45 port 2 ssh2\n"
        "garbage line\n"
        "Sep 20 14:10:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2\n",
        encoding="utf-8",
    )

    result = parse_file(log, YEAR)

    assert result.total_lines == 3
    assert result.skipped_lines == 1
    assert [event.username for event in result.events] == ["root", "bob"]


def test_parse_file_handles_an_empty_file(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")

    result = parse_file(log, YEAR)

    assert result.events == []
    assert result.total_lines == 0


def test_parse_file_survives_undecodable_bytes(tmp_path):
    """A corrupt byte in the middle of a log must not stop the analysis."""
    log = tmp_path / "auth.log"
    log.write_bytes(
        b"Sep 20 14:10:01 web01 sshd[1]: Failed password for ro\xffot from 203.0.113.45 port 1 ssh2\n"
        b"Sep 20 14:10:02 web01 sshd[2]: Failed password for bob from 203.0.113.45 port 2 ssh2\n"
    )

    result = parse_file(log, YEAR)

    assert len(result.events) == 2
