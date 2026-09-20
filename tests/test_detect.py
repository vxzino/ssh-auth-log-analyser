"""Tests for the detection rules.

These build LogEvent objects directly rather than parsing text, so a
failure here points at the detection logic and not at the regexes.
"""

from datetime import datetime, timedelta

from ssh_analyser.detect import (
    RULE_BRUTE_FORCE,
    RULE_SUCCESS_AFTER_FAILURES,
    detect_all,
    find_brute_force,
    find_success_after_failures,
)
from ssh_analyser.parser import EVENT_ACCEPTED, EVENT_FAILED_PASSWORD, LogEvent

BASE = datetime(2026, 9, 20, 3, 0, 0)
ATTACKER = "203.0.113.45"


def event(minutes_in, event_type=EVENT_FAILED_PASSWORD, ip=ATTACKER, username="root"):
    """Build one event, `minutes_in` minutes after a fixed starting point."""
    return LogEvent(
        timestamp=BASE + timedelta(minutes=minutes_in),
        event_type=event_type,
        username=username,
        source_ip=ip,
        line_number=0,
    )


# --- brute force -----------------------------------------------------------

def test_flags_exactly_at_the_threshold():
    """5 failures with a threshold of 5 must be flagged: the rule is
    'N or more', not 'more than N'."""
    events = [event(minute) for minute in range(5)]

    findings = find_brute_force(events, threshold=5, window_minutes=10)

    assert len(findings) == 1
    assert findings[0].source_ip == ATTACKER
    assert findings[0].rule == RULE_BRUTE_FORCE
    assert findings[0].failure_count == 5


def test_does_not_flag_one_below_the_threshold():
    events = [event(minute) for minute in range(4)]

    assert find_brute_force(events, threshold=5, window_minutes=10) == []


def test_window_edge_is_inclusive():
    """Failures at 0 and 10 minutes are 10 minutes apart, so a 10 minute
    window contains both."""
    events = [event(0), event(1), event(2), event(3), event(10)]

    assert len(find_brute_force(events, threshold=5, window_minutes=10)) == 1


def test_just_outside_the_window_is_not_flagged():
    """The same five failures, with the last one a second too late."""
    events = [event(0), event(1), event(2), event(3), event(10.02)]

    assert find_brute_force(events, threshold=5, window_minutes=10) == []


def test_finds_a_burst_inside_a_long_quiet_period():
    """The window slides: a burst in the middle of hours of slow activity
    is still caught, which is the point of not simply counting per hour."""
    events = [event(0), event(60), event(120)]
    events += [event(180 + minute) for minute in range(5)]
    events += [event(400)]

    findings = find_brute_force(events, threshold=5, window_minutes=10)

    assert len(findings) == 1
    assert findings[0].failure_count == 5


def test_each_ip_is_counted_separately():
    """Four failures from two different IPs are not eight from one."""
    events = [event(minute, ip="203.0.113.45") for minute in range(4)]
    events += [event(minute, ip="198.51.100.77") for minute in range(4)]

    assert find_brute_force(events, threshold=5, window_minutes=10) == []


def test_successful_logins_do_not_count_towards_the_threshold():
    events = [event(0), event(1), event(2), event(3)]
    events.append(event(4, event_type=EVENT_ACCEPTED))

    assert find_brute_force(events, threshold=5, window_minutes=10) == []


def test_lower_threshold_flags_more():
    """The thresholds are configurable, so the same log can be looked at
    more or less strictly."""
    events = [event(minute) for minute in range(3)]

    assert find_brute_force(events, threshold=5, window_minutes=10) == []
    assert len(find_brute_force(events, threshold=3, window_minutes=10)) == 1


def test_finding_records_the_targeted_usernames():
    events = [event(minute, username=name) for minute, name in
              enumerate(["root", "admin", "test", "root", "git"])]

    finding = find_brute_force(events, threshold=5, window_minutes=10)[0]

    assert finding.usernames == ("admin", "git", "root", "test")


def test_no_events_produces_no_findings():
    assert find_brute_force([], threshold=5, window_minutes=10) == []


# --- success after failures ------------------------------------------------

def test_flags_success_after_repeated_failures():
    events = [event(0), event(1), event(2)]
    events.append(event(3, event_type=EVENT_ACCEPTED, username="deploy"))

    findings = find_success_after_failures(events, min_failures=3)

    assert len(findings) == 1
    assert findings[0].rule == RULE_SUCCESS_AFTER_FAILURES
    assert findings[0].failure_count == 3
    assert "deploy" in findings[0].detail


def test_ignores_a_success_after_only_a_couple_of_typos():
    events = [event(0), event(1)]
    events.append(event(2, event_type=EVENT_ACCEPTED))

    assert find_success_after_failures(events, min_failures=3) == []


def test_only_failures_before_the_success_count():
    """Logging in first time and failing afterwards is a different story,
    and must not be flagged."""
    events = [event(0, event_type=EVENT_ACCEPTED)]
    events += [event(minute) for minute in range(1, 6)]

    assert find_success_after_failures(events, min_failures=3) == []


def test_failures_from_a_different_ip_do_not_count():
    events = [event(minute, ip="198.51.100.77") for minute in range(5)]
    events.append(event(6, event_type=EVENT_ACCEPTED, ip="192.0.2.10"))

    assert find_success_after_failures(events, min_failures=3) == []


# --- combined --------------------------------------------------------------

def test_a_confirmed_success_is_reported_before_failed_attempts():
    """An attacker who got in matters more than one who did not, so that
    finding must appear first in the report."""
    events = [event(minute) for minute in range(6)]
    events.append(event(7, event_type=EVENT_ACCEPTED))

    findings = detect_all(events, threshold=5, window_minutes=10)

    assert [finding.rule for finding in findings] == [
        RULE_SUCCESS_AFTER_FAILURES,
        RULE_BRUTE_FORCE,
    ]
