"""Build the plain-text summary printed to the terminal.

build_report() returns a string instead of printing it. That keeps the
formatting testable (a test can assert on the returned text) and leaves
the decision of where output goes to the caller.

Only ASCII characters and plain spaces are used: no colour codes and no
box-drawing characters. Colour needs extra setup to work in the default
Windows terminal, and the brief was that this must run on all three
operating systems without extra dependencies.
"""

from collections import Counter
from pathlib import Path
from typing import List

from .detect import RULE_BRUTE_FORCE, Finding
from .parser import EVENT_ACCEPTED, FAILURE_EVENTS, ParseResult

WIDTH = 64
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Human readable names for the internal event type codes.
EVENT_LABELS = {
    "failed_password": "Failed password",
    "invalid_user": "Invalid user",
    "accepted": "Accepted login",
}

RULE_LABELS = {
    RULE_BRUTE_FORCE: "BRUTE FORCE",
    "success_after_failures": "SUCCESS AFTER FAILURES",
}


def build_report(
    log_path: Path,
    result: ParseResult,
    findings: List[Finding],
    threshold: int,
    window_minutes: int,
    top_n: int = 5,
) -> str:
    """Return the full analysis report as one block of text."""
    lines: List[str] = []
    lines.append("=" * WIDTH)
    lines.append(" SSH AUTH LOG ANALYSIS")
    lines.append("=" * WIDTH)
    lines.extend(_overview(log_path, result, threshold, window_minutes))
    lines.append("")
    lines.extend(_event_totals(result))
    lines.append("")
    lines.extend(_top_source_ips(result, top_n))
    lines.append("")
    lines.extend(_top_usernames(result, top_n))
    lines.append("")
    lines.extend(_findings_section(findings))
    return "\n".join(lines)


def _plural(count: int, word: str) -> str:
    """Return '1 event' but '2 events'. A small detail, but a report full
    of '1 events' looks unfinished."""
    return "{0} {1}".format(count, word if count == 1 else word + "s")


def _section(title: str) -> str:
    """A section heading padded out to a fixed width, e.g. '--- TOTALS ---'."""
    return "--- {0} {1}".format(title, "-" * max(0, WIDTH - len(title) - 5))


def _overview(log_path: Path, result: ParseResult, threshold: int, window_minutes: int) -> List[str]:
    lines = [
        " File       : {0}".format(log_path),
        " Lines read : {0} ({1} SSH auth events, {2} other lines ignored)".format(
            result.total_lines, len(result.events), result.skipped_lines
        ),
    ]
    if result.events:
        lines.append(
            " Period     : {0} to {1}".format(
                result.events[0].timestamp.strftime(TIME_FORMAT),
                result.events[-1].timestamp.strftime(TIME_FORMAT),
            )
        )
    lines.append(
        " Threshold  : {0} failures within {1} minutes".format(threshold, window_minutes)
    )
    return lines


def _event_totals(result: ParseResult) -> List[str]:
    counts = Counter(event.event_type for event in result.events)
    lines = [_section("EVENT TOTALS")]
    if not result.events:
        lines.append(" No SSH authentication events found in this file.")
        return lines

    for event_type, label in EVENT_LABELS.items():
        lines.append(" {0:<22}{1:>6}".format(label, counts.get(event_type, 0)))
    lines.append(" {0:<22}{1:>6}".format("Total", len(result.events)))
    return lines


def _top_source_ips(result: ParseResult, top_n: int) -> List[str]:
    """The busiest source addresses, with the failed/accepted split.

    The split matters: 40 events from your own jump host is routine, while
    40 events from an unknown address that are all failures is not.
    """
    totals = Counter(event.source_ip for event in result.events)
    failures = Counter(
        event.source_ip for event in result.events if event.event_type in FAILURE_EVENTS
    )
    accepted = Counter(
        event.source_ip for event in result.events if event.event_type == EVENT_ACCEPTED
    )

    lines = [_section("TOP SOURCE IPS")]
    if not totals:
        lines.append(" (none)")
        return lines

    for source_ip, count in totals.most_common(top_n):
        lines.append(
            " {0:<18}{1:>10}   {2} failed / {3} accepted".format(
                source_ip,
                _plural(count, "event"),
                failures.get(source_ip, 0),
                accepted.get(source_ip, 0),
            )
        )
    return lines


def _top_usernames(result: ParseResult, top_n: int) -> List[str]:
    """Which accounts were aimed at. Only failures count here, because a
    list dominated by legitimate daily logins would hide the guessing."""
    counts = Counter(
        event.username for event in result.events if event.event_type in FAILURE_EVENTS
    )
    lines = [_section("MOST TARGETED USERNAMES (failed attempts)")]
    if not counts:
        lines.append(" (none)")
        return lines

    for username, count in counts.most_common(top_n):
        lines.append(" {0:<18}{1:>12}".format(username, _plural(count, "attempt")))
    return lines


def _findings_section(findings: List[Finding]) -> List[str]:
    lines = [_section("FLAGGED IPS ({0})".format(len(findings)))]
    if not findings:
        lines.append(" No source IP met the detection thresholds.")
        return lines

    for finding in findings:
        label = RULE_LABELS.get(finding.rule, finding.rule)
        lines.append("")
        lines.append(" [{0}] {1}".format(label, finding.source_ip))
        lines.append("   Reason     : {0}".format(finding.detail))
        lines.append("   First seen : {0}".format(finding.first_seen.strftime(TIME_FORMAT)))
        lines.append("   Last seen  : {0}".format(finding.last_seen.strftime(TIME_FORMAT)))
        lines.append("   Usernames  : {0}".format(", ".join(finding.usernames)))
    return lines
