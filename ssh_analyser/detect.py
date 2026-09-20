"""Detection rules applied to the parsed events.

Two rules are implemented:

1. brute_force            - one IP produced N or more failures inside a
                            rolling time window (default: 5 in 10 minutes).
2. success_after_failures - an IP failed several times and then logged in
                            successfully, which is what a *successful*
                            password-guessing attack looks like.

Both rules are deliberately simple and explainable. They describe patterns
that are worth a human analyst's attention; they are not proof of an attack.
"""

from datetime import datetime, timedelta
from typing import Dict, List, NamedTuple, Tuple

from .parser import EVENT_ACCEPTED, FAILURE_EVENTS, LogEvent

RULE_BRUTE_FORCE = "brute_force"
RULE_SUCCESS_AFTER_FAILURES = "success_after_failures"

# Default thresholds, overridable from the command line.
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 10

# How many failures must precede a success before we treat it as high risk.
# Set to 3 because mistyping a password once or twice and then getting it
# right is ordinary user behaviour: flagging that would bury the real
# findings in noise. Three failures is where guessing becomes more likely
# than fat fingers.
MIN_FAILURES_BEFORE_SUCCESS = 3


class Finding(NamedTuple):
    """One flagged IP address and the reason it was flagged."""

    source_ip: str
    rule: str
    detail: str
    failure_count: int
    first_seen: datetime
    last_seen: datetime
    usernames: Tuple[str, ...]


def group_by_ip(events: List[LogEvent]) -> Dict[str, List[LogEvent]]:
    """Bucket events by their source IP, keeping each bucket in time order."""
    grouped: Dict[str, List[LogEvent]] = {}
    for event in events:
        grouped.setdefault(event.source_ip, []).append(event)
    return grouped


def find_brute_force(
    events: List[LogEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> List[Finding]:
    """Flag any IP with `threshold` or more failures inside `window_minutes`.

    The rolling window uses two indexes over the (time sorted) list of
    failures for one IP:

        start ---------------> end
          [ f f f f f f f f f f ]

    `end` walks forward one failure at a time. `start` is dragged forward
    until the gap between the two is within the window, so the slice
    start..end is always "the failures in the last N minutes". If that
    slice ever grows to `threshold` items, the IP is flagged.

    This is O(number of failures) rather than the O(n^2) of comparing every
    failure against every other one, and it correctly catches a slow attack
    that never bursts but keeps a steady rate.
    """
    window = timedelta(minutes=window_minutes)
    findings: List[Finding] = []

    for source_ip, ip_events in sorted(group_by_ip(events).items()):
        failures = [event for event in ip_events if event.event_type in FAILURE_EVENTS]
        if len(failures) < threshold:
            # Cannot possibly reach the threshold; skip the scan entirely.
            continue

        peak_count = 0
        peak_slice: List[LogEvent] = []
        start = 0

        for end in range(len(failures)):
            # Drag `start` forward until the window is no wider than allowed.
            while failures[end].timestamp - failures[start].timestamp > window:
                start += 1

            count = end - start + 1
            if count > peak_count:
                peak_count = count
                peak_slice = failures[start:end + 1]

        if peak_count >= threshold:
            findings.append(
                Finding(
                    source_ip=source_ip,
                    rule=RULE_BRUTE_FORCE,
                    detail=(
                        "{count} failed logins within {window} minutes "
                        "(threshold {threshold})".format(
                            count=peak_count, window=window_minutes, threshold=threshold
                        )
                    ),
                    failure_count=peak_count,
                    first_seen=peak_slice[0].timestamp,
                    last_seen=peak_slice[-1].timestamp,
                    usernames=_unique_usernames(peak_slice),
                )
            )

    return findings


def find_success_after_failures(
    events: List[LogEvent],
    min_failures: int = MIN_FAILURES_BEFORE_SUCCESS,
) -> List[Finding]:
    """Flag a successful login from an IP that failed `min_failures` times first.

    Only failures *before* the successful login count. A login that succeeds
    first time and fails afterwards is a different (much less worrying)
    story, and lumping the two together would produce false positives.
    """
    findings: List[Finding] = []

    for source_ip, ip_events in sorted(group_by_ip(events).items()):
        failures = [event for event in ip_events if event.event_type in FAILURE_EVENTS]
        successes = [event for event in ip_events if event.event_type == EVENT_ACCEPTED]
        if not failures or not successes:
            continue

        for success in successes:
            earlier = [f for f in failures if f.timestamp < success.timestamp]
            if len(earlier) < min_failures:
                continue

            findings.append(
                Finding(
                    source_ip=source_ip,
                    rule=RULE_SUCCESS_AFTER_FAILURES,
                    detail=(
                        "successful login as '{user}' after {count} failed "
                        "attempts".format(user=success.username, count=len(earlier))
                    ),
                    failure_count=len(earlier),
                    first_seen=earlier[0].timestamp,
                    last_seen=success.timestamp,
                    usernames=_unique_usernames(earlier + [success]),
                )
            )
            # One finding per IP is enough to get an analyst looking; later
            # successes from the same IP would just repeat the same story.
            break

    return findings


def detect_all(
    events: List[LogEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> List[Finding]:
    """Run every rule and return the findings, worst first."""
    findings = find_brute_force(events, threshold, window_minutes)
    findings += find_success_after_failures(events)

    # A confirmed success is more urgent than failed attempts, so sort those
    # to the top; within a rule, the noisiest IP first.
    findings.sort(
        key=lambda finding: (
            finding.rule != RULE_SUCCESS_AFTER_FAILURES,
            -finding.failure_count,
            finding.source_ip,
        )
    )
    return findings


def _unique_usernames(events: List[LogEvent]) -> Tuple[str, ...]:
    """The distinct usernames seen in these events, in alphabetical order."""
    return tuple(sorted({event.username for event in events}))
