"""Write findings out as CSV or JSON, for evidence or further processing.

Both formats contain the same fields, so a finding can be pasted into a
spreadsheet (CSV) or picked up by another script or a SIEM (JSON).
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from .detect import Finding

# Column order for CSV, and key order for JSON. Defined once so the two
# exports can never drift apart.
FIELDS = [
    "source_ip",
    "rule",
    "detail",
    "failure_count",
    "first_seen",
    "last_seen",
    "usernames",
]


def finding_to_row(finding: Finding) -> Dict[str, Any]:
    """Flatten one Finding into plain values that CSV and JSON can hold.

    datetime and tuple are Python types with no direct equivalent in either
    format, so they are converted here, in one place: ISO 8601 for the
    timestamps (sorts correctly as text, unambiguous across locales) and a
    semicolon-separated string for the usernames (a comma would fight with
    the CSV delimiter).
    """
    return {
        "source_ip": finding.source_ip,
        "rule": finding.rule,
        "detail": finding.detail,
        "failure_count": finding.failure_count,
        "first_seen": finding.first_seen.isoformat(sep=" "),
        "last_seen": finding.last_seen.isoformat(sep=" "),
        "usernames": ";".join(finding.usernames),
    }


def write_csv(path: Path, findings: List[Finding]) -> None:
    """Write findings to a CSV file.

    newline="" is required by the csv module: without it, Windows turns the
    \\r\\n the writer emits into \\r\\r\\n and every other row comes out blank.
    """
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding_to_row(finding))


def write_json(path: Path, findings: List[Finding], metadata: Dict[str, Any]) -> None:
    """Write findings to a JSON file, with the run's settings alongside.

    The metadata (source file, thresholds used) is included so a finding
    can still be interpreted months later, when nobody remembers which
    thresholds produced it.
    """
    document = {
        "metadata": metadata,
        "finding_count": len(findings),
        "findings": [finding_to_row(finding) for finding in findings],
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
