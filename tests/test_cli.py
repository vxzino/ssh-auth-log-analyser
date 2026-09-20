"""End-to-end tests: run main() against the real sample logs.

These are the tests that would catch the modules being wired together
wrongly, which the unit tests above cannot see.
"""

import csv
import json
from pathlib import Path

import pytest

from ssh_analyser.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_normal_log_flags_nothing(capsys):
    """The quiet sample must produce no findings. A tool that cries wolf on
    ordinary traffic is worse than useless."""
    exit_code = main([str(SAMPLES / "auth_normal.log"), "--year", "2026"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No source IP met the detection thresholds." in output


def test_brute_force_log_flags_both_attackers(capsys):
    exit_code = main([str(SAMPLES / "auth_bruteforce.log"), "--year", "2026"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "FLAGGED IPS (2)" in output
    assert "203.0.113.45" in output
    assert "198.51.100.77" in output
    assert "BRUTE FORCE" in output


def test_success_after_failures_log_reports_the_successful_login(capsys):
    main([str(SAMPLES / "auth_success_after_failures.log"), "--year", "2026"])
    output = capsys.readouterr().out

    assert "SUCCESS AFTER FAILURES" in output
    assert "198.51.100.23" in output
    assert "deploy" in output


def test_missing_file_reports_an_error(capsys):
    exit_code = main([str(SAMPLES / "does_not_exist.log")])

    assert exit_code == 1
    assert "log file not found" in capsys.readouterr().err


def test_threshold_flag_changes_what_is_flagged(capsys):
    """Two failures from 203.0.113.99 are ignored by default, but a
    threshold of 2 should pick them up."""
    log = str(SAMPLES / "auth_success_after_failures.log")

    main([log, "--year", "2026"])
    assert "203.0.113.99" not in _flagged_section(capsys.readouterr().out)

    main([log, "--year", "2026", "--threshold", "2"])
    assert "203.0.113.99" in _flagged_section(capsys.readouterr().out)


def test_rejects_a_threshold_of_zero():
    """argparse exits with code 2 on a bad argument; the point of the test
    is that the tool refuses rather than silently flagging everything."""
    with pytest.raises(SystemExit):
        main([str(SAMPLES / "auth_normal.log"), "--threshold", "0"])


def test_writes_csv_export(tmp_path):
    output = tmp_path / "findings.csv"
    main([str(SAMPLES / "auth_bruteforce.log"), "--year", "2026", "--csv", str(output)])

    # newline="" on read as well, so the blank-row problem on Windows would
    # show up here as extra empty rows.
    with output.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 2
    assert rows[0]["source_ip"] == "203.0.113.45"
    assert rows[0]["rule"] == "brute_force"
    assert rows[0]["failure_count"] == "12"
    assert "root" in rows[0]["usernames"]


def test_writes_json_export(tmp_path):
    output = tmp_path / "findings.json"
    main([str(SAMPLES / "auth_bruteforce.log"), "--year", "2026", "--json", str(output)])

    document = json.loads(output.read_text(encoding="utf-8"))

    assert document["finding_count"] == 2
    assert document["metadata"]["threshold"] == 5
    assert document["metadata"]["window_minutes"] == 10
    assert document["findings"][0]["source_ip"] == "203.0.113.45"


def test_export_files_are_still_written_when_there_is_nothing_to_report(tmp_path):
    """An empty findings file is a useful result: it records that the log
    was checked. A missing file looks like the tool never ran."""
    output = tmp_path / "findings.json"
    main([str(SAMPLES / "auth_normal.log"), "--year", "2026", "--json", str(output)])

    document = json.loads(output.read_text(encoding="utf-8"))

    assert document["finding_count"] == 0
    assert document["findings"] == []


def _flagged_section(output):
    """Just the 'FLAGGED IPS' part of the report, so that an IP appearing in
    the 'top source IPs' table does not make the assertion pass by accident."""
    return output.split("FLAGGED IPS")[-1]
