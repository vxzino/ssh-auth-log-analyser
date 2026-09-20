"""Command-line interface: argument parsing and the top-level flow.

The flow is deliberately linear and easy to follow:

    parse arguments -> read the log -> run the rules -> print -> export

main() takes argv as a parameter and returns an exit code rather than
calling sys.exit() itself. That means a test can call main(["file.log"])
directly and check what came back, without the test process exiting.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import __version__
from .detect import DEFAULT_THRESHOLD, DEFAULT_WINDOW_MINUTES, detect_all
from .export import write_csv, write_json
from .parser import parse_file
from .report import build_report

EXIT_OK = 0
EXIT_ERROR = 1


def build_arg_parser() -> argparse.ArgumentParser:
    """Define every command-line flag.

    Kept in its own function so the tests can inspect the parser, and so
    main() stays short.
    """
    parser = argparse.ArgumentParser(
        prog="ssh-auth-log-analyser",
        description=(
            "Analyse a Linux SSH authentication log and flag suspicious "
            "login activity (brute-force attempts and successful logins "
            "that follow repeated failures)."
        ),
        epilog=(
            "example: python -m ssh_analyser samples/auth_bruteforce.log "
            "--threshold 5 --window 10 --csv findings.csv"
        ),
    )
    parser.add_argument(
        "logfile",
        type=Path,
        help="path to the auth.log file to analyse",
    )
    parser.add_argument(
        "--threshold",
        type=positive_int,
        default=DEFAULT_THRESHOLD,
        metavar="N",
        help="failed logins from one IP needed to flag it (default: %(default)s)",
    )
    parser.add_argument(
        "--window",
        type=positive_int,
        default=DEFAULT_WINDOW_MINUTES,
        metavar="MINUTES",
        help="length of the time window in minutes (default: %(default)s)",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        metavar="YYYY",
        help=(
            "year to assume for log timestamps, which do not include one "
            "(default: the current year)"
        ),
    )
    parser.add_argument(
        "--csv",
        type=Path,
        metavar="PATH",
        help="also write the findings to this CSV file",
    )
    parser.add_argument(
        "--json",
        type=Path,
        metavar="PATH",
        help="also write the findings to this JSON file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {0}".format(__version__),
    )
    return parser


def positive_int(value: str) -> int:
    """An argparse type that rejects zero and negative numbers.

    A threshold of 0 would flag every IP that ever appeared, and a window
    of 0 minutes could never contain two events, so neither is meaningful.
    Catching it here gives a clear error message instead of a confusing
    empty (or enormous) report.
    """
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("'{0}' is not a whole number".format(value))
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or greater, got {0}".format(number))
    return number


def main(argv: Optional[List[str]] = None) -> int:
    """Run the tool. Returns 0 on success, 1 on an error."""
    args = build_arg_parser().parse_args(argv)

    if not args.logfile.is_file():
        # Written to stderr so that piping stdout to a file still shows it.
        print(
            "error: log file not found: {0}".format(args.logfile),
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        result = parse_file(args.logfile, args.year)
    except OSError as error:
        print("error: could not read {0}: {1}".format(args.logfile, error), file=sys.stderr)
        return EXIT_ERROR

    findings = detect_all(result.events, args.threshold, args.window)

    print(build_report(args.logfile, result, findings, args.threshold, args.window))

    metadata = {
        "source_file": str(args.logfile),
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "threshold": args.threshold,
        "window_minutes": args.window,
        "events_parsed": len(result.events),
    }

    try:
        if args.csv:
            write_csv(args.csv, findings)
            print("\nFindings written to {0}".format(args.csv))
        if args.json:
            write_json(args.json, findings, metadata)
            print("Findings written to {0}".format(args.json))
    except OSError as error:
        print("error: could not write export file: {0}".format(error), file=sys.stderr)
        return EXIT_ERROR

    return EXIT_OK
