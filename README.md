# SSH Auth Log Analyser

[![tests](https://github.com/vxzino/ssh-auth-log-analyser/actions/workflows/tests.yml/badge.svg)](https://github.com/vxzino/ssh-auth-log-analyser/actions/workflows/tests.yml)

A command-line tool that reads Linux SSH authentication logs (`auth.log`) and
flags suspicious login activity: repeated failed logins from one address, and
successful logins that follow a run of failures.

It is written in Python using only the standard library, and runs on macOS,
Linux and Windows.

## Why this matters

Any SSH server reachable from the internet gets a steady stream of automated
password guessing. In MITRE ATT&CK this is
[T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), and its
sub-technique [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/).

The evidence is already in `auth.log`, but a busy server produces thousands of
lines a day, and the interesting ones are a small fraction of the total. This
tool does the first pass an analyst would otherwise do by hand: it counts
attempts per source address, applies a time-based threshold, and prints the
addresses worth looking at along with the reason each was flagged.

The output is a starting point for an investigation, not a verdict. Everything
it reports still needs a human to confirm.

## What it does

1. Parses SSH events out of an `auth.log` file: timestamp, event type, username
   and source IP.
2. Flags likely brute-force activity: any IP with N or more failed logins
   inside a time window (default 5 in 10 minutes, both configurable).
3. Flags high-risk events: a successful login from an address that failed
   repeatedly first.
4. Prints a summary: event totals, busiest source addresses, most-targeted
   usernames, and each flagged IP with its reason.
5. Optionally exports the findings to CSV or JSON.

## Requirements

- Python 3.9 or newer. Nothing else for normal use.
- `pytest` only if you want to run the test suite.

## Installation

Clone the repository, then set up a virtual environment.

**macOS / Linux**

```bash
git clone https://github.com/vxzino/ssh-auth-log-analyser.git
cd ssh-auth-log-analyser
python3 -m venv .venv
source .venv/bin/activate
python -m ssh_analyser --help
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/vxzino/ssh-auth-log-analyser.git
cd ssh-auth-log-analyser
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m ssh_analyser --help
```

The virtual environment is not strictly required, since the tool has no
dependencies, but it keeps the project self-contained and is the habit worth
having.

> If PowerShell refuses to run the activation script, the usual cause is the
> execution policy. `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
> allows it for that window only.

## Usage

```bash
python -m ssh_analyser <logfile> [options]
```

| Option | Description | Default |
| --- | --- | --- |
| `logfile` | Path to the auth.log file to analyse (required) | |
| `--threshold N` | Failed logins from one IP needed to flag it | `5` |
| `--window MINUTES` | Length of the time window | `10` |
| `--year YYYY` | Year to assume for timestamps | current year |
| `--csv PATH` | Also write findings to a CSV file | off |
| `--json PATH` | Also write findings to a JSON file | off |
| `--version` | Print the version and exit | |

Examples:

```bash
# Analyse a sample log with the default thresholds
python -m ssh_analyser samples/auth_bruteforce.log

# Be stricter: 3 failures in 5 minutes is enough to flag an address
python -m ssh_analyser samples/auth_bruteforce.log --threshold 3 --window 5

# Analyse a real log copied from a server, and export the findings
python -m ssh_analyser ./auth.log --year 2025 --csv findings.csv --json findings.json
```

### Example output

```text
================================================================
 SSH AUTH LOG ANALYSIS
================================================================
 File       : samples/auth_success_after_failures.log
 Lines read : 15 (12 SSH auth events, 3 other lines ignored)
 Period     : 2026-09-20 01:05:22 to 2026-09-20 09:03:17
 Threshold  : 5 failures within 10 minutes

--- EVENT TOTALS -----------------------------------------------
 Failed password            6
 Invalid user               2
 Accepted login             4
 Total                     12

--- TOP SOURCE IPS ---------------------------------------------
 198.51.100.23       7 events   6 failed / 1 accepted
 192.0.2.10          2 events   0 failed / 2 accepted
 203.0.113.99        2 events   2 failed / 0 accepted
 192.0.2.24           1 event   0 failed / 1 accepted

--- MOST TARGETED USERNAMES (failed attempts) ------------------
 deploy              6 attempts
 admin               2 attempts

--- FLAGGED IPS (2) --------------------------------------------

 [SUCCESS AFTER FAILURES] 198.51.100.23
   Reason     : successful login as 'deploy' after 6 failed attempts
   First seen : 2026-09-20 01:40:11
   Last seen  : 2026-09-20 01:42:33
   Usernames  : deploy

 [BRUTE FORCE] 198.51.100.23
   Reason     : 6 failed logins within 10 minutes (threshold 5)
   First seen : 2026-09-20 01:40:11
   Last seen  : 2026-09-20 01:42:09
   Usernames  : deploy
```

## Getting logs to analyse

This tool analyses log **files**. It does not connect to servers and does not
read live logs, so the log has to be on the machine running the tool.

On a Linux server the file is normally at `/var/log/auth.log` (Debian and
Ubuntu) or `/var/log/secure` (RHEL, CentOS and Fedora, same format). Reading it
usually needs `sudo`.

To analyse one from macOS or Windows, copy it across first, for example with
`scp`:

```bash
scp user@server:/var/log/auth.log ./auth.log
python -m ssh_analyser ./auth.log
```

Two points about copied logs:

- **Line endings.** A log copied to Windows may pick up CRLF line endings. The
  parser strips them, so the same file gives the same result on all three
  operating systems.
- **The year.** Classic syslog timestamps (`Sep 20 14:10:01`) contain no year.
  The tool assumes the current year unless you pass `--year`. When analysing an
  older log, set it, or every timestamp in the report will be wrong.

macOS keeps its own SSH logs in the unified logging system rather than in
`auth.log`, so this tool is not aimed at macOS's own logs. macOS here is a
workstation for analysing logs collected from Linux servers.

## How the detection works

### Parsing

Each line is matched in two steps: first the syslog prefix (timestamp, host,
process), then the sshd message itself. Lines from other processes, and sshd
messages that are not authentication results, are skipped and counted as
ignored. Three message types are recognised:

| Log message | Event type |
| --- | --- |
| `Failed password for bob ...` | `failed_password` |
| `Failed password for invalid user bob ...` | `invalid_user` |
| `Accepted password/publickey for bob ...` | `accepted` |

### Rule 1: brute force

Failures are grouped by source IP and kept in time order. Two indexes then walk
the list:

```text
failures for one IP, oldest to newest:

  [ f  f  f  f  f  f  f  f ]
    ^              ^
  start           end        <- the slice between them is always
                                "the failures in the last 10 minutes"
```

`end` moves forward one failure at a time, and `start` is dragged after it
until the gap between the two is no wider than the window. If the slice ever
holds `--threshold` failures or more, the IP is flagged, and the report shows
the busiest window found.

This is a single pass over the failures, and because the window slides rather
than being fixed to the clock, it catches an attack that straddles an hour
boundary as well as one that does not.

### Rule 2: successful login after failures

For each successful login, the tool counts the failures from the same IP that
happened **before** it. Three or more, and the success is flagged. This is the
pattern of a password guess that eventually worked, so it is reported above the
brute-force findings.

The threshold is three rather than two because mistyping a password once or
twice and then getting it right is ordinary user behaviour. The `auth_normal.log`
sample contains exactly that case, and is correctly left unflagged.

## Export formats

Both exports contain the same fields: `source_ip`, `rule`, `detail`,
`failure_count`, `first_seen`, `last_seen`, `usernames`. CSV suits a spreadsheet
or a report appendix; JSON suits another script picking the findings up. The
JSON file also records which thresholds produced the findings, so it can still
be interpreted later.

## Running the tests

```bash
python -m pip install pytest
python -m pytest -v
```

The suite covers parsing (including malformed lines, impossible dates, CRLF
endings and undecodable bytes), the detection thresholds and their exact
boundaries, and the command-line tool end to end against the sample logs.

The same suite runs automatically on `ubuntu-latest`, `macos-latest` and
`windows-latest` via GitHub Actions, which is what the badge at the top
reports.

## Docker

```bash
docker build -t ssh-auth-log-analyser .
docker run --rm -v "$(pwd)/samples:/logs:ro" ssh-auth-log-analyser /logs/auth_bruteforce.log
```

The log directory is mounted read-only, and the container runs as an
unprivileged user.

## Project structure

```text
ssh_analyser/
  parser.py     turns log lines into structured events
  detect.py     the two detection rules
  report.py     builds the terminal summary
  export.py     writes findings to CSV and JSON
  cli.py        argument parsing and the top-level flow
samples/        synthetic logs: normal, brute force, success after failures
tests/          pytest suite
```

The sample logs are synthetic. Every address in them comes from the ranges
reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so
no real host is implicated.

## Limitations

Worth being clear about, because they affect how far the output can be trusted:

- **Thresholds are not proof.** A shared office NAT address can trip the
  brute-force rule through ordinary users forgetting passwords. Every finding
  needs human confirmation.
- **A slow attacker is missed.** Anything under the threshold rate, for example
  three attempts an hour, stays invisible. This is the trade-off for not
  drowning the analyst in false positives.
- **Distributed attacks are missed.** Detection is per IP address, so an attack
  spread across many addresses, each trying a handful of passwords, is not
  caught.
- **One file at a time.** Rotated logs (`auth.log.1`, `auth.log.2.gz`) are not
  read automatically, and gzip is not supported.
- **No year in syslog timestamps.** The year is assumed rather than known, and a
  log that spans New Year's Eve will have the wrong date on part of it.
- **Only three message types.** Other sshd outcomes, such as failed public-key
  attempts or connections closed before authentication, are ignored.
- **`Invalid user` lines are counted once.** sshd logs both `Invalid user bob`
  and `Failed password for invalid user bob` for the same attempt. Only the
  second is counted, so a single attempt is not counted twice.
- **Files, not live logs.** There is no monitoring or alerting; it analyses a
  file that already exists.

## Possible improvements

- Read rotated and gzipped logs, and accept several files at once.
- Detect distributed guessing by grouping on subnet as well as single address.
- Add a rule for a single username targeted across many source addresses.
- Make the "failures before a success" threshold a command-line flag.
- Optional GeoIP or threat-intelligence lookup for flagged addresses.
- An exit code that reflects whether anything was flagged, for use in scripts.
- Output in a standard format such as JSONL for ingestion by a SIEM.

## Licence

MIT. See [LICENSE](LICENSE).
