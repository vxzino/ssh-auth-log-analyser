"""SSH authentication log analyser.

A small command-line tool that reads Linux SSH auth logs and flags
suspicious login activity (brute-force attempts and successful logins
that follow failures).
"""

__version__ = "1.0.0"
