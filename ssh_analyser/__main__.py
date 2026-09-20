"""Entry point for `python -m ssh_analyser`.

Keeping this separate from cli.py means cli.main() can be imported and
tested without anything trying to exit the interpreter.
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
