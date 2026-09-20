"""Let pytest import the ssh_analyser package from the project root.

Without this, running `pytest` from the project root fails with
"ModuleNotFoundError: No module named 'ssh_analyser'", because pytest puts
the tests/ folder on the import path, not the folder above it.

Doing it explicitly here (rather than installing the project, or relying
on pytest's automatic path handling) keeps the project runnable straight
from a clone on any of the three operating systems.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
