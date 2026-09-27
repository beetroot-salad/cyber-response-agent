"""`python -m defender.learning.leads.lead_author <run_dir>` — the lead-author's by-hand entry point.

A package runs as a program only through its `__main__.py`; the `if __name__ == "__main__"` block
that used to sit in `__init__.py` could never run, so the operator path the drains and their tests
describe had no door until this file.
"""
from __future__ import annotations

import sys

from defender.learning.leads.lead_author import main

if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
