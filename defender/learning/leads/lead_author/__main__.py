"""`python -m defender.learning.leads.lead_author --tenant T <run_id>` — the lead-author's
by-hand entry point.

A package runs as a program only through its `__main__.py`.
"""
from __future__ import annotations

import sys

from defender.learning.leads.lead_author import main

if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
