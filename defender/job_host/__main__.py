"""`python -m defender.job_host --kind {investigation,learning,post-step} [--job ID] --tenant T [--source S]
--parent-pid PID`: the per-job host helper, as the worker spawns it (#1170 H7)."""
from __future__ import annotations

import sys

from defender import _log
from defender.job_host._main import main

if __name__ == "__main__":
    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
