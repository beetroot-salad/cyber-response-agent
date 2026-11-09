"""Fixtures for the #1347 r6.4 lab-side contract (capture, make-a-case, launcher).

Nothing here touches docker, the VPS or a cluster: every lab operation goes through an injected
seam and is recorded in a shared journal. CI runs them in the lint job, step "Run lab frozen-case
tests"; locally, from the repository root:

    defender-pytest defender/.venv/bin/python -m pytest playground-v2/scripts/tests -q
"""
from __future__ import annotations

import sys
from pathlib import Path

PLAYGROUND_ROOT = Path(__file__).resolve().parents[2]
for path in (PLAYGROUND_ROOT, Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
