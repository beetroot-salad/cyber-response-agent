from __future__ import annotations

import os
import sys
from pathlib import Path

#: `defender/` — derived from THIS file's location, not the caller's. The previous form
#: walked `parents[3]` from the script that called it, which silently made the helper
#: correct only for callers sitting exactly three levels down and wrong (or a no-op) for
#: anything else. Every current caller happens to sit there; the lock was still the reason
#: the two top-level entrypoints could not have used it even in principle.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]


def reexec_into_venv(script: str) -> None:
    """Re-exec `script` under `defender/.venv` if it is not already running there.

    NOT usable from `defender/run.py` or `defender/learning/loop.py`, which hand-roll the
    same three lines. That is irreducible rather than drift: both must re-exec BEFORE any
    `defender.*` import can resolve, and importing this helper is itself such an import —
    reaching it would need the `sys.path` bootstrap the re-exec is supposed to precede.
    """
    venv_py = _DEFENDER_DIR / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(script), *sys.argv[1:]])
