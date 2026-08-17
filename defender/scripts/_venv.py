from __future__ import annotations

import os
import sys
from pathlib import Path

#: `defender/` — derived from THIS file's location, not the caller's, so the helper stays
#: correct however deep the calling script sits.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]


def reexec_into_venv(script: str) -> None:
    """Re-exec `script` under `defender/.venv` if it is not already running there.

    NOT usable from `defender/run.py` or `defender/learning/loop.py`, which hand-roll the same
    three lines — irreducibly: both must re-exec BEFORE any `defender.*` import resolves, and
    importing this helper is itself such an import.
    """
    venv_py = _DEFENDER_DIR / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(script), *sys.argv[1:]])
