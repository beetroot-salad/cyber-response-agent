from __future__ import annotations

import os
import sys
from pathlib import Path

#: `defender/`, the folder this module sits in, so it is right however deep the caller sits.
_DEFENDER_DIR = Path(__file__).resolve().parent


def reexec_into_venv(script: str) -> None:
    """Re-exec `script` under `defender/.venv` if it is not already running there.

    Not usable from `defender/run.py` or `defender/learning/loop.py`, which must re-exec before
    any `defender.*` import (importing this helper is one), so they inline the same re-exec —
    without the `DEFENDER_BOX` skip below: both are host-side entry points.

    Inside a box (`DEFENDER_BOX` set) the image's `python3` already has what is needed, and
    re-execing into the mounted `.venv` would undercut the boundary, so it is skipped. See
    `bin/README.md`'s Conventions section for what that does and does not guarantee.
    """
    if os.environ.get("DEFENDER_BOX"):
        return
    venv_py = _DEFENDER_DIR / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(script), *sys.argv[1:]])
