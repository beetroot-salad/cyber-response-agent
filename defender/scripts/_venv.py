from __future__ import annotations

import os
import sys
from pathlib import Path


def reexec_into_venv(script: str) -> None:
    venv_py = Path(script).resolve().parents[3] / "defender" / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(script), *sys.argv[1:]])
