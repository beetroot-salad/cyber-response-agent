"""Shared venv re-exec for defender CLIs (pure stdlib).

Collected from the copies that the lessons trio (`_lessons_common`) and the
lessons frontend (`frontend/build.py` + `frontend/serialize.py`) each hand-rolled,
so every CLI that needs a venv-only dependency (PyYAML) swaps into
`defender/.venv` through one implementation.

Deliberately **pure stdlib** — it imports nothing the venv provides, so a caller
can import it on a bare system `python3` (the actor's Bash tool, a direct
`python3 defender/.../x.py` run) *before* :func:`reexec_into_venv` swaps the
interpreter, then call it from the script's `__main__` guard before importing any
venv-only dependency.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def reexec_into_venv(script: str) -> None:
    """Re-exec the current process under `defender/.venv`'s python.

    `script` is the calling module's `__file__`; the venv is located relative to
    it (`<repo>/defender/.venv`, the script being 3 levels under the repo root).
    A no-op when the venv python is missing (e.g. CI without a bootstrapped venv)
    or is already the running interpreter (e.g. the `bin/` shim) — so it never
    double-execs. Call only from a `__main__` guard: an import-time `os.execv`
    would silently hijack an importing test runner.
    """
    venv_py = Path(script).resolve().parents[3] / "defender" / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(script), *sys.argv[1:]])
