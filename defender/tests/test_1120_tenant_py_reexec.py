"""#1120 piece 1 — `tenant.py`'s venv re-exec cannot loop (code review, max).

A checkout whose `defender/.venv/bin/python3` exists but whose `pyvenv.cfg` does not (an
interrupted `uv venv`) runs that interpreter with the BASE install's prefix. A guard keyed on
the prefix alone exec'd it again, forever, at full CPU with no output.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H


def test_a_venv_without_pyvenv_cfg_is_exec_d_once_not_forever(tmp_path: Path) -> None:
    """`.venv/bin/python3` a link to the base interpreter, no `pyvenv.cfg`: `tenant.py check
    --folder` finishes (whatever it then says), well inside the timeout. The precondition:
    the planted interpreter really reports a prefix other than the venv's."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    venv_bin = checkout / "defender" / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    base = Path(getattr(sys, "_base_executable", sys.executable))
    (venv_bin / "python3").symlink_to(base)
    prefix = subprocess.run([str(venv_bin / "python3"), "-c", "import sys; print(sys.prefix)"],
                            capture_output=True, text=True, check=True, timeout=30).stdout
    assert Path(prefix.strip()).resolve() != (venv_bin.parent).resolve(), (
        "precondition: the planted interpreter reports the venv's prefix")
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    try:
        subprocess.run([sys.executable, str(script), "check", "--folder", str(tmp_path)],
                       capture_output=True, text=True, timeout=30, check=False,
                       cwd=str(checkout))
    except subprocess.TimeoutExpired:
        raise AssertionError("tenant.py re-exec'd itself in a loop") from None
