"""#1162 — a command's refusal, and a `check`'s findings, are a message to the person who ran
it: plain text on stderr, the exit code carrying the verdict. Stdout stays for results a caller
consumes (and, after #1114, for a service's logs), so nothing here may land on it.

  * `tenant.py check` — a refusal and a finding — and `held_out`'s refusals print on stderr
    with stdout empty.
  * A refused path holding a byte that is not UTF-8 is still refused, not a traceback, under a
    strict-UTF-8 stdout: stderr escapes such bytes on every host, stdout does not.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from defender.evals import held_out
from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: A path whose last byte is not UTF-8 (0xE9), as argv carries it on POSIX.
_NOT_UTF8 = "/nonexistent/caf\udce9"
#: The stdout of a host with a UTF-8 locale and no `PYTHONUTF8` — this box's C locale is lax.
_STRICT_STDOUT = "utf-8:strict"


def _on_stderr_only(proc: subprocess.CompletedProcess, *names: str, rc: int = 1) -> None:
    H.assert_refused(proc, *names, rc=rc)
    assert proc.stdout == "", f"the refusal reached stdout:\n{proc.stdout}"
    for name in names:
        assert name in proc.stderr, f"stderr does not name {name!r}:\n{proc.stderr}"


def _held_out(*args: str, encoding: str = "") -> subprocess.CompletedProcess:
    return H.run_script(H.script_of(held_out), *args, root=None, PYTHONIOENCODING=encoding)


def test_tenant_check_refusal_is_on_stderr(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-folder"
    _on_stderr_only(H.check(tenant_py, None, "--folder", str(missing)),
                    "[tenant.py]", str(missing))


def test_tenant_check_finding_is_on_stderr(tmp_path: Path) -> None:
    """A folder the folder rules accept, in a repo with no commit: `check`'s finding."""
    folder = tmp_path / "fresh"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, "id")
    H.git(folder, "init", "-q", "-b", "main")
    _on_stderr_only(H.check(tenant_py, None, "--folder", str(folder)),
                    "[tenant.py]", "is not committed")


def test_held_out_refusals_are_on_stderr(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _on_stderr_only(_held_out(str(tmp_path / "absent")), "runs dir does not exist", rc=2)
    runs.mkdir()
    empty = tmp_path / "no-fixtures"
    empty.mkdir()
    _on_stderr_only(_held_out(str(runs), "--fixtures-dir", str(empty)),
                    "no held-out fixtures found")


def test_a_path_that_is_not_utf8_is_refused_not_crashed() -> None:
    _on_stderr_only(
        H.check(tenant_py, None, "--folder", _NOT_UTF8, PYTHONIOENCODING=_STRICT_STDOUT),
        "[tenant.py]")
    _on_stderr_only(_held_out(_NOT_UTF8, encoding=_STRICT_STDOUT), "runs dir does not exist", rc=2)
