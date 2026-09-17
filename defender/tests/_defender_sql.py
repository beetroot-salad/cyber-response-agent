"""One spawn of `scripts/gather_tools/sql.py`, for every test that runs it as a PROCESS.

Three files drove the tool this way, each with its own spelling of the argv, its own
timeout (none, 60 s, 120 s) and its own choice of bytes-or-text stdin — so a change to the
tool's CLI contract (a new required flag, a stdin encoding rule) had three easy-to-miss
call sites instead of one (#1058). This is the one.

`bin/defender-sql` is the shim a lead types, and it is deliberately bypassed here: it
re-execs into `$DEFENDER_DIR/.venv/bin/python3`, so driving it would test the venv layout
as much as the tool. `tests/e2e/test_query_tool_611.py` drives the shim with `DEFENDER_DIR`
set; this helper drives the program the shim ends in, with the interpreter the tests run
under.

The exit-code names are read off the tool itself rather than retyped as integers, so the
contract has one source of truth. Loading the module executes its top level, which is
cheap and imports duckdb lazily — nothing here needs the `runtime` extra.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender.tests._by_path import DEFENDER, load_module

SQL_PY: Path = DEFENDER / "scripts" / "gather_tools" / "sql.py"

_tool = load_module(SQL_PY, name="defender_sql")
EXIT_OK: int = _tool.EXIT_OK
EXIT_QUERY_ERROR: int = _tool.EXIT_QUERY_ERROR
EXIT_INPUT_ERROR: int = _tool.EXIT_INPUT_ERROR


def run_sql_py(
    *args: str,
    stdin: str = "",
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    """`cat <payload> | defender-sql '<query>'` as a lead types it: `args` is the argv after
    the program, `stdin` the payload text. Text mode, UTF-8 both ways, output captured."""
    return subprocess.run(
        [sys.executable, str(SQL_PY), *args],
        input=stdin, capture_output=True, text=True, encoding="utf-8",
        timeout=timeout, env=env, cwd=cwd,
    )
