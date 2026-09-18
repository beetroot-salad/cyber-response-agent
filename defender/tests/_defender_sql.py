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

The exit codes are LITERALS, deliberately not read off the tool: they are the contract
`skills/gather/defender-sql.md` teaches the lead (`1` = query error, `2` = payload never
arrived), and every `assert proc.returncode == EXIT_*` below a spawn is what holds the tool
to it. Read off the tool they would follow any renumbering and pin nothing. Keeping the
tool out of this process also keeps its top level (a `sys.path` insert, a `defender._io`
import) out of every importer, and a tool that cannot execute here fails one assertion
with the child's stderr rather than turning three modules into collection errors.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests._by_path import DEFENDER

SQL_PY: Path = DEFENDER / "scripts" / "gather_tools" / "sql.py"

EXIT_OK = 0
EXIT_QUERY_ERROR = 1
EXIT_INPUT_ERROR = 2
#: `duckdb` missing — the `runtime` extra is not installed. `run_sql_py` turns this into a
#: skip so the three files that spawn the tool share one policy instead of one skipping and
#: two failing with a message about the query.
EXIT_NO_RUNTIME = 69

#: The tool's own prefix on a duckdb refusal — prose `sql.py` owns, not duckdb's. Exit 1 is
#: also CPython's code for an uncaught exception, so the exit code alone cannot tell a
#: refusal from a crash; this can, without pinning duckdb's wording (#1057).
QUERY_ERROR_MARK = "defender-sql: query error:"


def run_sql_py(
    *args: str,
    stdin: str = "",
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    """`cat <payload> | defender-sql '<query>'` as a lead types it: `args` is the argv after
    the program, `stdin` the payload text. Text mode, UTF-8 both ways, output captured."""
    proc = subprocess.run(
        [sys.executable, str(SQL_PY), *args],
        input=stdin, capture_output=True, text=True, encoding="utf-8",
        timeout=timeout, env=env, cwd=cwd,
    )
    if proc.returncode == EXIT_NO_RUNTIME:
        pytest.skip(f"duckdb is not installed in {sys.executable} (the `runtime` extra)")
    return proc


def assert_query_error(proc: subprocess.CompletedProcess[str], why: str) -> None:
    """duckdb refused the query and the tool reported it — not a crash that also exits 1."""
    detail = f"{why}: exit {proc.returncode}, stderr {proc.stderr!r}"
    assert proc.returncode == EXIT_QUERY_ERROR, detail
    assert QUERY_ERROR_MARK in proc.stderr, detail
