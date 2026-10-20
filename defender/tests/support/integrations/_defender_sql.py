"""One spawn of the sql engine (`runtime/sql_engine/sql.py`), for every test that runs it as a
PROCESS."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._by_path import DEFENDER

#: The engine's source file (read as text by the census tests, loaded by `_sql_warm`).
SQL_PY: Path = DEFENDER / "runtime" / "sql_engine" / "sql.py"
#: How the shim starts it: as a module, the working directory kept off `sys.path`.
SQL_ARGV: tuple[str, ...] = (sys.executable, "-P", "-m", "defender.runtime.sql_engine.sql")


def sql_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """`env` (default: this process's) with this checkout's root first on `PYTHONPATH`, as the
    shim puts it."""
    out = dict(os.environ if env is None else env)
    root = str(DEFENDER.parent)
    out["PYTHONPATH"] = os.pathsep.join(p for p in (root, out.get("PYTHONPATH")) if p)
    return out

EXIT_OK = 0
EXIT_QUERY_ERROR = 1
EXIT_INPUT_ERROR = 2
#: The tool could not import duckdb. `run_sql_py` makes this a skip ONLY when the package
#: is absent from the interpreter it spawns (a dev-only checkout); an installed duckdb that
#: fails to import is a broken environment and stays a failure, so CI — where the `runtime`
#: extra is synced and these tests block a merge — cannot go green on skips.
EXIT_NO_RUNTIME = 69
#: Asked of `sys.executable`, the interpreter `run_sql_py` spawns, so the answer is the
#: child's; nothing is imported at collection.
_DUCKDB_INSTALLED = importlib.util.find_spec("duckdb") is not None

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
        [*SQL_ARGV, *args],
        input=stdin, capture_output=True, text=True, encoding="utf-8",
        timeout=timeout, env=sql_env(env), cwd=cwd,
    )
    if proc.returncode == EXIT_NO_RUNTIME and not _DUCKDB_INSTALLED:
        pytest.skip(f"duckdb is not installed in {sys.executable} (the `runtime` extra)")
    return proc


def assert_query_error(proc: subprocess.CompletedProcess[str], why: str) -> None:
    """duckdb refused the query and the tool reported it — not a crash that also exits 1."""
    detail = f"{why}: exit {proc.returncode}, stderr {proc.stderr!r}"
    assert proc.returncode == EXIT_QUERY_ERROR, detail
    assert QUERY_ERROR_MARK in proc.stderr, detail
