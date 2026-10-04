"""`run_sql_py`'s answer without a fresh interpreter per case: one warm child runs `sql.py`'s
own `main()` once per request.

Each real spawn of the tool costs ~0.3 s of interpreter start and the duckdb import, and the
#1138 / idiom suites ask the tool a few hundred questions. The child imports `sql.py` once and
then, per request, hands `main()` a fresh argv, a fresh stdin and fresh captured stdout/stderr,
and reports the exit code (`SystemExit` from argparse included; an uncaught exception becomes a
`Traceback` on stderr and exit 1, as CPython would). `main()` opens a new in-memory duckdb
connection on every call, so no engine state crosses requests.

What this does NOT exercise, and `run_sql_py` (a real spawn) still does: the `__main__` guard,
the process environment (`env=`), the working directory and the C-locale stdio. A call that sets
any of those falls through to the real spawn.
"""
from __future__ import annotations

import atexit
import json
import subprocess
import sys
from pathlib import Path

from defender.tests._defender_sql import SQL_PY, run_sql_py

_SERVER = r"""
import importlib.util, io, json, sys, traceback
spec = importlib.util.spec_from_file_location("defender_sql_warm", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
wire_in, wire_out = sys.stdin, sys.stdout
for line in wire_in:
    req = json.loads(line)
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    sys.argv = ["defender-sql", *req["argv"]]
    sys.stdin = io.TextIOWrapper(io.BytesIO(req["stdin"].encode("utf-8", "surrogatepass")),
                                 encoding="utf-8")
    sys.stdout, sys.stderr = out, err
    try:
        code = tool.main()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        if isinstance(exc.code, str):
            err.write(exc.code + "\n")
    except BaseException:
        traceback.print_exc(file=err)
        code = 1
    out.flush(); err.flush()
    sys.stdin, sys.stdout, sys.stderr = sys.__stdin__, sys.__stdout__, sys.__stderr__
    reply = {"rc": code,
             "out": out.buffer.getvalue().decode("utf-8", "surrogatepass"),
             "err": err.buffer.getvalue().decode("utf-8", "surrogatepass")}
    wire_out.write(json.dumps(reply) + "\n")
    wire_out.flush()
"""

_child: subprocess.Popen[str] | None = None


def _stop() -> None:
    global _child
    if _child is not None:
        _child.kill()
        _child.wait()
        _child = None


atexit.register(_stop)


def _ask(argv: tuple[str, ...], stdin: str) -> dict:
    global _child
    if _child is None or _child.poll() is not None:
        _child = subprocess.Popen(
            [sys.executable, "-c", _SERVER, str(SQL_PY)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8",
        )
    assert _child.stdin is not None
    assert _child.stdout is not None
    _child.stdin.write(json.dumps({"argv": list(argv), "stdin": stdin}) + "\n")
    _child.stdin.flush()
    line = _child.stdout.readline()
    if not line:
        _stop()
        raise RuntimeError("the warm defender-sql child died mid-request")
    return json.loads(line)


def run_sql_warm(
    *args: str,
    stdin: str = "",
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """`run_sql_py`, answered by the warm child; same result shape. `env`/`cwd` go to a real spawn."""
    if env is not None or cwd is not None:
        return run_sql_py(*args, stdin=stdin, env=env, cwd=cwd)
    try:
        reply = _ask(args, stdin)
    except (RuntimeError, BrokenPipeError):
        return run_sql_py(*args, stdin=stdin)
    return subprocess.CompletedProcess(
        [str(SQL_PY), *args], reply["rc"], stdout=reply["out"], stderr=reply["err"])
