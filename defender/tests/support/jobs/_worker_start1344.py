"""#1344 O15 test support: `python -m defender.worker` as a real process, and the probes around it.

The worker is started the way an image would: no PYTHONPATH, the code tree found from the working
directory (`-m` puts it first). `build_source` makes that tree once: the checkout's `defender/` without its
tests, plus a planted `.venv`, so a copy that carries it is visible."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[3]
MARKER = ".defender-code-copy.json"
STAMP = "1344" + "a" * 36
#: A database address nothing listens on: a worker that reaches for it fails with a connection error, not a refusal.
CLOSED_DSN = "postgresql://postgres:postgres@127.0.0.1:9/none?connect_timeout=1"
VENV_SENTINEL = ".venv/bin/sentinel"


def build_source(root: Path) -> Path:
    """`<root>/defender`: the checkout's package without `tests`, with a `.venv` planted. Returns `<root>`."""
    target = root / "defender"
    shutil.copytree(DEFENDER, target, ignore=shutil.ignore_patterns("tests", ".venv", "__pycache__", "*.db", ".git"))
    (target / ".venv" / "bin").mkdir(parents=True)
    (target / VENV_SENTINEL).write_text("venv\n", encoding="utf-8")
    return root


def worker_env(data_root: Path, *, dsn: str = CLOSED_DSN, stamp: str | None = STAMP, slots: str | None = None,
               learning: str | None = None, extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment of an image: no PYTHONPATH, no inherited `DEFENDER_*`, the settings as named (`None` leaves one
    unset). `PYTHONDONTWRITEBYTECODE` is whatever the host has: the worker owes the children that setting itself."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith("DEFENDER_")}
    env.update({"DEFENDER_DATABASE_DSN": dsn, "DEFENDER_DATA_ROOT": str(data_root)})
    for name, value in (("DEFENDER_BUILD_COMMIT", stamp), ("DEFENDER_WORKER_SLOTS", slots),
                        ("DEFENDER_WORKER_LEARNING_SLOTS", learning)):
        if value is not None:
            env[name] = value
    return {**env, **(extra or {})}


def start(source: Path, env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 — the worker under test
        [sys.executable, "-m", "defender.worker"], cwd=source, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_to_exit(source: Path, env: dict[str, str], *, timeout: float = 60) -> subprocess.CompletedProcess:
    """A start that is expected to end by itself (a refusal)."""
    proc = start(source, env)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise AssertionError(f"the worker neither served nor refused within {timeout}s; stderr: {err.decode(errors='replace')[-800:]}") from None
    return subprocess.CompletedProcess(proc.args, proc.returncode, out.decode(errors="replace"), err.decode(errors="replace"))


def wait_until(condition: Callable[[], bool], *, timeout: float, what: str, proc: subprocess.Popen | None = None) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if proc is not None and proc.poll() is not None:
            raise AssertionError(f"the worker exited ({proc.returncode}) while waiting for {what}: "
                                 f"{proc.stderr.read().decode(errors='replace')[-1200:]}")
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.02)


def code_copies(data_root: Path) -> list[Path]:
    """Every copy root under the data root: the folder holding the marker (the repository root's shape, with
    `defender/` inside it), whatever it is named or nested."""
    return sorted(p.parent for p in data_root.rglob(MARKER))


def files_under(root: Path) -> dict[str, tuple[str, int]]:
    """Relative path -> (content digest, mtime_ns) for every file, symlinks not followed. Not inodes: a delete and
    copy reuses them, so they cannot tell a replace from a reuse."""
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest() if not p.is_symlink() else os.readlink(p),
                                       p.lstat().st_mtime_ns)
            for p in sorted(root.rglob("*")) if not p.is_dir()}


def kill_group(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=30)
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


@contextmanager
def serving(source: Path, env: dict[str, str], *, ready: Callable[[], bool], what: str = "the worker to serve",
            timeout: float = 120) -> Iterator[subprocess.Popen]:
    """A worker process, waited on until `ready()`; killed at the end if the case left it running."""
    proc = start(source, env)
    try:
        wait_until(ready, timeout=timeout, what=what, proc=proc)
        yield proc
    finally:
        kill_group(proc)


def stop(proc: subprocess.Popen, *, timeout: float = 60) -> int:
    proc.send_signal(signal.SIGTERM)
    return proc.wait(timeout=timeout)


def stderr_of(proc: subprocess.Popen) -> str:
    return proc.stderr.read().decode(errors="replace") if proc.stderr is not None else ""


def children_of(pid: int) -> list[int]:
    found: list[int] = []
    for task in Path(f"/proc/{pid}/task").glob("*"):
        try:
            found += [int(p) for p in (task / "children").read_text(encoding="utf-8").split()]
        except OSError:
            continue
    return found


def _cmdline(pid: int) -> list[bytes]:
    return Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]


def snapshot_process(pid: int, *, forked_from: list[bytes] | None = None) -> dict | None:
    """argv, environment and working directory of a live process, or None while it is not readable as itself: gone,
    or still the image of its parent between fork and exec (`forked_from`: the parent's argv). Read twice around
    the environment, so a process that execs in between is retried, not mixed."""
    try:
        argv = _cmdline(pid)
        environ = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        cwd = os.readlink(f"/proc/{pid}/cwd")
        again = _cmdline(pid)
    except OSError:
        return None
    if not argv or argv != again or argv == forked_from:
        return None
    return {"pid": pid, "argv": [a.decode(errors="replace") for a in argv], "cwd": cwd,
            "env": dict(e.decode(errors="replace").split("=", 1) for e in environ if b"=" in e)}


def watch_children(proc: subprocess.Popen, done: Callable[[list[dict]], bool], *, timeout: float) -> list[dict]:
    """Poll the worker's children until `done(everything read so far)`; every child read after its exec is returned."""
    seen: dict[int, dict] = {}
    parent = _cmdline(proc.pid)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and proc.poll() is None:
        for pid in children_of(proc.pid):
            if pid not in seen and (info := snapshot_process(pid, forked_from=parent)) is not None:
                seen[pid] = info
        if done(list(seen.values())):
            break
        time.sleep(0.002)
    return list(seen.values())


#: Runs a script the way `python script args` does, then writes {module name: file} of every module that has one.
DUMP_WRAPPER = r"""
import atexit, json, os, runpy, sys
out, script, *rest = sys.argv[1:]
module = script.startswith("-m:")
if module:
    script = script[3:]
    sys.argv = [script, *rest]
else:
    sys.argv = [script, *rest]
    sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
def _dump():
    found = {n: os.path.realpath(m.__file__) for n, m in list(sys.modules.items()) if getattr(m, "__file__", None)}
    open(out, "w", encoding="utf-8").write(json.dumps(found))
atexit.register(_dump)
try:
    runpy.run_module(script, run_name="__main__", alter_sys=True) if module else runpy.run_path(script, run_name="__main__")
except SystemExit as exc:
    sys.exit(exc.code)
"""


def modules_of(script: Path | str, args: list[str], *, env: dict[str, str], cwd: Path, out: Path,
               timeout: float = 180) -> tuple[subprocess.CompletedProcess, dict[str, str]]:
    """Run `script args` as a script (a `-m:<module>` string: as a module, from `cwd`) under `DUMP_WRAPPER`; returns the process and every loaded module's file."""
    ran = subprocess.run(  # noqa: S603 — the entry under test
        [sys.executable, "-c", DUMP_WRAPPER, str(out), str(script), *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False)
    return ran, (json.loads(out.read_text(encoding="utf-8")) if out.exists() else {})


def module_files_outside(modules: dict[str, str], tree: Path) -> dict[str, str]:
    """First-party (`defender*`) modules whose file is not under `tree`."""
    root = os.path.realpath(tree)
    return {n: f for n, f in modules.items()
            if (n == "defender" or n.startswith("defender.")) and not f.startswith(root + os.sep)}
