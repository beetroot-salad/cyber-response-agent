"""Shared machinery for #1135's spec — "one learning-state handle with queue verbs, file-backed
on `Held`". NO test functions; underscore-prefixed so pytest never collects it."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import fcntl
import json
import os
import stat
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from defender.learning.core.config import LoopPaths
from defender.learning.core.state import LearningState, StateRefused  # noqa: F401 — re-exported: the tests open the handle as `S.LearningState`
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, run_of  # noqa: F401 — the 1135 suite's doors onto the planted run a row names (#1105 PR 2)

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"



def core_fn(name: str) -> Callable[..., Any]:
    """`move_at` / `open_lock_at`, beside `Held` in `defender._io`, reached by name so a missing
    one fails this test's own assertion rather than the file's import."""
    from defender import _io

    fn = getattr(_io, name, None)
    assert callable(fn), f"defender._io.{name} does not exist (D2 adds it beside Held)"
    return fn

# ---------------------------------------------------------------------------------------------
# Roots
# ---------------------------------------------------------------------------------------------


def built_paths(tmp_path: Path, *, repo_root: Path | None = None) -> LoopPaths:
    """`LoopPaths` over a CREATED state root at `<tmp>/learning-state` (the root must exist;
    the operator, here the fixture, creates it). Nothing below the root is made."""
    root = tmp_path / "learning-state"
    root.mkdir(parents=True, exist_ok=True)
    return LoopPaths(repo_root=repo_root or (tmp_path / "repo"), state_dir=root)


def outside(tmp_path: Path, name: str = "target.jsonl", text: str = '{"outside": 1}\n') -> Path:
    """A plain file OUTSIDE the state root — what a planted link points at."""
    d = tmp_path / "outside"
    d.mkdir(parents=True, exist_ok=True)
    f = d / name
    f.write_text(text, encoding="utf-8")
    return f


# ---------------------------------------------------------------------------------------------
# Plants: real non-plain entries made with the real primitive
# ---------------------------------------------------------------------------------------------

#: The non-plain entry shapes a record name can be planted as; `plant` makes each on disk.
SHAPES = ("symlink", "fifo", "folder", "hardlink")


def plant(at: Path, shape: str, *, target: Path | None = None) -> Path:
    """Make a non-plain entry at `at` (its parent is made): `symlink` to `target`, a dangling
    `symlink` when `target` does not exist, a `fifo`, a `folder`, or a `hardlink` to `target`
    (same filesystem). Returns `at`."""
    at.parent.mkdir(parents=True, exist_ok=True)
    if shape == "symlink":
        assert target is not None
        os.symlink(target, at)
    elif shape == "fifo":
        os.mkfifo(at)
    elif shape == "folder":
        at.mkdir()
    elif shape == "hardlink":
        assert target is not None, "a hardlink plant needs a target"
        assert target.is_file(), "a hardlink plant needs a plain target file"
        os.link(target, at)
    else:  # pragma: no cover — a typo in a test
        raise ValueError(shape)
    return at


@contextlib.contextmanager
def fifo_holding(at: Path, payload: bytes) -> Iterator[Callable[[], bool]]:
    """A FIFO at `at` that already holds `payload`, written through a read-write descriptor
    this helper keeps open (so neither end of the pipe blocks the test). Yields `unread()`,
    which is True while every byte of the payload is still in the pipe."""
    at.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(at)
    fd = os.open(at, os.O_RDWR | os.O_NONBLOCK)
    try:
        os.write(fd, payload)

        def unread() -> bool:
            try:
                got = os.read(fd, len(payload) + 4096)
            except BlockingIOError:
                got = b""
            if got:
                os.write(fd, got)  # put it back, so a later check reads the same pipe
            return got == payload

        yield unread
    finally:
        os.close(fd)


def entry_kind(p: Path) -> str:
    """What stands at `p`, never following it: absent / link / dir / fifo / file."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(st.st_mode):
        return "link"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISFIFO(st.st_mode):
        return "fifo"
    return "file"


def tree_snapshot(top: Path) -> dict[str, tuple[str, bytes | str | None]]:
    """Every entry under `top`, never following a link: relpath -> (kind, content). A file's
    content is its bytes, a link's its target text, a FIFO's nothing (it is never opened)."""
    out: dict[str, tuple[str, bytes | str | None]] = {}
    if entry_kind(top) != "dir":
        return out
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        for name in [*dirnames, *filenames]:
            p = Path(dirpath, name)
            kind = entry_kind(p)
            rel = str(p.relative_to(top))
            if kind == "file":
                out[rel] = (kind, p.read_bytes())
            elif kind == "link":
                out[rel] = (kind, os.readlink(p))
            else:
                out[rel] = (kind, None)
    return out


# ---------------------------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------------------------


def caught(fn: Callable[[], Any]) -> BaseException | None:
    """Run `fn`; the exception it raised, or None. The test asserts on what escaped."""
    try:
        fn()
    except KeyboardInterrupt:
        raise
    # `BaseException`: a refusal is not an `Exception`, and it is what most tests expect to escape.
    except BaseException as e:  # noqa: BLE001 — the test classifies what escaped, not this helper
        return e
    return None


def is_refusal(exc: BaseException | None) -> bool:
    return isinstance(exc, StateRefused)


def rows_of(answer: Any) -> list[dict]:
    """A read verb's rows, whether it answers the rows or `(rows, malformed)`."""
    if isinstance(answer, tuple) and len(answer) == 2 and isinstance(answer[0], list):
        return answer[0]
    return list(answer) if answer is not None else []


def jsonl_rows(p: Path) -> list[dict]:
    """The rows of a plain JSONL file read by its real name (absent -> [])."""
    if entry_kind(p) != "file":
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(p: Path, rows: list[dict]) -> None:
    """Seed a plain JSONL file by its real name (the fixture's write, not the handle's)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def request_body(case_id: str, run_dir: Path, **extra: Any) -> dict:
    """The curation request record body: `{case_id, tenant_id, run_id}`, the address of the
    natural run at `run_dir`, read off where it lives (`_state1135.curation_row`; plant the run
    with `_state1135.curation_run_dir`)."""
    return {**curation_row(case_id, run_dir), **extra}


def seed_request(paths: LoopPaths, case_id: str, run_dir: Path, *, inflight: bool = False,
                 **extra: Any) -> Path:
    """A plain request record at `author-queue/[inflight/]<case_id>.json`, written by the
    fixture."""
    run_dir.mkdir(parents=True, exist_ok=True)
    folder = location_path(paths.state_root) / "author-queue" / ("inflight" if inflight else "")
    folder.mkdir(parents=True, exist_ok=True)
    rec = folder / f"{case_id}.json"
    rec.write_text(json.dumps(request_body(case_id, run_dir, **extra)) + "\n", encoding="utf-8")
    return rec


# ---------------------------------------------------------------------------------------------
# Locks, held by an actor outside the handle
# ---------------------------------------------------------------------------------------------


@contextlib.contextmanager
def held_flock(path: Path) -> Iterator[None]:
    """Hold an exclusive `flock` on `path` through a separate open of the file — another
    holder, as a second process or an appender would be. Two opens of one name exclude each
    other even in one process. The file is made if absent (`O_CREAT`, as `a+` does)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def flock_free(path: Path) -> bool:
    """Whether another holder could take `path`'s lock right now (a try-once take, released)."""
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)  # closing the description releases a lock taken through it
    return True


def within(seconds: float, fn: Callable[[], Any]) -> tuple[bool, Any, BaseException | None]:
    """Run `fn` on a daemon thread under a hard wall-clock cap: `(finished, result, error)`.

    A wait the implementation never ends cannot hang the suite: the thread is abandoned and
    the test fails on `finished`."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = fn()
        except BaseException as e:  # noqa: BLE001 — reported to the test, which asserts on it
            box["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=seconds)
    return (not t.is_alive()), box.get("result"), box.get("error")


def child_env() -> dict[str, str]:
    """The environment of a child interpreter that imports `defender.*` from THIS checkout.

    pytest's `pythonpath = [".."]` only edits the parent's `sys.path`; a child launched with
    `sys.executable` inherits it only through `PYTHONPATH`, which CI does not set (the namespace
    package is not installed). The checkout's root goes first, as `_drain719.run_in_subprocess`
    does."""
    inherited = os.environ.get("PYTHONPATH")
    path = os.pathsep.join([str(REPO_ROOT), *([inherited] if inherited else [])])
    return {**os.environ, "PYTHONPATH": path}
