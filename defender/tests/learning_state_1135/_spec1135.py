"""Shared machinery for #1135's spec — "one learning-state handle with queue verbs, file-backed
on `Held`". NO test functions; underscore-prefixed so pytest never collects it.

Imported by every test file here as
`from defender.tests.learning_state_1135 import _spec1135 as S`.

The change (`spec-flow/specs/spec_graph_1135-learning-state-handle.yaml`; the design is
revision 3 as clarified by revision 3.1, `.spec-flow/inputs/design.md`): every host touch of the
learning-state tree goes behind ONE handle, `LearningState`, opened at an entry point on an
EXISTING root (R15; a missing or non-folder root is `FatalConfigError` naming the root and
`DEFENDER_LEARNING_STATE_DIR`). Today's request layout is unchanged (R14). The one new behaviour
is that a non-plain entry planted below the root (a link, hard link, FIFO, or a folder where a
file belongs) is refused as `StateRefused(record, reason)`: not an `OSError`, a member of
`faults.SYSTEMIC_FAULTS`, so a drain tick exits 2 through `_run_stage` (R16, 3.1 A/B). The
exemptions are E1 (the run-end enqueue logs and continues), E2 (the queue page counts it
unreadable) and E3 (the judge logs and continues). Ordinary I/O errors keep today's routing.

NONE OF THE NEW NAMES EXISTS AT BASE d9128afa. The handle's module is imported ONCE below inside
a `try`, so a missing module is ONE failure per test at the point the test first uses the
handle (`ModuleNotFoundError` from `_Missing`), never a collection error hiding every other
test. The two core functions D2 adds to an EXISTING module (`defender._io.move_at`,
`open_lock_at`) are reached through `core_fn(name)`, so their absence is an `AssertionError`
naming the missing function in the test that needs it.

THE NAMES THE DESIGN FIXES (F1, auto-resolved at §7): the module
`defender/learning/core/state.py`; `LearningState.open(paths)` as the only constructor;
`StateRefused(record, reason)`; `Channel`, `Claimed`; D1's verbs as spelled there
(`rows`, `append(channel, rows, *, dedup_key=None) -> (appended, malformed)`,
`rotate(channel, held, consumed, commit_sha, *, timeout)`, `deadletter_rows`, `has_requests`,
`claim(identity_key)`, `stamp(claimed, spec)`, `requeue(claimed) -> bool`, `done(claimed)`,
`lock(role, *, wait)` (a context manager), `describe(record) -> str`, `stage_dir(lane) -> Path`);
`move_at(held, src, dst)` and `open_lock_at(held, name)` in `defender._io`.

COINED NAMES LIVE HERE AND NOWHERE ELSE. The design does not spell these, so this suite does;
if write-code-from-spec names anything differently it renames it HERE (`COINED`), never
through a `conceptAliases` entry:
  * the channels, as module-level `Channel` values: `FINDINGS`, `QUESTIONER_FINDINGS`,
    `PITFALLS` (the three `QueueChannel`s `LoopPaths` spells today);
  * the lock roles, as module-level values: `REPO_LOCK` (`_author.lock`, a deadline role),
    `AUTHOR_DRAIN_LOCK` (`.author-drain.lock`, try-once), `LEAD_AUTHOR_DRAIN_LOCK`
    (`.lead-author-drain.lock`, try-once), `LEAD_QUEUE_LOCK` (`_pending_leads/.lock`),
    `CURATOR_DRAIN_LOCK` (`_pending/.lock`, try-once). No append-lock role is exposed (the
    lock-nesting rule);
  * the `wait=` spellings: `TRY_ONCE` and `BLOCK` are module-level values; a deadline is a
    number of seconds (`wait=0` tries exactly once, as `_flock.take(timeout_seconds=0)` does).
    A try-once take yields whether it was taken (`with state.lock(r, wait=TRY_ONCE) as taken`);
    a deadline take raises `TimeoutError` on expiry;
  * a `stage_dir` lane is a drain lane label `config` already spells once
    (`AUTHOR_DRAIN_LABEL` -> `_pending/`, `LEAD_AUTHOR_DRAIN_LABEL` -> `_pending_leads/`);
  * `Claimed.spec` (the request body) and `Claimed.key` (the request key: the record name's
    stem, JF7);
  * `claim("case_id")` takes the identity key positionally, as today's `claim_markers` does.

RECORD NAMES ARE TODAY'S (R14). Every oracle in this suite reads the tree by the names
`LoopPaths` spells at base (`author-queue/<case_id>.json`, `author-queue/inflight/`,
`_pending/findings.jsonl`, `_pending/consumed.jsonl`, `<queue>.deadletter.jsonl`,
`<queue>.stuck.jsonl`, `_author.lock`, ...), through `os.lstat`/`readlink`, never through the
handle under test — so an absence assert fails if the code wrote that record anywhere it names.

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE (the author charge's rule 1): the
links, hard links, FIFOs, folders at file names, missing and dangling roots are made on disk in
the test itself. The fakes are the entry points' own injection seams (`author_drain`'s
`branch=` / `start_box=` / `stop_box=` / `scrub=`, a stage's model seam), which record what they
are handed and decide nothing — never `monkeypatch.setattr` (`scripts/lint/lint_monkeypatch.py`).
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import stat
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from defender.learning.core.config import LoopPaths

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFENDER = REPO_ROOT / "defender"

#: The handle's module, as F1 names it.
STATE_MODULE = "defender.learning.core.state"
STATE_MODULE_FILE = DEFENDER / "learning" / "core" / "state.py"


class _Missing:
    """Stands in for a name of the not-yet-written handle module.

    NOT a skip and NOT a soften: every use raises `ModuleNotFoundError`, so each test fails on
    its own at the point it first needs the handle. The indirection exists only so a missing
    target does not abort the collection of this whole directory."""

    def __init__(self, name: str, err: BaseException) -> None:
        self._name, self._err = name, err

    def _raise(self) -> Any:
        raise ModuleNotFoundError(
            f"{STATE_MODULE}.{self._name} cannot be imported — this suite is the executable "
            f"spec for it (spec_graph_1135-learning-state-handle.yaml). Original: {self._err}"
        )

    def __getattr__(self, item: str) -> Any:
        return self._raise()

    def __call__(self, *a: Any, **k: Any) -> Any:
        return self._raise()


# NOT YET WRITTEN at d9128afa — the module this suite is the contract for. One `try` per name,
# so an implementation that exists but spells one name differently fails only where it is used.
try:
    from defender.learning.core.state import LearningState  # type: ignore[import-not-found]
except ImportError as _absent:  # pragma: no cover — the pre-implementation state
    LearningState = _Missing("LearningState", _absent)  # type: ignore[assignment,misc]
try:
    from defender.learning.core.state import StateRefused  # type: ignore[import-not-found]
except ImportError as _absent:  # pragma: no cover
    StateRefused = _Missing("StateRefused", _absent)  # type: ignore[assignment,misc]
try:
    from defender.learning.core.state import Channel  # type: ignore[import-not-found]
except ImportError as _absent:  # pragma: no cover
    Channel = _Missing("Channel", _absent)  # type: ignore[assignment,misc]
try:
    from defender.learning.core.state import Claimed  # type: ignore[import-not-found]
except ImportError as _absent:  # pragma: no cover
    Claimed = _Missing("Claimed", _absent)  # type: ignore[assignment,misc]


#: Every spelling this suite coins (see the module docstring). Renamed here, and only here.
COINED = (
    "FINDINGS", "QUESTIONER_FINDINGS", "PITFALLS",
    "REPO_LOCK", "AUTHOR_DRAIN_LOCK", "LEAD_AUTHOR_DRAIN_LOCK", "LEAD_QUEUE_LOCK",
    "CURATOR_DRAIN_LOCK", "TRY_ONCE", "BLOCK",
)


def coined(name: str) -> Any:
    """A module-level value this suite coins on the handle's module (`COINED`)."""
    assert name in COINED, f"{name} is not one of this suite's coined names"
    mod = sys.modules.get(STATE_MODULE)
    if mod is None:
        raise ModuleNotFoundError(
            f"{STATE_MODULE} does not exist yet — this suite is the executable spec for it")
    try:
        return getattr(mod, name)
    except AttributeError:
        raise AssertionError(
            f"{STATE_MODULE} has no {name} — a name this suite coins (_spec1135.COINED); rename "
            "it there if the implementation spells it differently") from None


def core_fn(name: str) -> Callable[..., Any]:
    """`move_at` / `open_lock_at` — D2's two module functions beside `Held` in `defender._io`.

    Reached by name so their absence at base is this test's own assertion, not an import error
    hiding the file."""
    from defender import _io

    fn = getattr(_io, name, None)
    assert callable(fn), f"defender._io.{name} does not exist (D2 adds it beside Held)"
    return fn


# ---------------------------------------------------------------------------------------------
# Roots
# ---------------------------------------------------------------------------------------------


def built_paths(tmp_path: Path, *, repo_root: Path | None = None) -> LoopPaths:
    """`LoopPaths` over a CREATED state root at `<tmp>/learning-state` (R15: the root must
    exist; the operator, here the fixture, creates it). Nothing below the root is made."""
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

#: The four entry shapes revision 3.1 D names for a record name, and the folder shapes of
#: R16 / 3.1 D. Each is made on disk by `plant`.
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
    which is True while every byte of the payload is still in the pipe.

    This is how a test SEES "the link's target is unread": a regular file's bytes are the same
    after a read, but a read through any link to this FIFO consumes the payload. A reader that
    reads to end of file also blocks (this helper's descriptor is a live writer), so the test
    runs the operation under `within`. `tree_snapshot` lists the FIFO without opening it. The
    descriptor is closed on exit, which ends any reader still blocked on it."""
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
    except Exception as e:  # noqa: BLE001 — the test classifies what escaped, not this helper
        return e
    return None


def refusal_class() -> type[BaseException] | None:
    """`StateRefused` when it is a real exception class (it is not at base or under a stub)."""
    return StateRefused if isinstance(StateRefused, type) and issubclass(
        StateRefused, BaseException) else None


def is_refusal(exc: BaseException | None) -> bool:
    cls = refusal_class()
    return cls is not None and isinstance(exc, cls)


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
    """Today's request record body (`markers.enqueue_case_for_curation`, R14: unchanged)."""
    return {"case_id": case_id, "run_dir": str(run_dir.resolve()), **extra}


def seed_request(paths: LoopPaths, case_id: str, run_dir: Path, *, inflight: bool = False,
                 **extra: Any) -> Path:
    """A plain request record at today's name, written by the fixture."""
    run_dir.mkdir(parents=True, exist_ok=True)
    folder = paths.author_queue_dir / ("inflight" if inflight else "")
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
    other even in one process (C7). The file is made if absent (`O_CREAT`, as `a+` does)."""
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


def errno_name(e: BaseException | None) -> str | None:
    n = getattr(e, "errno", None)
    return errno.errorcode.get(n) if isinstance(n, int) else None
