"""Watches, seams and the unprivileged child runner for `test_1134_shared_readers.py`. It
defines no tests.

Like `_tree_listing_1134` (whose `RealOs`, `fd_path`, `spelled`, `NOBODY` and privilege drop
it reuses), it imports only the standard library and that module at module level, and the
readers only inside the functions that call them, so a child interpreter loads it fast and
imports every reader BEFORE it drops privileges.

* `kernel_watch`: an inotify watch below Python. `IN_ACCESS` reports each read(2) of a watched
  file (and each listing of a watched folder), by whatever name, whatever the mount's atime
  policy; `IN_OPEN` reports each open of one for reading (an `O_PATH` open, a `stat`, an
  `fstat` report nothing). So a reader that opens a link's target, or reads a hard link before
  refusing it, is seen however it reached the file: through the `os_` seam, around it, or by
  a `Path` the reader formatted itself.
* `os_` stand-ins over the real `os`: `SpellingRecorder` (every `os_.open` with its flags and
  `dir_fd`, judged for a spelling that could follow a link), `RefusesFolder` (one folder,
  named by its real path, refused on one route with one errno: a `_draft` folder appears at two
  depths in the test tree, so a last-component match would refuse both; with `once`, only its
  first listing; `RefusesFolders` holds several at once), `VanishesOnOpen`
  (a listed record removed the moment it is opened: absent at read time), and
  `SwapsFolderBetweenListings` (a folder its parent's listing showed as a directory REALLY
  moved out of the tree, and a link to a marked folder, a file, a FIFO or nothing left at its
  name, the moment its own listing first steps into it). `RefusesFolder`'s
  `step` route also refuses a plain FILE's open at its path, as a real unreadable file is
  refused: at the open, never at a `stat`.
* `run_readers` / `child`: run the shared readers over trees with REAL permission bits, as an
  unprivileged user (in-process when the caller is unprivileged; in a child interpreter that
  drops to uid/gid 65534 after its imports when the caller is root), reporting each reader's
  records and warnings as JSON.
* `audit_readers` / `child` in `audit` mode: run the readers in a child interpreter with an
  audit hook (never installed in a pytest worker: a hook cannot be removed) that records every
  `open` by a name, with its flags, while the reader runs. The bare `Path` form has no `os_`
  seam, so this is how its opens are seen.
"""
from __future__ import annotations

import contextlib
import ctypes
import json
import logging
import os
import struct
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from defender.tests._tree_listing_1134 import NOBODY, RealOs, _drop_privileges, fd_path
from defender.tests._tree_listing_1134 import spelled as _spelled

__all__ = ["NOBODY", "REFUSAL_ROUTES", "SWAP_PLANTS", "RefusesFolder", "RefusesFolders",
           "SpellingRecorder",
           "SwapsFolderBetweenListings", "VanishesOnOpen", "audit_readers", "child", "fd_path",
           "kernel_watch", "project_record", "run_readers"]

# -- the kernel's read and open watch ---------------------------------------------------------

_LIBC = ctypes.CDLL(None, use_errno=True)
IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020
_IN_IGNORED = 0x00008000
_IN_Q_OVERFLOW = 0x00004000
_IN_DONT_FOLLOW = 0x02000000
#: `struct inotify_event`: wd, mask, cookie, len, then `len` bytes of name.
_EVENT = struct.Struct("iIII")


def _libc_fault(call: str, what: object = "") -> OSError:
    code = ctypes.get_errno()
    return OSError(code, f"{call}{f'({what})' if what else ''}: {os.strerror(code)}; "
                         "the kernel watch cannot run")


def _events_in(buf: bytes, watched: dict[int, Path]) -> Iterator[tuple[str, str]]:
    """The `(path, "read" | "open")` events one `read` of an inotify descriptor returned."""
    at = 0
    while at < len(buf):
        wd, mask, _cookie, length = _EVENT.unpack_from(buf, at)
        name = buf[at + _EVENT.size:at + _EVENT.size + length].rstrip(b"\0")
        at += _EVENT.size + length
        if mask & _IN_Q_OVERFLOW:
            raise AssertionError("the kernel watch overflowed; its record is void")
        if mask & _IN_IGNORED or wd not in watched:
            continue
        where = watched[wd] / os.fsdecode(name) if name else watched[wd]
        if mask & IN_OPEN:
            yield str(where), "open"
        if mask & IN_ACCESS:
            yield str(where), "read"


@contextlib.contextmanager
def kernel_watch(*, reads: Iterable[Path] = (),
                 opens: Iterable[Path] = ()) -> Iterator[Callable[[], list[tuple[str, str]]]]:
    """An inotify watch: `IN_ACCESS` on each of `reads` and `opens`, `IN_OPEN` on each of
    `opens`. A watched folder also reports those events for every entry directly in it, named.
    Yields a function answering every event seen so far as `(path, "read" | "open")`."""
    masks: dict[Path, int] = {}
    for p in reads:
        masks[Path(p)] = masks.get(Path(p), 0) | IN_ACCESS
    for p in opens:
        masks[Path(p)] = masks.get(Path(p), 0) | IN_ACCESS | IN_OPEN
    fd = _LIBC.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise _libc_fault("inotify_init1")
    try:
        watched: dict[int, Path] = {}
        for p, mask in masks.items():
            wd = _LIBC.inotify_add_watch(fd, os.fsencode(p), mask | _IN_DONT_FOLLOW)
            if wd < 0:
                raise _libc_fault("inotify_add_watch", p)
            watched[wd] = p
        seen: list[tuple[str, str]] = []

        def events() -> list[tuple[str, str]]:
            with contextlib.suppress(BlockingIOError):
                while buf := os.read(fd, 65536):
                    seen.extend(_events_in(buf, watched))
            return list(seen)

        yield events
    finally:
        os.close(fd)


# -- `os_` stand-ins -------------------------------------------------------------------------

def _opened_path(path: Any, dir_fd: Any) -> str | None:
    """The real path an `os.open(path, dir_fd=dir_fd)` names, joined without resolving it."""
    spelled = _spelled(path)
    if spelled is None:
        return None
    if dir_fd is None:
        return os.path.realpath(spelled)
    base = fd_path(dir_fd)
    if base is None:
        return None
    return base if spelled == "." else os.path.join(base, spelled)


class SpellingRecorder(RealOs):
    """The real `os` handed in as `os_`, recording every `os_.open` as `(spelling, flags,
    what its dir_fd names)`. `mark()` forgets what was recorded so far (the root's own open at
    `bind` / `hold`, which follows its spelling by design)."""

    def __init__(self) -> None:
        self.opens: list[tuple[str | None, int | None, str | None]] = []

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        flags = args[0] if args else kwargs.get("flags")
        self.opens.append((_spelled(path), flags, fd_path(kwargs.get("dir_fd"))))
        return os.open(path, *args, **kwargs)

    def mark(self) -> None:
        self.opens.clear()

    def following(self) -> list[tuple[str | None, int | None, str | None]]:
        """The opens since `mark()` that could have followed a link: any open by a spelling
        (no `dir_fd`, or a name with a `/` in it), and any open of a name off a held folder
        without `O_NOFOLLOW` but the reopen of that folder itself (`.`)."""
        bad = []
        for spelled, flags, base in self.opens:
            by_spelling = spelled is None or base is None or "/" in spelled
            if by_spelling or (spelled != "." and (flags is None or not flags & os.O_NOFOLLOW)):
                bad.append((spelled, flags, base))
        return bad


#: The routes by which listing one folder can be refused: `_step`'s open of it off its parent
#: (or a root's open by its spelling), the reopen of `.` off its handle for reading, and
#: `scandir` of the reopened descriptor.
REFUSAL_ROUTES = ("step", "reopen", "scandir")


class RefusesFolder(RealOs):
    """The real `os` handed in as `os_`, except that the folder at the real path `folder` is
    refused with `err` on `route` (see `REFUSAL_ROUTES`). Matched by its whole real path, so a
    folder of the same name elsewhere in the tree is untouched. On the `step` route `folder` may
    be a plain file: its open off its holding folder is refused, and nothing else (a `stat` of
    it answers). `refused` counts the refusals (non-vacuity). With `once`, only the first such
    call is refused and every later one runs for real (a transient fault: a reader that asked
    again would get an answer the first listing never gave); `asked` counts every such call,
    refused or not."""

    def __init__(self, folder: Path, route: str, err: int, *, once: bool = False) -> None:
        assert route in REFUSAL_ROUTES, route
        self.folder = os.path.realpath(folder)
        self.route, self.err, self.once = route, err, once
        self.refused = 0
        self.asked = 0

    def _fail(self) -> None:
        self.asked += 1
        if self.once and self.refused:
            return
        self.refused += 1
        raise OSError(self.err, os.strerror(self.err), self.folder)

    def check_open(self, path: Any, dir_fd: Any) -> None:
        """Refuse an `os_.open(path, dir_fd=dir_fd)` this seam refuses; else nothing."""
        opened = _opened_path(path, dir_fd)
        is_reopen = _spelled(path) == "." and dir_fd is not None
        if opened == self.folder and (self.route == "reopen") == is_reopen \
                and self.route in ("step", "reopen"):
            self._fail()

    def check_scandir(self, path: Any) -> None:
        """Refuse an `os_.scandir(path)` this seam refuses; else nothing."""
        if self.route == "scandir" and fd_path(path) == self.folder:
            self._fail()

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        self.check_open(path, kwargs.get("dir_fd"))
        return os.open(path, *args, **kwargs)

    def scandir(self, path: Any) -> Any:
        self.check_scandir(path)
        return os.scandir(path)


class RefusesFolders(RealOs):
    """Several `RefusesFolder`s at once, each judging every call as it would alone."""

    def __init__(self, seams: list[RefusesFolder]) -> None:
        self.seams = seams

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        for seam in self.seams:
            seam.check_open(path, kwargs.get("dir_fd"))
        return os.open(path, *args, **kwargs)

    def scandir(self, path: Any) -> Any:
        for seam in self.seams:
            seam.check_scandir(path)
        return os.scandir(path)


class VanishesOnOpen(RealOs):
    """The real `os` handed in as `os_`, except that the file at the real path `victim` is
    removed the moment something opens it off its holding folder: a record the listing showed is
    gone when it is read. `fired` says the removal happened (non-vacuity)."""

    def __init__(self, victim: Path) -> None:
        self.victim = os.path.realpath(victim)
        self.fired = False

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        if not self.fired and kwargs.get("dir_fd") is not None \
                and _opened_path(path, kwargs["dir_fd"]) == self.victim:
            self.fired = True
            os.unlink(self.victim)
        return os.open(path, *args, **kwargs)


#: What `SwapsFolderBetweenListings` leaves at the moved folder's name.
SWAP_PLANTS = ("link", "file", "fifo", "nothing")


class SwapsFolderBetweenListings(RealOs):
    """The real `os` handed in as `os_`, except that the first time the folder `<parent>/<name>`
    is stepped into (`os_.open(name, ..., dir_fd=<a descriptor naming parent>)`), BEFORE that
    open is delegated, the folder is REALLY renamed out of the tree to `away`, everything in it
    included, and `plant` is put at its name: a symlink to `target` (a folder the test built and
    marked), a regular file holding `body`, a FIFO, or nothing. Then the real open runs and
    meets whatever now stands there. So a reader's parent listing saw a real directory, and the
    folder's own listing sees the plant. `fired` says it happened (non-vacuity)."""

    def __init__(self, parent: Path, name: str, *, away: Path, plant: str,
                 target: Path | None = None, body: str = "") -> None:
        assert plant in SWAP_PLANTS, plant
        assert (plant == "link") == (target is not None), (plant, target)
        self.parent = os.path.realpath(parent)
        self.name, self.away, self.plant = name, Path(away), plant
        self.target, self.body = target, body
        self.fired = False

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        if not self.fired and _spelled(path) == self.name \
                and fd_path(kwargs.get("dir_fd")) == self.parent:
            self.fired = True
            at = Path(self.parent) / self.name
            os.rename(at, self.away)
            if self.plant == "link":
                assert self.target is not None
                at.symlink_to(os.path.relpath(self.target, at.parent), target_is_directory=True)
            elif self.plant == "file":
                at.write_text(self.body, encoding="utf-8")
            elif self.plant == "fifo":
                os.mkfifo(at)
        return os.open(path, *args, **kwargs)


# -- the readers over a real permission bit, as an unprivileged user --------------------------

class _Said(logging.Handler):
    """Collects the `defender` loggers' warnings."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.said: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith("defender"):
            self.said.append(record.getMessage())


def project_record(reader: str, record: Any) -> Any:
    """A record as JSON: what the parent compares."""
    if reader == "iter_lesson_paths":
        return str(record)
    if reader == "iter_lessons":
        return [str(record.path), record.raw, record.body]
    return [str(record.path), record.id, record.system, record.status]


def _read_one(scenario: dict[str, Any]) -> list[Any]:
    """`read_query_template` in one call form: the bare `Path` `file`, or `bind(top)` with
    `name` and `where=top`. Answers `[the projected template or None, the reason]`."""
    from defender import _corpus, _io

    if scenario["form"] == "path":
        got = _corpus.read_query_template(Path(scenario["file"]))
    else:
        top = Path(scenario["top"])
        with _io.bind(top) as bound:
            got = _corpus.read_query_template(bound, scenario["name"], where=top)
    return [None if got[0] is None else project_record("template", got[0]), got[1]]


def _run_one(scenario: dict[str, Any]) -> dict[str, Any]:
    """One reader in one call form over one tree (`path`: the bare `Path` of `top`; `bound`:
    `bind(top)`; `held-view-under`: `hold(mount).view().under(prefix)`), with `where=top`.
    `read_query_template` goes through `_read_one`."""
    from defender import _corpus, _io
    from defender.learning.leads import lead_neighbors

    readers: dict[str, Callable[..., Any]] = {
        "iter_lesson_paths": _corpus.iter_lesson_paths,
        "iter_lessons": _corpus.iter_lessons,
        "iter_query_templates": _corpus.iter_query_templates,
        "load_catalog": lead_neighbors.load_catalog,
    }
    top, form = Path(scenario["top"]), scenario["form"]
    said = _Said()
    logging.getLogger().addHandler(said)
    out: dict[str, Any] = {}
    try:
        if scenario["reader"] == "read_query_template":
            out["records"] = _read_one(scenario)
            return out
        reader = readers[scenario["reader"]]
        with contextlib.ExitStack() as stack:
            if form == "path":
                got = list(reader(top))
            elif form == "bound":
                bound = stack.enter_context(_io.bind(top))
                got = list(reader(bound, where=top))
            elif form == "held-view-under":
                held = stack.enter_context(_io.hold(Path(scenario["mount"])))
                got = list(reader(held.view().under(scenario["prefix"]), where=top))
            else:
                raise ValueError(form)
        out["records"] = [project_record(scenario["reader"], r) for r in got]
    except Exception as e:  # noqa: BLE001 — reported in the row, for the test to judge
        out["raised"] = f"{type(e).__name__}: {e}"
    finally:
        logging.getLogger().removeHandler(said)
        out["warnings"] = said.said
    return out


def run_readers(scenarios: list[dict[str, Any]], *, drop: bool) -> dict[str, Any]:
    """Each scenario through `_run_one`, as an unprivileged user. With `drop` and running as
    root, every scenario first runs once as root (its answer discarded) so that every module the
    readers import lazily is loaded while the interpreter can still read its own files; then
    this process drops to `NOBODY` and runs them for real."""
    import defender._corpus  # noqa: F401 — loaded before any privilege drop
    import defender._frontmatter  # noqa: F401
    import defender.learning.leads.lead_neighbors  # noqa: F401

    if drop and os.geteuid() == 0:
        for scenario in scenarios:
            _run_one(scenario)
        _drop_privileges()
    return {"uid": os.geteuid(),
            "rows": {scenario["id"]: _run_one(scenario) for scenario in scenarios}}


class _OpenAudit:
    """An audit hook recording, while armed, every `open` event given a name (not a descriptor):
    `[the name as given, the flags]`."""

    def __init__(self) -> None:
        self.armed = False
        self.seen: list[list[Any]] = []

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if not self.armed or event != "open" or not args:
            return
        what = args[0]
        if isinstance(what, (str, bytes, os.PathLike)):
            flags = args[2] if len(args) > 2 else None
            self.seen.append([os.fsdecode(os.fspath(what)), flags])


def audit_readers(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    """Each scenario through `_run_one` with an audit hook armed (`opens` in each row), after a
    first unarmed run that loads whatever the readers import lazily. Only for a child
    interpreter: the hook can never be removed."""
    audit = _OpenAudit()
    sys.addaudithook(audit)
    import defender._corpus  # noqa: F401
    import defender._frontmatter  # noqa: F401
    import defender.learning.leads.lead_neighbors  # noqa: F401

    rows: dict[str, Any] = {}
    for scenario in scenarios:
        _run_one(scenario)
        audit.seen = []
        audit.armed = True
        try:
            row = _run_one(scenario)
        finally:
            audit.armed = False
        row["opens"] = audit.seen
        rows[scenario["id"]] = row
    return {"rows": rows}


def child() -> None:
    """A child interpreter's entry point: one JSON request (`scenarios`, and `mode`: `audit`, or
    by default the unprivileged run) on stdin, one JSON answer on stdout."""
    request = json.loads(sys.stdin.read())
    try:
        if request.get("mode") == "audit":
            answer = audit_readers(request["scenarios"])
        else:
            answer = run_readers(request["scenarios"], drop=True)
    except Exception as e:  # noqa: BLE001 — the parent reports it
        answer = {"child_failed": f"{type(e).__name__}: {e}"}
    sys.stdout.write(json.dumps(answer))
