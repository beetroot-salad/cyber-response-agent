"""Seams, plants and child-process runners for #1134 v3 step 1's suite
(`test_1134_tree_listing.py`). It defines no tests.

It imports only the standard library at module level. `defender._io` is resolved inside the
functions that use it, so a missing name fails the row that calls it (never collection), and a
child interpreter loads this module in a fraction of a second.

* `os_` stand-ins: pass-throughs over the real `os`, handed in through `bind(root, os_=...)` or
  `hold(root, os_=...)` (nothing is monkeypatched):
  - `CallRecorder` records the name of every attribute asked of the seam, so an empty record
    after a call means it made no I/O through the seam at all;
  - `OsCallLog` records every call with its descriptors named by what they open, so the I/O of
    two calls can be compared as a sequence or a multiset;
  - `FailsOn` fails opening or stat-ing one name with an errno;
  - `RefusesListing` fails the listing of one folder on one route (`LISTING_ROUTES`);
  - `ListingFaults` fails the reopen of chosen folders with an errno, and REALLY removes chosen
    folders at a chosen moment of their own listing (`REMOVAL_MOMENTS`), after the step into
    them (addendum 3, D2);
  - `ReportsLinks` reports a chosen link count for the `fstat` of a folder's reopened descriptor
    only, flipping it when that folder's scan ends (H2: a judgement after the scan, not before);
  - `SwapsOnStep` REALLY moves a folder out of the tree, and plants a file, a FIFO, a symlink or
    nothing at its name, the moment it is first stepped into (#1134 v2 finding #2).
* `ParkedWriter`: a thread parked in a FIFO's write open. While it stays parked, nothing has
  opened the FIFO to read.
* Plants (`plant_entry`, `plant_folder`): real filesystem entries.
* The child: `run_child(request)` runs `child()` in a fresh interpreter under `CHILD_DEADLINE`
  (the test worker never forks). Mode `as_nobody` drops to uid/gid 65534 after its imports when
  it runs as root, so a real permission bit bites; mode `low_fd_limit` lowers its own soft
  `RLIMIT_NOFILE` to a few descriptors above what it holds; mode `audited` installs an audit
  hook (in the child; the test worker never gets one) and reports every audit event raised
  during each helper call, whatever `os` the code under test reached. Each runs listing
  scenarios and answers JSON. Not `subprocess.run(user=65534)`: where `sys.executable` resolves under a folder
  uid 65534 cannot search (uv's `/root/.local/share/uv/python`, mode 0700), that exec fails
  with EACCES before any test code runs.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import importlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

#: The unprivileged identity a child drops to when it runs as root.
NOBODY = 65534
#: How long one in-process call may take before it counts as wedged.
DEADLINE = 3.0
#: How long a child interpreter may take: a whole batch of scenarios takes well under a second.
CHILD_DEADLINE = DEADLINE * 20
#: How many descriptors above what it already holds the `low_fd_limit` child may open. One
#: listing needs about five at its peak; a descriptor per level of an 1100-deep chain does not
#: fit.
FD_MARGIN = 16

#: Each route by which listing one folder can be refused: `_step`'s `O_PATH` open of the
#: folder's own component, the reopen of `.` for reading off that handle, `scandir` of the
#: reopened descriptor, the listing failing partway through, judging a listed entry's type, and
#: the `fstat` of the reopened descriptor that judges whether the folder is dead (addendum 3).
LISTING_ROUTES = ("step", "reopen", "scandir", "midway", "entry", "fstat")

#: What a planted entry holds, or what a link or hard link reaches.
HOST_BYTES = b'{"planted": "HOST"}\n'
#: What a plain entry at the address under test holds.
PLAIN = b"plain entry at its own address\n"


def io_module() -> Any:
    return importlib.import_module("defender._io")


# ---------------------------------------------------------------------------------------
# The `os_` stand-ins
# ---------------------------------------------------------------------------------------

class RealOs:
    """The real `os` module, handed in as the seam's `os_`: every attribute is the real one
    unless a subclass overrides it."""

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)


def fd_path(fd: Any) -> str | None:
    """What the descriptor `fd` names (`/proc/self/fd`), else None."""
    if not isinstance(fd, int) or isinstance(fd, bool):
        return None
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None


def fd_folder(fd: Any) -> str | None:
    """The last component of what the descriptor `fd` names, else None."""
    named = fd_path(fd)
    return None if named is None else os.path.basename(named)


def last_component(path: Any) -> str:
    spelled = os.fsdecode(path)
    return PurePosixPath(spelled).name or spelled


def spelled(path: Any) -> str | None:
    return os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else None


class CallRecorder(RealOs):
    """The real `os`, recording the name of every `os_` attribute the code under test asks for
    (`open`, `dup`, `scandir`, ...). An empty record after a call: no I/O through the seam."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        self.calls.append(name)
        return getattr(os, name)


#: `os` calls whose first argument is a descriptor.
_FD_FIRST = frozenset({"dup", "close", "fstat", "scandir", "fdopen", "fsync", "fchmod",
                       "fstatvfs", "fchdir", "read", "lseek"})


class OsCallLog(RealOs):
    """The real `os` (or the seam `inner`, a fault-injecting one among them), logging every call
    made through the seam as a comparable tuple: the call's name, then its arguments, each
    descriptor (a `dir_fd`, or the first argument of a descriptor call) replaced by what it
    names. A call is logged before it runs, so one that fails is logged too. Two calls that make
    the same I/O log equal sequences, whatever descriptor numbers they happened to get."""

    def __init__(self, inner: Any = os) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.inner = inner

    def __getattr__(self, name: str) -> Any:
        real = getattr(self.inner, name)
        if not callable(real):
            self.calls.append(("attribute", name))
            return real

        def logged(*args: Any, **kwargs: Any) -> Any:
            shown = list(args)
            if name in _FD_FIRST and shown:
                shown[0] = ("fd", fd_path(shown[0]))
            else:
                shown = [spelled(a) if isinstance(a, os.PathLike) else a for a in shown]
            named = tuple(sorted(
                (k, ("fd", fd_path(v)) if k.endswith("_fd") else v) for k, v in kwargs.items()))
            self.calls.append((name, tuple(shown), named))
            return real(*args, **kwargs)

        return logged


class FailsOn(RealOs):
    """The real `os`, except that opening or stat-ing any name in `names` (spelled as the call
    spells it: a root's path, a folder component, a leaf) fails with `err`, as the real call
    would. EACCES is the `PermissionError` a real unreadable folder gives a non-root user."""

    def __init__(self, *names: str, err: int = errno.EACCES) -> None:
        self.names = frozenset(names)
        self.err = err

    def _deny(self, path: Any) -> None:
        named = spelled(path)
        if named is not None and named in self.names:
            raise OSError(self.err, os.strerror(self.err), named)

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        self._deny(path)
        return os.open(path, *args, **kwargs)

    def stat(self, path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        self._deny(path)
        return os.stat(path, *args, **kwargs)

    def lstat(self, path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        self._deny(path)
        return os.lstat(path, *args, **kwargs)


class _FailsPartway:
    """`os.scandir`'s iterator that yields at most `after` real entries, then fails with `err`
    (`entry=True`: each entry it yields fails with `err` when asked its type instead):
    iterable, a context manager, closable."""

    def __init__(self, it: Any, err: int, *, after: int = 1, entry: bool = False) -> None:
        self._it, self._err, self._after, self._entry, self._given = it, err, after, entry, 0

    def __iter__(self) -> _FailsPartway:
        return self

    def __next__(self) -> Any:
        if self._entry:
            return _UntypableEntry(next(self._it), self._err)
        if self._given >= self._after:
            raise OSError(self._err, os.strerror(self._err), "partway")
        self._given += 1
        try:
            return next(self._it)
        except StopIteration:
            raise OSError(self._err, os.strerror(self._err), "partway") from None

    def __enter__(self) -> _FailsPartway:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._it.close()


class _UntypableEntry:
    """A real `os.DirEntry` whose type questions fail with `err`; its name is the real one."""

    def __init__(self, real: Any, err: int) -> None:
        self._err, self.name, self.path = err, real.name, real.path

    def _fail(self, *_args: Any, **_kwargs: Any) -> bool:
        raise OSError(self._err, os.strerror(self._err), self.path)

    is_symlink = is_dir = is_file = _fail


class RefusesListing(RealOs):
    """The real `os`, except that listing a folder whose last component is in `names` fails
    with `err` on `route`: `step` fails `os_.open` of that component; `reopen` fails
    `os_.open(".")` off that folder's handle; `scandir` fails `os_.scandir` of its descriptor;
    `midway` lets `scandir` start, then fails after `after` entries; `entry` fails each listed
    entry's type questions; `fstat` fails `os_.fstat` of the descriptor the reopen handed back
    (never of an `O_PATH` step handle). `seen` records every folder asked of `os_` (by last
    component, BEFORE any failure), so a folder that must never be entered is caught even when
    refused."""

    def __init__(self, route: str, *names: str, err: int = errno.EACCES, after: int = 1) -> None:
        assert route in LISTING_ROUTES, route
        self.route, self.names, self.err, self.after = route, frozenset(names), err, after
        self.seen: list[str] = []
        self._reopened: set[int] = set()

    def _fail(self, what: Any) -> None:
        named = fd_folder(what) if isinstance(what, int) else os.fsdecode(what)
        raise OSError(self.err, os.strerror(self.err), named)

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        named = spelled(path)
        self.seen.append(
            f"{fd_folder(kwargs.get('dir_fd'))}/." if named == "." else str(named))
        if self.route == "step" and named in self.names:
            self._fail(path)
        reopen = named == "." and fd_folder(kwargs.get("dir_fd")) in self.names
        if self.route == "reopen" and reopen:
            self._fail(path)
        fd = os.open(path, *args, **kwargs)
        if reopen:
            self._reopened.add(fd)
        return fd

    def fstat(self, fd: Any) -> os.stat_result:
        if self.route == "fstat" and fd in self._reopened:
            self._fail(fd)
        return os.fstat(fd)

    def close(self, fd: Any) -> None:
        self._reopened.discard(fd)
        os.close(fd)

    def scandir(self, path: Any) -> Any:
        self.seen.append(f"{fd_folder(path)}/*")
        if self.route in ("scandir", "midway", "entry") and fd_folder(path) in self.names:
            if self.route == "scandir":
                self._fail(path)
            return _FailsPartway(os.scandir(path), self.err, after=self.after,
                                 entry=self.route == "entry")
        return os.scandir(path)

    def touched(self, name: str) -> bool:
        """Did anything ask `os_` to open or list the folder `name` (by last component)?"""
        return any(seen in (name, f"{name}/.", f"{name}/*") for seen in self.seen)


#: When `ListingFaults` REALLY removes a folder during its own listing, always after the step
#: into it succeeded: before the `"."` reopen off that handle (`reopen`), between the reopen and
#: `os_.scandir` of the reopened descriptor (`scan`), or once the real scan has handed back its
#: first entry (`midway`).
REMOVAL_MOMENTS = ("reopen", "scan", "midway")


class _RemovesAfterFirst:
    """The real `os.scandir` iterator over a folder, which REALLY removes that folder
    (`shutil.rmtree`) right after handing back its first entry, then goes on with the real
    iteration (whatever the kernel and the C library still give a removed folder)."""

    def __init__(self, it: Any, remove: Callable[[], None]) -> None:
        self._it, self._remove, self._given = it, remove, 0

    def __iter__(self) -> _RemovesAfterFirst:
        return self

    def __next__(self) -> Any:
        if self._given == 1:
            self._remove()
        self._given += 1
        return next(self._it)

    def __enter__(self) -> _RemovesAfterFirst:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._it.close()


class ListingFaults(RealOs):
    """The real `os`, with two faults keyed by a folder's last component. A folder in `refuse`
    fails its `"."` reopen with that errno (EACCES: refused). A folder in `remove` is REALLY
    removed (`shutil.rmtree`, everything in it) at `moment` (`REMOVAL_MOMENTS`) of its own
    listing, and the real call then runs against the removed folder, so what the kernel and
    CPython answer for a deleted folder is what `entries()` sees (addendum 3, D2: absent).
    The folder is named off the descriptor BEFORE it is removed (once removed, `/proc` spells
    it with a `" (deleted)"` suffix). `removed` lists the real paths removed, in order."""

    def __init__(self, refuse: dict[str, int] | None = None, *, remove: Iterable[str] = (),
                 moment: str = "reopen") -> None:
        assert moment in REMOVAL_MOMENTS, moment
        self.refuse, self.remove, self.moment = dict(refuse or {}), frozenset(remove), moment
        self.removed: list[str] = []

    def _target(self, fd: Any) -> str | None:
        named = fd_path(fd)
        if named is None or named in self.removed \
                or os.path.basename(named) not in self.remove:
            return None
        return named

    def _rmtree(self, named: str) -> None:
        self.removed.append(named)
        shutil.rmtree(named)

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        if spelled(path) == ".":
            folder = fd_folder(kwargs.get("dir_fd"))
            if folder in self.refuse:
                err = self.refuse[folder]
                raise OSError(err, os.strerror(err), folder)
            named = self._target(kwargs.get("dir_fd"))
            if named is not None and self.moment == "reopen":
                self._rmtree(named)
        return os.open(path, *args, **kwargs)

    def scandir(self, path: Any) -> Any:
        named = self._target(path)
        if named is not None and self.moment == "scan":
            self._rmtree(named)
        it = os.scandir(path)
        if named is not None and self.moment == "midway":
            return _RemovesAfterFirst(it, lambda: self._rmtree(named))
        return it


class _MarksExhausted:
    """The real `os.scandir` iterator over a descriptor, calling `done()` once it is
    exhausted (its `StopIteration`)."""

    def __init__(self, it: Any, done: Callable[[], None]) -> None:
        self._it, self._done = it, done

    def __iter__(self) -> _MarksExhausted:
        return self

    def __next__(self) -> Any:
        try:
            return next(self._it)
        except StopIteration:
            self._done()
            raise

    def __enter__(self) -> _MarksExhausted:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._it.close()


class ReportsLinks(RealOs):
    """The real `os`, except the link count `fstat` reports for a descriptor a `"."` reopen
    handed back (a folder being listed; never an `O_PATH` step handle): `during` until that
    descriptor's scan is exhausted, `after` from then on (`None`: the real count). A filesystem
    such as btrfs counts 1 for every live directory (`during == after == 1`); flipping the count
    at the end of the scan tells a judgement made after the scan from one made before it.
    `asked` counts those `fstat`s, `asked_after` the ones after the scan."""

    def __init__(self, during: int | None, after: int | None) -> None:
        self.during, self.after = during, after
        self.asked = self.asked_after = 0
        self._phase: dict[int, str] = {}

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        fd = os.open(path, *args, **kwargs)
        if spelled(path) == ".":
            self._phase[fd] = "during"
        return fd

    def scandir(self, path: Any) -> Any:
        it = os.scandir(path)
        if path in self._phase:
            return _MarksExhausted(it, lambda: self._phase.__setitem__(path, "after"))
        return it

    def fstat(self, fd: Any) -> os.stat_result:
        st = os.fstat(fd)
        phase = self._phase.get(fd)
        if phase is None:
            return st
        self.asked += 1
        self.asked_after += phase == "after"
        nlink = self.during if phase == "during" else self.after
        if nlink is None:
            return st
        fields = list(st)
        fields[stat.ST_NLINK] = nlink
        return os.stat_result(fields)

    def close(self, fd: Any) -> None:
        self._phase.pop(fd, None)
        os.close(fd)


#: What `SwapsOnStep` can leave at the moved folder's name.
SWAP_PLANTS = ("file", "fifo", "symlink", "nothing")


class SwapsOnStep(RealOs):
    """#1134 v2 finding #2, for real. The first time the folder `<parent>/<name>` is stepped
    into (`os_.open(name, ..., dir_fd=<a descriptor naming parent>)`), BEFORE that open is
    delegated: the folder is renamed out of the tree to `away` (with everything in it), and
    `plant` is put at its name: a plain file, a FIFO, a symlink to the moved folder, or nothing.
    Then the real open runs and meets whatever now stands there. `fired` says it happened."""

    def __init__(self, parent: Path, name: str, *, away: Path, plant: str) -> None:
        assert plant in SWAP_PLANTS, plant
        self.parent = os.path.realpath(parent)
        self.name = name
        self.away = Path(away)
        self.plant = plant
        self.fired = False

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        if not self.fired and spelled(path) == self.name \
                and fd_path(kwargs.get("dir_fd")) == self.parent:
            self.fired = True
            at = Path(self.parent) / self.name
            os.rename(at, self.away)
            if self.plant == "file":
                at.write_bytes(HOST_BYTES)
            elif self.plant == "fifo":
                os.mkfifo(at)
            elif self.plant == "symlink":
                at.symlink_to(self.away, target_is_directory=True)
        return os.open(path, *args, **kwargs)


# ---------------------------------------------------------------------------------------
# Answers as JSON rows (the child's, and the in-process runner's)
# ---------------------------------------------------------------------------------------

def entries_row(got: Any) -> dict[str, Any]:
    return {"name": got.name, "absent": got.absent, "reason": got.reason,
            "entries": None if got.entries is None else sorted(map(list, got.entries.items()))}


def _raised(e: BaseException) -> dict[str, Any]:
    return {"raised": type(e).__name__, "errno": getattr(e, "errno", None), "text": str(e)}


@contextlib.contextmanager
def _scenario_view(io: Any, scenario: dict[str, Any]) -> Iterator[Any]:
    root, how, prefix = Path(scenario["root"]), scenario.get("how", "bind"), scenario.get("prefix")
    if how == "held":
        with io.hold(root) as held:
            view = held.view()
            yield view.under(prefix) if prefix else view
    else:
        with io.bind(root) as bound:
            yield bound.under(prefix) if prefix else bound


def _answer(view: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    op = scenario["op"]
    if op == "entries":
        return entries_row(view.entries())
    if op == "read":
        got = view.read(scenario["name"])
        return {"name": got.name, "absent": got.absent, "reason": got.reason, "text": got.text}
    raise ValueError(op)


def run_scenarios(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each scenario (`root`, `how` = bind | held, optional `prefix`, `op` = entries |
    read, and its `name`) answered as a JSON row, or
    the exception it raised. Runs in whatever process calls it."""
    io = io_module()
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        try:
            with _scenario_view(io, scenario) as view:
                rows.append(_answer(view, scenario))
        except Exception as e:  # noqa: BLE001 — reported in the row, for the test to judge
            rows.append(_raised(e))
    return rows


class _AuditLog:
    """A `sys.addaudithook` hook (installed in a child only, never in the test worker) that
    records every audit event raised while `events` is a list: its name and its arguments
    (each an `int`, a `str` or `None`, else its `repr`)."""

    def __init__(self) -> None:
        self.events: list[list[Any]] | None = None

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if self.events is not None:
            self.events.append([event, [a if a is None or isinstance(a, (int, str)) else repr(a)
                                        for a in args]])


def run_audited(scenarios: list[dict[str, Any]], log: _AuditLog) -> list[dict[str, Any]]:
    """Each scenario as `run_scenarios` answers it, with the audit events raised during the
    helper call itself (the view is made, and closed, outside the recording)."""
    io = io_module()
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        with _scenario_view(io, scenario) as view:
            log.events = []
            try:
                answer = _answer(view, scenario)
            except Exception as e:  # noqa: BLE001 — reported in the row, for the test to judge
                answer = _raised(e)
            finally:
                events, log.events = log.events, None
        rows.append({"answer": answer, "events": events})
    return rows


# ---------------------------------------------------------------------------------------
# The child interpreter
# ---------------------------------------------------------------------------------------

def _drop_privileges() -> None:
    os.setgroups([])
    os.setresgid(NOBODY, NOBODY, NOBODY)
    os.setresuid(NOBODY, NOBODY, NOBODY)


def _open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


def _spare_descriptors(cap: int) -> int:
    """How many more descriptors this process can open (at most `cap`), each closed after."""
    held: list[int] = []
    try:
        while len(held) < cap:
            held.append(os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC))
    except OSError as e:
        if e.errno != errno.EMFILE:
            raise
    finally:
        for fd in held:
            os.close(fd)
    return len(held)


def child() -> None:
    """A child interpreter's entry point: one JSON request on stdin, one JSON answer on stdout.
    Every module the scenarios need is imported BEFORE privileges drop or the limit is lowered:
    once dropped, the interpreter may not read its own files."""
    request = json.loads(sys.stdin.read())
    try:
        io_module()
        if request["mode"] == "as_nobody":
            if os.geteuid() == 0:
                _drop_privileges()
            answer: dict[str, Any] = {"uid": os.geteuid(), "gid": os.getegid(),
                                      "rows": run_scenarios(request["scenarios"])}
        elif request["mode"] == "low_fd_limit":
            import resource

            held = _open_fds()
            _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (held + FD_MARGIN, hard))
            answer = {"held": held, "limit": held + FD_MARGIN,
                      "spare": _spare_descriptors(4 * FD_MARGIN),
                      "rows": run_scenarios(request["scenarios"])}
        elif request["mode"] == "plain":
            answer = {"rows": run_scenarios(request["scenarios"])}
        elif request["mode"] == "audited":
            run_scenarios(request["warmup"])  # any first-call import happens here, unrecorded
            log = _AuditLog()
            sys.addaudithook(log)
            answer = {"rows": run_audited(request["scenarios"], log)}
        else:
            raise ValueError(request["mode"])
    except Exception as e:  # noqa: BLE001 — the parent reports it
        answer = {"child_failed": f"{type(e).__name__}: {e}"}
    sys.stdout.write(json.dumps(answer))


def run_child(request: dict[str, Any], *, deadline: float = CHILD_DEADLINE) -> dict[str, Any]:
    """Run `child()` in a fresh interpreter over THIS tree's `defender`, under `deadline`
    (killed when it runs past it), and answer its JSON. A child that failed, timed out or reported its own
    failure fails the calling row, naming why."""
    source = Path(io_module().__file__).resolve().parents[1]
    path = [str(source), *([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(path), "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        done = subprocess.run(
            [sys.executable, "-c", "from defender.tests._tree_listing_1134 import child; child()"],
            input=json.dumps(request), capture_output=True, text=True, env=env, cwd=source,
            timeout=deadline, check=False)
    except subprocess.TimeoutExpired:
        raise AssertionError(
            f"the child interpreter did not finish within {deadline}s") from None
    assert done.returncode == 0, f"the child interpreter failed: {done.stderr[-4000:]}"
    answer = json.loads(done.stdout)
    assert "child_failed" not in answer, f"the child interpreter failed: {answer['child_failed']}"
    return answer


def run_unprivileged(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each scenario through the default `os`, as an unprivileged user: in-process when this
    process is not root (CI), else in a child that drops to `NOBODY` itself (root's override
    would list anything). The root path is checked to have dropped, so it never passes vacuously."""
    if os.geteuid() != 0:
        return run_scenarios(scenarios)
    answer = run_child({"mode": "as_nobody", "scenarios": scenarios})
    assert (answer["uid"], answer["gid"]) == (NOBODY, NOBODY), (
        f"the unprivileged child ran as uid/gid {answer['uid']}/{answer['gid']}")
    return answer["rows"]


@contextlib.contextmanager
def owned_tree(tmp_path: Path) -> Iterator[Path]:
    """A folder an unprivileged reader can reach and OWNS (as the drain host owns its tree):
    under `tmp_path` when this process is not root; as root, a fresh folder under `/tmp` opened
    to all (pytest's own tmp chain is 0700 to root), handed to `NOBODY` by `hand_over()`. Yields
    the root to build under.

    Every folder's mode is put back before removal, however the body left it (an unreadable or
    unsearchable folder included), through descriptors only: `os.fwalk` opens each folder
    no-follow. As root (which enters any folder) each folder is `fchmod`ed through the
    descriptor `fwalk` opened; never by path, since by then `NOBODY` owns the tree and could
    swap a name for a link. Unprivileged, each child folder is restored off its parent's
    descriptor before `fwalk` descends into it (and the top through its own)."""
    if os.geteuid() != 0:
        top = tmp_path / "owned"
        top.mkdir()
    else:
        top = Path(tempfile.mkdtemp(prefix="tree-listing-1134-", dir="/tmp"))
    os.chmod(top, 0o755)
    try:
        yield top / "root"
    finally:
        _restore_modes(top)
        shutil.rmtree(top, ignore_errors=True)


def _restore_modes(top: Path) -> None:
    root = os.geteuid() == 0
    for _dirpath, dirs, _files, dirfd in os.fwalk(top, follow_symlinks=False):
        with contextlib.suppress(OSError):
            os.fchmod(dirfd, 0o755)
        if root:
            continue
        for name in dirs:
            with contextlib.suppress(OSError):
                os.chmod(name, 0o755, dir_fd=dirfd)


def hand_over(root: Path) -> None:
    """Give the owned tree to `NOBODY` when this process is root, through descriptors only:
    `os.fwalk` bottom-up opens each folder no-follow and changes it through that descriptor,
    and each other entry off its folder's descriptor without following it. Bottom-up, so the
    top changes hands last: nothing below is `NOBODY`'s to swap while root is still working."""
    if os.geteuid() != 0:
        return
    for _dirpath, _dirs, files, dirfd in os.fwalk(root.parent, topdown=False,
                                                  follow_symlinks=False):
        for name in files:
            os.chown(name, NOBODY, NOBODY, dir_fd=dirfd, follow_symlinks=False)
        os.fchown(dirfd, NOBODY, NOBODY)


def set_mode(top: Path, rel: str, mode: int) -> None:
    """Set the permission bits of the folder `top/rel` through a descriptor reached no-follow
    from `top`, one component at a time (never `chmod` by path). Call it before `hand_over`."""
    fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in PurePosixPath(rel).parts:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=fd)
            os.close(fd)
            fd = nxt
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------------------
# Descriptors, the parked FIFO writer, a deep chain
# ---------------------------------------------------------------------------------------

def descriptors_under(top: Path) -> list[str]:
    """What this process's open descriptors name at or under `top` (Linux `/proc/self/fd`)."""
    real = os.path.realpath(top)
    out = []
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if target == real or target.startswith(real + os.sep):
            out.append(target)
    return out


def open_fd_count() -> int:
    return _open_fds()


#: `openat`'s syscall number, for reading `/proc/.../syscall` where `wchan` says nothing.
_OPENAT = {"x86_64": b"257", "aarch64": b"56"}


class ParkedWriter:
    """A thread parked in `open(fifo, O_WRONLY)`. The kernel lets it go only when something
    opens the FIFO to read, from any process. So while it is still parked, nothing has done
    that. A no-follow stat, a listing of the folder holding it, or an `O_PATH` handle does not
    release it. `release()` opens the read end itself and reports whether that let the writer
    go, so a writer that never parked cannot pass for one that stayed parked."""

    def __init__(self, fifo: Path) -> None:
        self.fifo = fifo
        self._native = 0
        self._started = threading.Event()
        self._thread = threading.Thread(target=self._park, daemon=True)

    def _park(self) -> None:
        self._native = threading.get_native_id()
        self._started.set()
        os.close(os.open(self.fifo, os.O_WRONLY))

    def _in_open(self) -> bool:
        task = Path(f"/proc/self/task/{self._native}")
        with contextlib.suppress(OSError):
            wchan = (task / "wchan").read_bytes()
            if b"wait_for_partner" in wchan or b"fifo_open" in wchan:
                return True
        with contextlib.suppress(OSError, IndexError):
            return (task / "syscall").read_bytes().split()[0] \
                == _OPENAT.get(platform.machine(), b"?")
        return False

    def __enter__(self) -> ParkedWriter:
        """Start the writer and wait until it is parked. A writer that never parks (or any
        failure while waiting) is released before the failure propagates: `__exit__` never
        runs for a failed `__enter__`, and an unreleased writer would sit in its open, holding a
        descriptor slot, for the rest of the worker's life."""
        self._thread.start()
        try:
            self._started.wait(DEADLINE)
            give_up = time.monotonic() + DEADLINE
            while not self._in_open():
                if time.monotonic() > give_up:
                    raise AssertionError(
                        "the FIFO writer never parked in its open, so the check is void")
                time.sleep(0.005)
        except BaseException:
            with contextlib.suppress(OSError):
                self.release()
            raise
        return self

    def parked(self) -> bool:
        """Still in its FIFO open, by the kernel's account (after a grace join)."""
        self._thread.join(0.2)
        return self._thread.is_alive() and self._in_open()

    def release(self) -> bool:
        """Open the read end; True when that is what let the writer go."""
        if not self._thread.is_alive():
            return False
        reader = os.open(self.fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            self._thread.join(DEADLINE)
        finally:
            os.close(reader)
        return not self._thread.is_alive()

    def __exit__(self, *_exc: object) -> None:
        with contextlib.suppress(OSError):
            self.release()


def build_chain(base: Path, depth: int, leaf: str, body: bytes = PLAIN) -> None:
    """`depth` nested folders `d` under `base`, `leaf` in the deepest, made one level at a time
    off a descriptor (`os.makedirs` recurses once per level, past Python's recursion limit)."""
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for _ in range(depth):
            os.mkdir("d", dir_fd=fd)
            below = os.open("d", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = below
        out = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644, dir_fd=fd)
        try:
            os.write(out, body)
        finally:
            os.close(out)
    finally:
        os.close(fd)


def remove_chain(base: Path, depth: int, leaf: str) -> None:
    """Undo `build_chain` bottom-up by full path (each well under PATH_MAX). `shutil.rmtree`
    recurses once per level, past Python's recursion limit at this depth."""
    deepest = Path(base, *["d"] * depth)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(deepest / leaf)
    for level in range(depth, 0, -1):
        with contextlib.suppress(FileNotFoundError):
            os.rmdir(Path(base, *["d"] * level))


# ---------------------------------------------------------------------------------------
# Plants (real filesystem entries)
# ---------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Planted:
    kind: str
    at: Path

    @property
    def fifo(self) -> Path | None:
        return self.at if self.kind in ("fifo", "folder_fifo") else None

    def remove(self) -> None:
        if self.at.is_symlink() or not self.at.is_dir():
            self.at.unlink()
        else:
            shutil.rmtree(self.at)


#: Real device nodes (`mknod` needs CAP_MKNOD: root here, never CI's runner).
DEVICES = {"char_device": (stat.S_IFCHR, os.makedev(1, 3)),
           "block_device": (stat.S_IFBLK, os.makedev(7, 200))}


class NoDeviceNodes(Exception):
    """This host refuses `mknod` of a device node (no CAP_MKNOD)."""


def put_plain(path: Path, body: bytes = PLAIN) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def _dir_link(at: Path, base: Path) -> None:
    target = base / f"linked-dir-of-{at.name}"
    target.mkdir()
    (target / "inner.md").write_bytes(HOST_BYTES)
    at.symlink_to(target, target_is_directory=True)


def _plant_symlink(at: Path, root: Path, host: Path, body: bytes) -> None:
    target = host / f"link-target-of-{at.name}"
    target.write_bytes(body)
    at.symlink_to(target)


def _plant_hardlink(at: Path, root: Path, host: Path, body: bytes) -> None:
    other = host / f"other-name-of-{at.name}"
    other.write_bytes(body)
    os.link(other, at)


def _plant_directory(at: Path, root: Path, host: Path, body: bytes) -> None:
    at.mkdir()
    (at / "keep").write_bytes(body)


def _plant_device(at: Path, kind: str) -> None:
    fmt, dev = DEVICES[kind]
    try:
        os.mknod(at, fmt | 0o600, dev)
    except PermissionError:
        raise NoDeviceNodes(kind) from None


#: How each kind `plant_entry` makes is made: `(at, root, host, body)`.
_PLANTERS: dict[str, Callable[[Path, Path, Path, bytes], None]] = {
    "plain": lambda at, root, host, body: put_plain(at),
    "directory": _plant_directory,
    "empty_directory": lambda at, root, host, body: at.mkdir(),
    "symlink": _plant_symlink,
    "dangling": lambda at, root, host, body: at.symlink_to(host / f"dangling-target-of-{at.name}"),
    "dir_link_inside": lambda at, root, host, body: _dir_link(at, root),
    "dir_link_outside": lambda at, root, host, body: _dir_link(at, host),
    "hardlink": _plant_hardlink,
    "fifo": lambda at, root, host, body: os.mkfifo(at),
    # `mknod` makes a socket inode unprivileged; a bound AF_UNIX socket needs a short path.
    "socket": lambda at, root, host, body: os.mknod(at, stat.S_IFSOCK | 0o600),
    **{kind: (lambda at, root, host, body, kind=kind: _plant_device(at, kind)) for kind in DEVICES},
}
#: Every kind `plant_entry` can put at a name. `directory` holds `keep`; a `dir_link_*` points
#: at a real folder (inside the root, or under `host`) holding `inner.md`.
ENTRY_PLANTS = tuple(_PLANTERS)


def plant_entry(at: Path, kind: str, *, root: Path, host: Path,
                body: bytes = HOST_BYTES) -> Planted:
    """Plant `kind` at `at` (its holding folders made real). A link, hard link or directory
    reaches `body`, so a read that followed it would return those bytes. A device node where
    `mknod` is refused raises `NoDeviceNodes`."""
    at.parent.mkdir(parents=True, exist_ok=True)
    _PLANTERS[kind](at, root, host, body)
    return Planted(kind, at)


#: Links at a holding folder whose target holds NOTHING of the rest of the name (an empty
#: folder inside the root or under `host`, or nothing at all).
BARE_FOLDER_LINKS = ("folder_link_empty_inside", "folder_link_empty_outside",
                     "folder_link_dangling")
#: What a plant can put at a holding folder (or at the folder a view is bound to).
FOLDER_PLANTS = ("folder_link_inside", "folder_link_outside", "folder_file", "folder_fifo",
                 *BARE_FOLDER_LINKS)


def plant_folder(root: Path, rel: PurePosixPath, folder: PurePosixPath, kind: str, *,
                 host: Path, body: bytes = HOST_BYTES) -> Planted:
    """Plant `kind` at `folder`, one of `rel`'s holding folders (relative to `root`). A
    `folder_link_inside` / `_outside` points at a folder holding the rest of `rel` as a real
    file with `body` in it, so a walk that followed the link would find it."""
    at = root / folder
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind == "folder_file":
        at.write_bytes(body)
    elif kind == "folder_fifo":
        os.mkfifo(at)
    elif kind in ("folder_link_inside", "folder_link_outside"):
        stem = f"elsewhere-{'-'.join(folder.parts)}"
        elsewhere = (root if kind == "folder_link_inside" else host) / stem
        reached = elsewhere / rel.relative_to(folder)
        reached.parent.mkdir(parents=True, exist_ok=True)
        reached.write_bytes(body)
        at.symlink_to(elsewhere, target_is_directory=True)
    elif kind in BARE_FOLDER_LINKS:
        stem = f"bare-{'-'.join(folder.parts)}"
        if kind == "folder_link_dangling":
            target = host / f"no-such-{stem}"
        else:
            target = (root if kind == "folder_link_empty_inside" else host) / stem
            target.mkdir()
        at.symlink_to(target, target_is_directory=True)
    else:
        raise AssertionError(kind)
    return Planted(kind, at)


def census(top: Path) -> dict[str, tuple[Any, ...]]:
    """Every entry under `top`, judged without following: a link's target, a regular file's
    bytes, mode, mtime and link count, a folder's mode, or any other kind. It never opens a
    FIFO."""
    out: dict[str, tuple[Any, ...]] = {}
    for dirpath, dirnames, filenames in os.walk(top):
        for entry in (*dirnames, *filenames):
            p = Path(dirpath) / entry
            st = os.lstat(p)
            key = p.relative_to(top).as_posix()
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                out[key] = ("link", os.readlink(p))
            elif stat.S_ISREG(st.st_mode):
                out[key] = ("file", p.read_bytes(), mode, st.st_mtime_ns, st.st_nlink)
            elif stat.S_ISDIR(st.st_mode):
                out[key] = ("dir", mode)
            else:
                out[key] = ("other", stat.S_IFMT(st.st_mode), mode)
    return out


# ---------------------------------------------------------------------------------------
# Scratch trees and the states a `Bound` can be in
# ---------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Scratch:
    """A temp tree: the trust `root`, and a `host` folder outside it, where a link points and a
    hard link's other name lives. The census is taken over `tmp`, which holds both."""

    tmp: Path
    root: Path
    host: Path


def make_scratch(tmp_path: Path) -> Scratch:
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    return Scratch(tmp_path, root, host)


@contextlib.contextmanager
def opened(how: str, root: Path, os_: Any = os) -> Iterator[Any]:
    """A `Bound` on `root`: `bind(root)`'s own (`how="bind"`), or `hold(root)`'s view
    (`"held"`). Closed on exit."""
    io = io_module()
    if how == "bind":
        with io.bind(root, os_=os_) as bound:
            yield bound
    else:
        with io.hold(root, os_=os_) as held:
            yield held.view()


#: The states a `Bound` can be in when a malformed argument reaches it: each must refuse the
#: argument before any I/O, whatever it would otherwise answer.
STATES = ("present", "held", "under", "absent_at_bind", "refused_at_bind", "linked_prefix",
          "closed", "closed_held")


def state_tree(s: Scratch) -> None:
    """The tree `bound_in` binds: `rec.md` at the root and in `a/`, `linked` -> `a`, and a
    plain file to bind as a root that is not a directory."""
    put_plain(s.root / "rec.md")
    put_plain(s.root / "a" / "rec.md")
    (s.root / "linked").symlink_to(s.root / "a", target_is_directory=True)
    (s.tmp / "file-root").write_bytes(PLAIN)


@contextlib.contextmanager
def bound_in(state: str, s: Scratch, os_: Any = os) -> Iterator[Any]:
    """A `Bound` over `state_tree` in `state`: bound or held and live, `under("a")`, absent at
    `bind`, refused at `bind` (a file root), `under("linked")`, or closed (bound or held)."""
    io = io_module()
    if state == "held":
        with io.hold(s.root, os_=os_) as held:
            yield held.view()
        return
    if state == "closed_held":
        held = io.hold(s.root, os_=os_)
        held.close()
        yield held.view()
        return
    root = {"absent_at_bind": s.tmp / "no-such-root",
            "refused_at_bind": s.tmp / "file-root"}.get(state, s.root)
    bound = io.bind(root, os_=os_)
    try:
        if state == "closed":
            bound.close()
        yield {"under": lambda: bound.under("a"),
               "linked_prefix": lambda: bound.under("linked")}.get(state, lambda: bound)()
    finally:
        bound.close()
