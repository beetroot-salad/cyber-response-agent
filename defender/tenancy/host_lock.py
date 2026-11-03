"""The execution host's per-tenant lock and process registry (#1214 P3, RC-5).

One lock per tenant, beside (never inside) the tenant's folder: `<data root>/.host-locks/<T>/lock`,
an `flock` on that file. Run start, drain start and the connect command hold it SHARED for as long
as they work for the tenant, and record themselves first (`hold_shared`): one file per process under
`processes/`, naming its pid and its kernel start time (its box containers carry the tenant's
label instead, `box.TENANT_LABEL`). The host actor's install and old-file removal hold it shared too; prepare and teardown hold it EXCLUSIVE, so
neither runs while a process works for the tenant. Teardown signals what is recorded (the
lifecycle's own business); this module only locks and lists.

A process records itself BEFORE it takes the lock, so a holder is never invisible to teardown. A
record whose process is gone (or whose pid now names another process: the start time differs)
is stale; `holders` drops it. The lock file is never removed: a holder waiting on a removed file
would lock an inode nobody else can see. Nothing here reads the tenant's folder."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from defender import _io
from defender.records.formats import TenantRefused
from defender.tenancy._owner import process_start
from defender.tenancy._tenant import TenantId

#: The folder under the data root that holds every tenant's host lock.
LOCKS = ".host-locks"
_LOCK_FILE = "lock"
_REGISTRY = "processes"
#: How often a waiting acquirer tries again.
_POLL = 0.05
#: A record's name, `<pid>-<start>`: anything else in the registry (a record still being written,
#: staged beside its name) is not one, and is never judged or removed.
_RECORD_NAME = re.compile(r"[0-9]+-[0-9]+")


def lock_dir(data_root: Path, tenant_id: str) -> Path:
    """`<data root>/.host-locks/<T>/`: the tenant's lock and registry (outside `<data root>/<T>/`)."""
    return Path(data_root) / LOCKS / str(TenantId(tenant_id))


def _lock_file(data_root: Path, tenant_id: str) -> int:
    folder = lock_dir(data_root, tenant_id)
    _io.guarded_mkdir(folder, base=Path(data_root))
    return os.open(folder / _LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)


def acquire(data_root: Path, tenant_id: str, *, exclusive: bool, timeout: float | None) -> int | None:
    """Take the tenant's host lock (exclusive or shared): the descriptor holding it, or None once
    `timeout` seconds passed without it (`0` tries once; None waits as long as it takes). The
    descriptor is close-on-exec, so a child the holder starts does not inherit the lock."""
    fd = _lock_file(data_root, tenant_id)
    mode = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
    deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
    try:
        while True:
            try:
                fcntl.flock(fd, mode)
                return fd
            except BlockingIOError:
                if deadline is not None and time.monotonic() >= deadline:
                    os.close(fd)
                    return None
                time.sleep(_POLL)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def release_lock(fd: int | None) -> None:
    """Give the lock back (closing the descriptor releases it); None is accepted."""
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Holder:
    """A recorded process: its pid and its kernel start time."""

    pid: int
    start: str


def _write_record(path: Path, pid: int, start: str) -> None:
    _io.write_guarded(path, json.dumps({"pid": pid, "start": start}) + "\n")


@dataclass
class _Hold:
    """One tenant's hold in this process: the scopes open on it, the descriptor holding the lock and
    this process's record under the tenant's registry."""

    scopes: int
    fd: int
    record: Path


#: This process's open holds (r10 "Data model"), keyed by this process's pid and the tenant's
#: resolved lock folder, so two spellings of one data root meet and a forked child inherits none.
_HOLDS: dict[tuple[int, Path], _Hold] = {}
#: Guards `_HOLDS` and `_GATES`; never held while waiting for a lock.
_TABLE = threading.Lock()
#: One gate per key, held while a first scope claims its entry and takes the tenant's lock (and while
#: the last scope gives it back): a second thread waits on it, then reuses the hold.
_GATES: dict[tuple[int, Path], threading.Lock] = {}


def _waiting_line(tenant_id: str) -> str:
    return f"waiting for tenant {tenant_id}'s host lock (prepare or teardown is running)\n"


@contextlib.contextmanager
def hold_shared(data_root: Path, tenant_id: str) -> Iterator[Holder]:
    """Record this process, then hold the tenant's lock shared until the scope ends (run start,
    drain start, the connect command and every other host entry point, through the host
    acceptance). Waits, with no timeout, while prepare or teardown holds it exclusive, saying so
    once on stderr (r10.1 C4: one try without waiting, the line, then the wait); the caller checks
    the tenant's state only once it holds the lock (Flow 4).

    A nested scope of the same tenant in this process, from any thread and under any spelling of
    the data root, reuses the open hold: it neither records again nor releases early, and the
    record and the lock go when the last scope ends (r10 A2, O-A3)."""
    pid = os.getpid()
    start = process_start(pid)
    if start is None:
        raise TenantRefused(f"process {pid} cannot read its own start time to record itself")
    folder = lock_dir(data_root, tenant_id)
    _io.guarded_mkdir(folder, base=Path(data_root))
    key = (pid, folder.resolve())
    hold = _enter(key, data_root, tenant_id, pid, start)
    try:
        yield Holder(pid, start)
    finally:
        _leave(key, hold)


def _key_gate(key: tuple[int, Path]) -> threading.Lock:
    with _TABLE:
        return _GATES.setdefault(key, threading.Lock())


def _enter(key: tuple[int, Path], data_root: Path, tenant_id: str, pid: int, start: str) -> _Hold:
    """The open hold for `key`, one scope more; the first scope records this process, then takes
    the lock shared (recorded first, so a holder is never invisible to teardown)."""
    with _key_gate(key):
        with _TABLE:
            hold = _HOLDS.get(key)
            if hold is not None:
                hold.scopes += 1
                return hold
        registry = lock_dir(data_root, tenant_id) / _REGISTRY
        _io.guarded_mkdir(registry, base=Path(data_root))
        record = registry / f"{pid}-{start}"
        _write_record(record, pid, start)
        try:
            fd = acquire(data_root, tenant_id, exclusive=False, timeout=0)
            if fd is None:
                sys.stderr.write(_waiting_line(tenant_id))
                sys.stderr.flush()
                fd = acquire(data_root, tenant_id, exclusive=False, timeout=None)
        except BaseException:
            record.unlink(missing_ok=True)
            raise
        assert fd is not None  # a wait with no timeout returns the descriptor or raises
        hold = _Hold(scopes=1, fd=fd, record=record)
        with _TABLE:
            _HOLDS[key] = hold
        return hold


def _leave(key: tuple[int, Path], hold: _Hold) -> None:
    """One scope fewer; the last gives the lock back and removes this process's record."""
    with _key_gate(key):
        with _TABLE:
            hold.scopes -= 1
            if hold.scopes:
                return
            del _HOLDS[key]
        try:
            release_lock(hold.fd)
        finally:
            hold.record.unlink(missing_ok=True)


def holders(data_root: Path, tenant_id: str) -> list[Holder]:
    """The recorded processes of the tenant that still run; a stale or unreadable record is
    removed. Only entries named as records are read: a writer's staged file is left alone."""
    registry = lock_dir(data_root, tenant_id) / _REGISTRY
    try:
        entries = sorted(registry.iterdir())
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
        if not _RECORD_NAME.fullmatch(entry.name):
            continue
        holder = _read_record(entry)
        if holder is None or process_start(holder.pid) != holder.start:
            entry.unlink(missing_ok=True)
            continue
        found.append(holder)
    return found


def _read_record(path: Path) -> Holder | None:
    try:
        raw = json.loads(_io.read_text_utf8(path))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    pid, start = raw.get("pid"), raw.get("start")
    if not isinstance(pid, int) or isinstance(pid, bool) or not isinstance(start, str):
        return None
    return Holder(pid, start)
