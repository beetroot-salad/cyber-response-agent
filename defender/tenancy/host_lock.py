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


@contextlib.contextmanager
def hold_shared(data_root: Path, tenant_id: str) -> Iterator[Holder]:
    """Record this process, then hold the tenant's lock shared until the block ends (run start,
    drain start, the connect command). Waits while prepare or teardown holds it exclusive; the
    caller checks the tenant's state only once it holds the lock (Flow 4)."""
    pid = os.getpid()
    start = process_start(pid)
    if start is None:
        raise TenantRefused(f"process {pid} cannot read its own start time to record itself")
    registry = lock_dir(data_root, tenant_id) / _REGISTRY
    _io.guarded_mkdir(registry, base=Path(data_root))
    record = registry / f"{pid}-{start}"
    _write_record(record, pid, start)
    fd = None
    try:
        fd = acquire(data_root, tenant_id, exclusive=False, timeout=None)
        yield Holder(pid, start)
    finally:
        release_lock(fd)
        record.unlink(missing_ok=True)


def holders(data_root: Path, tenant_id: str) -> list[Holder]:
    """The recorded processes of the tenant that still run; a stale or unreadable record is
    removed."""
    registry = lock_dir(data_root, tenant_id) / _REGISTRY
    try:
        entries = sorted(registry.iterdir())
    except FileNotFoundError:
        return []
    found = []
    for entry in entries:
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
