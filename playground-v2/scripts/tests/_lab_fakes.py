"""Fakes that record lab operations and inject failures. None of them implements policy.

One `Journal` is shared by every fake in a test, so order across the lock store, the clock and
the lab operations is read from a single list of `(op, detail)` entries.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any
from collections.abc import Callable


class Journal(list):
    def ops(self) -> list[str]:
        return [op for op, _ in self]


class FakeLockStore:
    """The lab-side record store the lock module drives: three primitives, nothing more.

    `create_exclusive` is the only way to write a record, and it is atomic (the fake's own mutex
    stands in for the filesystem's). `read` yields briefly so a read-then-write take would race.
    """

    def __init__(self, journal: Journal | None = None) -> None:
        self.journal = journal if journal is not None else Journal()
        self.records: dict[str, str] = {}
        self.on_delete: Callable[[str], None] | None = None
        self._mutex = threading.Lock()

    def create_exclusive(self, name: str, record: str) -> bool:
        with self._mutex:
            self.journal.append(("lock.create", name))
            if name in self.records:
                return False
            self.records[name] = record
            return True

    def read(self, name: str) -> str | None:
        self.journal.append(("lock.read", name))
        value = self.records.get(name)
        time.sleep(0.005)
        return value

    def delete(self, name: str) -> None:
        self.journal.append(("lock.delete", name))
        if self.on_delete is not None:
            self.on_delete(name)
        self.records.pop(name, None)


class FakeClock:
    """`now()` advances one minute per call, so later reads are always later."""

    def __init__(self, journal: Journal, start: str = "2026-10-21T00:00:00+00:00",
                 fail_at: str | None = None, exc: type[BaseException] = RuntimeError) -> None:
        self.journal, self.fail_at, self.exc = journal, fail_at, exc
        self._t = datetime.fromisoformat(start)

    def now(self) -> datetime:
        self._t += timedelta(minutes=1)
        return self._t

    def sleep(self, seconds: float) -> None:
        self.journal.append(("clock.sleep", seconds))
        if self.fail_at == "settle":
            raise self.exc("settle failed")

    def sleep_until(self, moment: Any) -> None:
        self.journal.append(("clock.sleep_until", moment))
        if self.fail_at == "wait_as_of":
            raise self.exc("wait_as_of failed")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def instant(value: Any) -> datetime:
    """A timestamp however it is spelled, as an aware datetime (spelling is the builder's)."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


ALERT_AT = "2026-10-20T08:00:00Z"
ES_NOW = "2026-10-20T09:03:17.250Z"
FINGERPRINT = {"logs-system.auth-2026.10.20|2026-10-20T08": [1200, 1200]}
PART_BYTES = {
    "proc-tree.txt": b"PID PPID\n1 0 init\n",
    "stubs.tar": b"stub-dump-bytes",
    "web-1.image": b"image-bytes-web-1",
    "var-log-web-1.tar": b"volume-bytes",
}
STEP_PARTS = {
    "proc_tree": ["proc-tree.txt"],
    "stub_dumps": ["stubs.tar"],
    "commit_hosts": ["web-1.image"],
    "copy_volumes": ["var-log-web-1.tar"],
}


class FakeCaptureOps:
    """The lab operations capture drives. Each call is journaled with its arguments;
    `fail_at` names the step (or steps) that raise `exc`; `on_step(name)` observes each step
    as it starts. Snapshot steps write their part files into `dest`."""

    def __init__(self, journal: Journal, fail_at: str | tuple[str, ...] | None = None,
                 ledger_ref: str | None = "chaos-abc123",
                 fingerprint_result: dict | None = None,
                 exc: type[BaseException] = RuntimeError,
                 on_step: Callable[[str], None] | None = None) -> None:
        self.fingerprint_result = fingerprint_result if fingerprint_result is not None else FINGERPRINT
        self.journal, self.ledger_ref, self.exc, self.on_step = journal, ledger_ref, exc, on_step
        self.fail_at = (fail_at,) if isinstance(fail_at, str) else tuple(fail_at or ())
        self.fault_live = False
        self.fire_kwargs: dict[str, Any] = {}
        self.fingerprint_kwargs: dict[str, Any] = {}
        self.revert_refs: list[str] = []

    def _step(self, name: str, detail: Any = None) -> None:
        self.journal.append((name, detail))
        if self.on_step is not None:
            self.on_step(name)
        if name in self.fail_at:
            raise self.exc(f"{name} failed")

    def fire(self, scenario: str, chaos: str, seed: int, lock_token: str) -> dict:
        self.fire_kwargs = {"scenario": scenario, "chaos": chaos, "seed": seed,
                            "lock_token": lock_token}
        self._step("fire", dict(self.fire_kwargs))
        self.fault_live = self.ledger_ref is not None
        return {"ledger_ref": self.ledger_ref}

    def wait_alert(self, fired: dict) -> dict:
        self.waited_for = dict(fired)
        self._step("wait_alert")
        return {"@timestamp": ALERT_AT}

    def _snapshot(self, name: str, dest: Path) -> list[str]:
        self._step(name, dest)
        dest.mkdir(parents=True, exist_ok=True)
        for part in STEP_PARTS[name]:
            (dest / part).write_bytes(PART_BYTES[part])
        return STEP_PARTS[name]

    def proc_tree(self, dest: Path) -> list[str]:
        return self._snapshot("proc_tree", dest)

    def stub_dumps(self, dest: Path) -> list[str]:
        return self._snapshot("stub_dumps", dest)

    def commit_hosts(self, dest: Path, as_of: Any = None) -> list[str]:
        return self._snapshot("commit_hosts", dest)

    def copy_volumes(self, dest: Path) -> list[str]:
        return self._snapshot("copy_volumes", dest)

    def revert(self, ledger_ref: str) -> None:
        self.revert_refs.append(ledger_ref)
        self._step("revert", ledger_ref)
        self.fault_live = False

    def es_now(self) -> str:
        self._step("es_now")
        return ES_NOW

    def refresh(self) -> None:
        self._step("refresh")

    def fingerprint(self, window: Any, as_of: Any, arrived_by: Any) -> dict:
        self.fingerprint_kwargs = {"window": window, "as_of": as_of, "arrived_by": arrived_by}
        self._step("fingerprint", dict(self.fingerprint_kwargs))
        return self.fingerprint_result


class LocalContainer:
    """Stands in for `docker --context C exec [opts] CONTAINER <argv>`: runs the argv on this
    machine with absolute paths re-rooted under `root`, so a script meant for the lab container
    acts on a throwaway directory. It never touches a path outside `root` (an absolute path it
    cannot re-root raises AssertionError). It knows nothing about locks."""

    _PATH = re.compile(r"(?<![\w./~$-])/[A-Za-z0-9_.][^\s'\"`;|&<>()$\\]*")

    def __init__(self, root: Path) -> None:
        self.root, self.argvs = root, []

    def _reroot(self, text: str) -> str:
        root = str(self.root)

        def sub(m: re.Match) -> str:
            path = m.group(0)
            if path == root or path.startswith(root + "/"):
                return path
            if path in ("/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"):
                return path
            return root + path

        return self._PATH.sub(sub, text)

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        import subprocess
        self.argvs.append(list(argv))
        assert argv[:2] == ["docker", "--context"] and argv[3] == "exec", argv
        rest, i = list(argv[4:]), 0
        while rest[i].startswith("-"):  # docker exec options: -i, -u X, -e K=V, -w D
            i += 2 if rest[i] in ("-u", "-e", "-w", "--user", "--env", "--workdir") else 1
        inner = [self._reroot(a) for a in rest[i + 1:]]  # rest[i] is the container
        assert inner, argv
        if inner[0] == "/" or any(a == "/" for a in inner):
            raise AssertionError(f"bare root path in {argv}")
        run_kwargs = {k: v for k, v in kwargs.items() if k in ("input", "stdin", "timeout")}
        return subprocess.run(inner, capture_output=True, text=True, **run_kwargs)
