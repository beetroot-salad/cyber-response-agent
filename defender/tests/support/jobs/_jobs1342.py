"""#1342 machinery: tenants in the database, alert bytes, the job store under test, its audit
events, a scripted stand-in child for the worker's `child_argv` seam, and a stand-in container set.

The scripted child only writes the files its spec names and exits with the spec's code; it never
decides an outcome. Host-record contents are fixtures in the shapes the runtime writes them."""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import sys
import textwrap
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

WORKTREE = Path(__file__).resolve().parents[4]
DEFENDER = WORKTREE / "defender"
GOLDEN_REPORT = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "report.md"  # disposition: inconclusive
MALICIOUS_REPORT = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-sshpivot-ab3" / "report.md"  # malicious

NOW = dt.datetime(2026, 10, 29, 12, 0, tzinfo=dt.UTC)
T1 = fixture_uuid("tenant:jobs-1342-a")
T2 = fixture_uuid("tenant:jobs-1342-b")
JOBS_AUDIT_LOGGER = "defender.jobs.audit"
WORKER_LOGGER = "defender.worker"

#: Exact bytes `admit()` accepts, with key order, spacing, a trailing zero and an escape that any
#: re-serialization would change.
ALERT_BYTES = (b'{"rule": {"id": "r-1342",  "description": "sketch"},\n'
               b' "z": 1.50, "a": "\\u00e9", "alert_timestamp": "2026-10-29T00:00:00Z"}\n')
ALERT_DIGEST = hashlib.sha256(ALERT_BYTES).hexdigest()
#: Exact bytes `admit()` accepts that a text-mode read or a line-end normalization would change:
#: CRLF line ends, a tab, multibyte text, a trailing CRLF.
AWKWARD_ALERT_BYTES = '{"rule":\t"caf\u00e9 \u2713",\r\n "n": 1,\r\n\t"text": "line\\r\\nend"}\r\n'.encode()
#: Exact bytes `admit()` accepts that a strip of whitespace would change: leading whitespace (a line
#: end, a tab) and spaces before the final line end.
PADDED_ALERT_BYTES = b'\n\t {"rule": {"id": "r-1342"},  "n": 1}   \n'
#: Exact bytes `admit()` accepts that a Unicode normalization would change: "e" + U+0301 (NFD).
DECOMPOSED_ALERT_BYTES = '{"rule": {"id": "r-1342"}, "text": "cafe\u0301"}\n'.encode()
#: Exact bytes `admit()` accepts that a strip of a leading byte-order mark would change: U+FEFF inside a
#: JSON string value (not at the start).
ZWNBSP_ALERT_BYTES = '{"rule": {"id": "r-1342"}, "text": "a\ufeffb"}\n'.encode()
TITLE = "SSH success after failures"
DESCRIPTION = "Three failures then a success from one source."


def register_tenant(dsn: str, tenant_id: str) -> None:
    """The tenant row #1339 owns, inserted directly (the identity service is not under test)."""
    execute(dsn, "INSERT INTO identity.tenants (id, created_at) VALUES (%s, %s)", (tenant_id, NOW))


def fixed_clock() -> dt.datetime:
    return NOW


@asynccontextmanager
async def job_store(dsn: str) -> AsyncIterator[Any]:
    """The store under test on `dsn`, closed after."""
    from defender.jobs import JobStore

    store = JobStore(dsn, clock=fixed_clock)
    try:
        yield store
    finally:
        await store.close()


async def an_alert(store: Any, tenant_id: str, *, ticket: str = "T-1",
                   raw: bytes = ALERT_BYTES) -> Any:
    """Insert one alert through the trusted insert with this module's display fields."""
    return await store.insert_alert(
        tenant_id, vendor="elastic", vendor_ticket_id=ticket, fired_at=NOW, changed_at=NOW,
        received_at=NOW, title=TITLE, description=DESCRIPTION, raw=raw)


def row(dsn: str, investigation_id: str) -> dict[str, Any] | None:
    """The investigation row as the database holds it (read on a separate connection)."""
    cols = ("stage", "attempt", "request_key", "started_at", "finished_at", "disposition",
            "cost_usd", "knowledge", "failure_reason", "failure_message")
    found = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.investigations WHERE id = %s",  # noqa: S608
                    (investigation_id,))
    return dict(zip(cols, found[0], strict=True)) if found else None


# --- audit -----------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Event:
    action: str
    actor: str
    tenant_id: str | None
    target: str | None
    detail: str | None


class JobsAudit:
    """Structured events on `defender.jobs.audit`, read from the record extras. Construct it
    before the actions it watches."""

    def __init__(self, caplog: Any) -> None:
        caplog.set_level(logging.DEBUG, logger=JOBS_AUDIT_LOGGER)
        self._caplog = caplog

    def events(self) -> list[Event]:
        return [Event(r.action, r.actor, getattr(r, "tenant_id", None), getattr(r, "target", None),
                      getattr(r, "detail", None))
                for r in self._caplog.records if r.name == JOBS_AUDIT_LOGGER]


class VisibleAtEmit(logging.Handler):
    """On each audit event, reads the target row's stage from a separate connection: an event
    emitted after commit sees the row it names."""

    def __init__(self, dsn: str) -> None:
        super().__init__(logging.DEBUG)
        self.dsn = dsn
        self.seen: list[tuple[str, str | None]] = []

    def emit(self, record: logging.LogRecord) -> None:
        target = getattr(record, "target", None)
        found = execute(self.dsn, "SELECT stage FROM jobs.investigations WHERE id = %s", (target,))
        self.seen.append((record.action, found[0][0] if found else None))


# --- the worker's seams ------------------------------------------------------------------------

#: The stand-in child: `child.py <spec.json> --job <id> --tenant <T> --parent-pid <pid>`. It records
#: what it was given (argv, environment, process group, whether the launch files existed) in
#: `<seen_dir>/<id>.json`, appends `start <id>` / `end <id>` to the events file, optionally waits for
#: a release file, writes the spec's host records (paths relative to the runs container, `{id}`
#: expanded) and exits with the spec's code. It never decides an outcome.
CHILD_SCRIPT = textwrap.dedent("""
    import json, os, signal, subprocess, sys, time
    from pathlib import Path

    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    argv = sys.argv[2:]
    runs = Path(spec["runs"])
    run_id = argv[argv.index("--job") + 1]

    def fill(text):
        return text.replace("{id}", run_id)

    def event(kind):
        with open(spec["events"], "a", encoding="utf-8") as handle:
            handle.write(f"{kind} {run_id}\\n")

    term = spec.get("term", "default")
    if term == "ignore":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    elif term == "mark":
        def on_term(*_):
            Path(fill(spec["term_mark"])).touch()
            event("end")
            os._exit(0)
        signal.signal(signal.SIGTERM, on_term)
    grandchild = None
    if spec.get("grandchild"):
        grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"]).pid
    seen_dir = Path(spec["seen_dir"])
    seen_dir.mkdir(parents=True, exist_ok=True)
    (seen_dir / f"{run_id}.json").write_text(json.dumps({
        "argv": argv, "pid": os.getpid(), "pgid": os.getpgid(0), "sid": os.getsid(0),
        "data_root": os.environ.get("DEFENDER_DATA_ROOT"), "grandchild": grandchild,
        "launch_at_start": (runs / f"{run_id}.launch.json").is_file(),
        "alert_at_start": (runs / f"{run_id}.alert.json").is_file(),
        "stdio": [[os.fstat(fd).st_dev, os.fstat(fd).st_ino] for fd in (1, 2)],
    }), encoding="utf-8")
    event("start")
    if spec.get("print"):
        print(spec["print"]); print(spec["print"], file=sys.stderr)
    release = spec.get("wait_for")
    deadline = time.monotonic() + 60
    while release and not Path(release).exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    for rel in spec.get("dirs", []):
        (runs / fill(rel)).mkdir(parents=True, exist_ok=True)
    for rel, text in spec.get("files", {}).items():
        path = runs / fill(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for rel, hexbytes in spec.get("binary", {}).items():
        path = runs / fill(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes.fromhex(hexbytes))
    for rel, (head, size) in spec.get("padded", {}).items():
        path = runs / fill(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(head.encode("utf-8"))
            for _ in range(size // (1 << 20)):
                handle.write(b" " * (1 << 20))
    for rel, (head, size) in spec.get("sparse", {}).items():
        path = runs / fill(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(head.encode("utf-8"))
            handle.truncate(size)
    for rel, target in spec.get("links", {}).items():
        path = runs / fill(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
    event("end")
    sys.exit(spec.get("exit", 0))
""")


@dataclasses.dataclass
class ScriptedChild:
    """`child_argv` for a worker: every launch runs `CHILD_SCRIPT` with this spec.

    `files` (text), `binary` (hex), `sparse` (`{head, size}`), `links` (symlink targets) and `dirs`
    name what the child leaves in the runs container (`padded`: `{head, size}`, the head then spaces
    up to `size` bytes, so a document that stays valid however much of it is read); `term` is how it takes SIGTERM (`default`,
    `ignore`, or `mark`: touch `term_mark` and exit); `grandchild` starts a `sleep` in its group."""

    where: Path
    runs: Path
    files: dict[str, str] = dataclasses.field(default_factory=dict)
    binary: dict[str, str] = dataclasses.field(default_factory=dict)
    sparse: dict[str, tuple[str, int]] = dataclasses.field(default_factory=dict)
    padded: dict[str, tuple[str, int]] = dataclasses.field(default_factory=dict)
    links: dict[str, str] = dataclasses.field(default_factory=dict)
    dirs: list[str] = dataclasses.field(default_factory=list)
    exit: int = 0
    wait_for: Path | None = None
    term: str = "default"
    term_mark: str | None = None
    grandchild: bool = False
    printed: str | None = None

    def __post_init__(self) -> None:
        self.where.mkdir(parents=True, exist_ok=True)
        self.script = self.where / "child.py"
        self.script.write_text(CHILD_SCRIPT, encoding="utf-8")
        self.spec = self.where / "spec.json"
        self.seen_dir = self.where / "seen"
        self.events_path = self.where / "events.log"

    def spec_dict(self) -> dict[str, Any]:
        return {
            "runs": str(self.runs), "seen_dir": str(self.seen_dir), "events": str(self.events_path),
            "files": self.files, "binary": self.binary, "sparse": self.sparse, "padded": self.padded, "links": self.links,
            "dirs": self.dirs, "exit": self.exit, "term": self.term, "term_mark": self.term_mark,
            "grandchild": self.grandchild, "print": self.printed,
            "wait_for": None if self.wait_for is None else str(self.wait_for),
        }

    def __call__(self, launch: Any) -> list[str]:
        self.spec.write_text(json.dumps(self.spec_dict()), encoding="utf-8")
        return [sys.executable, str(self.script), str(self.spec), "--job", launch.investigation_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

    def seen_all(self) -> dict[str, dict[str, Any]]:
        """What each child that started saw, keyed by run id."""
        if not self.seen_dir.exists():
            return {}
        return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in self.seen_dir.glob("*.json")}

    def seen(self, run_id: str | None = None) -> dict[str, Any] | None:
        """One child's record: `run_id`'s, or the only one (None when none ran)."""
        everything = self.seen_all()
        if run_id is not None:
            return everything.get(run_id)
        assert len(everything) <= 1, f"{len(everything)} children ran; name one"
        return next(iter(everything.values()), None)

    def events(self) -> list[tuple[str, str]]:
        """`("start"|"end", run id)` in the order the children wrote them."""
        if not self.events_path.exists():
            return []
        return [tuple(line.split()) for line in self.events_path.read_text(encoding="utf-8").splitlines()]  # type: ignore[misc]

    def max_alive(self) -> int:
        """The most children alive at once, from the order of the start and end events."""
        alive = peak = 0
        for kind, _ in self.events():
            alive += 1 if kind == "start" else -1
            peak = max(peak, alive)
        return peak


class StandInContainers:
    """The worker's `containers` seam over marker files: a container exists while its file does.
    Records every call so a test can tell a look from a removal."""

    def __init__(self, where: Path) -> None:
        self.where = where
        where.mkdir(parents=True, exist_ok=True)
        self.calls: list[tuple[str, str]] = []

    def plant(self, name: str) -> None:
        (self.where / name).touch()

    def exists(self, name: str) -> bool:
        self.calls.append(("exists", name))
        return (self.where / name).exists()

    def remove(self, name: str) -> None:
        self.calls.append(("remove", name))
        (self.where / name).unlink()


class FaultyContainers(StandInContainers):
    """The stand-in containers whose `exists` or `remove` (named by `fail`) raises: a daemon that
    cannot be asked or will not remove."""

    def __init__(self, where: Path, *, fail: str) -> None:
        super().__init__(where)
        self.fail = fail

    def exists(self, name: str) -> bool:
        if self.fail == "exists":
            self.calls.append(("exists", name))
            raise RuntimeError("the container daemon cannot be asked")
        return super().exists(name)

    def remove(self, name: str) -> None:
        if self.fail == "remove":
            self.calls.append(("remove", name))
            raise RuntimeError("the container daemon will not remove it")
        super().remove(name)


def fd_identity(fd: int) -> list[int]:
    """`[device, inode]` of what `fd` is open on, comparable with a child's `seen()["stdio"]`."""
    found = os.fstat(fd)
    return [found.st_dev, found.st_ino]


def make_worker(store: Any, data_root: Path, child: Callable[[Any], list[str]], *,
                containers: Any = None, slots: int = 3, stop_grace: float | None = None) -> Any:
    from defender.worker import Worker

    extra = {} if stop_grace is None else {"stop_grace": stop_grace}
    return Worker(store, data_root=data_root, child_argv=child,
                  containers=containers if containers is not None else StandInContainers(data_root.parent / "containers"),
                  slots=slots, clock=fixed_clock, **extra)


def plant_queued_investigation(dsn: str, *, tenant: str, alert_id: str, investigation_id: str,
                               key: str = "planted") -> None:
    """A `queued` row with a chosen id, as SQL (the store mints ids; a case that must plant a file
    named for the id before the claim needs to know it)."""
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, "
                 "stage, created_at, cost_usd) VALUES (%s, %s, %s, %s, 1, 'queued', %s, 0)",
            (investigation_id, tenant, alert_id, key, NOW))


def tree(root: Path) -> dict[str, bytes | None]:
    """Every path under `root` (relative) with its bytes, or None for a directory; symlinks are
    reported as such, not followed."""
    found: dict[str, bytes | None] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            found[rel] = b"-> " + os.readlink(path).encode()
        else:
            found[rel] = None if path.is_dir() else path.read_bytes()
    return found


# --- host records, in the shapes the runtime writes ----------------------------------------------

def job_end(*, setup: str = "done", box: str = "started", report_committed: bool = True,
            scrub_verified: bool = True) -> str:
    """The ratified job-end record (`<runs>/<id>.job-end.json`), exactly its four facts."""
    return json.dumps({"setup": setup, "box": box, "report_committed": report_committed,
                       "scrub_verified": scrub_verified})


def scrub_verdict(*, ran: bool) -> str:
    """`box/_scrub.py`'s verdict document. The worker does not read it (M9); a case may plant it
    to show that."""
    return json.dumps({"ran": ran} if ran else {"ran": False, "reason": "fixture"})


def knowledge_record(commit: str) -> str:
    """`KnowledgeSource.host_record()` for a fresh publish."""
    return json.dumps({"kind": "fresh", "commit": commit, "stale_kind": None, "reason": None})


def knowledge_record_of(kind: str, commit: str, *, stale_kind: str | None = None,
                        reason: str | None = None) -> str:
    """A knowledge record of any kind, in the shape `KnowledgeSource.host_record()` writes."""
    return json.dumps({"kind": kind, "commit": commit, "stale_kind": stale_kind, "reason": reason})


def session_pointer(case_id: str, *, session_id: str | None = None) -> str:
    """The pointer as `write_case_pointer` writes it, its `store_path` deliberately elsewhere:
    the reader locates the database from the case id, never from this string."""
    body = {"case_id": case_id, "store_path": "/nonexistent/elsewhere.db"}
    if session_id is not None:
        body["session_id"] = session_id
    return json.dumps(body)


def _paths(runs: Path):
    from defender.records import SessionPaths
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    return SessionPaths(fixture_runs_base(runs))


def session_db(runs: Path, case_id: str) -> Path:
    """Where the layout puts `case_id`'s session database beside `runs`."""
    from defender.records.session_store._write import store_path_for

    return store_path_for(case_id, sessions=_paths(runs))


def _response(model: str, usage: dict[str, int]) -> list:
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
    from pydantic_ai.usage import RequestUsage

    return [ModelRequest(parts=[UserPromptPart(content="go")]),
            ModelResponse(parts=[TextPart(content="ok")], model_name=model,
                          usage=RequestUsage(**usage))]


def plant_sessions(runs: Path, case_id: str, spend: list[tuple[str, str, dict[str, int]]],
                   ) -> dict[str, tuple[str, list[int]]]:
    """A session database for `case_id` beside `runs`: one root session per `(agent_id, model,
    usage)`, each holding one priced response. Returns `{agent_id: (session_id, message ids)}`."""
    from defender.records.session_store._write import open_store

    made: dict[str, tuple[str, list[int]]] = {}
    with open_store(case_id=case_id, sessions=_paths(runs)) as handle:
        for agent_id, model, usage in spend:
            session = handle.new_session(agent_id)
            made[agent_id] = (session, handle.append(session, _response(model, usage), agent_id=agent_id))
    return made


def plant_fork(runs: Path, case_id: str, parent: tuple[str, list[int]], *, agent_id: str, model: str,
               usage: dict[str, int]) -> str:
    """A session forked from `parent`'s response (its inherited prefix is the request and that
    response) that adds one priced response of its own. Returns the fork's session id."""
    from defender.records.session_store._write import open_store

    with open_store(case_id=case_id, sessions=_paths(runs)) as handle:
        fork = handle.fork(parent[0], parent[1][-1])
        handle.append(fork, _response(model, usage), agent_id=agent_id)
    return fork
