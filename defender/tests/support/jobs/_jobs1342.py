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
GOLDEN_REPORT = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "report.md"

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

#: The stand-in child: `child.py <spec.json> --job <id> --tenant <T> --parent-pid <pid>`. Records
#: its argv and whether the launch files existed at start, writes the spec's files (paths relative
#: to the runs container), optionally waits for a release file, then exits with the spec's code.
CHILD_SCRIPT = textwrap.dedent("""
    import json, os, sys, time
    from pathlib import Path

    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    argv = sys.argv[2:]
    runs = Path(spec["runs"])
    run_id = argv[argv.index("--job") + 1]
    Path(spec["seen"]).write_text(json.dumps({
        "argv": argv, "pid": os.getpid(),
        "launch_at_start": (runs / f"{run_id}.launch.json").is_file(),
        "alert_at_start": (runs / f"{run_id}.alert.json").is_file(),
    }), encoding="utf-8")
    release = spec.get("wait_for")
    deadline = time.monotonic() + 60
    while release and not Path(release).exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    for rel, text in spec.get("files", {}).items():
        path = runs / rel.replace("{id}", run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    sys.exit(spec.get("exit", 0))
""")


@dataclasses.dataclass
class ScriptedChild:
    """`child_argv` for a worker: every launch runs `CHILD_SCRIPT` with this spec."""

    where: Path
    runs: Path
    files: dict[str, str] = dataclasses.field(default_factory=dict)
    exit: int = 0
    wait_for: Path | None = None

    def __post_init__(self) -> None:
        self.where.mkdir(parents=True, exist_ok=True)
        self.script = self.where / "child.py"
        self.script.write_text(CHILD_SCRIPT, encoding="utf-8")
        self.spec = self.where / "spec.json"
        self.seen_path = self.where / "seen.json"

    def __call__(self, launch: Any) -> list[str]:
        self.spec.write_text(json.dumps({
            "runs": str(self.runs), "seen": str(self.seen_path), "files": self.files,
            "exit": self.exit, "wait_for": None if self.wait_for is None else str(self.wait_for),
        }), encoding="utf-8")
        return [sys.executable, str(self.script), str(self.spec), "--job", launch.investigation_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

    def seen(self) -> dict[str, Any] | None:
        return json.loads(self.seen_path.read_text(encoding="utf-8")) if self.seen_path.exists() else None


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


def make_worker(store: Any, data_root: Path, child: Callable[[Any], list[str]], *,
                containers: Any = None, slots: int = 3) -> Any:
    from defender.worker import Worker

    return Worker(store, data_root=data_root, child_argv=child,
                  containers=containers if containers is not None else StandInContainers(data_root.parent / "containers"),
                  slots=slots, clock=fixed_clock)


# --- host records, in the shapes the runtime writes ----------------------------------------------

def job_end(*, setup: str = "done", box: str = "started", report_committed: bool = True,
            scrub_verified: bool = True) -> str:
    """The proposed job-end record (`<runs>/<id>.job-end.json`)."""
    return json.dumps({"setup": setup, "box": box, "report_committed": report_committed,
                       "scrub_verified": scrub_verified})


def scrub_verdict(*, ran: bool) -> str:
    """`box/_scrub.py`'s verdict document, kept consistent with the job-end's `scrub_verified`."""
    return json.dumps({"ran": ran} if ran else {"ran": False, "reason": "fixture"})


def knowledge_record(commit: str) -> str:
    """`KnowledgeSource.host_record()` for a fresh publish."""
    return json.dumps({"kind": "fresh", "commit": commit, "stale_kind": None, "reason": None})


def session_pointer(case_id: str) -> str:
    """The pointer as `write_case_pointer` writes it, its `store_path` deliberately elsewhere:
    the reader locates the database from the case id, never from this string."""
    return json.dumps({"case_id": case_id, "store_path": "/nonexistent/elsewhere.db"})


def plant_sessions(runs: Path, case_id: str, spend: list[tuple[str, str, dict[str, int]]]) -> None:
    """A session database for `case_id` beside `runs`: one session per `(agent_id, model, usage)`,
    each holding one priced response. The first is the root (MAIN)."""
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
    from pydantic_ai.usage import RequestUsage

    from defender.records import SessionPaths
    from defender.records.session_store._write import open_store
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    with open_store(case_id=case_id, sessions=SessionPaths(fixture_runs_base(runs))) as handle:
        for agent_id, model, usage in spend:
            session = handle.new_session(agent_id)
            handle.append(session, [
                ModelRequest(parts=[UserPromptPart(content="go")]),
                ModelResponse(parts=[TextPart(content="ok")], model_name=model,
                              usage=RequestUsage(**usage)),
            ], agent_id=agent_id)
