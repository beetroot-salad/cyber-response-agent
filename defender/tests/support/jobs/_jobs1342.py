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
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._mapping1345 import (
    ALERT_BYTES_DESCRIPTION,
    ALERT_BYTES_TITLE,
    FIXTURE_ALERT_MAPPING,
    seed_postgres,
)
from defender.tests.support.shared.filesystem._handoff import write_whole

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
#: U+FEFF at the start of a value, at the end of one, twice in a row, twice apart, and inside an object key.
FEFF_RICH_ALERT_BYTES = ('{"rule": {"id": "r-1342"}, "lead": "\ufeffx", "tail": "y\ufeff", "pair": "p\ufeff\ufeffq", '
                         '"apart": "\ufeffm\ufeffn", "k\ufeffey": 1}\n').encode()

#: #1345: the store derives an alert's display (`insert_alert` takes no title or description), so these are what the
#: default mapping (`_mapping1345.FIXTURE_ALERT_MAPPING`: title `rule.description`, description `rule.id`) derives from
#: `ALERT_BYTES`; they were free-standing strings (#1342) that `an_alert` passed in.
TITLE = ALERT_BYTES_TITLE
DESCRIPTION = ALERT_BYTES_DESCRIPTION


def register_tenant(dsn: str, tenant_id: str, *, state: str = "active", wiring: bool = True,
                    data_root: Path | None = None, generations: Any = None,
                    alert_mapping: Mapping[str, str | None] | None = FIXTURE_ALERT_MAPPING,
                    origin: str | None = None) -> None:
    """A `tenancy.tenants` row (default: active, forge wiring recorded, at `origin` when given) by main's #1214 helper
    (r6), and #1345's default alert mapping saved through the store (`alert_mapping=None`: a tenant with none, for a test
    of absence).

    An active tenant gets one live generation with a sign login (the fixture tenant's elastic is proxied,
    #1391 P1/D12: run start signs request tokens), unless `generations` says otherwise (`()` for none)."""
    from defender.tests.support.tenancy._active1214 import insert_active_tenant
    from defender.tests.support.tenancy._proxied1391 import sign_generation

    if generations is None:
        generations = [sign_generation(tenant_id)] if state == "active" else ()
    insert_active_tenant(dsn, tenant_id, state=state, wiring=wiring, data_root=data_root, generations=generations,
                         alert_mapping=alert_mapping, origin=origin)


def drop_tenant(dsn: str, tenant_id: str) -> None:
    """Delete `tenant_id`'s record and the tenancy rows that reference it (alert mapping, generations, publish status,
    forge wiring)."""
    for table in ("alert_mappings", "generations", "publish_status", "forge_wiring"):
        execute(dsn, f'DELETE FROM tenancy."{table}" WHERE tenant_id = %s', (tenant_id,))  # noqa: S608
    execute(dsn, "DELETE FROM tenancy.tenants WHERE id = %s", (tenant_id,))


def restate_tenant(dsn: str, tenant_id: str, *, state: str, wiring: bool = True, data_root: Path | None = None) -> None:
    """Replace `tenant_id`'s record by one in `state` (a case's premise: do it before any alert names the tenant).
    The tenant's alert mapping is not part of the record being replaced: it is read first, taken away with the row it
    refers to, and saved again as it was (no mapping stays none). (#1345 repair)"""
    entries = tuple(FIXTURE_ALERT_MAPPING)
    saved = execute(dsn, f"SELECT {', '.join(entries)} FROM tenancy.alert_mappings WHERE tenant_id = %s",  # noqa: S608
                    (tenant_id,))
    drop_tenant(dsn, tenant_id)
    register_tenant(dsn, tenant_id, state=state, wiring=wiring, data_root=data_root,
                    alert_mapping=dict(zip(entries, saved[0], strict=True)) if saved else None)


def move_tenant(dsn: str, tenant_id: str, *, state: str) -> None:
    """Move `tenant_id`'s existing record to `state` in place (rows that reference it stay), as a lifecycle step would."""
    from defender.tests.support.tenancy._active1214 import _JOB

    action, step, actor = _JOB.get(state, (None, None, None))
    execute(dsn, "UPDATE tenancy.tenants SET state = %s, pending_action = %s, step = %s, step_actor = %s WHERE id = %s",
            (state, action, step, actor, tenant_id))


def fixed_clock() -> dt.datetime:
    return NOW


@asynccontextmanager
async def job_store(dsn: str, **knobs: Any) -> AsyncIterator[Any]:
    """The store under test on `dsn`, closed after. `knobs` (#1343 sketch, unratified): `lease`,
    the lease length in seconds a claim or renewal sets."""
    from defender.jobs import JobStore

    store = JobStore(dsn, clock=fixed_clock, **knobs)
    try:
        yield store
    finally:
        await store.close()


def seed_alert_mapping(dsn: str, tenant_id: str, paths: Mapping[str, str | None]) -> None:
    """Replace `tenant_id`'s alert mapping with `paths` (entries not named are unmapped) through the store's own
    replace (#1345 O1), from sync code. The row's shape is the store's: this names no table or column."""
    seed_postgres(dsn, tenant_id, paths)


async def an_alert(store: Any, tenant_id: str, *, ticket: str = "T-1",
                   raw: bytes = ALERT_BYTES) -> Any:
    """Insert one alert through the trusted insert; the store derives its title and description (#1345 O2)."""
    return await store.insert_alert(
        tenant_id, vendor="elastic", vendor_ticket_id=ticket, fired_at=NOW, changed_at=NOW,
        received_at=NOW, raw=raw)


def lease_left(dsn: str, investigation_id: str) -> float | None:
    """Seconds from the database's `now()` to the row's lease expiry (negative: lapsed; None: no
    lease). #1343 sketch: the column name `lease_expires_at` is unratified."""
    found = execute(dsn, "SELECT EXTRACT(EPOCH FROM lease_expires_at - now()) FROM jobs.investigations "
                         "WHERE id = %s", (investigation_id,))
    return None if not found or found[0][0] is None else float(found[0][0])


def lapse_lease(dsn: str, investigation_id: str) -> None:
    """Set the row's lease to lapsed by the database's clock (B Clock: tests lapse it in SQL)."""
    execute(dsn, "UPDATE jobs.investigations SET lease_expires_at = now() - interval '1 second' "
                 "WHERE id = %s", (investigation_id,))


def accounting_written(dsn: str, investigation_id: str) -> Any:
    """The row's internal final-accounting mark (#1343 sketch: `accounting_written_at`, unratified)."""
    found = execute(dsn, "SELECT accounting_written_at FROM jobs.investigations WHERE id = %s",
                    (investigation_id,))
    return found[0][0] if found else None


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

    def leave_records():
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

    sealed_by = {}  # r7.3 T1: what a child that ends cleanly seals: set once its ledger rows are being written

    def sealing():
        if sealed_by and not sealed_by.get("done"):
            sealed_by["done"] = True
            try:
                sealed_by["seal"](runs, sealed_by["case"], run_id)
                Path(spec["sessions"]["marks"], "sealed").touch()
            except Exception as fault:  # noqa: BLE001 - a missing seal is the code stage's red, named by its own mark
                Path(spec["sessions"]["marks"], "seal-failed").write_text(repr(fault), encoding="utf-8")

    term = spec.get("term", "default")
    if term == "ignore":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    elif term in ("mark", "finish"):
        def on_term(*_):
            Path(fill(spec["term_mark"])).touch()
            if term == "finish":  # #1343 B11: a child that completes on its own as the SIGTERM lands
                sealing()  # it completes: the run's exit seals its ledger before the records are left
                leave_records()
            event("end")
            os._exit(0)
        signal.signal(signal.SIGTERM, on_term)
    grandchild = None
    if spec.get("grandchild"):
        grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"]).pid
    seen_dir = Path(spec["seen_dir"])
    seen_dir.mkdir(parents=True, exist_ok=True)
    # Written whole, then renamed into place: `seen_all` polls this folder and must never read
    # a half-written record.
    part = seen_dir / f"{run_id}.json.part"
    part.write_text(json.dumps({
        "argv": argv, "pid": os.getpid(), "pgid": os.getpgid(0), "sid": os.getsid(0),
        "data_root": os.environ.get("DEFENDER_DATA_ROOT"), "grandchild": grandchild,
        "claim": os.environ.get("DEFENDER_BOX_CLAIM"),
        "launch_at_start": (runs / f"{run_id}.launch.json").is_file(),
        "alert_at_start": (runs / f"{run_id}.alert.json").is_file(),
        "stdio": [[os.fstat(fd).st_dev, os.fstat(fd).st_ino] for fd in (1, 2)],
    }), encoding="utf-8")
    os.replace(part, seen_dir / f"{run_id}.json")
    event("start")
    if spec.get("print"):
        print(spec["print"]); print(spec["print"], file=sys.stderr)
    box = spec.get("box")
    if box:  # the box this child's start created: stamped with the token its launch record handed it, or another
        launch_token = json.loads((runs / f"{run_id}.launch.json").read_text(encoding="utf-8")).get("box_token") or ""
        stamp = {"launch": launch_token, "other": "f" * 32, "none": ""}[box["token"]]
        # Its own start's box carries the claim its worker handed it; another start's carries none. A
        # docker stand-in's box holds it as its third line; a `StandInContainers` one is filed under it.
        claim = os.environ.get("DEFENDER_BOX_CLAIM", "") if box["token"] == "launch" else ""
        folder = Path(box["dir"]) / "claims" / claim if claim and not box.get("state") else Path(box["dir"])
        planted = folder / f"defender-run-{run_id}"
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text(f"{box['state']}\\n{stamp}\\n{claim}" if box.get("state") else stamp, encoding="utf-8")
    claimed = spec.get("claimed")
    if claimed:  # boxes this child's process tree started: each carries the claim its worker handed it
        folder = Path(claimed["dir"]) / "claims" / os.environ["DEFENDER_BOX_CLAIM"]
        folder.mkdir(parents=True, exist_ok=True)
        for name in claimed["names"]:
            (folder / name).write_text("", encoding="utf-8")
    spend = spec.get("sessions")
    if spend:  # #1343 B2/B6: the live child writes its session database while the worker reads it
        sys.path.insert(0, spend["path"])
        from defender.records.session_store._write import open_store
        from defender.tests.support.jobs._jobs1342 import _paths, _response, insert_spend, seal_spend, session_db, session_pointer
        import hashlib
        case = hashlib.md5(run_id.encode()).hexdigest() if spend.get("per_run") else spend["case"]  # per run: a retry never shares its parent's database
        (runs / f"{run_id}.session-pointer.json").write_text(session_pointer(case), encoding="utf-8")
        marks = Path(spend["marks"])
        marks.mkdir(parents=True, exist_ok=True)
        if spend.get("seal", True):
            sealed_by.update(seal=seal_spend, case=case)
        with open_store(case_id=case, sessions=_paths(runs)) as handle:
            session = handle.new_session("main")
            for n, (model, usage) in enumerate(spend["steps"]):
                began = time.monotonic()
                handle.append(session, _response(model, usage), agent_id="main")
                appended = time.monotonic() - began
                began = time.monotonic()
                try:
                    insert_spend(session_db(runs, case), run_id, [(model, usage)])  # #1377: the ledger row cost is read from
                except Exception as fault:  # noqa: BLE001 - a missing ledger is the code stage's red, named by its own mark
                    (marks / f"insert-failed-{n}").write_text(repr(fault), encoding="utf-8")
                else:
                    (marks / f"ledger-{n}").write_text(str(time.monotonic() - began), encoding="utf-8")
                (marks / f"wrote-{n}").write_text(str(appended), encoding="utf-8")  # after the insert: a test that waits on this mark then signals the child must find the ledger row (or insert-failed-n)
                until = time.monotonic() + 60
                while not (marks / f"go-{n}").exists() and time.monotonic() < until:
                    time.sleep(0.02)
            sealing()
    release = spec.get("wait_for")
    deadline = time.monotonic() + 60
    while release and not Path(release).exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    leave_records()
    event("end")
    die_by = spec.get("die_by")
    if die_by:  # dies by a signal it sends itself, as a crash does: its default action, nothing handled
        sys.stdout.flush(); sys.stderr.flush()
        if die_by != signal.SIGKILL:
            signal.signal(die_by, signal.SIG_DFL)
        os.kill(os.getpid(), die_by)
    sys.exit(spec.get("exit", 0))
""")


@dataclasses.dataclass
class ScriptedChild:
    """`child_argv` for a worker: every launch runs `CHILD_SCRIPT` with this spec.

    `files` (text), `binary` (hex), `sparse` (`{head, size}`), `links` (symlink targets) and `dirs`
    name what the child leaves in the runs container (`padded`: `{head, size}`, the head then spaces
    up to `size` bytes, so a document that stays valid however much of it is read); `term` is how it takes SIGTERM (`default`,
    `ignore`, `mark`: touch `term_mark` and exit with nothing written, or `finish`: touch it, write its records, exit 0); `grandchild` starts a `sleep` in its group.
    `die_by`: in place of exiting, it dies by that signal, sent to itself."""

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
    die_by: int | None = None
    #: A box the child leaves behind, as a start would have made it: `box_dir` is where, `box_token`
    #: whose (`launch`: its own start's, stamped with its launch record's token and, as a
    #: `StandInContainers` marker, carrying its claim; `other`: another start's; `none`: no token
    #: label), `box_state` the docker stand-in's state word (unset: a `StandInContainers` marker).
    box_dir: Path | str | None = None
    box_token: str = "launch"
    box_state: str | None = None
    #: Boxes the child's process tree starts under the claim its worker handed it (`box.CLAIM_ENV`), as
    #: `StandInContainers` markers in `claimed_dir`: a sibling's, an oracle's, a drain's.
    claimed_dir: Path | str | None = None
    claimed_names: tuple[str, ...] = ()
    #: #1343 B2/B6: `{"case", "steps": [(model, usage)], "marks"}`: the child writes its session
    #: pointer, holds its session database open and appends one priced response per step, touching
    #: `marks/wrote-<n>` (its text: how long the append took) and waiting for `marks/go-<n>`. With
    #: `"per_run": True` its case id (so database) is derived from its run id, so two runs never share one.
    sessions: dict[str, Any] | None = None

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
            "grandchild": self.grandchild, "print": self.printed, "die_by": self.die_by,
            "box": None if self.box_dir is None else {"dir": str(self.box_dir), "token": self.box_token,
                                                     "state": self.box_state},
            "claimed": None if self.claimed_dir is None else {"dir": str(self.claimed_dir),
                                                               "names": list(self.claimed_names)},
            "wait_for": None if self.wait_for is None else str(self.wait_for),
            "sessions": None if self.sessions is None else {**self.sessions, "path": str(WORKTREE)},
        }

    def __call__(self, launch: Any) -> list[str]:
        # A child launched a moment ago (another worker's, in the same test) may be reading the
        # spec right now, and must never see it half-written.
        write_whole(self.spec, json.dumps(self.spec_dict()))
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
    """The worker's `containers` seam over marker files. A container a child's process tree started carries its
    claim: a marker file under `claims/<claim>/`, which `remove_claimed(claim)` removes, noting the claim in `swept`.
    A container under a name with no claim (another start's, `plant`) is a file directly in `where`, which no sweep
    removes. `present(name)` answers whether either holds the name, and is noted in `probed`."""

    def __init__(self, where: Path) -> None:
        self.where = where
        where.mkdir(parents=True, exist_ok=True)
        self.swept: list[str] = []
        self.probed: list[str] = []

    def claimed(self, claim: str) -> list[str]:
        """The containers still carrying `claim`."""
        folder = self.where / "claims" / claim
        return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []

    def remove_claimed(self, claim: str) -> None:
        self.swept.append(claim)
        folder = self.where / "claims" / claim
        if folder.is_dir():
            for path in folder.iterdir():
                path.unlink()

    def plant(self, name: str, token: str = "") -> None:
        (self.where / name).write_text(token, encoding="utf-8")

    def held(self, name: str) -> bool:
        return (self.where / name).exists() or any((self.where / "claims").glob(f"*/{name}"))

    def present(self, name: str) -> bool:
        self.probed.append(name)
        return self.held(name)


class FaultyContainers(StandInContainers):
    """The stand-in containers whose every question raises: a daemon that cannot be asked or will not remove."""

    def present(self, name: str) -> bool:
        self.probed.append(name)
        raise RuntimeError("the container daemon cannot be asked")

    def remove_claimed(self, claim: str) -> None:
        self.swept.append(claim)
        raise RuntimeError("the container daemon cannot be asked")


class FaultableStore:
    """The real store, except for faults the test switches on: `renew_down` makes every renewal raise
    a connection error, `finish_fails` makes that many `finish` calls raise one (counted in
    `finish_tries`). Counts renewals that raised (`renews_failed`) and that answered (`renews_ok`).
    Notes the held ids each renewal that succeeded left out (`omitted`, and
    `omitted_event` for a thread that waits for the worker to see a fence)."""

    def __init__(self, store: Any) -> None:
        import threading

        self._store = store
        self.renew_down = False
        self.finish_fails = 0
        self.finish_tries = 0
        self.renews_failed = 0
        self.renews_ok = 0
        self.omitted: set[str] = set()
        self.omitted_event = threading.Event()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    async def renew(self, held: Any, **kw: Any) -> Any:
        if self.renew_down:
            self.renews_failed += 1
            raise ConnectionError("the database is gone")
        covered = await self._store.renew(held, **kw)
        self.renews_ok += 1
        left_out = set(held) - set(covered)
        if left_out:
            self.omitted |= left_out
            self.omitted_event.set()
        return covered

    async def finish(self, *args: Any, **kw: Any) -> Any:
        self.finish_tries += 1
        if self.finish_fails > 0:
            self.finish_fails -= 1
            raise ConnectionError("the database is gone")
        return await self._store.finish(*args, **kw)


class LaneLanding:
    """A job-lane door whose lanes are the real ones, except that the first launch write of the
    worker runs `land()` (in the worker's thread): `moment="during"` just before the real
    `write_launch`, `"after"` once it has returned and the lane closes. Nothing else changes."""

    def __init__(self, land: Callable[[], None], moment: str) -> None:
        assert moment in ("during", "after")
        self._land, self._moment, self.landed = land, moment, False

    def __call__(self, root: Any, tenant: str) -> Any:
        from defender.records import job_lane

        door = self
        lane = job_lane.JobLane.open(root, tenant)

        class _Lane:
            wrote = False

            def __getattr__(self, name: str) -> Any:
                return getattr(lane, name)

            def write_launch(self, launch: Any, raw: bytes) -> Any:
                if door._moment == "during" and not door.landed:
                    door.landed = True
                    door._land()
                done = lane.write_launch(launch, raw)
                self.wrote = True
                return done

            def close(self) -> None:
                lane.close()
                if door._moment == "after" and self.wrote and not door.landed:
                    door.landed = True
                    door._land()

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_exc: Any) -> None:
                self.close()

        return _Lane()


def fd_identity(fd: int) -> list[int]:
    """`[device, inode]` of what `fd` is open on, comparable with a child's `seen()["stdio"]`."""
    found = os.fstat(fd)
    return [found.st_dev, found.st_ino]


def make_worker(store: Any, data_root: Path, child: Callable[[Any], list[str]], *,
                containers: Any = None, slots: int = 3, stop_grace: float | None = None,
                open_lane: Any = None, **knobs: Any) -> Any:
    """`knobs` (#1343 sketch, unratified): `renewal_interval`, `cost_interval`, `takeover_interval`
    in seconds."""
    from defender.worker import Worker

    if containers is None:
        # The default stand-in sits beside the data root, so it is only safe when that is a test's own
        # temp directory; a made-up root must come with its own `containers=`.
        import tempfile

        beside = data_root.parent
        if not beside.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()):
            raise ValueError(f"make_worker: {data_root} is not under the temp directory; pass containers=StandInContainers(tmp_path / ...)")
        containers = StandInContainers(beside / "containers")
    extra = {**knobs, **({} if stop_grace is None else {"stop_grace": stop_grace})}
    if open_lane is not None:
        extra["open_lane"] = open_lane
    return Worker(store, data_root=data_root, child_argv=child,
                  containers=containers,
                  slots=slots, clock=fixed_clock, **extra)


def plant_queued_investigation(dsn: str, *, tenant: str, alert_id: str, investigation_id: str,
                               key: str = "planted") -> None:
    """A `queued` row with a chosen id, as SQL (the store mints ids; a case that must plant a file
    named for the id before the claim needs to know it)."""
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, "
                 "stage, created_at, cost_usd, cost_is_lower_limit) VALUES (%s, %s, %s, %s, 1, 'queued', %s, 0, false)",
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

def is_box_token(value: object) -> bool:
    """32 lowercase hex characters, exactly (r5 C1): no other case, length, whitespace or type."""
    import re

    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def job_end(*, setup: str = "done", box: str = "started", report_committed: bool = True,
            scrub_verified: bool = True, cut_short: str | None = None) -> str:
    """The ratified job-end record (`<runs>/<id>.job-end.json`), exactly its five facts (#1421). r7.3 T1: no spend fact
    rides on it; the ledger's seal says whether the run's spend is complete."""
    return json.dumps({"setup": setup, "box": box, "report_committed": report_committed,
                       "scrub_verified": scrub_verified, "cut_short": cut_short})


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


#: The spend ledger's table and columns as #1377's sketch names them (the design leaves them open). r7 row model: the
#: requesting agent, the requested and reported model, the four billed counts and the request's outcome.
SPEND_LEDGER = "spend_ledger"
SPEND_COUNTS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
SPEND_COLUMNS = ("run_id", "agent_id", "requested_model", "reported_model", "outcome", *SPEND_COUNTS)
#: r7 S2a: a request's outcome as the model-request hook saw it (sketch spelling).
RESPONSE, REFUSED, UNSEEN = "response", "refused", "unseen"


def insert_spend(database: Path, run_id: str, spend: list[tuple[str, dict[str, int]]], *, agent_id: str = "main",
                 outcome: str = RESPONSE, reported: str | None = None) -> None:
    """#1377: one ledger row per `(requested model, billed usage)` for `run_id` and `agent_id` in an existing session
    database; `reported` (default the requested name; None on a refused or unseen row) is what the provider said."""
    import sqlite3

    conn = sqlite3.connect(database, timeout=30)
    try:
        for model, usage in spend:
            said = reported if reported is not None else (model if outcome == RESPONSE else None)
            values = (run_id, agent_id, model, said, outcome, *(usage.get(k, 0) for k in SPEND_COUNTS))
            conn.execute(f"INSERT INTO {SPEND_LEDGER} ({', '.join(SPEND_COLUMNS)}) "  # noqa: S608
                         f"VALUES ({', '.join('?' * len(SPEND_COLUMNS))})", values)
        conn.commit()
    finally:
        conn.close()


def plant_spend(runs: Path, case_id: str, run_id: str, spend: list[tuple[str, dict[str, int]]], *, sealed: bool = True,
                **row: str) -> None:
    """#1377: `case_id`'s session database (made by the real store, so its own schema, and with a
    `main` session when this call makes the file) holding one ledger row per `(model, billed usage)`
    for `run_id`; `row` is `insert_spend`'s agent id, outcome and reported name. r7.3 T1: `sealed` (default) seals the
    run's ledger after the rows land, as a run that ended without a failed write leaves it; a test that plants a run's rows in
    several calls seals with the last one only (`sealed=False` before), and `sealed=False` throughout is a run killed before
    its seal."""
    from defender.records.session_store._write import open_store

    fresh = not session_db(runs, case_id).exists()
    with open_store(case_id=case_id, sessions=_paths(runs)) as handle:
        if fresh:
            handle.new_session("main")
    insert_spend(session_db(runs, case_id), run_id, spend, **row)
    if sealed:
        seal_spend(runs, case_id, run_id)


def seal_spend(runs: Path, case_id: str, run_id: str) -> None:
    """r7.3 T1: seal `run_id`'s ledger in `case_id`'s database through the real `session_store.seal_ledger`."""
    from defender.records import session_store
    from defender.records.session_store._write import open_store

    with open_store(case_id=case_id, sessions=_paths(runs)) as handle:
        session_store.seal_ledger(handle, run_id)


def seal_at(runs: Path, case_id: str, run_id: str) -> None:
    """r7.3 T1: seal `run_id`'s ledger in `case_id`'s database (a store a test did not open itself: a fixture run's) through the
    real `session_store.seal_ledger`, on a handle opened as production opens a store for writing."""
    seal_spend(runs, case_id, run_id)


def lower_limit(dsn: str, investigation_id: str) -> bool | None:
    """#1377: the row's `cost_is_lower_limit` (kept apart from `row`, whose columns every #1342 case reads)."""
    found = execute(dsn, "SELECT cost_is_lower_limit FROM jobs.investigations WHERE id = %s", (investigation_id,))
    return found[0][0] if found else None


@contextmanager
def session_database_held_locked(runs: Path, case_id: str) -> Iterator[None]:
    """#1343 B2: while the block runs, any read of `case_id`'s planted session database waits on a real
    SQLite lock (its busy timeout is 30 s). The database is put in rollback-journal mode first, so a
    held `BEGIN EXCLUSIVE` blocks readers (a WAL database's does not)."""
    import sqlite3

    path = session_db(runs, case_id)
    plain = sqlite3.connect(path)
    plain.execute("PRAGMA journal_mode=DELETE")
    plain.close()
    holder = sqlite3.connect(path, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        yield
    finally:
        holder.execute("ROLLBACK")
        holder.close()
