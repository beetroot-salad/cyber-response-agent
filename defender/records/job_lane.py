"""The job lane's door to one tenant's runs container (#1342 M1): every host file the worker and
the job entry share, keyed by `(data root, tenant id)` and opened without accepting the tenant.

The worker writes a job's launch record and alert file here before it starts the child; the
child's job entry opens the same door first thing — before tenant acceptance, so a refusal there
still leaves its job-end record — checks the launch record, and writes the job-end record as it
exits; the worker then reads the job-end record, the knowledge record, the session pointer and
the report through it, and the run's cost from the session database the pointer names.

`<data root>/<T>/runs` is held no-follow from the tenant's folder and never made (#1342 R1: tenant
setup makes it): absent, a link or anything but a folder is `JobLaneRefused`. Every read is a
no-follow, size-limited read off that held folder; every write is create-only."""
from __future__ import annotations

import json
import re
import sqlite3
import stat
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from defender import _io
from defender.records._errors import RunRefused
from defender.records._held import hold_level, level_fault
from defender.records._id import RunId
from defender.records.job_facts import (
    BOX_NOT_STARTED, BOX_START_FAILED, BOX_STARTED, SETUP_CRASHED, SETUP_DONE, SETUP_REFUSED,
)
from defender.records._knowledge_status import UNREADABLE, api_knowledge, knowledge_status
from defender.records._layout import RUN_LAYOUT, RunPaths, SessionPaths
from defender.records._locations import DataRoot, RunsBase, unwrap_data_root
from defender.records._store_errors import StoreError
from defender.records._tenant_id import TenantId, TenantRefused
from defender.records.run_end import normalized_truncated_by

#: The tenant's runs container below its folder: the tenant layout's name for it
#: (`tenancy._TenantLayout.runs`), which this door may not import (records sits below tenancy).
_RUNS = "runs"

#: The job-end record's vocabulary: `setup`, then `box`.
_SETUPS = frozenset({SETUP_REFUSED, SETUP_CRASHED, SETUP_DONE})
_BOXES = frozenset({BOX_NOT_STARTED, BOX_START_FAILED, BOX_STARTED})

_DIGEST = re.compile(r"[0-9a-f]{64}")
#: The box token's form (#1342 r5 C1): the box's own start-token form, 32 lowercase hex.
_BOX_TOKEN = re.compile(r"[0-9a-f]{32}")


class JobLaneRefused(Exception):
    """The job lane cannot be used for this tenant or this id: its runs container is absent or
    cannot be held, or a launch record is missing or does not check. The message names which."""


class CostUnreadable(Exception):
    """The run's session pointer is there but its cost cannot be read: the pointer does not
    parse, names no usable case id, its database is missing or will not open, or the lineage is
    not a fresh one (its main session has a parent)."""


@dataclass(frozen=True)
class LaunchRecord:
    """The worker's launch record (`<runs>/<id>.launch.json`): what the child runs, and the
    box token the worker minted for this claim (#1342 r5 C1): the child's box is stamped with
    it, and the worker's backstop removes only a container carrying it."""

    investigation_id: str
    tenant_id: str
    alert_id: str
    digest: str
    label: str
    box_token: str

    def text(self) -> str:
        return json.dumps(asdict(self))


@dataclass(frozen=True)
class Launched:
    """A launch record that checked (`JobLane.check_launch`): the record, and the alert file
    beside it that run setup admits once, comparing its digest to the record's."""

    record: LaunchRecord
    alert: Path

    @property
    def run_id(self) -> RunId:
        return RunId.parse(self.record.investigation_id)


_JOB_END_KEYS_BEFORE_1377 = frozenset({"setup", "box", "report_committed", "scrub_verified", "cut_short"})
_JOB_END_KEYS = _JOB_END_KEYS_BEFORE_1377 | {"spend_write_failed"}


@dataclass(frozen=True)
class JobEnd:
    """The job-end record (`<runs>/<id>.job-end.json`): six facts, each set by the job entry at
    the point it became true. `cut_short` is the run's exit class (`run_end.TRUNCATED_BY_VALUES`,
    the whole vocabulary) as the driver returned it, or `None`: a run nothing cut short, or one
    that never returned from its driver (setup refused or crashed, a group that propagated)
    (#1421). `spend_write_failed` is true when a spend write failed in the run, so its cost may be
    missing recorded spend (#1377)."""

    setup: str
    box: str
    report_committed: bool
    scrub_verified: bool
    cut_short: str | None
    spend_write_failed: bool

    def text(self) -> str:
        return json.dumps({"setup": self.setup, "box": self.box,
                           "report_committed": self.report_committed,
                           "scrub_verified": self.scrub_verified,
                           "cut_short": self.cut_short,
                           "spend_write_failed": self.spend_write_failed})

    @classmethod
    def parse(cls, text: str) -> JobEnd | None:
        """The record `text` holds, or `None` when it is not one the job entry could have written.
        `cut_short` must be JSON null or a vocabulary word exactly, so no child's text can reach
        the fixed job message that names it."""
        obj, unreadable = _io.load_json_artifact(text)
        if unreadable is not None or not isinstance(obj, dict) or set(obj) not in (_JOB_END_KEYS, _JOB_END_KEYS_BEFORE_1377):
            return None
        obj = {"spend_write_failed": False, **obj}  # a record from before #1377 names no spend fact: none failed
        setup, box = obj["setup"], obj["box"]
        committed, verified, cut_short = obj["report_committed"], obj["scrub_verified"], obj["cut_short"]
        spend_failed = obj["spend_write_failed"]
        if not (isinstance(setup, str) and setup in _SETUPS and isinstance(box, str) and box in _BOXES
                and isinstance(committed, bool) and isinstance(verified, bool)
                and isinstance(spend_failed, bool)
                and (cut_short is None or normalized_truncated_by(cut_short) is not None)):
            return None
        return cls(setup=setup, box=box, report_committed=committed, scrub_verified=verified,
                   cut_short=cut_short, spend_write_failed=spend_failed)


@dataclass(frozen=True)
class RunCost:
    """A run's spend read from its ledger, whether the run ever opened its store (a pointer
    exists), and whether the ledger is complete (no unseen request, no unpriced model; r7 S2):
    the worker applies the lower-limit rule from this one read (#1377)."""

    usd: float
    store_opened: bool
    complete: bool = True


def _run_id(raw: object) -> RunId:
    if isinstance(raw, RunId):
        return raw
    try:
        return RunId.parse(str(raw))
    except RunRefused as refused:
        raise JobLaneRefused(f"{raw!r} is not a job id: {refused}") from None


class JobLane:
    """One tenant's runs container, held for the job lane. A context manager: `open` holds the
    folder, `close` releases it."""

    def __init__(self, held: _io.Held, runs: Path, tenant_id: TenantId) -> None:
        self._held = held
        self._runs = runs
        self.tenant_id = tenant_id

    @classmethod
    def open(cls, data_root: DataRoot, tenant_id: object) -> JobLane:
        """`<data root>/<tenant_id>/runs`, held no-follow from the tenant's folder; never made.
        The tenant is not accepted here: only its id's grammar is judged."""
        try:
            tenant = TenantId(tenant_id)
        except TenantRefused as refused:
            raise JobLaneRefused(str(refused)) from None
        folder = Path(unwrap_data_root(data_root)) / str(tenant)
        runs = folder / _RUNS
        try:
            top = _io.hold(folder, follow=False)
        except FileNotFoundError:
            raise JobLaneRefused(f"the tenant folder {folder} is absent") from None
        except OSError as exc:
            raise JobLaneRefused(f"the tenant folder {folder} {level_fault(exc)}") from None
        try:
            held = hold_level(top, _RUNS, runs, io=_io, what="the runs folder")
        except FileNotFoundError:
            raise JobLaneRefused(f"the runs folder {runs} is absent: tenant setup makes it, and "
                                 "the job lane never does") from None
        except TenantRefused as refused:
            raise JobLaneRefused(str(refused)) from None
        finally:
            top.close()
        return cls(held, runs, tenant)

    def close(self) -> None:
        self._held.close()

    def __enter__(self) -> JobLane:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- names -----------------------------------------------------------------------------------

    def _paths(self, run_id: RunId) -> RunPaths:
        return RunPaths(self._runs / str(run_id))

    def _plain_file(self, name: str) -> bool:
        found = _io.stat_entry(self._held.view(), name)
        return found.st is not None and stat.S_ISREG(found.st.st_mode)

    # -- the launch (worker writes, job entry checks) --------------------------------------------

    def write_launch(self, record: LaunchRecord, alert: bytes) -> None:
        """The alert file, then the launch record, create-only: the record is the only mark of a
        launch, so its presence says both are complete (#1342 r7 D-af). An entry already at the
        record's name is `FileExistsError` and nothing is written; an alert file without a record
        (a launch whose record write failed) is replaced."""
        paths = self._paths(_run_id(record.investigation_id))
        where = paths.launch_record().name
        if _io.stat_entry(self._held.view(), where).st is not None:
            raise FileExistsError(f"a launch record is already at {where}")
        self._held.write(paths.launch_alert().name, alert, mode="replace")
        self._held.write(where, record.text(), mode="create")

    def check_launch(self, run_id: object) -> Launched:
        """The launch record of `run_id`, checked: present and a plain file, a JSON object of
        the six fields, naming this id and this tenant, with a digest and a box token of the
        box's form, and its alert file beside it. Anything else is `JobLaneRefused` naming the launch record. The digest is
        compared on the bytes run setup admits, not here."""
        run_id = _run_id(run_id)
        paths = self._paths(run_id)
        where = paths.launch_record()
        read = self._held.view().read(where.name)
        if read.text is None:
            why = "is absent" if read.absent else f"cannot be read ({read.reason})"
            raise JobLaneRefused(f"job {run_id}: its launch record {where} {why} — a job id is "
                                 "only run from the launch record its worker wrote")
        obj, unreadable = _io.load_json_artifact(read.text)
        if unreadable is not None or not isinstance(obj, dict):
            raise JobLaneRefused(f"job {run_id}: its launch record {where} is not a JSON object")
        fields = ("investigation_id", "tenant_id", "alert_id", "digest", "label", "box_token")
        if any(not isinstance(obj.get(k), str) for k in fields):
            raise JobLaneRefused(f"job {run_id}: its launch record {where} lacks one of "
                                 f"{', '.join(fields)}")
        record = LaunchRecord(**{k: obj[k] for k in fields})
        if record.investigation_id != str(run_id):
            raise JobLaneRefused(f"job {run_id}: its launch record {where} names another id")
        if record.tenant_id != str(self.tenant_id):
            raise JobLaneRefused(f"job {run_id}: its launch record {where} names another tenant")
        if not _DIGEST.fullmatch(record.digest):
            raise JobLaneRefused(f"job {run_id}: its launch record {where} carries no alert digest")
        if not _BOX_TOKEN.fullmatch(record.box_token):
            raise JobLaneRefused(f"job {run_id}: its launch record {where} carries no box token "
                                 "of the form its worker mints (32 lowercase hex)")
        alert = paths.launch_alert()
        if not self._plain_file(alert.name):
            raise JobLaneRefused(f"job {run_id}: the alert file {alert} beside its launch record "
                                 "is absent or not a plain file")
        return Launched(record=record, alert=alert)

    # -- the job-end record -----------------------------------------------------------------------

    def write_job_end(self, run_id: object, end: JobEnd) -> None:
        """The job-end record, create-only: one already there is `FileExistsError` and is kept."""
        self._held.write(self._paths(_run_id(run_id)).job_end().name, end.text(),
                         mode="create")

    def read_job_end(self, run_id: object) -> JobEnd | None:
        """The job-end record, or `None` when it is absent, unreadable or not one the job entry
        writes (the worker treats all three alike)."""
        read = self._held.view().read(self._paths(_run_id(run_id)).job_end().name)
        return None if read.text is None else JobEnd.parse(read.text)

    # -- what the run left ------------------------------------------------------------------------

    def run_started(self, run_id: object) -> bool:
        """Whether the run folder exists, a real directory: host setup makes it exclusively,
        before any box, so it is what "the run started" means (#1342 M6)."""
        found = _io.stat_entry(self._held.view(), str(_run_id(run_id)))
        return found.st is not None and stat.S_ISDIR(found.st.st_mode)

    def knowledge(self, run_id: object) -> dict[str, str | None] | None:
        """The run's knowledge in the API's shape (`api_knowledge`): `None` when the run never
        started; otherwise its host record, read no-follow — missing or unreadable is stale,
        operator kind, no commit."""
        run_id = _run_id(run_id)
        if not self.run_started(run_id):
            return None
        read = self._held.view().read(self._paths(run_id).knowledge_source().name)
        return api_knowledge(knowledge_status(read.text, stamp_names_source=True))

    @staticmethod
    def unreadable_knowledge() -> dict[str, str | None] | None:
        """A started run's knowledge when its record cannot be read (OD22'), in the API's shape:
        stale, operator kind, no commit. What `knowledge` gives for a missing or garbled record, and
        what the worker records when the read itself faults (#1396)."""
        return api_knowledge(UNREADABLE)

    def report_disposition(self, run_id: object) -> str | None:
        """The disposition of the run's `report.md`, read no-follow and size-limited, or `None`
        when there is no readable report or it names no disposition."""
        from defender.records._report import parse_report_text

        name = PurePosixPath(str(_run_id(run_id))) / RUN_LAYOUT.report
        read = self._held.view().read(name)
        return None if read.text is None else parse_report_text(read.text).disposition

    # -- cost -------------------------------------------------------------------------------------

    def session_database(self, run_id: object) -> tuple[Path, str | None] | None:
        """The session database the run's pointer names, located from its case id through the
        session paths (never from its stored path), with the session the pointer names (`None`:
        the lineage's main root). `None` when there is no pointer. `CostUnreadable` when there is
        one that does not parse or names no usable case id."""
        run_id = _run_id(run_id)
        where = self._paths(run_id).session_pointer()
        read = self._held.view().read(where.name)
        if read.text is None:
            if read.absent:
                return None
            raise CostUnreadable(f"run {run_id}: its session pointer cannot be read ({read.reason})")
        obj, unreadable = _io.load_json_artifact(read.text)
        if unreadable is not None or not isinstance(obj, dict) or not isinstance(obj.get("case_id"), str):
            raise CostUnreadable(f"run {run_id}: its session pointer names no case")
        session_id = obj.get("session_id")
        if session_id is not None and not isinstance(session_id, str):
            raise CostUnreadable(f"run {run_id}: its session pointer names no usable session")
        try:
            database = SessionPaths(RunsBase(self._runs)).session_db(obj["case_id"])
        except StoreError as bad:
            raise CostUnreadable(f"run {run_id}: its session pointer's case id is refused: {bad}") from None
        return database, session_id or None

    def cost(self, run_id: object) -> RunCost:
        """What the run spent: the sum of the spend ledger's rows for this run id in the database
        its pointer names (#1377), each priced from the pricing table. Rows of another run in the
        same database (a branch arm's source, a sibling) are not counted; no conversation is read.
        It is `session_store.read_ledger`, the one read the run file and the page use too.
        No pointer: 0, `store_opened` false (the store was never opened, so no model request was
        made). `CostUnreadable` for a pointer or database that cannot be read, a database without
        the ledger, or a pointer naming a session the database lacks."""
        run_id = _run_id(run_id)
        located = self.session_database(run_id)
        if located is None:
            return RunCost(0.0, store_opened=False)
        database, session_id = located
        from defender.records import session_store

        try:
            with session_store.open_store_for_read(database) as store:
                main = session_id if session_id is not None else session_store.main_session_id(store)
                if store.connection.execute("SELECT 1 FROM session WHERE session_id = ?", (main,)).fetchone() is None:
                    raise CostUnreadable(f"run {run_id}: its main session {main} is not in {database}")
                read = session_store.read_ledger(store, str(run_id))
                return RunCost(read.total, store_opened=True, complete=read.complete)
        except CostUnreadable:
            raise
        except (OSError, sqlite3.Error, StoreError, ValueError) as fault:
            raise CostUnreadable(f"run {run_id}: its session database {database} cannot be read: "
                                 f"{fault!r}") from None
