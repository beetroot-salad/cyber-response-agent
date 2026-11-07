"""The job lane's door to one tenant's runs container (#1342 M1): every host file the worker and
the job entry share, keyed by `(data root, tenant id)` and opened without accepting the tenant.

Learning jobs (#1344) share three host-held records here, keyed by the learning job's id and
written by its children, read by the worker: the job entry's progress record
(`LearningProgress`, replaced whole), its end record (`LearningEnd`, create-only) and the
post-step's record (`PostStepRecord`). Each has one parser, and text that is not a record of its
shape parses as no record (`None`), which the worker treats like an absent one. A family-less
post-step (#1344 amendment 1: no job to follow) keys its record by the tenant's own id instead
(`post_step_key`), one record per tenant replaced at each check.

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
import math
import re
import sqlite3
import stat
import sys
from collections.abc import Sequence
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


@dataclass(frozen=True)
class JobEnd:
    """The job-end record (`<runs>/<id>.job-end.json`): four facts, each set by the job entry at
    the point it became true."""

    setup: str
    box: str
    report_committed: bool
    scrub_verified: bool

    def text(self) -> str:
        return json.dumps({"setup": self.setup, "box": self.box,
                           "report_committed": self.report_committed,
                           "scrub_verified": self.scrub_verified})

    @classmethod
    def parse(cls, text: str) -> JobEnd | None:
        """The record `text` holds, or `None` when it is not one the job entry could have written."""
        obj, unreadable = _io.load_json_artifact(text)
        if unreadable is not None or not isinstance(obj, dict) or set(obj) != {
                "setup", "box", "report_committed", "scrub_verified"}:
            return None
        setup, box = obj["setup"], obj["box"]
        committed, verified = obj["report_committed"], obj["scrub_verified"]
        if not (isinstance(setup, str) and setup in _SETUPS and isinstance(box, str) and box in _BOXES
                and isinstance(committed, bool) and isinstance(verified, bool)):
            return None
        return cls(setup=setup, box=box, report_committed=committed, scrub_verified=verified)


# -- learning jobs (#1344): the vocabulary and the three records -----------------------------------

#: How the job entry ended, in its end record. `stopped` is a hand-back (the worker retries it,
#: using an attempt); the other three are the row's own terminal statuses.
LEARNING_COMPLETED, LEARNING_SKIPPED, LEARNING_FAILED, LEARNING_STOPPED = (
    "completed", "skipped", "failed", "stopped")

#: The reasons the job entry decides (r5's outcome table, plus `entry_error`), by the status each
#: belongs to. `completed` and `stopped` carry no reason.
NO_FORK_POINT, HISTORY_UNREADABLE, FAMILY_UNUSABLE = (
    "no_fork_point", "history_unreadable", "family_unusable")
CONTROL_FAILED, LAUNCH_REFUSED, VERIFY_REFUSED = "control_failed", "launch_refused", "verify_refused"
SOURCE_UNAVAILABLE, JUDGE_FAILED, ENTRY_ERROR = "source_unavailable", "judge_failed", "entry_error"
SKIPPED_BY_THE_ENTRY = frozenset({NO_FORK_POINT, HISTORY_UNREADABLE, FAMILY_UNUSABLE})
FAILED_BY_THE_ENTRY = frozenset({CONTROL_FAILED, LAUNCH_REFUSED, VERIFY_REFUSED, SOURCE_UNAVAILABLE,
                                 JUDGE_FAILED, ENTRY_ERROR})
#: The reasons only the worker records (no end record carries them).
EXPIRED, EXITED_WITHOUT_RESULT, WORKER_ERROR, LEASE_LAPSED, RETRY_CAP = (
    "expired", "exited_without_result", "worker_error", "lease_lapsed", "retry_cap")

_END_REASONS: dict[str, frozenset[str | None]] = {
    LEARNING_COMPLETED: frozenset({None}),
    LEARNING_STOPPED: frozenset({None}),
    LEARNING_SKIPPED: frozenset(SKIPPED_BY_THE_ENTRY),
    LEARNING_FAILED: frozenset(FAILED_BY_THE_ENTRY),
}

#: The largest findings count an end record may carry: what the row's `findings_count` column
#: (a 32-bit `INTEGER`) holds. A larger one is no count, so the record is not one.
MAX_FINDINGS_COUNT = 2**31 - 1

_PROGRESS_FIELDS = frozenset({"fork_message_id", "stage", "sibling_cost_usd"})
_END_FIELDS = frozenset({"status", "reason", "message", "fork_message_id", "stage",
                         "findings_count", "sibling_cost_usd"})
_POST_STEP_FIELDS = frozenset({"published", "refused"})


def _optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _cost(value: object) -> bool:
    """A cost in dollars: a finite, non-negative JSON number (never a bool). An integer beyond
    the float range is not one (`math.isfinite` would overflow on it)."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    if isinstance(value, int) and abs(value) > sys.float_info.max:
        return False
    return math.isfinite(value) and value >= 0


def _record_object(text: str, fields: frozenset[str]) -> dict | None:
    """`text` as a JSON object of exactly `fields`, or `None`."""
    obj, unreadable = _io.load_json_artifact(text)
    if unreadable is not None or not isinstance(obj, dict) or set(obj) != fields:
        return None
    return obj


@dataclass(frozen=True)
class LearningProgress:
    """The job entry's progress record (`<runs>/<job id>.learning-progress.json`): the fork it
    picked (a message id as text, `None` until picked), its stage, and what its siblings have cost
    so far (dollars, partial: each sibling's own main session and descendants). Replaced whole as
    each changes; the worker copies it to the row on its loop."""

    fork_message_id: str | None
    stage: str | None
    sibling_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if not (_optional_text(self.fork_message_id) and _optional_text(self.stage)
                and _cost(self.sibling_cost_usd)):
            raise ValueError(f"not a learning progress record: {self!r}")

    def text(self) -> str:
        return json.dumps({"fork_message_id": self.fork_message_id, "stage": self.stage,
                           "sibling_cost_usd": self.sibling_cost_usd})

    @classmethod
    def parse(cls, text: str) -> LearningProgress | None:
        """The record `text` holds, or `None` when it is not one of this shape."""
        obj = _record_object(text, _PROGRESS_FIELDS)
        if obj is None:
            return None
        try:
            return cls(fork_message_id=obj["fork_message_id"], stage=obj["stage"],
                       sibling_cost_usd=obj["sibling_cost_usd"])
        except (TypeError, ValueError, OverflowError):
            return None


@dataclass(frozen=True)
class LearningEnd:
    """The job entry's end record (`<runs>/<job id>.learning-end.json`), written create-only at
    every exit: the status and reason it decided (a reason only for `skipped` and `failed`, one
    of that status's own), a message from the entry's own code (required for `skipped` and
    `failed`; never run text), and the final pick, stage, findings count and sibling cost."""

    status: str
    reason: str | None
    message: str | None
    fork_message_id: str | None
    stage: str | None
    findings_count: int = 0
    sibling_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        allowed = _END_REASONS.get(self.status) if isinstance(self.status, str) else None
        if allowed is None or self.reason not in allowed:
            raise ValueError(f"not an end the job entry decides: {self.status!r}/{self.reason!r}")
        if not (_optional_text(self.message) and _optional_text(self.fork_message_id)
                and _optional_text(self.stage) and _cost(self.sibling_cost_usd)):
            raise ValueError(f"not a learning end record: {self!r}")
        if not isinstance(self.findings_count, int) or isinstance(self.findings_count, bool) \
                or not 0 <= self.findings_count <= MAX_FINDINGS_COUNT:
            raise ValueError(f"not a findings count: {self.findings_count!r}")
        if self.reason is not None and not (self.message or "").strip():
            raise ValueError(f"a {self.status} end names why in its message")

    def text(self) -> str:
        return json.dumps({"status": self.status, "reason": self.reason, "message": self.message,
                           "fork_message_id": self.fork_message_id, "stage": self.stage,
                           "findings_count": self.findings_count,
                           "sibling_cost_usd": self.sibling_cost_usd})

    @classmethod
    def parse(cls, text: str) -> LearningEnd | None:
        """The record `text` holds, or `None` when it is not one the job entry could write."""
        obj = _record_object(text, _END_FIELDS)
        if obj is None:
            return None
        try:
            return cls(**{name: obj[name] for name in _END_FIELDS})
        except (TypeError, ValueError, OverflowError):
            return None


@dataclass(frozen=True)
class PostStepRecord:
    """The post-step's record (`<runs>/<key>.post-step.json`, `post_step_key`: the job it
    followed, or the tenant's own id for a family-less one): the pending jobs whose findings it
    published and those it refused for good (their rows failed validation). A job in neither
    stays pending (a queue-level or transient failure)."""

    published: tuple[str, ...] = ()
    refused: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for ids in (self.published, self.refused):
            if not isinstance(ids, tuple) or not all(isinstance(i, str) for i in ids):
                raise ValueError(f"not a post-step record: {self!r}")
        if set(self.published) & set(self.refused):
            raise ValueError("a job is published or refused, never both")

    def text(self) -> str:
        return json.dumps({"published": list(self.published), "refused": list(self.refused)})

    @classmethod
    def of(cls, published: Sequence[str], refused: Sequence[str]) -> PostStepRecord:
        return cls(published=tuple(published), refused=tuple(refused))

    @classmethod
    def parse(cls, text: str) -> PostStepRecord | None:
        """The record `text` holds, or `None` when it is not one of this shape."""
        obj = _record_object(text, _POST_STEP_FIELDS)
        if obj is None or not all(isinstance(obj[k], list) for k in _POST_STEP_FIELDS):
            return None
        try:
            return cls.of(obj["published"], obj["refused"])
        except ValueError:
            return None


def post_step_key(tenant_id: object, job_id: object | None) -> RunId:
    """The name a post-step's record is kept under (#1344): the job it followed, or, for a
    family-less post-step (amendment 1: `job_id` None), the tenant's own id. Both are canonical
    UUID text, so the name has the job lane's `<id><suffix>` shape; a tenant's id never names a
    job or a run in its own runs folder, so the two never meet, and the family-less record is one
    per tenant, replaced at each check rather than one more file per check. The one place the
    choice is made: the post-step writes, and the worker reads, through it."""
    return _run_id(str(tenant_id) if job_id is None else job_id)


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
    def open(cls, data_root: DataRoot, tenant_id: object, *, make: bool = False) -> JobLane:
        """`<data root>/<tenant_id>/runs`, held no-follow from the tenant's folder. Never made,
        except with `make` (a learning post-step, #1344, whose record must land for a tenant whose
        runs folder nothing has made yet): then a missing one is made below the held tenant
        folder, never through a link. The tenant is not accepted here: only its id's grammar is
        judged."""
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
            if make:
                try:
                    top.mkdir(_RUNS)  # lint-unguarded-tree-write: ok — `Held.mkdir`, the rooted mkdir below the tenant folder held no-follow
                except OSError as exc:
                    raise JobLaneRefused(f"the runs folder {runs} {level_fault(exc)}") from None
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

    # -- a learning job's three records (#1344) ------------------------------------------------------

    def write_learning_progress(self, job_id: object, progress: LearningProgress) -> None:
        """The progress record, replaced whole (a reader sees the old record or the new one)."""
        self._held.write(self._paths(_run_id(job_id)).learning_progress().name, progress.text(),
                         mode="replace")

    def read_learning_progress(self, job_id: object) -> LearningProgress | None:
        """The progress record, or `None` when it is absent, unreadable or not of its shape."""
        read = self._held.view().read(self._paths(_run_id(job_id)).learning_progress().name)
        return None if read.text is None else LearningProgress.parse(read.text)

    def write_learning_end(self, job_id: object, end: LearningEnd) -> None:
        """The end record, create-only: one already there is `FileExistsError` and is kept."""
        self._held.write(self._paths(_run_id(job_id)).learning_end().name, end.text(),
                         mode="create")

    def read_learning_end(self, job_id: object) -> LearningEnd | None:
        """The end record, or `None` when it is absent, unreadable or not one the job entry
        writes (the worker treats all three alike)."""
        read = self._held.view().read(self._paths(_run_id(job_id)).learning_end().name)
        return None if read.text is None else LearningEnd.parse(read.text)

    def write_post_step(self, job_id: object | None, record: PostStepRecord) -> None:
        """The post-step's record for the job it followed (`None`: a family-less post-step, kept
        under the tenant's id, `post_step_key`), replaced whole."""
        self._held.write(self._paths(post_step_key(self.tenant_id, job_id)).post_step().name,
                         record.text(), mode="replace")

    def read_post_step(self, job_id: object | None) -> PostStepRecord | None:
        """The post-step's record (`job_id` as `write_post_step` takes it), or `None` when it is
        absent, unreadable or not of its shape."""
        read = self._held.view().read(self._paths(post_step_key(self.tenant_id, job_id)).post_step().name)
        return None if read.text is None else PostStepRecord.parse(read.text)

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

    def cost(self, run_id: object) -> float:
        """What the run spent: the sum, over every session in the database its pointer names, of
        that session's own model responses priced from the pricing table (a fork's inherited
        prefix is its parent's, so counted once). No pointer: 0 — the store was never opened, so
        no model request was made. `CostUnreadable` for a pointer or database that cannot be
        read, or a lineage whose main session has a parent: the sum is the run's spend only for a
        fresh lineage, never a resume."""
        located = self.session_database(run_id)
        if located is None:
            return 0.0
        database, session_id = located
        from defender.configuration import billed_usage, usage_cost
        from defender.records import session_store

        try:
            with session_store.open_store_for_read(database) as store:
                sessions = {s.session_id: s for s in session_store.list_sessions(store)}
                main = session_id if session_id is not None else session_store.main_session_id(store)
                if main not in sessions:
                    raise CostUnreadable(f"run {run_id}: its main session {main} is not in {database}")
                if sessions[main].parent_session_id is not None:
                    raise CostUnreadable(f"run {run_id}: its main session {main} has a parent; the "
                                         "cost of a resumed lineage is not this run's spend")
                return sum(usage_cost(m.model_name or "", billed_usage(m.usage))
                           for s in sessions for m in session_store.own_responses(store, s))
        except CostUnreadable:
            raise
        except (OSError, sqlite3.Error, StoreError, ValueError) as fault:
            raise CostUnreadable(f"run {run_id}: its session database {database} cannot be read: "
                                 f"{fault!r}") from None


def sibling_cost(store: object, session_id: str) -> float:
    """What one sibling cost (#1344 O13): its own main session `session_id` and every session
    forked from it, at any depth, priced from their own model responses — never the prefix a
    fork inherited, never the source's sessions or any other sibling's, and never the
    questioner, oracle or judge, which are outside it. Siblings fork the source's database, so
    the lineage there has a parent; unlike `JobLane.cost`, a forked lineage is what this reads.
    `store` is an open session store holding `session_id`; a session it does not hold is
    `CostUnreadable`."""
    from defender.configuration import billed_usage, usage_cost
    from defender.records import session_store

    try:
        sessions = session_store.list_sessions(store)
        children: dict[str | None, list[str]] = {}
        for row in sessions:
            children.setdefault(row.parent_session_id, []).append(row.session_id)
        if session_id not in {row.session_id for row in sessions}:
            raise CostUnreadable(f"session {session_id} is not in the store")
        lineage, frontier = set(), [session_id]
        while frontier:
            current = frontier.pop()
            if current in lineage:
                continue
            lineage.add(current)
            frontier.extend(children.get(current, ()))
        return sum(usage_cost(m.model_name or "", billed_usage(m.usage))
                   for s in sorted(lineage) for m in session_store.own_responses(store, s))
    except CostUnreadable:
        raise
    except (OSError, sqlite3.Error, StoreError, ValueError) as fault:
        raise CostUnreadable(f"session {session_id}: its cost cannot be read: {fault!r}") from None
