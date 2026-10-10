"""The learning-state handle (#1135): the one front door to the learning state tree.

Everything the host keeps under the learning state root — the curation request queue, the
pending deliveries, the three findings-shaped queues with their consumed ledgers, dead letters
and stuck reports, the gap ledger, the disposition reports, the lock files — is reached through
`LearningState`, opened at an entry point on an EXISTING root (`LearningState.open(paths)`). No
production module outside this one composes, opens, lists, locks or renames a path to one of
those records (the census in `tests/learning_state_1135/test_1135_front_door.py` holds that).
`runs/`, under the same root, is #1166's and is still reached by path, and the eval harness
seeds its own scratch tree by path; neither is a record of this handle.

A planted link, hard link, FIFO, or a folder where a file belongs, anywhere below the root is
refused as `StateRefused`, never followed and never read as absent (the display verbs below
turn it into an unreadable count instead of raising). `StateRefused` is not an `Exception`,
so no `except OSError` or `except Exception` arm swallows it, and it is a member of
`faults.SYSTEMIC_FAULTS`, so a drain tick stops and exits 2. Only an arm that names it catches
it: the queue page, the run-end enqueue, the judge and the eval harness are the declared
exemptions (the display verbs convert it to an unreadable count for the page,
`run_common.enqueue_curation` catches it at the run-end enqueue, `branch/cli._grade` for the
judge, `evals/harness.run_author` for the harness). Ordinary I/O errors
keep today's routes. A link at or above the root is operator configuration and is followed once,
at `open`.

The verbs are queue-shaped: records are named by their meaning (channel, request key, delivery
id, lock role), never by a path, and rename and lock are private to the file backend. The one
path-returning verb is `stage_dir`, the escape that hands the stage harness its folder until
#1142 gives that harness its own handle.

@owns the record names of the learning state tree — the folder and file names below are the one
spelling of what lives where; the tests derive the paths they check from these constants
(`paths.state_root / FINDINGS.queue`), so a rename here moves their oracles with it.
"""
from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
from functools import partial
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from defender import _flock
from defender._clock import now_iso
from defender._env import FatalConfigError
from defender._io import (
    ALIAS_READ_REFUSAL,
    Bound,
    Held,
    NotPlainEntry,
    hold,
    is_plain_entry,
    load_json_artifact,
    move_at,
    open_lock_at,
    stat_entry,
)

from defender.learning.core.config import DrainLabel

if TYPE_CHECKING:
    from defender.run_repository import RunAddress
    from defender.learning.core.config import LoopPaths

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")

STATE_DIR_ENV = "DEFENDER_LEARNING_STATE_DIR"


class StateRefused(BaseException):  # noqa: N818 — named for the refusal it reports, like `NotPlainEntry`
    """An entry below the state root the handle will not follow: a link, a hard link, a FIFO, a
    folder where a file belongs, a linked or non-folder holding folder.

    Deliberately not an `Exception`, like `KeyboardInterrupt`: every broad arm between a verb and
    its entry point (`_run_curator_module`'s `except OSError`, the stuck recorders' and the
    curator containment's `except Exception`) would otherwise swallow a refusal as an ordinary
    fault, and each new one would need its own re-raise. Only an arm that names it catches it.
    It is a `SYSTEMIC_FAULTS` member, so the stage runner stops the tick and names `record`.

    `record` is the record the operation named (an absolute path string, for the operator);
    `reason` is why it was refused."""

    def __init__(self, record: str, reason: str) -> None:
        super().__init__(f"refused {record}: {reason}")
        self.record = record
        self.reason = reason


# ---------------------------------------------------------------------------------------------
# Record names
# ---------------------------------------------------------------------------------------------

def _join_record(folder: str, name: str) -> str:
    """`name` below `folder`, as a root-relative record name."""
    return f"{folder}/{name}"


_QUEUE = "author-queue"
_INFLIGHT = _join_record(_QUEUE, "inflight")
_FAILED = _join_record(_QUEUE, "failed")
_DELIVERY = "_pending_delivery"
_DELIVERY_FAILED = _join_record(_DELIVERY, "failed")
_PENDING = "_pending"
_PENDING_LEADS = "_pending_leads"
_PENDING_PITFALLS = "_pending_pitfalls"

#: The gap ledger: the forward check's BAD verdicts, one record per tick that gave up on a pair.
GAP_LEDGER_NAME = "findings.forward_bad.jsonl"


@dataclass(frozen=True)
class LockRole:
    """One of the locks the host takes below the root: its file's name and its poll interval
    (SLOW for the repo lock, held for a whole authoring run; FAST for the rest)."""

    name: str
    file: str
    poll: float


REPO_LOCK = LockRole("repo", "_author.lock", _flock.SLOW_POLL)
AUTHOR_DRAIN_LOCK = LockRole("author-drain", ".author-drain.lock", _flock.FAST_POLL)
LEAD_AUTHOR_DRAIN_LOCK = LockRole("lead-author-drain", ".lead-author-drain.lock", _flock.FAST_POLL)
LEAD_QUEUE_LOCK = LockRole("lead-queue", _join_record(_PENDING_LEADS, ".lock"), _flock.FAST_POLL)
CURATOR_DRAIN_LOCK = LockRole("curator-drain", _join_record(_PENDING, ".lock"), _flock.FAST_POLL)


@dataclass(frozen=True)
class Wait:
    """How a lock take ends when the lock is held: `TRY_ONCE` answers not-taken, `BLOCK` waits for
    ever, a number of seconds is a deadline (`0` tries exactly once) that raises `TimeoutError`."""

    kind: str


TRY_ONCE = Wait("try-once")
BLOCK = Wait("block")


@dataclass(frozen=True)
class Channel:
    """One queue: its record names (relative to the root), its lock topology and its row key.

    `append_lock` excludes concurrent appenders (and the drain's read, rotate and retire
    windows); `drain_role` is the non-blocking one-drainer-per-channel gate, `None` for a channel
    no drain holds exclusively (the pitfalls queue is drained inside the lead-author tick). Both
    roles live on the channel since #719.
    `reads_on_append` is the judge channels' append (a dedup and torn-tail read under the lock);
    the pitfalls channel appends without reading."""

    name: str
    queue: str
    consumed: str
    deadletter: str
    stuck: str
    append_lock: str
    drain_role: LockRole | None
    id_key: str
    reads_on_append: bool
    #: The report beside the queue the lane writes after a rotation (`disposition_report`).
    report: str | None = None


FINDINGS = Channel(
    name="findings",
    queue=_join_record(_PENDING, "findings.jsonl"),
    consumed=_join_record(_PENDING, "consumed.jsonl"),
    deadletter=_join_record(_PENDING, "findings.deadletter.jsonl"),
    stuck=_join_record(_PENDING, "findings.stuck.jsonl"),
    append_lock=_join_record(_PENDING, ".findings.lock"),
    drain_role=CURATOR_DRAIN_LOCK,
    id_key="finding_id",
    reads_on_append=True,
    report=_join_record(_PENDING, "findings.held_report.log"),
)
QUESTIONER_FINDINGS = Channel(
    name="questioner_findings",
    queue=_join_record(_PENDING, "questioner_findings.jsonl"),
    consumed=_join_record(_PENDING, "questioner_consumed.jsonl"),
    deadletter=_join_record(_PENDING, "questioner_findings.deadletter.jsonl"),
    stuck=_join_record(_PENDING, "questioner_findings.stuck.jsonl"),
    append_lock=_join_record(_PENDING, ".questioner_findings.lock"),
    drain_role=CURATOR_DRAIN_LOCK,
    id_key="finding_id",
    reads_on_append=True,
    report=_join_record(_PENDING, "questioner_findings.skip_report.log"),
)


def names_systems(value: object) -> bool:
    """Whether a questioner-channel row's `systems` can key a lesson: a non-empty list of
    non-empty names (a lesson is selected for a tenant by system). The one rule for both ends of
    the channel — the judge's enqueue refuses a row that fails it, and the questioner's drain
    only ever meets such a row from before #1224."""
    return (isinstance(value, list) and bool(value)
            and all(isinstance(s, str) and s.strip() for s in value))


PITFALLS = Channel(
    name="pitfalls",
    queue=_join_record(_PENDING_PITFALLS, "pitfalls.jsonl"),
    consumed=_join_record(_PENDING_PITFALLS, "pitfalls.consumed.jsonl"),
    deadletter=_join_record(_PENDING_PITFALLS, "pitfalls.deadletter.jsonl"),
    stuck=_join_record(_PENDING_PITFALLS, "pitfalls.stuck.jsonl"),
    append_lock=_join_record(_PENDING_PITFALLS, ".pitfalls.lock"),
    drain_role=None,
    id_key="pitfall_id",
    reads_on_append=False,
)


def _address_fault(spec: dict) -> str | None:
    """Why a curation row's `tenant_id` / `run_id` cannot be read as a run address — missing,
    not a string, or off its grammar — or `None` when they can. The shape alone: no tenant
    folder is read (#1105 D-stored)."""
    from defender._tenant import TenantRefused
    from defender.run_repository import RunAddress, RunRefused

    for key in ("tenant_id", "run_id"):
        if not isinstance(spec.get(key), str):
            return f"{key} is missing or not a string"
    try:
        RunAddress(spec["tenant_id"], spec["run_id"])
    except (TenantRefused, RunRefused) as off:
        return f"the run address is off its grammar ({off})"
    return None


@dataclass(frozen=True)
class Claimed:
    """One request this pass owns: moved into `inflight/`, read, servable.

    It carries names, never paths: `name` is the record's file name (the same in the top-level
    slot and in `inflight/`), `key` its request key (the name's stem) and `spec` the request
    body. Held until it is consumed (for the lead-author drain, after the scrub)."""

    key: str
    name: str
    spec: dict

    @property
    def address(self) -> RunAddress:
        """The run the request is about, as the row stores it (#1105 D-stored): its tenant and
        run id, checked on their grammars when the claim admitted the row. The drain accepts
        the tenant and opens the run through its repository."""
        from defender.run_repository import RunAddress

        return RunAddress(self.spec["tenant_id"], self.spec["run_id"])

    @property
    def identity(self) -> str:
        """The id an operator greps for when a request is dropped or deferred: the body's
        `case_id`, else its `run_id`, else the record name's stem (a row too damaged to carry
        either)."""
        return request_identity(self.spec, self.key)


def request_identity(spec: dict, stem: str) -> str:
    """@owns request_identity — what a request is called in a log line or a dead letter."""
    for key in ("case_id", "run_id"):
        value = spec.get(key)
        if isinstance(value, str) and value:
            return value
    return stem


@dataclass(frozen=True)
class PendingDelivery:
    """One batch whose commit is on a local branch and whose push or PR has not yet landed:
    its record's id (the file name's stem), the branch and the batch id.

    @owns branch @owns batch_id — the one reader that builds a `PendingDelivery` from a
    delivery record is `LearningState.deliveries`, the only constructor of this type; a caller
    that needs either value for a delivery to land takes it from the `PendingDelivery` it is
    handed. The queue page reads the raw bodies `delivery_rows` returns, for display only."""

    id: str
    branch: str
    batch_id: str


def canonical_row(row: dict) -> str:
    """One spelling of a row's whole content, stable across ticks and processes: how a row with
    no id is recognised (`rotate`'s `drop`) and named (`drain._stuck_row_ids`)."""
    return json.dumps(row, sort_keys=True, default=str)


@dataclass(frozen=True)
class RootRecord:
    """The state root itself, as a thing `describe` can name."""


STATE_ROOT = RootRecord()

#: Each lane's stage folder, by its member: no string names a lane (#1179 O1').
_LANES: dict[DrainLabel, str] = {
    DrainLabel.AUTHOR: _PENDING,
    DrainLabel.LEAD_AUTHOR: _PENDING_LEADS,
}


def retirement_stamp() -> dict[str, str]:
    """@owns retired_at — when a graveyard record was written, on every writer's record.

    Shared by every dead-letter writer (`_bump_rows`, `_retire_unkeyable`, the pitfalls
    curator's `_graveyard_dropped_rows`); the queue page sorts and places records by it."""
    return {"retired_at": now_iso()}


# ---------------------------------------------------------------------------------------------
# Refusal conversion
# ---------------------------------------------------------------------------------------------

_NOT_A_FOLDER_REASON = os.strerror(errno.ENOTDIR)


def _refusal_reason(exc: BaseException) -> str | None:
    """Why `exc` is a refusal of an entry below the root, or `None` when it is an ordinary I/O
    outcome (JF2 A: refusal by shape — a link, hard link, FIFO or folder where a file belongs,
    a linked holding folder, ENOTDIR on the walk; everything else keeps today's route)."""
    if isinstance(exc, NotPlainEntry):
        return "a link, hard link or other non-plain entry"
    if isinstance(exc, NotADirectoryError):
        return "a file where a folder belongs"
    if isinstance(exc, OSError) and exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
        return "a link or non-plain entry on the way"
    return None


# ---------------------------------------------------------------------------------------------
# The handle
# ---------------------------------------------------------------------------------------------


class LearningState:
    """The learning state tree, held open by one descriptor on its root.

    Opened at an entry point by `LearningState.open(paths)`; the root is resolved once there and
    never again (a spelling re-pointed after `open` moves nothing). Use it as a context manager,
    or `close()` it; an unclosed handle closes on collection."""

    def __init__(self, held: Held, root: Path) -> None:
        self._held = held
        self._view: Bound = held.view()
        self._root = root

    # -- lifetime -------------------------------------------------------------------------------

    @classmethod
    def open(cls, paths: LoopPaths) -> LearningState:
        """Hold the state root `paths` names, resolved once to its real path (a link at or above
        it is operator configuration, followed here and nowhere else). The root must exist: a
        missing root, or one that is not a folder, is a `FatalConfigError` naming it and
        `DEFENDER_LEARNING_STATE_DIR`. Nothing is created."""
        root = Path(paths.state_root).resolve()
        if not root.is_dir():
            raise FatalConfigError(
                f"the learning state root {root} does not exist or is not a folder — create it, "
                f"or point {STATE_DIR_ENV} at an existing folder (nothing here creates it)")
        return cls(hold(root), root)

    def close(self) -> None:
        self._held.close()

    def __enter__(self) -> LearningState:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- naming ---------------------------------------------------------------------------------

    def describe(self, record: Channel | Claimed | PendingDelivery | RootRecord) -> str:
        """A display string for `record`, for logs, the queue page's `state_root` field and the
        judge's yaml: an absolute path string. Reads and opens nothing."""
        if isinstance(record, Channel):
            return str(self._root / record.queue)
        if isinstance(record, Claimed):
            return str(self._root / _INFLIGHT / record.name)
        if isinstance(record, PendingDelivery):
            return str(self._root / _DELIVERY / f"{record.id}.json")
        if isinstance(record, RootRecord):
            return str(self._root)
        raise ValueError(f"cannot describe {record!r}")

    def stage_dir(self, lane: DrainLabel) -> Path:
        """The folder a drain lane's agent stages write into (`_pending/` for the author lane,
        `_pending_leads/` for the lead-author lane), made below the root without following a
        link. N3's one path escape: the stage harness (#1142) still writes there by path."""
        folder = _LANES.get(lane)
        if folder is None:
            raise ValueError(f"unknown drain lane {lane!r}; known: {sorted(map(str, _LANES))}")
        self._guarded(folder, lambda: self._held.mkdir(folder))  # lint-unguarded-tree-write: ok — a descriptor-level mkdir below the held root (no link followed)
        return self._root / folder

    # -- the refusal rule -----------------------------------------------------------------------

    def _abs(self, name: str) -> str:
        return str(self._root / name)

    def _guarded(self, name: str, fn: Callable[[], _T]) -> _T:
        """`fn()`, with a core refusal converted to `StateRefused(name, …)`. The conversion is
        raised after the `except` block closes, so the refusal carries no `__context__` for the
        stage runner to report as the fault it displaced."""
        refused: StateRefused | None = None
        try:
            return fn()
        except OSError as e:
            reason = _refusal_reason(e)
            if reason is None:
                raise
            refused = StateRefused(self._abs(name), reason)
        raise refused

    def _raise_if_unread(self, name: str, reason: str | None) -> None:
        """Raise for a `Bound` read or stat of `name` refused with `reason` (`None`: it was not).
        A refusal by shape (`_read_reason` folds a link, hard link, FIFO and linked folder into
        `ALIAS_READ_REFUSAL`, an ENOTDIR into its strerror) is `StateRefused`; any other (EIO,
        EACCES, over the read bound) is an ordinary `OSError`, never an empty read."""
        if reason is None:
            return
        if reason in (ALIAS_READ_REFUSAL, _NOT_A_FOLDER_REASON):
            raise StateRefused(self._abs(name), reason)
        raise OSError(f"{self._abs(name)}: {reason}")

    def _read(self, name: str) -> tuple[str | None, bool]:
        """`(text, present)` of the plain file at `name`: `(None, False)` when absent. A refusal
        by shape is `StateRefused`; any other refused read (EIO, EACCES, over the read bound) is
        an ordinary `OSError`, never an empty read."""
        rec = self._view.read(name, errors="replace")
        self._raise_if_unread(name, rec.reason)
        return rec.text, not rec.absent

    def _read_rows(self, name: str) -> tuple[list[dict], int, str | None]:
        """`(rows, malformed, text)` of the JSONL file at `name` (absent: no rows, no text)."""
        rows, malformed, rec = self._view.read_jsonl(name)
        self._raise_if_unread(name, rec.reason)
        return rows, malformed, rec.text

    def _judge(self, name: str) -> None:
        """Refuse unless `name` is absent or a plain, single-linked file (no read, no open: a FIFO
        cannot block it)."""
        st = stat_entry(self._view, name)
        self._raise_if_unread(name, st.reason)
        if st.st is not None and not is_plain_entry(st.st):
            raise StateRefused(self._abs(name), "a link, hard link or other non-plain entry")

    def _write(self, name: str, text: str, mode: str) -> None:
        self._guarded(name, lambda: self._held.write(name, text, mode=mode))

    def _unlink(self, name: str) -> bool:
        return self._guarded(name, lambda: self._held.unlink(name))

    def _append_rows(self, name: str, rows: list[dict]) -> None:
        self._write(name, "".join(json.dumps(row) + "\n" for row in rows), "append")

    # -- locks ----------------------------------------------------------------------------------

    def _open_lock(self, file: str) -> Any:
        return self._guarded(file, lambda: open_lock_at(self._held, file))

    @contextlib.contextmanager
    def lock(self, role: LockRole, *, wait: Wait | float) -> Iterator[bool]:
        """Hold `role`'s lock for the block. `wait` says how a held lock ends the take:

        * `TRY_ONCE` — yields whether the lock was taken; the block should run only when it was;
        * a number of seconds — a deadline (`0` tries exactly once, never coerced to a default),
          polled at the role's interval; raises `TimeoutError` when it expires;
        * `BLOCK` — waits until the holder releases.

        The lock file and its holding folder are made below the root as needed. A refused lock
        file is `StateRefused` for every role: never "not taken". A channel's append lock is not
        a role: `append`, `rotate`, `retire_rows` and `read_window` take it inside, so no caller
        holds it (a second open of one name blocks against the same process)."""
        if not isinstance(role, LockRole):
            raise ValueError(f"not a lock role: {role!r}")
        if not isinstance(wait, (Wait, int, float)) or isinstance(wait, bool):
            raise ValueError(f"not a wait: {wait!r}")
        fh = self._open_lock(role.file)
        try:
            if wait is TRY_ONCE:
                taken = _flock.take(fh, timeout_seconds=0)
            elif wait is BLOCK:
                taken = _flock.take(fh, timeout_seconds=None)
            elif isinstance(wait, Wait):
                raise ValueError(f"not a wait: {wait!r}")
            else:
                taken = _flock.take(fh, timeout_seconds=wait, poll=role.poll)
                if not taken:
                    raise TimeoutError(
                        f"{role.name} lock {self._abs(role.file)} held by another for >{wait}s")
        except BaseException:
            fh.close()
            raise
        if not taken:
            fh.close()
            yield False
            return
        try:
            yield True
        finally:
            _flock.release(fh)

    @contextlib.contextmanager
    def _append_lock(self, channel: Channel, timeout: float | None) -> Iterator[None]:
        """The channel's append lock: `timeout=None` waits for ever (an appender that gave up
        would lose its row), a number is a deadline that raises `TimeoutError`."""
        fh = self._open_lock(channel.append_lock)
        try:
            taken = _flock.take(fh, timeout_seconds=timeout)
        except BaseException:
            fh.close()
            raise
        if not taken:
            fh.close()
            raise TimeoutError(
                f"queue lock {self._abs(channel.append_lock)} held by an appender for >{timeout}s")
        try:
            yield
        finally:
            _flock.release(fh)

    # -- channels -------------------------------------------------------------------------------

    @staticmethod
    def _channel(channel: Channel) -> Channel:
        if not isinstance(channel, Channel):
            raise ValueError(f"not a channel: {channel!r}")
        return channel

    def rows(self, channel: Channel) -> list[dict]:
        """The channel's queued rows (absent: none). A refused queue is `StateRefused`, never an
        empty read."""
        channel = self._channel(channel)
        return self._read_rows(channel.queue)[0]

    def rows_report(self, channel: Channel) -> tuple[list[dict], int]:
        """`(rows, unreadable)`: the queued rows plus how many non-blank lines were not rows."""
        channel = self._channel(channel)
        rows, malformed, _text = self._read_rows(channel.queue)
        return rows, malformed

    def read_window(self, channel: Channel, *, timeout: float) -> tuple[list[dict], int] | None:
        """The drain's read of the queue under the channel's append lock: `(rows, unreadable)`, or
        `None` when an appender held the lock past `timeout` (a busy channel is not a fault, so the
        tick skips)."""
        channel = self._channel(channel)
        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(self._append_lock(channel, timeout))
            except TimeoutError:  # the lock's own deadline only, never a fault inside the read
                return None
            return self.rows_report(channel)

    def append(
        self, channel: Channel, rows: list[dict], *, dedup_key: str | None = None,
    ) -> tuple[int, int]:
        """Append `rows` to the channel's queue, one `json.dumps` line each: `(appended,
        malformed)`.

        A judge channel (`reads_on_append`) reads the queue under its append lock first: a torn
        trailing row is closed with a leading newline rather than concatenated onto, `dedup_key`
        drops rows whose id the queue already holds, and `malformed` counts the unreadable lines
        the read saw. The pitfalls channel appends without reading (`(len(rows), 0)`). An empty
        append takes no lock and makes nothing: a pass that enqueued nothing must not create the
        queue."""
        channel = self._channel(channel)
        if not rows:
            return 0, (self._read_rows(channel.queue)[1] if channel.reads_on_append else 0)
        if not channel.reads_on_append:
            with self._append_lock(channel, None):
                self._append_rows(channel.queue, rows)
            return len(rows), 0
        with self._append_lock(channel, None):
            existing, malformed, text = self._read_rows(channel.queue)
            to_write = rows
            if dedup_key is not None:
                # String ids only on both sides: an unhashable id off the shared file would raise
                # `TypeError` inside the lock, and a non-string id can only fail to suppress a
                # write, the safe direction.
                seen = {r[dedup_key] for r in existing if isinstance(r.get(dedup_key), str)}
                to_write = [r for r in rows
                            if not (isinstance(r.get(dedup_key), str) and r[dedup_key] in seen)]
            if not to_write:
                return 0, malformed
            body = "".join(json.dumps(row) + "\n" for row in to_write)
            if text and not text.endswith("\n"):
                body = "\n" + body
            self._write(channel.queue, body, "append")
        return len(to_write), malformed

    def rotate(
        self, channel: Channel, held: list[dict], consumed: list[dict], commit_sha: str | None,
        *, drop: Sequence[dict] = (), timeout: float | None = None,
    ) -> None:
        """The locked rewrite: under the channel's append lock (`timeout` a deadline, `None` blocks),
        replace the queue with `held` plus whatever was appended since the batch's read (a row
        the batch already handled is dropped: by id, or, for a row with no id, when it is exactly
        one of the rows as read that `drop` names), then append `consumed` to the ledger.

        Both files are judged before either is written, so a refused ledger stops the rotate
        with the queue untouched (D8). The crash window between the replace and the append is
        today's."""
        channel = self._channel(channel)
        key = channel.id_key
        with self._append_lock(channel, timeout):
            self._judge(channel.queue)
            self._judge(channel.consumed)
            # Always merges: a non-merging rewrite would drop rows appended between the batch's
            # read and its rewrite. A row with no id has nothing to match by, so the caller names
            # it as it read it (`drop`) and it leaves only on exact content; a different keyless
            # row appended since the read stays queued, and `None` is never a "handled id".
            processed = {e[key] for e in [*held, *consumed] if e.get(key) is not None}
            dropped = {canonical_row(r) for r in drop}
            current = self._read_rows(channel.queue)[0]
            survivors = list(held) + [
                r for r in current
                if (r[key] not in processed if r.get(key) is not None
                    else canonical_row(r) not in dropped)]
            self._write(channel.queue, "".join(json.dumps(e) + "\n" for e in survivors),
                        "replace")
            if consumed:
                now = now_iso()
                out = []
                for entry in consumed:
                    rec = dict(entry)
                    rec.setdefault("consumed_at", now)
                    if rec.get("consumed_category") == "consumed_committed" and commit_sha:
                        rec["consumed_commit"] = commit_sha
                    out.append(rec)
                self._append_rows(channel.consumed, out)

    def retire_rows(
        self, channel: Channel, batch_ids: list[str], retire: Callable[[list[dict]], _T],
        *, timeout: float | None = None,
    ) -> _T:
        """The retire window: under the channel's append lock, read the rows named by `batch_ids`
        and hand them to `retire` (which may `deadletter` but must not take the append lock
        itself: no `append`, `rotate`), answering what it answers. One hold for the read and the
        bump, as `drain.retire` always did."""
        channel = self._channel(channel)
        ids = {str(i) for i in batch_ids}
        key = channel.id_key
        with self._append_lock(channel, timeout):
            named = [row for row in self._read_rows(channel.queue)[0]
                     if isinstance(row.get(key), str) and row[key] in ids]
            return retire(named)

    def deadletter(self, channel: Channel, entries: list[dict]) -> None:
        """Append `entries` to the channel's graveyard (advisory: the queue rewrite is
        authoritative; only the queue page reads it back). Takes no lock."""
        channel = self._channel(channel)
        if entries:
            self._append_rows(channel.deadletter, entries)

    def deadletter_rows(self, channel: Channel) -> tuple[list[dict], int]:
        """`(records, unreadable)` of the graveyard, for display: a graveyard that cannot be read
        (refused or otherwise) is one unreadable and no records, never an exception."""
        channel = self._channel(channel)
        return self._display_rows(channel.deadletter)

    def stuck_rows(self, channel: Channel) -> list[dict]:
        """The channel's stuck-report records (absent: none). A refusal is `StateRefused`."""
        channel = self._channel(channel)
        return self._read_rows(channel.stuck)[0]

    def stuck_report(self, channel: Channel) -> tuple[list[dict], int]:
        """`(records, unreadable)` of the stuck report, for display."""
        channel = self._channel(channel)
        return self._display_rows(channel.stuck)

    def stuck_count(self, channel: Channel) -> int:
        """How many records the channel's stuck report holds right now."""
        return len(self.stuck_rows(channel))

    def stuck_append(self, channel: Channel, record: dict) -> None:
        """Append one stuck record. Lock-free, as always. `run_batch`'s own recorders run under the
        repo lock, which keeps them in order; the record `_drain_one_curator` writes for a fault
        raised above `run_batch` runs outside it, under the author-drain lock alone."""
        channel = self._channel(channel)
        self._append_rows(channel.stuck, [record])

    def gap_record(self, record: dict) -> None:
        """Append one record to the gap ledger (`_pending/findings.forward_bad.jsonl`)."""
        self._append_rows(f"{_PENDING}/{GAP_LEDGER_NAME}", [record])

    def disposition_report(self, channel: Channel, text: str) -> None:
        """Append one line to the channel's disposition report (the lessons channel's held report,
        the questioner channel's skip report): the only trace that a declined finding was seen."""
        channel = self._channel(channel)
        if channel.report is None:
            raise ValueError(f"channel {channel.name} has no disposition report")
        self._write(channel.report, text, "append")

    def _display_rows(self, name: str) -> tuple[list[dict], int]:
        try:
            rows, malformed, _text = self._read_rows(name)
        except (StateRefused, OSError):
            return [], 1
        return rows, malformed

    # -- requests -------------------------------------------------------------------------------

    def enqueue_curation(self, case_id: str, spec: dict) -> None:
        """File the curation request `spec` (its fields' one producer is
        `run_common.enqueue_curation`: `{case_id, tenant_id, run_id}`, the run's address) for
        `case_id`, replacing any earlier one: a repeat
        investigation of one case coalesces onto one request, and the later run wins. Lock-free
        and atomic (a staged replace), so the end-of-run enqueue never waits on a drain."""
        name = f"{_QUEUE}/{case_id}.json"
        self._write(name, json.dumps(spec) + "\n", "replace")
        _logger.info(f"enqueued for curation: {self._abs(name)}")

    def _json_names(self, folder: str) -> list[str]:
        """The `*.json` record names directly in `folder`, of every kind (an entry at a record
        name is judged when it is opened, so a planted one halts there); a folder that is absent
        holds none, and a refused one is `StateRefused`. Foreign names are never opened."""
        listed = self._view.under(folder).entries()
        self._raise_if_unread(folder, listed.reason)
        return sorted(n for n in (listed.entries or {}) if n.endswith(".json"))

    def has_requests(self) -> bool:
        """Whether any request is waiting: a queued record, or one stranded in `inflight/` by a
        drain that died mid-serve (the drainer reclaims it, so the wake gate must see it). Opens
        no record."""
        return bool(self._json_names(_QUEUE)) or bool(self._json_names(_INFLIGHT))

    def claim(
        self, identity_key: str, *, label: DrainLabel = DrainLabel.LEAD_AUTHOR,
        noun: str = "lead-author",
        extra: str = "",
    ) -> Iterator[Claimed]:
        """Claim every queued request and yield the servable ones, orphans first.

        Claiming moves the record out of the queue (`move_at`) before serving, so a re-ask
        landing mid-serve gets a free top-level slot. Orphans in `inflight/` from a dead pass are
        reclaimed unconditionally — sound only because every caller must hold the drainer lock, so
        no live pass can own a claim (today's one caller, the lead-author drain, does). A queued request whose name is already claimed in this pass
        is not moved, which would overwrite the claim: it waits for the next pass.

        An unreadable record is quarantined rather than skipped, or it would be reclaimed and
        fail every tick while keeping the wake gate true; `identity_key` names its dead letter
        (`run_id` or `case_id`). An entry planted at a record name is `StateRefused` when the
        claim reaches it."""
        orphans = self._json_names(_INFLIGHT)
        queued = self._json_names(_QUEUE)
        _logger.info(
            f"{label}: {len(queued)} run(s) queued for {noun}, "
            f"{len(orphans)} reclaimed from a prior claim{extra}")
        for name, orphan in [*((n, True) for n in orphans), *((n, False) for n in queued)]:
            claimed_name = f"{_INFLIGHT}/{name}"
            if not orphan:
                slot = stat_entry(self._view, claimed_name)
                self._raise_if_unread(claimed_name, slot.reason)
                if not slot.absent:
                    _logger.info(
                        f"{label}: {name} waits a pass — a request of that name is already "
                        "claimed in this one")
                    continue
                try:
                    self._guarded(f"{_QUEUE}/{name}", partial(
                        move_at, self._held, f"{_QUEUE}/{name}", f"{_INFLIGHT}/{name}"))
                except FileNotFoundError:
                    continue
            spec, reason = self._claim_spec(claimed_name)
            stem = name.removesuffix(".json")
            if spec is None:
                self._quarantine_name(name, {identity_key: stem}, reason)
                continue
            unshaped = _address_fault(spec)
            if unshaped is not None:
                # The shape only (#1105 D-stored): the claim reads no tenant folder. A field the
                # address cannot be built from would raise out of this generator and wedge the
                # drain; an old `{case_id, run_dir}` row is one (nothing serves that shape).
                self._quarantine_name(name, spec, f"unreadable: {unshaped}")
                continue
            yield Claimed(key=stem, name=name, spec=spec)

    def _claim_spec(self, name: str) -> tuple[dict | None, str]:
        """The claimed record's spec, or `(None, reason)` for one that cannot be served. A row
        that parses but is no mapping is unreadable too: asking it for `run_dir` would raise
        `AttributeError` past every dead-letter path."""
        try:
            text, _present = self._read(name)
        except OSError as e:
            return None, f"unreadable: {e!r}"
        if text is None:
            return None, "unreadable: the claimed record vanished"
        spec, why = load_json_artifact(text)
        if why is not None:
            return None, f"unreadable: {why}"
        if not isinstance(spec, dict):
            return None, f"unreadable: not a mapping ({type(spec).__name__})"
        return spec, ""

    def stamp(self, claimed: Claimed, spec: dict) -> None:
        """Replace the claim's record in `inflight/` with `spec` (the attempts bump)."""
        self._write(f"{_INFLIGHT}/{claimed.name}", json.dumps(spec) + "\n", "replace")

    def requeue(self, claimed: Claimed) -> bool:
        """Put the claim back in the queue's top-level slot, create-if-absent: `False` when the
        slot is no longer free (a fresher request for the same case landed mid-serve; the later
        run wins, so the caller drops its retry). A refused slot is `StateRefused`, never False.
        The claim itself stays in `inflight/` until `done`."""
        name = f"{_QUEUE}/{claimed.name}"
        try:
            self._write(name, json.dumps(claimed.spec) + "\n", "create")
        except FileExistsError:
            return False
        return True

    def done(self, claimed: Claimed) -> None:
        """Release the claim: unlink its record in `inflight/`. Best-effort: an ordinary failure
        leaves it for the next pass's reclaim; a refusal is not an `OSError` and still stops."""
        with contextlib.suppress(OSError):
            self._unlink(f"{_INFLIGHT}/{claimed.name}")

    def quarantine(self, claimed: Claimed, reason: str) -> None:
        """Park the claim in `failed/` with `reason`, and release it."""
        self._quarantine_name(claimed.name, claimed.spec, reason)

    def _quarantine_name(self, name: str, spec: dict, reason: str) -> None:
        rec = {**spec, "failed": reason}
        self._write(f"{_FAILED}/{name}", json.dumps(rec) + "\n", "replace")
        with contextlib.suppress(OSError):
            # An ordinary failure to unlink leaves the claim for the next pass's reclaim; a
            # refusal is not an OSError and still stops the tick.
            self._unlink(f"{_INFLIGHT}/{name}")
        _logger.warning(f"quarantined {request_identity(spec, name.removesuffix('.json'))} — {reason}")

    def failed_requests(self) -> tuple[list[tuple[str, dict]], int]:
        """`([(record key, body)], unreadable)` of the quarantined requests, for display: a
        folder or record that cannot be read is counted unreadable, never raised."""
        return self._json_records(_FAILED)

    def _json_records(self, folder: str) -> tuple[list[tuple[str, dict]], int]:
        try:
            names = self._json_names(folder)
        except (StateRefused, OSError):
            return [], 1
        out: list[tuple[str, dict]] = []
        unreadable = 0
        for name in names:
            try:
                text, _present = self._read(f"{folder}/{name}")
            except (StateRefused, OSError):
                unreadable += 1
                continue
            value, why = load_json_artifact(text or "")
            if text is None or why is not None or not isinstance(value, dict):
                unreadable += 1
                continue
            out.append((name.removesuffix(".json"), value))
        return out, unreadable

    # -- deliveries -----------------------------------------------------------------------------

    def record_delivery(self, record_id: str, spec: dict) -> None:
        """Record a batch that committed but whose push or PR failed, under `record_id`."""
        self._write(f"{_DELIVERY}/{record_id}.json", json.dumps(spec) + "\n", "replace")

    def deliveries(self, branch_prefix: str) -> list[PendingDelivery]:
        """This lane's undelivered batches — only those whose branch starts with `branch_prefix`,
        since the other lane delivers under its own drain lock. An unreadable record names no
        branch or lane, so it is quarantined rather than logged every tick forever."""
        out: list[PendingDelivery] = []
        for name in self._json_names(_DELIVERY):
            stem = name.removesuffix(".json")
            try:
                text, _present = self._read(f"{_DELIVERY}/{name}")
            except OSError:
                text = None
            spec = None
            if text is not None:
                value, why = load_json_artifact(text)
                spec = value if why is None else None
            if not isinstance(spec, dict) or not isinstance(spec.get("batch_id"), str):
                self.quarantine_delivery(stem, "unreadable pending-delivery record")
                continue
            branch = str(spec.get("branch", ""))
            if branch.startswith(branch_prefix):
                out.append(PendingDelivery(stem, branch, spec["batch_id"]))
        return out

    def delivered(self, delivery: PendingDelivery) -> None:
        """Drop the record of a batch that has now been delivered. Best-effort, like `done`."""
        with contextlib.suppress(OSError):
            self._unlink(f"{_DELIVERY}/{delivery.id}.json")

    def quarantine_delivery(self, delivery: PendingDelivery | str, reason: str) -> None:
        """Park a delivery record in `failed/` with `reason` and drop it."""
        stem = delivery.id if isinstance(delivery, PendingDelivery) else delivery
        self._write(f"{_DELIVERY_FAILED}/{stem}.json", json.dumps({"failed": reason}) + "\n",
                    "replace")
        with contextlib.suppress(OSError):
            self._unlink(f"{_DELIVERY}/{stem}.json")
        _logger.warning(f"quarantined {stem} — {reason}")

    def failed_deliveries(self) -> tuple[list[tuple[str, dict]], int]:
        """`([(record id, body)], unreadable)` of the quarantined deliveries, for display."""
        return self._json_records(_DELIVERY_FAILED)

    def delivery_rows(self) -> tuple[list[tuple[str, dict]], int]:
        """`([(record id, body)], unreadable)` of the live delivery records, for the queue page:
        read-only, so a torn record is counted and never quarantined (that is the drain's verb)."""
        return self._json_records(_DELIVERY)
