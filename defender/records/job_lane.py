"""The job lane's door to one tenant's runs container (#1342 M1): every host file the worker and
the job entry share, keyed by `(data root, tenant id)` and opened without accepting the tenant.

Learning jobs (#1344) share two host-held records here, keyed by the learning job's id and
written by the job entry, read by the worker: its progress record (`LearningProgress`, replaced
whole) and its end record (`LearningEnd`, create-only), which carries the job's findings in an
optional field of its own (#1487, `findings_of`). Each has one parser, and text that is not a
record of its shape parses as no record (`None`), which the worker treats like an absent one.

The worker writes a job's launch record and alert file here before it starts the child; the
child's job entry opens the same door first thing — before tenant acceptance, so a refusal there
still leaves its job-end record — checks the launch record, and writes the job-end record as it
exits; the worker then reads the job-end record, the knowledge record and the session pointer
through it, and the run's closing record and cost from the session database the pointer's case id
derives.

Host requests (#1471: readiness checks and adoptions) share two records here, keyed by the request id: the result
record (`ReadinessRecord`, `AdoptionRecord`), written create-only by the request's helper or its container, one writer
per request, and, for a readiness check whose publish gave a source, the knowledge record its helper writes
(`write_request_knowledge`). The worker reads each into three states: absent, malformed (present, but not of a record's
shape, or over its cap), or the record; the vocabulary they are judged by lives here, so writer and worker share it.

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
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Protocol

from defender import _io
from defender._text import postgres_can_hold
from defender.records._errors import RunRefused
from defender.records._held import hold_level, level_fault
from defender.records._id import RunId
from defender.records.job_facts import (  # noqa: F401 — the worker's reasons, re-exported
    EXITED_WITHOUT_RESULT, EXPIRED, LEASE_LAPSED, RETRY_CAP, WORKER_ERROR,
    BOX_NOT_STARTED, BOX_START_FAILED, BOX_STARTED, SETUP_CRASHED, SETUP_DONE, SETUP_REFUSED,
)
from defender.records._knowledge_status import PINNED, UNREADABLE, _record_status, api_knowledge, knowledge_status
from defender.records._layout import RunPaths, SessionPaths
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


_JOB_END_KEYS = frozenset({"setup", "box", "report_committed", "scrub_verified", "cut_short"})


@dataclass(frozen=True)
class JobEnd:
    """The job-end record (`<runs>/<id>.job-end.json`): five facts, each set by the job entry at
    the point it became true. `cut_short` is the run's exit class (`run_end.TRUNCATED_BY_VALUES`,
    the whole vocabulary) as the driver returned it, or `None`: a run nothing cut short, or one
    that never returned from its driver (setup refused or crashed, a group that propagated)
    (#1421). No spend fact rides on it: the run's ledger says for itself whether it is complete
    (#1377 r7.3 T1)."""

    setup: str
    box: str
    report_committed: bool
    scrub_verified: bool
    cut_short: str | None

    def text(self) -> str:
        return json.dumps({"setup": self.setup, "box": self.box,
                           "report_committed": self.report_committed,
                           "scrub_verified": self.scrub_verified,
                           "cut_short": self.cut_short})

    @classmethod
    def parse(cls, text: str) -> JobEnd | None:
        """The record `text` holds, or `None` when it is not one the job entry could have written.
        `cut_short` must be JSON null or a vocabulary word exactly, so no child's text can reach
        the fixed job message that names it."""
        obj, unreadable = _io.load_json_artifact(text)
        if unreadable is not None or not isinstance(obj, dict) or set(obj) != _JOB_END_KEYS:
            return None
        setup, box = obj["setup"], obj["box"]
        committed, verified, cut_short = obj["report_committed"], obj["scrub_verified"], obj["cut_short"]
        if not (isinstance(setup, str) and setup in _SETUPS and isinstance(box, str) and box in _BOXES
                and isinstance(committed, bool) and isinstance(verified, bool)
                and (cut_short is None or normalized_truncated_by(cut_short) is not None)):
            return None
        return cls(setup=setup, box=box, report_committed=committed, scrub_verified=verified,
                   cut_short=cut_short)


@dataclass(frozen=True)
class RunCost:
    """A run's spend read from its ledger, and whether the ledger is complete (sealed at its last row,
    no unseen request, no unpriced model; #1377 r7.3 T1): the worker's whole lower-limit rule. A run
    that never opened its store is exactly 0, complete."""

    usd: float
    complete: bool
# -- learning jobs (#1344): the vocabulary and the two records -----------------------------------

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
#: The reasons only the worker records (no end record carries them): in `job_facts`, which the
#: store reads without loading the record readers.

_END_REASONS: dict[str, frozenset[str | None]] = {
    LEARNING_COMPLETED: frozenset({None}),
    LEARNING_STOPPED: frozenset({None}),
    LEARNING_SKIPPED: frozenset(SKIPPED_BY_THE_ENTRY),
    LEARNING_FAILED: frozenset(FAILED_BY_THE_ENTRY),
}

_PROGRESS_FIELDS = frozenset({"fork_message_id", "stage", "sibling_cost_usd"})
_END_FIELDS = frozenset({"status", "reason", "message", "fork_message_id", "stage", "sibling_cost_usd"})
#: The end record's one optional field (#1487): the job's findings, which the envelope never looks inside.
_FINDINGS_FIELD = "findings"
#: The findings count an entry before #1589 still writes: accepted whatever its value, and never read.
_OLD_COUNT_FIELD = "findings_count"


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
    `failed`; never run text), and the final pick, stage and sibling cost.

    `findings` (#1487) is the record's one optional field, the job's findings as the entry read
    them (`{state, text}`, `findings_of`): `None` when the record carries none. The envelope judges
    no field of it, so no shape of it makes the record unreadable (the record's one JSON nesting
    bound still covers it, as every record's does); the worker reads it after the
    envelope, and only for a `completed` end. A record from an entry before #1589 also carries a
    `findings_count`, which is accepted whatever its value and ignored."""

    status: str
    reason: str | None
    message: str | None
    fork_message_id: str | None
    stage: str | None
    sibling_cost_usd: float = 0.0
    findings: Any = None

    def __post_init__(self) -> None:
        allowed = _END_REASONS.get(self.status) if isinstance(self.status, str) else None
        if allowed is None or self.reason not in allowed:
            raise ValueError(f"not an end the job entry decides: {self.status!r}/{self.reason!r}")
        if not (_optional_text(self.message) and _optional_text(self.fork_message_id)
                and _optional_text(self.stage) and _cost(self.sibling_cost_usd)):
            raise ValueError(f"not a learning end record: {self!r}")
        if self.reason is not None and not (self.message or "").strip():
            raise ValueError(f"a {self.status} end names why in its message")

    def text(self) -> str:
        body: dict[str, Any] = {"status": self.status, "reason": self.reason, "message": self.message,
                                "fork_message_id": self.fork_message_id, "stage": self.stage,
                                "sibling_cost_usd": self.sibling_cost_usd}
        if self.findings is not None:  # absent and null read alike: the field is written only when it says something
            body[_FINDINGS_FIELD] = self.findings
        return json.dumps(body)

    @classmethod
    def parse(cls, text: str) -> LearningEnd | None:
        """The record `text` holds, or `None` when it is not one the job entry could write: exactly
        the envelope's fields, with or without `findings` and an older entry's `findings_count`, neither of whose
        values is looked at here."""
        obj, unreadable = _io.load_json_artifact(text)
        if unreadable is not None or not isinstance(obj, dict) \
                or set(obj) - {_FINDINGS_FIELD, _OLD_COUNT_FIELD} != _END_FIELDS:
            return None
        try:
            return cls(**{name: obj[name] for name in _END_FIELDS}, findings=obj.get(_FINDINGS_FIELD))
        except (TypeError, ValueError, OverflowError):
            return None


# -- a completed job's findings, in its end record (#1487) -----------------------------------------

#: The most findings text one job carries, in UTF-8 bytes of the `text` (`findings_text_bytes`): a generous guess
#: (owner decision 7), to tighten once real sizes are seen. Over it the findings are refused, never the ending.
FINDINGS_CAP_BYTES = 8 * 1024 * 1024

#: The findings field's states: `ok` (with the text), or why the entry could not carry them.
FINDINGS_OK, FINDINGS_OVER_CAP, FINDINGS_UNREADABLE, FINDINGS_MALFORMED = "ok", "over_cap", "unreadable", "malformed"
FINDINGS_STATES = frozenset({FINDINGS_OK, FINDINGS_OVER_CAP, FINDINGS_UNREADABLE, FINDINGS_MALFORMED})
#: The findings text's channels: the learning store's kind of each, as the worker inserts them.
FINDINGS_CHANNELS = ("finding", "questioner_finding")

#: Why a completed record's findings are refused before any row is looked at (`findings_of`): a closed vocabulary
#: (the state the entry recorded, or what the reader found), so a refusal's log line never carries the job's text.
FINDINGS_ABSENT, FINDINGS_NOT_A_FIELD, FINDINGS_NOT_JSON, FINDINGS_NOT_AN_OBJECT = (
    "absent", "not_a_findings_field", "text_not_json", "text_not_an_object")


def findings_text_bytes(text: str) -> int:
    """The size of findings text, in UTF-8 bytes: the one measure of the cap, used by the entry and the worker alike,
    and of a row's and an id's bounds. Total: a lone surrogate (which JSON can carry) counts as the 3 bytes its
    code point would take, never an error."""
    return len(text.encode("utf-8", "surrogatepass"))


def parse_findings_text(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """The one bounded parser of findings text, for the entry's own check and the worker's read: `(object, None)`
    for text of at most `FINDINGS_CAP_BYTES` that decodes (nesting checked before decoding,
    `load_json_artifact`) to a JSON object of exactly the two channels; else `(None, why)`, `why` one of
    `FINDINGS_OVER_CAP`, `FINDINGS_NOT_JSON`, `FINDINGS_NOT_AN_OBJECT`. The channels' rows are not looked at."""
    if findings_text_bytes(text) > FINDINGS_CAP_BYTES:
        return None, FINDINGS_OVER_CAP
    obj, unreadable = _io.load_json_artifact(text)
    if unreadable is not None:
        return None, FINDINGS_NOT_JSON
    if not isinstance(obj, dict) or set(obj) != set(FINDINGS_CHANNELS):
        return None, FINDINGS_NOT_AN_OBJECT
    return obj, None


def findings_of(found: object) -> tuple[dict[str, Any] | None, str | None]:
    """A completed end record's `findings` field (`LearningEnd.findings`, any JSON value) as the worker reads it:
    `(channels, None)` only for exactly `{"state": "ok", "text": <text>}` whose text `parse_findings_text` accepts;
    else `(None, why)`: `FINDINGS_ABSENT`, the state the entry recorded (`over_cap`, `unreadable`, `malformed`),
    `FINDINGS_NOT_A_FIELD` for any other value, or the parser's refusal."""
    if found is None:
        return None, FINDINGS_ABSENT
    if not isinstance(found, dict) or not isinstance(found.get("state"), str):
        return None, FINDINGS_NOT_A_FIELD
    state = found["state"]
    if state != FINDINGS_OK:
        return None, state if state in FINDINGS_STATES and set(found) == {"state"} else FINDINGS_NOT_A_FIELD
    if set(found) != {"state", "text"} or not isinstance(found["text"], str):
        return None, FINDINGS_NOT_A_FIELD
    return parse_findings_text(found["text"])


def findings_field(text: str | None) -> tuple[dict[str, Any], int]:
    """The end record's findings field for the findings `text` the entry built, and how many rows it holds (0 when it
    refuses them; the entry's own count, which only the job's message carries: the store's finish event names how many
    rows its end added), from one parse: `{"state": "ok", "text": text}` when `parse_findings_text` accepts it, the worker's own check run first;
    `over_cap` over the cap; `malformed` for any other refusal, or for `text` None (a held row that was not one)."""
    if text is None:
        return {"state": FINDINGS_MALFORMED}, 0
    channels, why = parse_findings_text(text)
    if channels is None:
        return {"state": FINDINGS_OVER_CAP if why == FINDINGS_OVER_CAP else FINDINGS_MALFORMED}, 0
    return {"state": FINDINGS_OK, "text": text}, sum(len(rows) for rows in channels.values() if isinstance(rows, list))


def unreadable_findings() -> dict[str, Any]:
    """The findings field of a completed end whose findings could not be read: `unreadable`, written first and kept
    unless the read succeeds."""
    return {"state": FINDINGS_UNREADABLE}


# -- host requests (#1471): the result records, their vocabulary and the knowledge record ---------------

#: A host-request record's outcomes besides an adoption's own (surface §5).
REFUSED, READY, FAILED = "refused", "ready", "failed"
#: A readiness refusal's steps (surface §5): P-1's sequence (`runs_folder` is machinery, never a step: R13-1.1), then
#: the container's tenant step and its systems step.
READINESS_STEPS = ("tenant", "records", "alert_mapping", "publish", "knowledge_copy", "run_tenant", "roster",
                   "tenant_verdict", "signing", "first_pass", "container_tenant", "systems")
#: The steps after `publish`: a refusal there carries the knowledge record's status, as `ready` does (R3, R13-1.5).
READINESS_STEPS_WITH_KNOWLEDGE = frozenset(READINESS_STEPS[READINESS_STEPS.index("publish") + 1:])


def is_readiness_step(step: object) -> bool:
    """Whether `step` is one of a readiness check's refusal steps (`READINESS_STEPS`)."""
    return isinstance(step, str) and step in READINESS_STEPS
#: A `ready` record's warning kinds (surface §5, R13-3): one warning per census finding line.
READINESS_WARNING_KINDS = ("case_system", "system_down", "grant_ignored", "verb_undecided", "verb_undeclared",
                           "tacit_registry", "tacit_grant", "feedback_setting", "retired_file")
#: A readiness `failed` record's reasons, by writer (R13-1.2, .3, R13-3). The worker judges the union: it cannot tell
#: the writers apart and need not.
READINESS_HELPER_REASONS = frozenset({"start_failed", WORKER_ERROR})
READINESS_CONTAINER_REASONS = frozenset({"census_unavailable", "handover"})
#: An adoption's outcomes (r11), and those that name a pull request by its number.
ADOPTION_OUTCOMES = ("opened", "already_open", "rejected", "nothing_to_adopt")
ADOPTION_OUTCOMES_WITH_NUMBER = frozenset({"opened", "already_open", "rejected"})
#: An adoption `failed` record's reasons, by writer (A3, R13-1.2, .3; surface §9 addenda).
ADOPTION_HELPER_REASONS = frozenset({"system_gone", "no_base_files", "tenant_not_active", "setup_refused",
                                     "start_failed", WORKER_ERROR})
ADOPTION_CONTAINER_REASONS = frozenset({"tenant_not_active", "repository_busy", "delivery_failed", "handover"})
#: The most text one readiness record holds, in UTF-8 bytes of the whole record (`findings_text_bytes`, R13-4): a
#: generous guess, as the findings cap is; over it the record is malformed. There is no per-sentence cap and no cap on the
#: number of warnings.
READINESS_RECORD_TEXT_CAP_BYTES = 1024 * 1024
#: An adoption record carries no free text: a bound on what is read of one, far above any record of its shapes.
_ADOPTION_RECORD_CAP_BYTES = 4096

_READINESS_FIELDS = {REFUSED: frozenset({"outcome", "step", "sentence"}), READY: frozenset({"outcome", "warnings"}),
                     FAILED: frozenset({"outcome", "reason"})}
_WARNING_FIELDS = frozenset({"kind", "sentence"})


def _holds_sentence(value: object) -> bool:
    """A record's sentence: text with something in it that PostgreSQL text can hold. Kept as written (D7)."""
    return isinstance(value, str) and bool(value.strip()) and postgres_can_hold(value)


class MalformedRecord:
    """A host-request record that is present but not one its writers write (`JobLane.read_readiness`,
    `read_adoption`): not of its shape, not readable text, or over its cap. One value, `MALFORMED`."""

    def __repr__(self) -> str:
        return "MALFORMED"


MALFORMED = MalformedRecord()


@dataclass(frozen=True)
class ReadinessWarning:
    """One warning of a `ready` readiness record: a closed kind and its sentence."""

    kind: str
    sentence: str

    def __post_init__(self) -> None:
        if not (isinstance(self.kind, str) and self.kind in READINESS_WARNING_KINDS and _holds_sentence(self.sentence)):
            raise ValueError(f"not a readiness warning: {self!r}")


@dataclass(frozen=True)
class ReadinessRecord:
    """A readiness check's result record (`<runs>/<request id>.readiness.json`, R13-1): exactly one of
    `refused {outcome, step, sentence}`, `ready {outcome, warnings}` or `failed {outcome, reason}`, each the JSON field
    of its name. It carries no knowledge and no commit: the worker reads those from the knowledge record. Build one
    with `refused`, `ready` or `failed`."""

    outcome: str
    step: str | None = None
    sentence: str | None = None
    warnings: tuple[ReadinessWarning, ...] | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self._holds():
            raise ValueError(f"not a readiness record: {self!r}")

    @property
    def is_failed(self) -> bool:
        return self.outcome == FAILED

    @property
    def is_refused(self) -> bool:
        return self.outcome == REFUSED

    @property
    def is_ready(self) -> bool:
        return self.outcome == READY

    def _holds(self) -> bool:
        if self.outcome == REFUSED:
            return (self.warnings is None and self.reason is None and isinstance(self.step, str)
                    and self.step in READINESS_STEPS and _holds_sentence(self.sentence))
        if self.outcome == READY:
            return (self.step is None and self.sentence is None and self.reason is None
                    and isinstance(self.warnings, tuple) and all(isinstance(w, ReadinessWarning) for w in self.warnings))
        return (self.outcome == FAILED and self.step is None and self.sentence is None and self.warnings is None
                and isinstance(self.reason, str) and self.reason in READINESS_HELPER_REASONS | READINESS_CONTAINER_REASONS)

    @classmethod
    def refused(cls, step: str, sentence: str) -> ReadinessRecord:
        return cls(REFUSED, step=step, sentence=sentence)

    @classmethod
    def ready(cls, warnings: Iterable[ReadinessWarning] = ()) -> ReadinessRecord:
        return cls(READY, warnings=tuple(warnings))

    @classmethod
    def failed(cls, reason: str) -> ReadinessRecord:
        return cls(FAILED, reason=reason)

    def body(self) -> dict[str, Any]:
        """The record's JSON object: its variant's fields only."""
        if self.outcome == REFUSED:
            return {"outcome": self.outcome, "step": self.step, "sentence": self.sentence}
        if self.outcome == READY:
            return {"outcome": self.outcome,
                    "warnings": [{"kind": w.kind, "sentence": w.sentence} for w in self.warnings or ()]}
        return {"outcome": self.outcome, "reason": self.reason}

    def text(self) -> str:
        return json.dumps(self.body())

    @classmethod
    def parse(cls, text: str) -> ReadinessRecord | None:
        """The record `text` holds, or `None` when it is not one of the three shapes exactly (every field of its
        variant and no other, a known step, kind or reason, a sentence with text in it), or its whole text is over
        `READINESS_RECORD_TEXT_CAP_BYTES` (R13-4)."""
        if findings_text_bytes(text) > READINESS_RECORD_TEXT_CAP_BYTES:
            return None
        obj, unreadable = _io.load_json_artifact(text)
        if unreadable is not None or not isinstance(obj, dict):
            return None
        outcome = obj.get("outcome")
        if not isinstance(outcome, str) or _READINESS_FIELDS.get(outcome) != set(obj):
            return None
        try:
            if outcome == READY:
                return cls.ready(_warnings(obj["warnings"]))
            return cls(outcome, step=obj.get("step"), sentence=obj.get("sentence"), reason=obj.get("reason"))
        except (TypeError, ValueError):
            return None


def _warnings(raw: object) -> list[ReadinessWarning]:
    """A `ready` record's warnings, in order; `ValueError` for anything but a list of exact `{kind, sentence}`."""
    if not isinstance(raw, list) or not all(isinstance(w, dict) and set(w) == _WARNING_FIELDS for w in raw):
        raise ValueError("not a list of warnings")
    return [ReadinessWarning(kind=w["kind"], sentence=w["sentence"]) for w in raw]


@dataclass(frozen=True)
class AdoptionRecord:
    """An adoption's result record (`<runs>/<request id>.adoption.json`, A3, R13-1): `{outcome, pr_number}` for one of
    `ADOPTION_OUTCOMES`, the number a positive integer exactly for `opened`, `already_open` and `rejected` and null
    otherwise; or `failed {outcome, reason}`. Each the JSON field of its name; there is no `refused` shape."""

    outcome: str
    pr_number: int | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self._holds():
            raise ValueError(f"not an adoption record: {self!r}")

    @property
    def is_failed(self) -> bool:
        return self.outcome == FAILED

    def _holds(self) -> bool:
        if self.outcome == FAILED:
            return (self.pr_number is None and isinstance(self.reason, str)
                    and self.reason in ADOPTION_HELPER_REASONS | ADOPTION_CONTAINER_REASONS)
        if self.reason is not None or self.outcome not in ADOPTION_OUTCOMES:
            return False
        if self.outcome not in ADOPTION_OUTCOMES_WITH_NUMBER:
            return self.pr_number is None
        number = self.pr_number
        return isinstance(number, int) and not isinstance(number, bool) and number > 0

    @classmethod
    def failed(cls, reason: str) -> AdoptionRecord:
        return cls(FAILED, reason=reason)

    def body(self) -> dict[str, Any]:
        """The record's JSON object: its variant's fields only."""
        if self.outcome == FAILED:
            return {"outcome": self.outcome, "reason": self.reason}
        return {"outcome": self.outcome, "pr_number": self.pr_number}

    def text(self) -> str:
        return json.dumps(self.body())

    @classmethod
    def parse(cls, text: str) -> AdoptionRecord | None:
        """The record `text` holds, or `None` when it is not one of its shapes exactly."""
        if findings_text_bytes(text) > _ADOPTION_RECORD_CAP_BYTES:
            return None
        obj, unreadable = _io.load_json_artifact(text)
        if unreadable is not None or not isinstance(obj, dict):
            return None
        fields = {"outcome", "reason"} if obj.get("outcome") == FAILED else {"outcome", "pr_number"}
        if set(obj) != fields or not isinstance(obj["outcome"], str):
            return None
        try:
            return cls(obj["outcome"], pr_number=obj.get("pr_number"), reason=obj.get("reason"))
        except (TypeError, ValueError):
            return None


class _HostRecorded(Protocol):
    """What the knowledge record is written from: a `tenancy.run_knowledge.KnowledgeSource` (records sits below
    tenancy, so the type is not named)."""

    def host_record(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class RequestKnowledge:
    """A host request's knowledge record as the worker reads it (`JobLane.read_request_knowledge`, R13-1.5): one of
    `RequestKnowledge.ABSENT`, `RequestKnowledge.MALFORMED` (present, but no knowledge status), or a present status,
    whose `knowledge` is its `api_knowledge` shape. Unlike `JobLane.knowledge`, an absent record is not read as stale."""

    knowledge: dict[str, str | None] | None
    state: str = "present"

    ABSENT: ClassVar[RequestKnowledge]
    MALFORMED: ClassVar[RequestKnowledge]


RequestKnowledge.ABSENT = RequestKnowledge(None, "absent")
RequestKnowledge.MALFORMED = RequestKnowledge(None, "malformed")


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
        """`<data root>/<tenant_id>/runs`, held no-follow from the tenant's folder. Never made: the host's `prepare`
        step makes it with the tenant (#1471 R13-0), and a missing one is damage, refused. The tenant is not accepted
        here: only its id's grammar is judged."""
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

    # -- a learning job's two records (#1344) ------------------------------------------------------

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

    # -- a host request's records (#1471) ----------------------------------------------------------

    def write_readiness(self, request_id: object, record: ReadinessRecord) -> None:
        """A readiness check's result record, create-only: one already there is `FileExistsError` and is kept."""
        self._held.write(self._paths(_run_id(request_id)).readiness_record().name, record.text(), mode="create")

    def read_readiness(self, request_id: object) -> ReadinessRecord | MalformedRecord | None:
        """A readiness check's result record: `None` when nothing is at its name, `MALFORMED` when something is that is
        not a readable record of its shapes within its cap (R13-4), else the record."""
        return self._host_record(self._paths(_run_id(request_id)).readiness_record().name,
                                 READINESS_RECORD_TEXT_CAP_BYTES, ReadinessRecord.parse)

    def write_adoption(self, request_id: object, record: AdoptionRecord) -> None:
        """An adoption's result record, create-only: one already there is `FileExistsError` and is kept."""
        self._held.write(self._paths(_run_id(request_id)).adoption_record().name, record.text(), mode="create")

    def read_adoption(self, request_id: object) -> AdoptionRecord | MalformedRecord | None:
        """An adoption's result record, read as `read_readiness` reads its own."""
        return self._host_record(self._paths(_run_id(request_id)).adoption_record().name,
                                 _ADOPTION_RECORD_CAP_BYTES, AdoptionRecord.parse)

    def _host_record(self, name: str, cap: int, parse: Any) -> Any:
        """One host-request record, no-follow, at most `cap` bytes plus one taken off the file (so one over its cap is
        seen over it and refused): absent `None`, anything unreadable or refused by `parse` `MALFORMED`."""
        read = self._held.view().read(name, max_bytes=cap + 1)
        if read.text is None:
            return None if read.absent else MALFORMED
        found = parse(read.text)
        return MALFORMED if found is None else found

    def write_request_knowledge(self, request_id: object, source: _HostRecorded) -> None:
        """A readiness check's knowledge record (R13-1.2): the source its publish step gave, in the host record's
        format (`tenancy.run_knowledge.write_host_record`), at `<request id>.knowledge-source.json`, create-only."""
        text = json.dumps(source.host_record(), indent=2, sort_keys=True) + "\n"
        self._held.write(self._paths(_run_id(request_id)).knowledge_source().name, text, mode="create")

    def read_request_knowledge(self, request_id: object) -> RequestKnowledge:
        """A host request's knowledge record, with no run-started gate (R13-1.5): `RequestKnowledge.ABSENT` when nothing
        is at its name, `MALFORMED` when what is there is not a knowledge status (or is a pinned one), else its status in
        the API's shape."""
        read = self._held.view().read(self._paths(_run_id(request_id)).knowledge_source().name)
        if read.text is None:
            return RequestKnowledge.ABSENT if read.absent else RequestKnowledge.MALFORMED
        status = _record_status(read.text)
        # A request's knowledge is never pinned: its helper publishes (surface §2), so a pinned status is no record of it.
        if status is None or status.kind == PINNED:
            return RequestKnowledge.MALFORMED
        return RequestKnowledge(api_knowledge(status))

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

    def closing_disposition(self, run_id: object) -> Any:
        """The run's closing record through the job-lane route (#1534): the pointer read through the held view, then
        the closing lookup's own `from_pointer`, which the run-handle route uses too, with this lane's rule for the
        database: derived from the pointer's case id, never its stored path. Returns `closing.Record | NeverClosed | CouldNotLook`."""
        from defender.records import closing
        from defender.records.session_store import _LEGACY_LINK_NAME

        run_id = _run_id(run_id)
        view = self._held.view()
        where = self._paths(run_id).session_pointer()
        return closing.from_pointer(
            view.read(where.name), where=str(where), run_id=str(run_id),
            locate=lambda pointer: SessionPaths(RunsBase(self._runs)).session_db(pointer.case_id),
            legacy_link=lambda: not view.read(PurePosixPath(str(run_id)) / _LEGACY_LINK_NAME).absent)

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
        from defender.records import session_store

        try:
            pointer = session_store.parse_case_pointer(read.text)
            database = SessionPaths(RunsBase(self._runs)).session_db(pointer.case_id)
        except StoreError as bad:
            raise CostUnreadable(f"run {run_id}: its session pointer {bad}") from None
        return database, pointer.session_id

    def cost(self, run_id: object) -> RunCost:
        """What the run spent: the sum of the spend ledger's rows for this run id in the database
        its pointer names (#1377), each priced from the pricing table. Rows of another run in the
        same database (a branch arm's source, a sibling) are not counted; no conversation is read.
        It is `session_store.read_ledger`, the one read the run file and the page use too.
        No pointer: exactly 0 (the store was never opened, so no model request was made), a different
        case from a ledger that exists and is not sealed. `CostUnreadable` for a pointer or database
        that cannot be read, a database without the ledger, or a pointer naming a session the
        database lacks."""
        run_id = _run_id(run_id)
        located = self.session_database(run_id)
        if located is None:
            return RunCost(0.0, complete=True)
        database, session_id = located
        from defender.records import session_store

        try:
            with session_store.open_store_for_read(database) as store:
                main = session_id if session_id is not None else session_store.main_session_id(store)
                if not session_store.has_session(store, main):
                    raise CostUnreadable(f"run {run_id}: its main session {main} is not in {database}")
                read = session_store.read_ledger(store, str(run_id))
                return RunCost(read.total, complete=read.complete)
        except CostUnreadable:
            raise
        except (OSError, sqlite3.Error, StoreError, ValueError) as fault:
            raise CostUnreadable(f"run {run_id}: its session database {database} cannot be read: "
                                 f"{fault!r}") from None


def sibling_cost(store: object, run_id: str) -> float:
    """What one sibling cost (#1344 O13, #1377 r7.5 L1): its own spend ledger's total, from the one
    ledger read, so every agent of the sibling run counts, priced at the model it was built to
    request. The source run's rows and every other sibling's belong to other run ids, an inherited
    conversation prefix made no request, and the questioner, oracle and judge write no ledger row.
    Not marked when the ledger is not complete (r7.5 L2). `store` is an open session store; a
    ledger that cannot be read is `CostUnreadable`."""
    from defender.records import session_store

    try:
        return session_store.read_ledger(store, run_id).total
    except (OSError, sqlite3.Error, StoreError, ValueError) as fault:
        raise CostUnreadable(f"run {run_id}: its spend ledger cannot be read: {fault!r}") from None
