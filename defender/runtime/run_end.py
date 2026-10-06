"""How a run ended: the exit-class vocabulary, its one normalizer, and the host-side record.

The vocabulary: `truncated_by` holds every value any writer of the session store's column
may use (the driver on the main session, the gather dispatch on a lead's), spelled one way for
every reader. `dead-end` is lead-only: it covers all host guards (the repeat guard, the
above-guard repeat guard, the rejection budget); which one fired is recovered from the last
trip row's `payload_digest`, whose phrases `record_query.repeat_trip_detail` and
`record_query.rejection_detail` own. Defined here rather than in `session_store` so the ticket
lane and family judge need not import SQLite or the agent framework.

The record: a main run's exit class plus whether the model had already closed when it was
stamped, so a model verdict is distinguishable from a host-forced one. `truncated_by: None`
means "not cut short", not absence.

The record is a sidecar beside the run dir (like `scrub.verdict_path`), never inside it: the
box has an rw bind on the run dir, and `validate_report` admits unknown keys, so a planted
`truncated_by:` in report.md could let a graded run exclude itself from grading.

Written by the driver before the forced report write; consumed in-process by `run.py`'s
`--update-ticket` step and on disk by the family judge via the archive copy and
`parse_record`.
"""
from __future__ import annotations

import json
from defender._model import model
from pathlib import Path
from typing import Any

from defender._io import write_guarded
from defender.run_repository import RunPaths

TRUNCATED_BY_REQUEST_LIMIT = "request-limit"
TRUNCATED_BY_RETRY_EXHAUSTED = "retry-exhausted"
TRUNCATED_BY_ABORTED = "aborted"
TRUNCATED_BY_BUDGET = "budget"
TRUNCATED_BY_STORE = "store"
TRUNCATED_BY_DEAD_END = "dead-end"
TRUNCATED_BY_VALUES = (
    TRUNCATED_BY_REQUEST_LIMIT, TRUNCATED_BY_RETRY_EXHAUSTED, TRUNCATED_BY_ABORTED,
    TRUNCATED_BY_BUDGET, TRUNCATED_BY_STORE, TRUNCATED_BY_DEAD_END,
)

#: Exits where the model spent its budget without closing, so the host writes an `unresolved`
#: report (otherwise the run dead-letters for a missing report.md). Shared by the driver's
#: forced close and the ticket lane, so a failed forced close still escalates. The driver
#: explains why the breaker, budget kill and store exits are absent.
FORCED_CLOSE_EXITS = frozenset({TRUNCATED_BY_REQUEST_LIMIT, TRUNCATED_BY_RETRY_EXHAUSTED})


def normalized_truncated_by(value: object) -> str | None:
    """A `truncated_by` value if it is a `TRUNCATED_BY_VALUES` member, else `None`. Every
    reader uses this so they all refuse the same values.

    Strict (unlike `_vocab.normalized_disposition`): no strip or case fold, since the only
    producer is the driver's own constrained stamp. `None` ("not cut short") maps to `None`.
    """
    if not isinstance(value, str):
        return None
    return value if value in TRUNCATED_BY_VALUES else None


@model(frozen=True)
class RunEnd:
    """How one MAIN run ended: its exit class (`None` when it ended cleanly) and whether the
    model had already closed when that exit was stamped."""

    truncated_by: str | None
    closed_before_cut: bool

    def doc(self) -> dict[str, Any]:
        """The record's JSON document."""
        return {"truncated_by": self.truncated_by, "closed_before_cut": self.closed_before_cut}


def sidecar_path(run_dir: Path) -> Path:
    """The host-side run-end record's path, beside `run_dir`. A pure function of the path so
    no box-writable content influences it.
    """
    run_dir = Path(run_dir)
    return RunPaths(run_dir).run_end_sidecar(run_dir.parent)


def write_sidecar(run_dir: Path, record: RunEnd) -> None:
    """Write the sidecar beside `run_dir`. Written for every run reaching the agent loop,
    clean ones included, so "not cut short" differs from "the host never said". Atomically
    replaces a stale sidecar.
    """
    write_guarded(sidecar_path(run_dir), json.dumps(record.doc()))


def parse_record(doc: object) -> RunEnd | None:
    """The record a parsed JSON document holds, or `None`.

    Strict: both fields required, `truncated_by` null or a vocabulary member,
    `closed_before_cut` a real bool. Anything else reads as no record, so a corrupted file
    fails toward "the host said nothing", never toward a verdict. Extra keys are ignored.
    """
    if not isinstance(doc, dict) or {"truncated_by", "closed_before_cut"} - set(doc):
        return None
    truncated_by, closed = doc["truncated_by"], doc["closed_before_cut"]
    if truncated_by is not None and normalized_truncated_by(truncated_by) is None:
        return None
    if not isinstance(closed, bool):
        return None
    return RunEnd(truncated_by, closed)


__all__ = [
    "FORCED_CLOSE_EXITS",
    "TRUNCATED_BY_ABORTED",
    "TRUNCATED_BY_BUDGET",
    "TRUNCATED_BY_DEAD_END",
    "TRUNCATED_BY_REQUEST_LIMIT",
    "TRUNCATED_BY_RETRY_EXHAUSTED",
    "TRUNCATED_BY_STORE",
    "TRUNCATED_BY_VALUES",
    "RunEnd",
    "normalized_truncated_by",
    "parse_record",
    "sidecar_path",
    "write_sidecar",
]
