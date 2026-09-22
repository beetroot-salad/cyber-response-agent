"""How a run ended: the exit-class vocabulary, its one normalizer, and the host-side record.

THE VOCABULARY. `truncated_by` is every value any writer of the session store's column may
put in it. Two writers (the driver's run-end flush on the MAIN session, the gather dispatch's
terminator stamp on a lead's) spelling the same shape differently would make "was this cut
off, and by what" a per-session-kind question for every reader joining `session` rows.
`dead-end` is the only value with no main-session analogue: only a lead can be stopped by a
host guard, and since #1015 there are THREE of them — `wrap_tool_execute`'s repeat guard, the
above-guard repeat guard, and the rejection budget. All three stamp this one value: the
terminator column says a HOST guard ended the lead, and WHICH of them is recovered from the
last trip row's `payload_digest` (the queries table has no `detail` column —
`QueryCapture._record` folds the detail into that digest behind an `exit={code}; ` prefix),
not from a second stamp. Which row that is depends on the guard: `wrap_tool_execute`'s writes
a `REPEAT_TRIP_QUERY_ID` row whose phrase `record_query.repeat_trip_detail` owns, the two
above-guard guards write an ordinary `ABOVE_GUARD_QUERY_ID` row whose phrase
`record_query.rejection_detail` owns.

It lives HERE rather than in `session_store` because its readers are not all store readers:
the ticket lane (`scripts/case_history/ticket_writer.py`) and the family judge key on the
exit class and have no business importing the SQLite store — or, through it, the agent
framework. `session_store` re-exports the names so the column's own writers are unchanged.

THE RECORD (#1047). The exit class of a MAIN run, plus whether the model had already closed
(`challenge_gate.ReviewState.of(deps).closed`) when the exit was stamped — without the second
field a genuine model verdict is indistinguishable from one the host manufactured. `None` for
`truncated_by` is valid CONTENT ("the run was not cut short"), not absence.

**Why a sidecar and not a file inside the run dir.** The design's first draft put the exit
class in the forced `report.md`'s frontmatter; the cold review refuted it — `validate_report`
admits an unknown key, and the judge reads the archived COPY of a file the box had an rw bind
on, so a planted `truncated_by:` line would have let the graded subject exclude its own world
from grading. The sidecar lives BESIDE the run dir, at a path derived from the run dir's own
name — `scrub.verdict_path`'s shape — on a path no box's rw bind ever reaches.

One writer, the driver (`runtime/driver/__init__.py`, before the forced report write). One
in-process consumer, `run.py`'s `--update-ticket` step, which takes both fields off the
driver's own summary and reads nothing off disk. One on-disk consumer, the family judge,
which reads the archive's copy (`worlds/<label>/run_end.json` — the archive copies the
sidecar exactly as it copies the scrub verdict, never anything inside the run dir) through
`parse_record`.
"""
from __future__ import annotations

import json
from defender._model import model
from pathlib import Path
from typing import Any

from defender._io import write_guarded
from defender._run_paths import RunPaths

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

#: The exits on which the MODEL was stopped before it could close and the run still says
#: something about the CASE — the request ceiling and the tool-retry budget: the model spent
#: what it had and settled nothing, which is what `unresolved` records. Each ends with no
#: report.md unless the host writes one, and a run with no report.md dead-letters at persist
#: for a missing artifact. Two readers key on this ONE set: the driver's forced close and the
#: ticket lane's "close off the host's forced report" arm — so a forced-close exit whose own
#: forced close failed (no report.md) still takes the escalation arm, never the report-driven
#: fallback. See the driver for why the breaker, the budget kill and the store arm are absent.
FORCED_CLOSE_EXITS = frozenset({TRUNCATED_BY_REQUEST_LIMIT, TRUNCATED_BY_RETRY_EXHAUSTED})


def normalized_truncated_by(value: object) -> str | None:
    """A `truncated_by` value as it RENDERS — a `TRUNCATED_BY_VALUES` member — or `None`.

    THE single answer to what an exit-class value means, for every reader downstream of the
    driver's own stamp (#1047): the family judge (through `parse_record`) and the ticket lane
    call this instead of writing their own membership test, so a value one of them refuses is
    refused identically by the other (`test_every_reader_of_the_exit_class_takes_the_owners_answer`).

    STRICT (fork F-M, deliberately unlike `_vocab.normalized_disposition`): no whitespace
    strip, no case fold, no confusable fold. The only legitimate producer of this value is the
    driver's own stamp, constrained to `TRUNCATED_BY_VALUES` at every call site — no real
    source of a variant spelling exists, so leniency here would only open a coercion path a
    future, less careful producer could lean on. `None` in, `None` out: "no exit class" is a
    real domain member (the run was not cut short), not a rejection.
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
        """The record's document — both fields, spelled once for the writer and the fixtures."""
        return {"truncated_by": self.truncated_by, "closed_before_cut": self.closed_before_cut}


def sidecar_path(run_dir: Path) -> Path:
    """The host-side run-end record's path — beside `run_dir`, never inside it.

    A pure function of a path the host already holds, exactly like `scrub.verdict_path`: the
    whole security argument is that no box-writable content is an input to this path.
    """
    run_dir = Path(run_dir)
    return RunPaths(run_dir).run_end_sidecar(run_dir.parent)


def write_sidecar(run_dir: Path, record: RunEnd) -> None:
    """Write the host-side sidecar beside `run_dir`. UNCONDITIONAL for every run that reaches
    the agent loop — a clean run writes `{"truncated_by": null, "closed_before_cut": false}`,
    not nothing, so "not cut short" and "the host never got to say" stay two different states.

    Through `write_guarded`'s `replace` mode, the same seam every other shared-tree write in
    this codebase uses — a stale sidecar from a retried run is atomically replaced, never
    appended to or read-modified.
    """
    write_guarded(sidecar_path(run_dir), json.dumps(record.doc()))


def parse_record(doc: object) -> RunEnd | None:
    """The record a parsed JSON document holds, or `None` when it holds no record.

    STRICT AS A WHOLE, because the record has exactly one shape and one writer: a mapping
    carrying both fields, `truncated_by` either `null` or a vocabulary member (the owner's
    answer, `normalized_truncated_by`), `closed_before_cut` a real boolean. Anything else —
    a list, a missing field, an unrecognized or padded exit class, `"false"` for a boolean —
    is NOT a record, and reads as the absent one rather than as "this run was not cut short"
    or "the model had closed": a corrupted or hand-edited file must fail toward "the host
    said nothing" and never toward a verdict. Extra keys are ignored; only the two named ones
    are ever looked at, so a row-shaped key (`ungradable`, `verdict`) in the document reaches
    nothing.
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
