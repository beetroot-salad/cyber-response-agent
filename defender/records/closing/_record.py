"""The closing record and its two entry types (#1534 V-FIELDS, V-TEXT).

Each holds treated text only: a model-text field is `treat`ed to its bound when the value is
built, so a record read back equals the one written (the treatment is a fixed point). Host
fields are values from closed vocabularies, and a combination outside the per-outcome
invariant cannot be built (`ValueError`)."""
from __future__ import annotations

import datetime as dt
import unicodedata
from typing import Any

from pydantic import model_validator

from defender import _clock
from defender._model import model, unwrap_before
from defender._vocab import DISPOSITION_VALUES, HOST_ONLY_DISPOSITION

from ._treat import treat
from ._vocab import (
    ANCHOR_ID_BOUND, ANCHOR_KINDS, BASELINE_LINES_BOUND, CAUSE_CEILING_EXAMINED,
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_NOT_REVIEWED, CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_REVIEW_INCOMPLETE, CAUSE_STORY_SETTLED, CAUSE_TURN_BUDGET_SPENT, CAUSES,
    CEILING_COUNT_CAP, CEILING_LINES_BOUND, CEILING_STATES, FAILURE_KINDS, FORCED_INCONCLUSIVE,
    GROUNDING_KINDS, LEAD_BOUND, NOTE_BOUND, OUTCOMES, REASONING_BOUND, RESULT_BOUND, STANDS,
    SUMMARY_BOUND, grounding_acceptable,
)

#: The cause a `stands` record carries, by disposition (any other: `CAUSE_STORY_SETTLED`).
_STANDING_CAUSE = {HOST_ONLY_DISPOSITION: CAUSE_NOT_REVIEWED, "inconclusive": CAUSE_CEILING_EXAMINED}
#: The causes a `forced-inconclusive` record carries without a failure kind.
_OVERRULE_CAUSES = frozenset({
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_TURN_BUDGET_SPENT, CAUSE_NOTHING_LEFT_TO_ASK})


def _treated(given: Any, bounds: dict[str, int]) -> Any:
    """`given` (a field-name dict) with each bounded text field treated to its bound; anything
    that is not a `str` is left for the field's own validation to refuse."""
    if not isinstance(given, dict):
        return given
    return {k: treat(v, bounds[k]) if k in bounds and isinstance(v, str) else v for k, v in given.items()}


def _refuse_control(name: str, value: str | None) -> None:
    """A host-checked value is one line of visible text: a category C character is refused."""
    if value is not None and any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ValueError(f"{name} {value!r} carries a control or invisible character")


def canonical_instant(value: dt.datetime | str) -> str:
    """An instant as ISO-8601 UTC with `Z`, with six-digit microseconds when they are non-zero.
    A string is parsed first (a naive one is UTC); one that does not parse is a `ValueError`."""
    instant = value if isinstance(value, dt.datetime) else _clock.parse_iso_utc(value)
    if instant is None:
        raise ValueError(f"{value!r} is not an ISO-8601 instant")
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=dt.UTC)
    utc = instant.astimezone(dt.UTC)
    fraction = f".{utc.microsecond:06d}" if utc.microsecond else ""
    return f"{utc:%Y-%m-%dT%H:%M:%S}{fraction}Z"


@model(frozen=True)
class CeilingEntry:
    """One ceiling receipt: `state` from `CEILING_STATES`, the host-checked `ref` (a lead id) or
    `cap` (a capability), and the model's `note`."""

    state: str
    ref: str | None
    cap: str | None
    note: str

    @model_validator(mode="before")
    @classmethod
    def _treat_text(cls, value: Any) -> Any:
        return _treated(unwrap_before(cls, value), {"note": NOTE_BOUND})

    def __post_init__(self) -> None:
        if self.state not in CEILING_STATES:
            raise ValueError(f"ceiling state {self.state!r} is not one of {CEILING_STATES}")
        _refuse_control("ref", self.ref)
        _refuse_control("cap", self.cap)


@model(frozen=True)
class BaselineEntry:
    """One `:R consultations` baseline: canonical anchor and grounding kinds, the window as
    canonical instants (`window_start`/`window_end`), and the model's `lead`, `anchor_id`,
    `result` and `reasoning`."""

    lead: str
    anchor_kind: str
    grounding_kind: str
    anchor_id: str
    window_start: str
    window_end: str
    result: str
    reasoning: str

    @model_validator(mode="before")
    @classmethod
    def _treat_text(cls, value: Any) -> Any:
        given = _treated(unwrap_before(cls, value), {
            "lead": LEAD_BOUND, "anchor_id": ANCHOR_ID_BOUND, "result": RESULT_BOUND,
            "reasoning": REASONING_BOUND})
        if isinstance(given, dict):
            for end in ("window_start", "window_end"):
                if isinstance(given.get(end), (str, dt.datetime)):
                    given[end] = canonical_instant(given[end])
        return given

    def __post_init__(self) -> None:
        if self.anchor_kind not in ANCHOR_KINDS:
            raise ValueError(f"anchor kind {self.anchor_kind!r} is not one of {ANCHOR_KINDS}")
        if not grounding_acceptable(self.grounding_kind):
            raise ValueError(f"grounding kind {self.grounding_kind!r} is not one of {GROUNDING_KINDS}, nor empty")


def ceiling_line(entry: CeilingEntry) -> str:
    """The receipt's one line: `ceiling_test (<state>, <ref or cap>): <note>`; a receipt with no
    note renders without the `: <note>` part."""
    return ceiling_line_of(state=entry.state, ref=entry.ref, cap=entry.cap, note=entry.note)


def ceiling_line_of(*, state: str, ref: str | None, cap: str | None, note: str) -> str:
    """`ceiling_line` over a receipt's parts, for a gate measuring rows not yet checked."""
    target = ref if ref is not None else cap
    head = f"ceiling_test ({state}, {target})" if target is not None else f"ceiling_test ({state})"
    return f"{head}: {note}" if note else head


def baseline_line(entry: BaselineEntry) -> str:
    """The baseline's one line: `<anchor kind> (<grounding>, <anchor id>, <lead>, <start>/<end>):
    <result>`, then ` — <reasoning>` when there is reasoning."""
    return baseline_line_of(
        lead=entry.lead, anchor_kind=entry.anchor_kind, grounding_kind=entry.grounding_kind,
        anchor_id=entry.anchor_id, window=f"{entry.window_start}/{entry.window_end}", result=entry.result,
        reasoning=entry.reasoning)


def baseline_line_of(*, lead: str, anchor_kind: str, grounding_kind: str, anchor_id: str, window: str,  # noqa: PLR0913 — the line's parts
                     result: str, reasoning: str) -> str:
    """`baseline_line` over a baseline's parts, for a gate measuring rows not yet checked."""
    line = f"{anchor_kind} ({grounding_kind}, {anchor_id}, {lead}, {window}): {result}"
    return f"{line} — {reasoning}" if reasoning else line


def ceiling_lines_length(entries: tuple[CeilingEntry, ...]) -> int:
    """Characters of every receipt's line, joined by `\\n`: what `CEILING_LINES_BOUND` bounds."""
    return len("\n".join(ceiling_line(e) for e in entries))


def baseline_lines_length(entries: tuple[BaselineEntry, ...]) -> int:
    """Characters of every baseline's line, joined by `\\n`: what `BASELINE_LINES_BOUND` bounds."""
    return len("\n".join(baseline_line(e) for e in entries))


def entry_lines(record: ClosingRecord, *, noted_only: bool) -> list[str]:
    """The record's entry lines: ceiling lines, then baseline lines. `noted_only` keeps only the
    ceiling receipts that carry a note (the ticket narrative); the judge renders every one."""
    ceiling = [ceiling_line(e) for e in record.ceiling_test if e.note or not noted_only]
    return [*ceiling, *(baseline_line(e) for e in record.runtime_evidence)]


@model(frozen=True)
class ClosingRecord:
    """One closed run's record: host-chosen values, the structured entries, and the summary.

    Invariant, per outcome: `stands` has no draft and no failure kind, with cause
    `not reviewed` exactly for `unresolved`, `ceiling examined` exactly for `inconclusive`, else
    `story settled`; `forced-inconclusive` is `unresolved` with a draft from the other
    dispositions, cause `review incomplete` exactly when there is a failure kind, else one of the
    three overrule causes. An `unresolved` record carries a summary (its opener at least)."""

    run_id: str
    disposition: str
    outcome: str
    cause: str
    failure_kind: str | None
    drafted_disposition: str | None
    ceiling_test: tuple[CeilingEntry, ...]
    runtime_evidence: tuple[BaselineEntry, ...]
    summary: str | None

    @model_validator(mode="before")
    @classmethod
    def _treat_text(cls, value: Any) -> Any:
        given = _treated(unwrap_before(cls, value), {"summary": SUMMARY_BOUND})
        if isinstance(given, dict) and given.get("summary") == "":
            given["summary"] = None
        return given

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("a closing record names its run")
        _refuse_control("run_id", self.run_id)
        self._check_vocabularies()
        self._check_invariant()
        if self.disposition == HOST_ONLY_DISPOSITION and self.summary is None:
            raise ValueError("an unresolved record carries a summary (its opener at least)")
        if len(self.ceiling_test) > CEILING_COUNT_CAP:
            raise ValueError(f"{len(self.ceiling_test)} ceiling receipts, over the cap of {CEILING_COUNT_CAP}")
        if (n := ceiling_lines_length(self.ceiling_test)) > CEILING_LINES_BOUND:
            raise ValueError(f"the ceiling lines are {n} characters, over {CEILING_LINES_BOUND}")
        if (n := baseline_lines_length(self.runtime_evidence)) > BASELINE_LINES_BOUND:
            raise ValueError(f"the baseline lines are {n} characters, over {BASELINE_LINES_BOUND}")

    def _check_vocabularies(self) -> None:
        for name, value, allowed in (
            ("disposition", self.disposition, DISPOSITION_VALUES), ("outcome", self.outcome, OUTCOMES),
            ("cause", self.cause, CAUSES),
        ):
            if value not in allowed:
                raise ValueError(f"{name} {value!r} is not one of {allowed}")
        if self.failure_kind is not None and self.failure_kind not in FAILURE_KINDS:
            raise ValueError(f"failure_kind {self.failure_kind!r} is not one of {FAILURE_KINDS}")
        if self.drafted_disposition is not None and self.drafted_disposition not in DISPOSITION_VALUES:
            raise ValueError(f"drafted_disposition {self.drafted_disposition!r} is not one of {DISPOSITION_VALUES}")

    def _check_invariant(self) -> None:
        if self.outcome == STANDS:
            want = _STANDING_CAUSE.get(self.disposition, CAUSE_STORY_SETTLED)
            if self.drafted_disposition is not None or self.failure_kind is not None or self.cause != want:
                raise ValueError(
                    f"a {STANDS} {self.disposition} record has no draft, no failure kind and the cause "
                    f"{want!r} (got draft {self.drafted_disposition!r}, failure kind "
                    f"{self.failure_kind!r}, cause {self.cause!r})")
            return
        assert self.outcome == FORCED_INCONCLUSIVE
        if self.disposition != HOST_ONLY_DISPOSITION:
            raise ValueError(f"a {FORCED_INCONCLUSIVE} record commits {HOST_ONLY_DISPOSITION!r}, "
                             f"not {self.disposition!r}")
        if self.drafted_disposition in (None, HOST_ONLY_DISPOSITION):
            raise ValueError(f"a {FORCED_INCONCLUSIVE} record names the model's drafted disposition "
                             f"(got {self.drafted_disposition!r})")
        if self.cause == CAUSE_REVIEW_INCOMPLETE:
            if self.failure_kind is None:
                raise ValueError(f"cause {CAUSE_REVIEW_INCOMPLETE!r} names how the review failed")
        elif self.cause not in _OVERRULE_CAUSES or self.failure_kind is not None:
            raise ValueError(f"a {FORCED_INCONCLUSIVE} record with cause {self.cause!r} and failure kind "
                             f"{self.failure_kind!r} is not one the close can make")
