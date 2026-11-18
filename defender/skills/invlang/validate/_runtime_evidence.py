"""Runtime-evidence receipts and their bounded time-window checks."""
from __future__ import annotations

import datetime as dt





from defender import _clock

from defender._model import model
from defender.records import closing




from defender.skills.invlang import _walkers
from defender.skills.invlang.schema import CompanionBody

from defender.skills.invlang.validate._structure import _cell


#: The anchor kind a `:R consultations` baseline carries, and its grounding. Consultation-only:
#: a statistical pattern is context about what the estate does, never a verdict on what it may do.
RUNTIME_EVIDENCE = "runtime-evidence"




@model(frozen=True)
class RuntimeEvidenceReceipt:
    """One parsed `:R consultations` baseline row.

    Split like `CeilingReceipt`: the structured half (`resolved_by_lead`/`anchor_kind`/
    `grounding_kind`/`anchor_id` and the window, verbatim and parsed) is checked mechanically;
    `result` and `reasoning` are free text for the analyst and never mined for numbers.

    @owns window_start

    The window is parsed once, here: the guard compares `window_end` with the alerted event and
    the close stores the parsed instants canonically. Frozen because it travels from the
    projection through the close into the closing record.
    """

    resolved_by_lead: str
    anchor_kind: str
    grounding_kind: str
    anchor_id: str
    result: str
    reasoning: str
    window: str
    window_start: dt.datetime
    window_end: dt.datetime




def _parse_halves(text: str) -> tuple[dt.datetime, dt.datetime] | None:
    """An `<start>/<end>` window as two aware datetimes, as written (any offset), or `None` if
    either half fails.

    A real parse, not a string comparison, since the guard must order instants. Through
    `_clock.parse_iso_utc`, which owns the naive-is-UTC rule (a local reading would vary by host,
    and comparing naive with aware raises).
    """
    start_text, sep, end_text = text.partition("/")
    if not sep:
        return None
    start = _clock.parse_iso_utc(start_text.strip())
    end = _clock.parse_iso_utc(end_text.strip())
    if start is None or end is None:
        return None
    return start, end


def _parse_window(text: str) -> tuple[dt.datetime, dt.datetime] | None:
    """An `<start>/<end>` window as two UTC datetimes, or `None` if either half fails to parse or
    has no UTC form (`0001-01-01T00:00:00+05:00` is before the first representable instant). The
    caller fails closed on `None`; the record stores the window in UTC, so a window with no UTC
    form is no baseline it could keep."""
    halves = _parse_halves(text)
    if halves is None:
        return None
    try:
        return halves[0].astimezone(dt.UTC), halves[1].astimezone(dt.UTC)
    except OverflowError:
        return None




def _alerted_moment(companion: CompanionBody) -> dt.datetime | None:
    """When the explained activity happened: the earliest parseable `when` on a
    `:E prologue.edges` row (the validator never sees `alert.json`). Earliest, because with
    several alerted edges a baseline ending after the first already contains the incident.
    """
    moments = [
        moment
        for edge in (companion.get("prologue") or {}).get("edges") or []
        if isinstance(edge, dict)
        # `when` projects as `{"timestamp": ...}`; `_cell` still unquotes the copied cell.
        and (moment := _clock.parse_iso_utc(_cell(edge.get("when") or {}, "timestamp")))
        is not None
    ]
    return min(moments) if moments else None




#: Every cell a baseline's line renders (`records.closing.baseline_line`): a row's identity.
_RENDERED_BASELINE_CELLS: tuple[str, ...] = (
    "anchor_kind", "grounding_kind", "anchor_id", "resolved_by_lead",
    "effective_window", "result", "reasoning",
)




@model(frozen=True)
class _BaselineWalk:
    """One walk of the `:R consultations` baseline rows: the accepted receipts in document
    order and every row-level refusal. Shared by the guard and the record builder, as
    `_CeilingWalk` is."""

    receipts: tuple[RuntimeEvidenceReceipt, ...]
    errors: tuple[str, ...]




def _walk_runtime_evidence_rows(companion: CompanionBody) -> _BaselineWalk:
    """Select the `runtime-evidence` consultations, parse each window, and hold it against the
    alerted event.

    Selected by anchor kind: the lead's `tacit-knowledge` lookup rows share the bucket and are
    not baselines. The guard — the window must end strictly before the alerted event, because a
    pattern that begins with the incident is the incident — applies only to `runtime-evidence`:
    a `tacit-knowledge` row carries the registry entry's validity span, which brackets the alert
    by design.
    """
    alerted = _alerted_moment(companion)
    receipts: list[RuntimeEvidenceReceipt] = []
    errors: list[str] = []
    seen: set[tuple[str, ...]] = set()
    for row in _walkers.iter_anchor_consultations(companion):
        if _cell(row, "anchor_kind") != RUNTIME_EVIDENCE:
            continue
        lead_id = _cell(row, "resolved_by_lead")
        window = _cell(row, "effective_window")
        where = (
            f"lead {lead_id or '?'}: `:R consultations` baseline "
            f"{_cell(row, 'anchor_id') or '<no anchor_id>'}"
        )
        # Deduplicated as in `_walk_ceiling_rows`: a repeat renders twice and spends the
        # column's budget twice. The identity is the whole rendered line, not the addressing cells:
        # `anchor_id` is optional, so two measurements by one lead over one window are legal.
        identity = tuple(_cell(row, cell) for cell in _RENDERED_BASELINE_CELLS)
        if identity in seen:
            errors.append(
                f"{where}: repeats an earlier baseline verbatim — a second copy measures "
                f"nothing further and renders the same line into the closing record twice. "
                f"Write one row per measurement"
            )
            continue
        seen.add(identity)
        parsed = _parse_window(window)
        if parsed is None and _parse_halves(window) is not None:
            errors.append(
                f"{where}: `effective_window` {window!r} has an end with no UTC form (it falls "
                f"outside the years 1-9999 once read in UTC) — the closing record keeps a "
                f"window in UTC. Write both ends as instants within that range"
            )
            continue
        if parsed is None:
            errors.append(
                f"{where}: `effective_window` {window!r} is not an "
                f"`<start>/<end>` pair of ISO-8601 instants — a baseline that cannot be placed "
                f"in time cannot be shown to PRECEDE the alerted event, which is the whole of "
                f"what makes it context rather than the incident describing itself"
            )
            continue
        start, end = parsed
        if not closing.grounding_acceptable(_cell(row, "grounding_kind")):
            # The record's own check: such a row is no baseline the record could keep. The
            # vocabulary gate reports it (`_check_vocab_anchor_kinds`), once.
            continue
        # Built first and judged on its own parsed fields, so the guard and the record read one
        # value.
        receipt = RuntimeEvidenceReceipt(
            resolved_by_lead=lead_id,
            anchor_kind=_cell(row, "anchor_kind"),
            grounding_kind=_cell(row, "grounding_kind"),
            anchor_id=_cell(row, "anchor_id"),
            result=_cell(row, "result"),
            reasoning=_cell(row, "reasoning"),
            window=window,
            window_start=start,
            window_end=end,
        )
        if receipt.window_end < receipt.window_start:
            errors.append(
                f"{where}: `effective_window` {window!r} ends before it begins — an inverted "
                f"span measures nothing, and read either way round it would silently change "
                f"which endpoint the guard below holds against the alert"
            )
            continue
        # Fails closed when the document cannot place its alert (no prologue edge, or no
        # parseable `when`); nothing requires a prologue edge, so this is not an exotic case.
        if alerted is None:
            errors.append(
                f"{where}: this document records no parseable `when` on any "
                f"`:E prologue.edges` row, so the baseline cannot be shown to PRECEDE the "
                f"alerted event — which is the whole of what makes it context rather than the "
                f"incident describing itself. Record the alerted edge's timestamp, or drop the "
                f"`{RUNTIME_EVIDENCE}` consultation"
            )
            continue
        if receipt.window_end >= alerted:
            errors.append(
                f"{where}: `effective_window` {window!r} does not end before the alerted event "
                f"at {alerted.isoformat()} — a `{RUNTIME_EVIDENCE}` consultation is evidence "
                f"about what PRECEDED the alert, and a window that reaches it (or past it) is "
                f"partly made of the thing being explained. Re-measure over a window that "
                f"closes before the alerted event"
            )
            continue
        receipts.append(receipt)
    return _BaselineWalk(receipts=tuple(receipts), errors=tuple(errors))




def _check_runtime_evidence_windows(companion: CompanionBody) -> list[str]:
    """The baseline-window guard at the write gate. The same walk's receipts are what
    `conclude_runtime_evidence_rows` hands the close."""
    return list(_walk_runtime_evidence_rows(companion).errors)




def conclude_runtime_evidence_rows(companion: CompanionBody) -> tuple[RuntimeEvidenceReceipt, ...]:
    """The `:R consultations` baseline receipts the guard accepted, in document order.

    Public for the reason `conclude_ceiling_test_rows` is: the close builds its record from
    them. Uses the guard's own walk so only accepted rows ship, and takes the
    parsed companion the close already has.
    """
    return _walk_runtime_evidence_rows(companion).receipts
