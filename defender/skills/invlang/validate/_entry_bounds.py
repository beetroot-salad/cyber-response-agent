"""The closing record's entry bounds, checked at the write gate and again at the close (#1534 OD16).

Over every parsed ceiling row (accepted by the walker or not) and every parsed baseline row, for
every disposition: each model-text field's treated length against its bound, the ceiling count
cap, and each column's aggregate of rendered lines. The close's record builder measures the same
treated text with the same line renderers, so for a document these accept it changes nothing.
A row's other faults are the walkers' to report; this measures only size."""
from __future__ import annotations

from typing import Any

from defender.records import closing
from defender.skills.invlang import _walkers
from defender.skills.invlang.schema import CompanionBody
from defender.skills.invlang.validate._ceiling import _parse_ceiling_row, _row_renders_as_empty_marker
from defender.skills.invlang.validate._runtime_evidence import RUNTIME_EVIDENCE, _parse_window
from defender.skills.invlang.validate._structure import _cell


def entry_bound_refusals(companion: CompanionBody) -> list[str]:
    """Every entry bound `companion`'s ceiling receipts and baselines break, as refusals naming
    the field or column and the bound."""
    return [*_ceiling_refusals(companion), *_baseline_refusals(companion)]


def _ceiling_refusals(companion: CompanionBody) -> list[str]:
    rows = (companion.get("conclude") or {}).get("ceiling_test")
    errors: list[str] = []
    lines: list[str] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, str) or _row_renders_as_empty_marker(row):
            continue
        receipt = _parse_ceiling_row(row)
        if receipt is None:
            continue
        note = closing.treat(receipt.note, None)
        if len(note) > closing.NOTE_BOUND:
            errors.append(
                f"`ceiling_test` row {row!r}: its `note` is {len(note)} characters once treated, over the "
                f"{closing.NOTE_BOUND}-character bound — shorten the note; it is free text for the analyst")
        lines.append(closing.ceiling_line_of(state=receipt.state, ref=receipt.ref, cap=receipt.cap, note=note))
    if len(lines) > closing.CEILING_COUNT_CAP:
        errors.append(
            f"`ceiling_test` carries {len(lines)} receipts, over the cap of {closing.CEILING_COUNT_CAP} — name "
            f"fewer, more specific gaps")
    if (total := len("\n".join(lines))) > closing.CEILING_LINES_BOUND:
        errors.append(
            f"the `ceiling_test` receipts render {total} characters, over the {closing.CEILING_LINES_BOUND}-"
            f"character bound — shorten the notes")
    return errors


#: A baseline's model-text cells and each one's bound.
_BASELINE_CELLS = (
    ("resolved_by_lead", "`resolved_by` (the lead)", closing.LEAD_BOUND),
    ("anchor_id", "`anchor_id`", closing.ANCHOR_ID_BOUND),
    ("result", "`result`", closing.RESULT_BOUND),
    ("reasoning", "`reasoning`", closing.REASONING_BOUND),
)


def _baseline_refusals(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    lines: list[str] = []
    for row in _walkers.iter_anchor_consultations(companion):
        if _cell(row, "anchor_kind") != RUNTIME_EVIDENCE:
            continue
        treated = {key: closing.treat(_cell(row, key), None) for key, _name, _bound in _BASELINE_CELLS}
        for key, name, bound in _BASELINE_CELLS:
            if len(treated[key]) > bound:
                errors.append(
                    f"lead {_cell(row, 'resolved_by_lead') or '?'}: `:R consultations` baseline {name} is "
                    f"{len(treated[key])} characters once treated, over the {bound}-character bound — shorten it")
        lines.append(closing.baseline_line_of(
            lead=treated["resolved_by_lead"], anchor_kind=RUNTIME_EVIDENCE,
            grounding_kind=_cell(row, "grounding_kind"), anchor_id=treated["anchor_id"],
            window=_window(_cell(row, "effective_window")), result=treated["result"],
            reasoning=treated["reasoning"]))
    if (total := len("\n".join(lines))) > closing.BASELINE_LINES_BOUND:
        errors.append(
            f"the `{RUNTIME_EVIDENCE}` `:R consultations` baselines (`runtime_evidence`) render {total} characters, "
            f"over the {closing.BASELINE_LINES_BOUND}-character bound — state the recurrence and its scope, not "
            f"every occurrence in full")
    return errors


def _window(written: Any) -> str:
    """The window as the record renders it (canonical instants), or as written when it does not
    parse (the walker refuses that row; its size still counts)."""
    parsed = _parse_window(written) if isinstance(written, str) else None
    if parsed is None:
        return str(written)
    return f"{closing.canonical_instant(parsed[0])}/{closing.canonical_instant(parsed[1])}"
