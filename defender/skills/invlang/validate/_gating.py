"""What a disposition costs: benign grounding, the false-positive gate, the screen's
structure, and the severity ceiling. A conclusion that has not paid its price is refused here.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any



from defender._model import model
from defender._text import strip_zero_width
from defender._vocab import DISPOSITION_ENUM
from .. import _walkers, vocab
from ..parser import (
    is_conclude_empty_marker,
    parse_dense_companion,
)
from ..schema import (
    CompanionBody,
    FindingRecord,
)
from ._diag import REFUTED_WEIGHT
from ._refs import _HYPOTHESIS_DECLARING_BLOCKS, _known_ids, _leads
from defender.records._run_id import run_id_fault

from ._structure import PAST_CASE, _cell, _check_vocab, _folded_grounding
from ._state import (
    _check_benign_authz,
    _check_benign_open_slots,
    _declarers_by_contract_id,
)


def _rendered_disposition(value: object) -> str | None:
    """What `value` renders as: zero-width characters stripped, then exact membership.

    More forgiving than `defender._vocab.normalized_disposition`, which is exact-only because
    the read side must never coerce a malformed verdict. This write-side price dispatch must
    still recognize a zero-width-laced priced keyword, so that it fails closed and charges the
    price."""
    if not isinstance(value, str):
        return None
    candidate = strip_zero_width(value).strip()
    # lint-vocabulary: ok — the write-side price dispatch must recognize a zero-width-laced
    # keyword to fail closed; `normalized_disposition` is exact-only by design.
    return candidate if candidate in DISPOSITION_ENUM else None




def _row_states_something(value: Any) -> bool:
    """A `:T conclude` scalar that says something: non-blank and not the format's own empty
    marker, which only the parser defines."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not is_conclude_empty_marker(value)
    )


def _lead_returned_a_result(lead: FindingRecord) -> bool:
    """Did this lead come back with a result, not merely a record that it ran.

    Stricter than `_check_loop_close`, which counts any outcome: a lead whose only outcome is a
    `fail_reason` worked the loop but tested the alerted entity for nothing.
    """
    if lead.get("resolutions"):
        return True
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(set(outcome) - {"failure_reason"})

from defender.skills.invlang.validate._ceiling import (
    CEILING_NOTHING_TO_TRY as CEILING_NOTHING_TO_TRY,
    CEILING_QUERY_EMPTY as CEILING_QUERY_EMPTY,
    CEILING_QUERY_FAILED as CEILING_QUERY_FAILED,
    CEILING_STATES as CEILING_STATES,
    CapabilitiesNotRead as CapabilitiesNotRead,
    CeilingReceipt as CeilingReceipt,
    _CHECKOUT_ROSTER as _CHECKOUT_ROSTER,
    _CeilingWalk as _CeilingWalk,
    _LEAD_ANCHORED_STATES as _LEAD_ANCHORED_STATES,
    _LEAD_REF_RE as _LEAD_REF_RE,
    _MAX_CEILING_FRONTMATTER_BYTES as _MAX_CEILING_FRONTMATTER_BYTES,
    _MAX_CEILING_NOTE_BYTES as _MAX_CEILING_NOTE_BYTES,
    _RECEIPT_FIELD_NAMES as _RECEIPT_FIELD_NAMES,
    _RECEIPT_FIELD_RE as _RECEIPT_FIELD_RE,
    _RECEIPT_ROW_RE as _RECEIPT_ROW_RE,
    _cap_is_identifier_shaped as _cap_is_identifier_shaped,
    _capability_exists as _capability_exists,
    _check_ceiling_receipt as _check_ceiling_receipt,
    _check_inconclusive_gating as _check_inconclusive_gating,
    _check_lead_anchored_receipt as _check_lead_anchored_receipt,
    _check_nothing_to_try_receipt as _check_nothing_to_try_receipt,
    _lead_by_id as _lead_by_id,
    _lead_retrieval_came_back as _lead_retrieval_came_back,
    _parse_ceiling_row as _parse_ceiling_row,
    _row_renders_as_empty_marker as _row_renders_as_empty_marker,
    _walk_ceiling_rows as _walk_ceiling_rows,
    ceiling_note_block as ceiling_note_block,
    ceiling_test_block as ceiling_test_block,
    conclude_ceiling_test_rows as conclude_ceiling_test_rows,
    hold_capabilities as hold_capabilities,
    known_capabilities as known_capabilities,
    release_capabilities as release_capabilities,
)



def _check_false_positive_gating(companion: CompanionBody) -> list[str]:
    """`false-positive` closes on a claim about the rule, so it must prove it also looked at
    the entity."""
    conclude = companion.get("conclude") or {}
    errors: list[str] = []

    notes = conclude.get("detection_notes")
    if not _row_states_something(notes):
        errors.append(
            "disposition false-positive blocked: no `detection_notes` row — the "
            "close rests on a claim about the rule, so the defect has to be stated"
        )

    lead_id = conclude.get("entity_check")
    if not (isinstance(lead_id, str) and lead_id.strip()):
        return errors + [
            "disposition false-positive blocked: no `entity_check` row — name the "
            "`:L findings` lead that tested the alerted entity for suspicion "
            "independent of the alert's claim, or conclude in another vocabulary"
        ]
    lead_id = lead_id.strip()

    lead = _lead_by_id(companion, lead_id)
    if lead is None:
        return errors + [
            f"disposition false-positive blocked: `entity_check` names {lead_id!r}, "
            f"which is not a lead in `:L findings`"
        ]

    if not _lead_returned_a_result(lead):
        errors.append(
            f"disposition false-positive blocked: `entity_check` lead {lead_id} "
            f"committed no result — a lead that was planned and never resolved, or "
            f"whose only outcome is a `fail_reason`, did not test anything"
        )

    prologue_vertices = {
        v.get("id") for v in (companion.get("prologue") or {}).get("vertices") or []
    }
    target = lead.get("target")
    if target not in prologue_vertices:
        errors.append(
            f"disposition false-positive blocked: `entity_check` lead {lead_id} "
            f"targets {target!r}, which the prologue does not carry — the check has "
            f"to be against an entity the ALERT named, not one the refutation "
            f"introduced"
        )

    return errors


def _check_benign_grounding(companion: CompanionBody) -> list[str]:
    """`benign` needs a log that recorded what the alert was about: a prologue vertex.

    The other benign checks refuse contradictions (an open slot, an unfulfilled contract) and
    are vacuous over a document with no vertices; guaranteeing one gives
    `_check_benign_open_slots` something to check. Not a demand for leads: how much measurement
    a case needs is the review gate's judgment, and a trivially-benign alert closed off the
    payload alone must pass.
    """
    if not (companion.get("prologue") or {}).get("vertices"):
        return [
            "disposition benign blocked: no `:V prologue.vertices` row — benign says the "
            "alerted activity was accounted for, so the log has to name the entity the "
            "alert was about. An `investigation.md` that records no vertex records no "
            "investigation; conclude `inconclusive` instead."
        ]
    return []


#: The anchor kind an authored, human-committed registry entry is filed under.
TACIT_KNOWLEDGE = "tacit-knowledge"

from defender.skills.invlang.validate._runtime_evidence import (
    RUNTIME_EVIDENCE as RUNTIME_EVIDENCE,
    RuntimeEvidenceReceipt as RuntimeEvidenceReceipt,
    _BaselineWalk as _BaselineWalk,
    _MAX_RUNTIME_EVIDENCE_BODY_BYTES as _MAX_RUNTIME_EVIDENCE_BODY_BYTES,
    _RENDERED_BASELINE_CELLS as _RENDERED_BASELINE_CELLS,
    _REPORT_CLOSE_DELIMITER as _REPORT_CLOSE_DELIMITER,
    _alerted_moment as _alerted_moment,
    _check_runtime_evidence_windows as _check_runtime_evidence_windows,
    _delimiter_bearing_cell as _delimiter_bearing_cell,
    _parse_window as _parse_window,
    _walk_runtime_evidence_rows as _walk_runtime_evidence_rows,
    conclude_runtime_evidence_rows as conclude_runtime_evidence_rows,
    runtime_evidence_block as runtime_evidence_block,
)

TELEMETRY_BASELINE = "telemetry-baseline"

#: Checked against the vocabularies they spell members of: gates here compare cells against
#: these strings, and a rename or typo in `vocab` would otherwise make them pass silently.
assert TACIT_KNOWLEDGE in vocab.ANCHOR_KINDS
assert RUNTIME_EVIDENCE in vocab.ANCHOR_KINDS
assert TELEMETRY_BASELINE in vocab.CONSULTATION_GROUNDING


#: The `:R authz` verdicts rules here branch on: `authorized` is what the benign gate demands
#: (and so what a fabricated citation is worth writing); `indeterminate` is the one `basis`
#: qualifies.
AUTHZ_AUTHORIZED = "authorized"
AUTHZ_INDETERMINATE = "indeterminate"


def _lookup_outcome(row: Any) -> str:
    """The `hit`/`miss` token before the colon opening a `tacit-knowledge` consultation's
    `result`, lowercased, or `""`. The rest of the sentence is free analyst-facing text.
    """
    head, sep, _rest = _cell(row, "result").partition(":")
    token = head.strip().lower()
    return token if sep and token in vocab.TACIT_LOOKUP_OUTCOMES else ""


def _check_tacit_lookup_outcomes(companion: CompanionBody) -> list[str]:
    """A `tacit-knowledge` `:R consultations` row says hit or miss, and its `anchor_id` agrees.

    The citation receipt reads "this lead came back holding this entry" off the `anchor_id`, so
    the outcome must be readable and consistent with it: a hit with no id names nothing to cite,
    and a miss with an id is a fabricated citation waiting to be written.
    """
    errors: list[str] = []
    for row in _walkers.iter_anchor_consultations(companion):
        if _cell(row, "anchor_kind") != TACIT_KNOWLEDGE:
            continue
        where = (
            f"lead {_cell(row, 'resolved_by_lead') or '?'}: `:R consultations` "
            f"`{TACIT_KNOWLEDGE}` row"
        )
        outcome = _lookup_outcome(row)
        cited = _cell(row, "anchor_id")
        if not outcome:
            errors.append(
                f"{where}: `result` {_cell(row, 'result')!r} does not open with "
                f"`{'`/`'.join(vocab.TACIT_LOOKUP_OUTCOMES)}` — a registry lookup came back "
                f"with an entry or it did not (`enum consultation.lookup_outcome`), and an "
                f"authorization citing this row is checked against WHICH. Write "
                f"`result=\"hit: <what the entry covers>\"` or "
                f"`result=\"miss: <what nothing covered>\"`"
            )
        elif outcome == "hit" and not cited:
            errors.append(
                f"{where}: `result` records a hit and the row names no `anchor_id` — a hit came "
                f"back holding an entry, and its id is what a `:R authz` row cites. Name the "
                f"entry, or record the lookup as a miss"
            )
        elif outcome == "miss" and cited:
            errors.append(
                f"{where}: `result` records a miss and the row names `anchor_id` {cited!r} — a "
                f"lookup that came back empty has no entry to name, and an id written beside a "
                f"recorded miss is a citation waiting to be written. Drop the `anchor_id`, or "
                f"record the outcome as a hit if the entry really came back"
            )
    return errors


def _recorded_lookup_ids(companion: CompanionBody, lead_id: str) -> set[str]:
    """Every registry entry id `lead_id` recorded as a `tacit-knowledge` lookup hit.

    Keyed on the stated outcome, not the mere presence of an `anchor_id`, so a recorded miss
    that carries an id cannot back a citation.
    """
    return {
        _cell(row, "anchor_id")
        for row in _walkers.iter_anchor_consultations(companion)
        if _cell(row, "anchor_kind") == TACIT_KNOWLEDGE
        and _cell(row, "resolved_by_lead") == lead_id
        and _lookup_outcome(row) == "hit"
        and _cell(row, "anchor_id")
    }


def _authz_row_grounding_error(companion: CompanionBody, row: Any) -> str | None:
    """Why this one `:R authz` row's grounding does not stand, or `None`."""
    where = f"`:R authz` row for contract {_cell(row, 'fulfills_contract') or '?'}"
    # Rule #27 reads `cites_past_case` to decide what is a past case, so the cell must be one
    # it can read: a run id when filled, and filled whenever the row says it rests on one.
    cites = _cell(row, "cites_past_case")
    if cites and run_id_fault(cites) is not None:
        return (
            f"{where}: `cites_past_case {cites}` is not a run id — the cell names the earlier "
            f"run whose verdict this row leans on, as the agent tag on its comment spells it "
            f"(`[defender agent comment, run <run id>]`)"
        )
    if not cites and _folded_grounding(_cell(row, "grounding_kind")) == PAST_CASE:
        return (
            f"{where}: `grounding {PAST_CASE}` with no `cites_past_case` — a past case names "
            f"the run it cites. Fill `cites_past_case <run id>` from the tag on the comment "
            f"you are leaning on"
        )
    if _folded_grounding(_cell(row, "grounding_kind")) == TELEMETRY_BASELINE:
        return (
            f"{where}: `grounding {TELEMETRY_BASELINE}` — a telemetry baseline is what the "
            f"estate HAS been doing, not what it is permitted to do, so it grounds a "
            f"`:R consultations` row and never an authorization. Record the recurrence as a "
            f"consultation (`anchor_kind {RUNTIME_EVIDENCE}`, `grounding "
            f"{TELEMETRY_BASELINE}`) and resolve this contract on an authored record — an "
            f"`{TACIT_KNOWLEDGE}` registry entry, an iam-policy or a change-mgmt hit — or "
            f"`indeterminate`"
        )
    if _cell(row, "anchor_kind") == RUNTIME_EVIDENCE:
        return (
            f"{where}: `anchor_kind {RUNTIME_EVIDENCE}` — that kind exists so a BASELINE has "
            f"one, and a baseline is context rather than a verdict. `:R consultations` is the "
            f"bucket it belongs in; its rows carry no `fulfills` cell precisely because they "
            f"cannot discharge a contract"
        )
    if _cell(row, "anchor_kind") != TACIT_KNOWLEDGE:
        return None
    cited = _cell(row, "anchor_id")
    lead_id = _cell(row, "resolved_by_lead")
    if not cited:
        # Owed only by `authorized`: `indeterminate` is what a lead writes after an empty
        # lookup, when there is no entry to name.
        if _cell(row, "verdict") != AUTHZ_AUTHORIZED:
            return None
        return (
            f"{where}: `verdict {AUTHZ_AUTHORIZED}` on an `anchor_kind {TACIT_KNOWLEDGE}` row "
            f"that names no `anchor_id`. The registry is a human-authored file, so the verdict "
            f"is only as good as the entry behind it — and an optional column left blank is the "
            f"whole receipt skipped, not a receipt paid. Cite the entry id lead "
            f"{lead_id or '<none>'} recorded coming back with (its own `:R consultations` "
            f"`result=\"hit: ...\"` row), or resolve `indeterminate`"
        )
    recorded = _recorded_lookup_ids(companion, lead_id)
    if cited in recorded:
        return None
    return (
        f"{where}: cites registry entry {cited!r}, which lead {lead_id or '<none>'} never "
        f"recorded coming back with. An `{TACIT_KNOWLEDGE}` authorization is only as good as "
        f"the lookup behind it, so the lead named by `resolved_by` has to have recorded the "
        f"matching entry as its own `:R consultations` outcome first (`anchor_kind "
        f"{TACIT_KNOWLEDGE}`, `anchor_id {cited}`, `result=\"hit: ...\"`). That lead recorded "
        f"{sorted(recorded) or 'no entry at all'} — a lookup that came back empty records "
        f"`result=\"miss: ...\"` and no `anchor_id`, and there is then nothing for a citation "
        f"to equal; resolve `indeterminate` instead"
    )


def _check_authz_row_grounding(companion: CompanionBody) -> list[str]:
    """Every `:R authz` row's grounding, anchor kind and citation.

    Collected at both the write gate (`diagnose`) and the close (`_check_benign_gating`); the
    close is what the learning loop and ticket lane read, so the price must be owed there too.
    """
    return [
        problem
        for row in _walkers.iter_authz_resolutions(companion)
        if (problem := _authz_row_grounding_error(companion, row)) is not None
    ]


def _check_benign_gating(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    errors += _check_benign_grounding(companion)
    errors += _check_benign_open_slots(companion)
    errors += _check_benign_authz(companion)
    errors += _check_authz_row_grounding(companion)
    return errors


#: The `basis` value that claims something about dispatch, and so owes a receipt. `retry`
#: claims only that the contract has not been worked yet, and is free.
BASIS_EXHAUSTED = "exhausted"

#: What an absent `basis` cell reads as (the parser drops empty cells, so absent and blank are
#: one document): the contract is still worth another retrieval loop.
BASIS_DEFAULT = "retry"

assert BASIS_EXHAUSTED in vocab.AUTHZ_INDET_BASIS
assert BASIS_DEFAULT in vocab.AUTHZ_INDET_BASIS


def _contract_anchor_kind(companion: CompanionBody, row: Any) -> str:
    """The anchor kind whose system a `basis=exhausted` claim is checked against: the contract's
    own, via `_declarers_by_contract_id`. When a shared `ac<n>` names several kinds, the row's
    own `anchor_kind` breaks the tie (as in `_authz_contract_error`), and it is the fallback when
    the contract cannot be resolved.
    """
    row_kind = _cell(row, "anchor_kind")
    cid = _cell(row, "fulfills_contract")
    kinds = {kind for _hid, kind in _declarers_by_contract_id(companion).get(cid, [])}
    if row_kind in kinds or not kinds:
        return row_kind
    return next(iter(kinds)) if len(kinds) == 1 else row_kind


def _exhausted_receipt_error(companion: CompanionBody, row: Any) -> str | None:
    """Does this `basis=exhausted` row's own lead back the claim, or `None`."""
    lead_id = _cell(row, "resolved_by_lead")
    where = (
        f"`:R authz` row for contract {_cell(row, 'fulfills_contract') or '?'}: "
        f"`basis={BASIS_EXHAUSTED}`"
    )
    lead = _lead_by_id(companion, lead_id) if lead_id else None
    if lead is None:
        return (
            f"{where} is resolved by {lead_id or '<none>'}, which `:L findings` does not "
            f"declare — the claim that every applicable registry was queried has to point at "
            f"the lead that queried them"
        )
    if not _lead_retrieval_came_back(lead):
        return (
            f"{where} rests on lead {lead_id}, whose own retrieval came back with nothing this "
            f"run — no observation, no `:R attr_updates` row. A lead that was planned and "
            f"never dispatched cannot show that anything was asked, so write `basis="
            f"{BASIS_DEFAULT}` (the contract has not been worked yet) or point the row at the "
            f"lead that made the calls"
        )
    kind = _contract_anchor_kind(companion, row)
    wanted = vocab.ANCHOR_KIND_SYSTEMS.get(kind)
    if wanted is None:
        return None
    went_to = _cell(lead.get("query_details") or {}, "system")
    if went_to == wanted:
        return None
    return (
        f"{where} on an {kind!r} contract is resolved by lead {lead_id}, whose own "
        f"`:L findings` row says it queried {went_to or '<no system>'!r} — the kind is answered "
        f"by the {wanted!r} system, and a lead that never went there cannot have exhausted it. "
        f"Dispatch a lead against {wanted}, or write `basis={BASIS_DEFAULT}`"
    )


def exhausted_contract_ids(companion: CompanionBody) -> frozenset[str]:
    """@owns exhausted_contract_ids

    The `ac<n>` ids a `:R authz` row declared `basis=exhausted` for, on an `indeterminate`
    verdict (the only one `basis` qualifies).

    Read by `frontier._open_contracts`, which stops offering these for another retrieval loop,
    while `outstanding_authz_contracts` still reports them so the benign gate blocks and
    `on_indet` escalates. Keyed per fulfilled id: one row's claim says nothing about a sibling
    contract. Whether the claim was paid is `_check_authz_basis`'s business.
    """
    return frozenset(
        cid
        for row in _walkers.iter_authz_resolutions(companion)
        if _cell(row, "basis") == BASIS_EXHAUSTED
        and _cell(row, "verdict") == AUTHZ_INDETERMINATE
        and (cid := _cell(row, "fulfills_contract"))
    )


def _check_authz_basis(companion: CompanionBody) -> list[str]:
    """`:R authz`' `basis` cell: a closed vocabulary, defined only on `verdict: indeterminate`,
    with a receipt owed for `exhausted`.

    Off-vocabulary values are refused because every reader is a membership test, so a
    misspelling (`exhausetd`) would claim exhaustion without paying for it. On any other verdict
    the cell is refused: it would drop a contract off the frontier (`unauthorized`) or charge a
    meaningless receipt (`authorized`).
    """
    errors: list[str] = []
    for row in _walkers.iter_authz_resolutions(companion):
        basis = _cell(row, "basis")
        if not basis:
            continue
        where = f"`:R authz` row for contract {_cell(row, 'fulfills_contract') or '?'}"
        verdict = _cell(row, "verdict")
        if verdict != AUTHZ_INDETERMINATE:
            errors.append(
                f"{where}: `basis={basis}` on `verdict {verdict or '<none>'}` — the cell says "
                f"whether an UNSETTLED contract is worth another retrieval loop, so it is "
                f"defined on `verdict {AUTHZ_INDETERMINATE}` and on nothing else. A settled "
                f"verdict has no loop left to price; drop the cell"
            )
            continue
        # Through `_check_vocab` so this arm and the `enum` CLI answer the same way.
        off_vocab = _check_vocab(
            basis, vocab.AUTHZ_INDET_BASIS,
            f"{where}: basis {basis!r} is not one of "
            f"{', '.join(vocab.AUTHZ_INDET_BASIS)} (`enum authz.basis`) — the cell says "
            f"whether an unsettled contract is worth another retrieval loop, and an "
            f"absent cell already reads as {BASIS_DEFAULT!r}",
        )
        if off_vocab:
            errors += off_vocab
            continue
        if basis != BASIS_EXHAUSTED:
            continue
        problem = _exhausted_receipt_error(companion, row)
        if problem is not None:
            errors.append(problem)
    return errors


@model(frozen=True)
class _Price:
    """What a keyword costs, and why.

    `check` answers whether this document has paid, naming the blocking vertex, contract or row.
    `rationale` tells a refused model why the price exists, so it can choose between paying and
    concluding in another vocabulary; it belongs to the keyword, so it lives beside the check.
    """

    check: Callable[[CompanionBody], list[str]]
    rationale: str


#: The structural price of a keyword. Read at both boundaries — `_check_disposition_gating`
#: (what `:T conclude` says) and `disposition_entry_price` (what the close commits) — so adding
#: a row arms both. The rationale rides in the row so a priced keyword cannot go unexplained.
#:
#: Each row is bound to a name rather than built inline: `lint_half_read_table` recognizes a
#: keyed gate table only when every value is a `Name`/`Attribute`/`Lambda`.
_BENIGN_PRICE = _Price(
    check=_check_benign_gating,
    rationale=(
        "`benign` says the alerted activity was accounted for, which an unresolved slot or "
        "an unfulfilled authorization contract on a live hypothesis directly contradicts, "
        "and which a log that never named the alerted entity does not support at all — so "
        "it is reachable only from an `investigation.md` that recorded the entity and "
        "settled what it left open."
    ),
)
_FALSE_POSITIVE_PRICE = _Price(
    check=_check_false_positive_gating,
    rationale=(
        "`false-positive` says the RULE misfired, which is no evidence about the alerted "
        "entity — so it is reachable only from an `investigation.md` that states the defect "
        "and names the lead that checked the entity anyway."
    ),
)


_INCONCLUSIVE_PRICE = _Price(
    check=_check_inconclusive_gating,
    rationale=(
        "`inconclusive` says the investigating model could not settle the case, which is "
        "worth nothing to an analyst unless the report names what specifically it could not "
        "check — so it is reachable only from a `:T conclude` naming at least one "
        "`ceiling_test` RECEIPT: `state=query-failed`/`state=query-empty` pointing (`ref=`) at "
        "a `:L findings` lead this run dispatched that failed or came back empty, consistent "
        "with that lead's own recorded outcome, or `state=nothing-to-try` naming (`cap=`) a "
        "capability that does not exist anywhere in this deployment. Mechanically verified "
        "against the run's own transcript — never a judgment of prose."
    ),
)

_DISPOSITION_GATES: dict[str, _Price] = {
    "benign": _BENIGN_PRICE,
    "false-positive": _FALSE_POSITIVE_PRICE,
    "inconclusive": _INCONCLUSIVE_PRICE,
}


@model(frozen=True)
class EntryPrice:
    """What a close still owes for its keyword, and why that keyword owes anything.

    Both halves come from one dispatch, so a caller cannot look up the rationale under a
    differently-normalized keyword than the one priced.
    """

    owed: tuple[str, ...]
    rationale: str

    def __bool__(self) -> bool:
        """Truthy when something is owed; an unpriced keyword and a paid document are both
        falsy."""
        return bool(self.owed)


def disposition_entry_price(disposition: str, companion_text: str) -> EntryPrice:
    """What `disposition` still owes, read off an `investigation.md`; nothing for an unpriced
    keyword."""
    return entry_price(disposition, parse_dense_companion(companion_text)[0])


def entry_price(disposition: str, companion: CompanionBody) -> EntryPrice:
    """`disposition_entry_price` over an already-parsed companion, for the close, which parses
    once at its price gate and hands that body downstream.
    """
    priced = _rendered_disposition(disposition)
    price = _DISPOSITION_GATES.get(priced) if priced else None
    if price is None:
        return EntryPrice(owed=(), rationale="")
    return EntryPrice(owed=tuple(price.check(companion)), rationale=price.rationale)


def _check_disposition_gating(companion: CompanionBody) -> list[str]:
    """Run the structural checks this document's disposition is priced at, and only those.

    Dispatched through the forgiving `_rendered_disposition`, since this branch decides whether
    the checks run at all and a zero-width character must not turn them off.
    `_check_conclude_vocab` separately refuses the laced spelling; either rule alone would leave
    a hole.
    """
    disposition = _rendered_disposition(
        (companion.get("conclude") or {}).get("disposition")
    )
    price = _DISPOSITION_GATES.get(disposition) if disposition else None
    return price.check(companion) if price is not None else []




#: `:L findings`' `mode` for a fast-path screen lead, and the `screen_result` meaning it hit:
#: the only two values the screen rule turns on.
SCREEN_MODE = "screen"
SCREEN_MATCH = "match"


def _check_screen_structure(companion: CompanionBody) -> list[str]:
    """Two ways a `screen_result` can decide nothing."""
    leads = _leads(companion)
    # Lowercased at the read: neither cell is vocab-checked, so a raw `Screen` would fail
    # closed and a raw `Match` would fail open. `mode` is read per row inside the loop so no
    # arm reaches across leads.
    results = [_cell(lead, "screen_result").lower() for lead in leads]
    if not any(results):
        # No `screen_result` anywhere: every run that never takes the fast path.
        return []
    first_match = ""
    errors: list[str] = []
    for lead, result in zip(leads, results, strict=True):
        # `none` / `n/a` is the format's empty-cell spelling, not a verdict; shipped examples
        # write it in unused trailing columns.
        if not result or is_conclude_empty_marker(result):
            continue
        lid = lead.get("id", "?")
        mode = _cell(lead, "mode").lower()
        # A `match` on a non-screen lead is only the mode arm's defect; letting it also reach
        # the fast-path arm would tell the author to delete a legitimate hypothesize block.
        if mode != SCREEN_MODE:
            errors.append(
                f"lead {lid}: `screen_result: {result}` on a lead whose mode is {mode!r} — "
                f"the column records a SCREEN's verdict; set `mode: screen` on the lead that "
                f"ran the screen, or drop the cell"
            )
        elif result == SCREEN_MATCH and not first_match:
            # First in `companion["findings"]` (first-mention) order, so with two matches the
            # message may name the later-written cell.
            first_match = str(lid)
    if first_match and _walkers.all_hypotheses(companion):
        errors.append(
            f"lead {first_match}: `screen_result: {SCREEN_MATCH}` closes the run on the fast "
            f"path, but {_HYPOTHESIS_DECLARING_BLOCKS} enumerates hypotheses — a matched "
            f"screen and an investigation are two different runs; drop the block, or record "
            f"the screen as `no_match` and keep investigating"
        )
    return errors


def _weight_text(weight: Any) -> str:
    """A hypothesis weight as the format spells it: `null` rather than the `None` the parser
    maps `weight null` (or an omitted cell) to."""
    return repr(weight if isinstance(weight, str) and weight else vocab.NULL_WEIGHT)


def _check_hypothesis_persistence(companion: CompanionBody) -> list[str]:
    """A close that enumerates its survivors must enumerate all of them: each hypothesis ends
    at `--` (refuted) or has a `:T conclude.surviving` row. Otherwise a dropped hypothesis reads
    exactly like one never proposed."""
    conclude = companion.get("conclude") or {}
    # Key presence, not row count: an absent block leaves the key off, while an explicit empty
    # table (`none`) claims that nothing survived, which a live hypothesis contradicts.
    if "surviving_hypotheses" not in conclude:
        return []
    surviving = {
        row["hypothesis"] for row in conclude["surviving_hypotheses"]
        if isinstance(row, dict) and isinstance(row.get("hypothesis"), str)
    }
    return [
        f"conclude: hypothesis {hid} is neither refuted nor carried into the close — its "
        f"final weight is {_weight_text(weight)} and the `:T conclude.surviving` table, "
        f"which names {_known_ids(surviving)}, omits it. Resolve it to "
        f"{REFUTED_WEIGHT!r}, or add its row; a hypothesis declared and then dropped reads "
        f"like one that was never proposed"
        for hid, weight in _walkers.final_weights(companion).items()
        if weight != REFUTED_WEIGHT and hid not in surviving
    ]


#: The `termination.category` that engages the ceiling-test rule. Free text with no closed
#: vocabulary (the spec's four values are contradicted by the shipped goldens' `data-ceiling`
#: and `adversarial-confirmed`), so a misspelling silently disables the rule: a miss, never a
#: wrongful refusal.
SEVERITY_CEILING = "severity-ceiling"


def _check_ceiling_test_scope(companion: CompanionBody) -> list[str]:
    """A run terminating on `severity-ceiling` must name the check it could not make."""
    conclude = companion.get("conclude") or {}
    category = (conclude.get("termination") or {}).get("category")
    # Per row, not list truthiness: `ceiling_test  ""` projects as `[""]`, truthy yet naming no
    # gap, while the honest `none` projects as absence and is refused.
    if category != SEVERITY_CEILING or any(
        _row_states_something(t) for t in conclude.get("ceiling_test") or []
    ):
        return []
    return [
        f"conclude: `termination.category {SEVERITY_CEILING}` with no `ceiling_test` — the "
        f"category says live hypotheses remain and their critical edges cannot be tested, so "
        f"the close owes the specific check it could not make. Add one "
        f"`ceiling_test  state=query-failed ref=<lead-id> note=<text>` (or "
        f"`state=query-empty`) row per gap to `:T conclude` (repeat the key; the SKILL's "
        f"§`:T conclude` has the shape). If you wrote a `:T conclude.ceiling_test "
        f"[kind|subject]` sub-table, that is the RETIRED spelling from "
        f"`defender/docs/dense-investigation-format.md` — the parser recognizes it and projects "
        f"nothing, so its rows never reach this rule; re-send them as flat rows. If nothing "
        f"was actually out of reach, this run did not hit a ceiling — terminate on the "
        f"category that describes what happened."
    ]
