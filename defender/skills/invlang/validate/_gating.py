"""What a disposition costs: benign grounding, the false-positive gate, the screen's
structure, and the severity ceiling. A conclusion that has not paid its price is refused here.
"""
from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any


from defender import _yaml

from defender import _clock
from defender._model import model
from defender._text import strip_zero_width
from defender._vocab import DISPOSITION_ENUM
from defender.runtime.verbs import RosterRead
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
from defender._run_id import is_valid_run_id

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


def _lead_retrieval_came_back(lead: FindingRecord) -> bool:
    """Did this lead's own retrieval return anything — an observation or an `:R attr_updates`
    row — as opposed to an analytical conclusion (`:R authz`/`anchor`/`impact`) about it.

    Narrower than `_lead_returned_a_result`, which also counts `resolutions` and is right for
    `entity_check`. A lead can resolve a contract `indeterminate` purely from absent telemetry
    (golden-v2sshd's `l-004`); counting that resolution as a result would make the most common
    real gap — a query that found nothing, with a conclusion drawn from the absence —
    unanchorable by any `ceiling_test` receipt.
    """
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(outcome.get("observations") or outcome.get("attribute_updates"))


#: The one lookup a `:L findings` lead reference resolves against, shared by `entity_check` and
#: a `ceiling_test` receipt's `ref`.
def _lead_by_id(companion: CompanionBody, lead_id: str) -> FindingRecord | None:
    return next((f for f in _leads(companion) if f.get("id") == lead_id), None)


def _check_false_positive_gating(companion: CompanionBody) -> list[str]:
    """`false-positive` closes on a claim about the rule, so it must prove it also looked at
    the entity.

    Checked: `detection_notes` states a defect (the empty marker is not one); `entity_check`
    names a lead that exists and returned a result (not merely planned, not only a
    `fail_reason`); and that lead targets a vertex the prologue carried, i.e. one the alert
    named rather than one the refutation introduced.

    Not checked: whether the lead's question was a good one (query parameters never reach this
    layer), or independent of the alert's claim. Closing those needs an indicator set the
    runtime executes; a passing gate is not a swept host.
    """
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

#: The anchor kind a `:R consultations` baseline carries, and its grounding. Consultation-only:
#: a statistical pattern is context about what the estate does, never a verdict on what it may do.
RUNTIME_EVIDENCE = "runtime-evidence"
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
    """Why this one `:R authz` row's grounding does not stand, or `None`.

    Refused:

      * `grounding telemetry-baseline` (folded, so case and separator variants cannot slip
        past): a baseline grounds a `:R consultations` row, never an authorization.
      * `anchor_kind runtime-evidence`: the same claim through the other cell.
      * a `tacit-knowledge` row citing an `anchor_id` its own lead never recorded as a hit, or
        an `authorized` one citing none. Checked against the document only (the validator never
        reads the registry), so this refuses cheap fabrications — an id from nowhere, another
        lead's id, a recorded miss — without proving the entry exists. Faking an authorization
        then takes two coordinated rows, the second a retrieval claim `executed_queries.jsonl`
        independently records.

    `grounding` is folded rather than closed against a vocabulary because the corpus writes
    specific record types (`iam-policy-binding`), not the documented pair; `anchor_kind` is the
    closed cell that says which registry answered.
    """
    where = f"`:R authz` row for contract {_cell(row, 'fulfills_contract') or '?'}"
    # Rule #27 reads `cites_past_case` to decide what is a past case, so the cell must be one
    # it can read: a run id when filled, and filled whenever the row says it rests on one.
    cites = _cell(row, "cites_past_case")
    if cites and not is_valid_run_id(cites):
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
    """Does this `basis=exhausted` row's own lead back the claim, or `None`.

    `exhausted` claims every anchor kind applicable to the contract was actually queried and
    none answered. Checked, like a `ceiling_test` `ref`, against what the document records about
    the resolving lead:

      * its retrieval came back with something (`_lead_retrieval_came_back`); a lead that exists
        only as a name in a `resolved_by` cell recorded no dispatch;
      * its `:L findings` `system` cell matches the contract's anchor kind via
        `vocab.ANCHOR_KIND_SYSTEMS`. Otherwise any lead would do, since every lead carries an
        ORIENT bookkeeping `:R attr_updates` row.

    Known limitation: an anchor kind missing from `ANCHOR_KIND_SYSTEMS` falls back to the
    retrieval check alone. `executed_queries.jsonl` is the authoritative dispatch record, but
    the validator sees only text, so the `system` cell is the closest in-document signal.
    """
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

def _row_renders_as_empty_marker(value: object) -> bool:
    """Does a `ceiling_test` row render as nothing or as the format's empty marker
    (`none`/`n/a`)? Such a row is the format's "no gap" spelling and is skipped, not refused."""
    return isinstance(value, str) and (not value.strip() or is_conclude_empty_marker(value))


#: The closed states a `ceiling_test` receipt may claim. A receipt is a pointer into this run's
#: own transcript, verified mechanically, never a judgment of prose.
#:
#: Three states because that is all current instrumentation distinguishes without reading the
#: model's words: `_lead_retrieval_came_back` splits "came back with something" from "did not",
#: and the presence (never content) of a lead's `fail_reason` splits "errored" from "empty".
#: `access-denied` / `out-of-retention` need a host-side signal that tells them apart from
#: `query-failed` mechanically (e.g. a distinct `error_class` for a permission refusal, or an
#: adapter reporting before-retention) before they can be added.
CEILING_QUERY_FAILED = "query-failed"
CEILING_QUERY_EMPTY = "query-empty"
CEILING_NOTHING_TO_TRY = "nothing-to-try"
CEILING_STATES: tuple[str, ...] = (
    CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY, CEILING_NOTHING_TO_TRY,
)

#: The states that anchor to a lead this run dispatched. `nothing-to-try` has no call to point
#: at: the capability does not exist.
_LEAD_ANCHORED_STATES: tuple[str, ...] = (CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY)

#: The shape of a `:L findings` lead id (`l-<alphanumeric>`). A receipt's `ref` is checked
#: against it before the lookup: `:L findings` ids are unconstrained free text, so exact
#: membership alone would accept a delimiter-shaped id a model declared.
_LEAD_REF_RE = re.compile(r"l-[A-Za-z0-9]+")


@model(frozen=True)
class CeilingReceipt:
    """One parsed `ceiling_test` row.

    `state`/`ref`/`cap` are the structured half, mechanically checked against this run's own
    transcript, and the only part that goes into the report frontmatter (`ceiling_test_block`).
    `note` is free text for the human analyst: checked only for the report delimiter and a total
    size bound, rendered into the report body, and passed verbatim (inside the untrusted frame)
    to the ceiling review composer."""

    state: str
    ref: str | None
    cap: str | None
    note: str
    raw: str


#: `state=... [ref=...] [cap=...] note=<free text>`. `note=` is always last and takes the rest
#: of the line, so it needs no quoting. The other fields are `\S+` tokens compared by exact
#: membership, so a homoglyph or zero-width variant simply fails to match.
_RECEIPT_ROW_RE = re.compile(r"^(?P<fields>(?:\S+=\S+\s+)*)note=(?P<note>.*)$")
_RECEIPT_FIELD_RE = re.compile(r"(\S+)=(\S+)")
_RECEIPT_FIELD_NAMES = frozenset({"ref", "state", "cap"})


def _parse_ceiling_row(row: str) -> CeilingReceipt | None:
    """Parse one `ceiling_test` row, or `None` if it is not receipt-shaped at all. `None` is not
    itself a refusal; the caller decides what it costs."""
    m = _RECEIPT_ROW_RE.match(row.strip())
    if not m:
        return None
    fields = dict(_RECEIPT_FIELD_RE.findall(m.group("fields")))
    if not fields or set(fields) - _RECEIPT_FIELD_NAMES or "state" not in fields:
        return None
    return CeilingReceipt(
        state=fields["state"], ref=fields.get("ref"), cap=fields.get("cap"),
        note=m.group("note").strip(), raw=row,
    )


#: The closed universe of `(system, verb)` pairs this codebase's adapters declare
#: (`defender/scripts/adapters/*_adapter.py`), which `nothing-to-try` is checked against. Closed
#: by construction: code this repo owns, never a catalogue of real-world data sources.
#:
#: Held, never fetched: the process's composition root reads the roster once and hands it over
#: through `hold_capabilities` before any validation. Reading lazily here would make whichever
#: document-path guard asked first catch the host's fault and blame the document. Holds the
#: `RosterRead` itself, the same object the run's registry holds.
_CHECKOUT_ROSTER: RosterRead | None = None


class CapabilitiesNotRead(RuntimeError):
    """`known_capabilities` was called before `hold_capabilities`: a composition-root defect,
    not a document diagnostic."""


def hold_capabilities(roster: RosterRead) -> None:
    """Hand the gate the checkout's roster (`read_roster(DefenderPaths(REPO_ROOT).adapters_dir)`,
    or the run's own when its tree is the checkout). Called once at process start; a later call
    replaces it, which only tests driving several checkouts rely on."""
    if not isinstance(roster, RosterRead):
        raise TypeError(
            f"hold_capabilities takes the RosterRead `read_roster` produced, got "
            f"{type(roster).__name__}"
        )
    global _CHECKOUT_ROSTER
    _CHECKOUT_ROSTER = roster


def release_capabilities() -> None:
    """Forget the held roster, so a test can observe the unheld state or avoid leaking a
    fixture roster to the next test."""
    global _CHECKOUT_ROSTER
    _CHECKOUT_ROSTER = None


def known_capabilities() -> Mapping[str, frozenset[str]]:
    """System -> the verb names its adapter declares, for this process's checkout. Raises
    `CapabilitiesNotRead` if `hold_capabilities` was never called.

    The checkout's tree (`REPO_ROOT`), not the run's `defender_dir`: the price is closed over what
    this repository owns. A failed or absent roster read fails at the composition root as
    `RegistryError`, never inside a guard on the document's path, which would blame the model for
    the host's fault."""
    if _CHECKOUT_ROSTER is None:
        raise CapabilitiesNotRead(
            "the checkout's adapters roster was never read: the process's composition root "
            "must `read_roster` it once and `hold_capabilities` the value before any "
            "document is validated"
        )
    return _CHECKOUT_ROSTER.verbs


def _capability_exists(cap: str) -> bool:
    """Does `cap` name a REAL `system` or `system.verb` this deployment's adapters declare?
    `nothing-to-try` pays only when this is False."""
    known = known_capabilities()
    system, sep, verb = cap.partition(".")
    if sep:
        return verb in known.get(system, frozenset())
    return cap in known


def _cap_is_identifier_shaped(cap: str) -> bool:
    """Is `cap` shaped like `<system>` or `<system.verb>`, rather than arbitrary text?

    `cap` is the one receipt field checked by absence (`not _capability_exists`), which any
    non-capability string satisfies, `</report>` included. `ref` and `state` are checked by exact
    membership, which already refuses non-members. Uses `runtime.verbs`' system-name alphabet for
    both halves, since verb names share it."""
    from defender.runtime.verbs import SYSTEM_PATTERN, is_system_name

    system, sep, verb = cap.partition(".")
    if not is_system_name(system):
        return False
    return not sep or bool(re.fullmatch(SYSTEM_PATTERN, verb))


#: `_artifact_schema.REPORT_CLOSE_DELIMITER`, duplicated because that module imports this
#: package. Text carrying it would break the report block boundary once rendered into
#: `report.md`'s body, so it is refused before the document lands.
_REPORT_CLOSE_DELIMITER = "</report>"


def _delimiter_bearing_cell(row: Any, keys: Sequence[str]) -> str | None:
    """The first of `keys` whose cell carries the report's closing delimiter, or `None`, so the
    refusal can name the cell to rewrite."""
    return next((key for key in keys if _REPORT_CLOSE_DELIMITER in _cell(row, key)), None)


def ceiling_test_block(receipts: Sequence[CeilingReceipt]) -> str:
    """@owns ceiling_test

    The `ceiling_test:` frontmatter block for `receipts` — `ref`/`state`/`cap` only, never the
    `note`. The one renderer, so the gate that bounds it (`_check_inconclusive_gating`) and
    `close_tool.render_report`, which emits it, measure the same bytes. Dumped through PyYAML
    because `ref`/`cap` are model-cited tokens in a host-owned file."""
    if not receipts:
        return ""
    rows: list[dict[str, str]] = []
    for r in receipts:
        row: dict[str, str] = {"state": r.state}
        if r.ref is not None:
            row["ref"] = r.ref
        if r.cap is not None:
            row["cap"] = r.cap
        rows.append(row)
    return _yaml.safe_dump(
        {"ceiling_test": rows},
        allow_unicode=True, default_flow_style=False, sort_keys=False, width=10**9,
    )


def _check_lead_anchored_receipt(companion: CompanionBody, receipt: CeilingReceipt) -> str | None:
    """The `query-failed`/`query-empty` half of `_check_ceiling_receipt`: `ref` must name a lead
    this run dispatched whose own retrieval came back with nothing, and the state must match
    whether that lead recorded a `fail_reason`."""
    if receipt.cap is not None:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state={receipt.state}` takes `ref=`, "
            f"not `cap=` — a call that was actually dispatched points at the lead that "
            f"made it"
        )
    if not receipt.ref:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state={receipt.state}` needs "
            f"`ref=<lead-id>` naming the `:L findings` row that made the attempt"
        )
    if not _LEAD_REF_RE.fullmatch(receipt.ref):
        # `:L findings` ids have no shape rule (a lead named `</report>` parses cleanly), so
        # exact membership alone does not constrain shape. Checked before the lookup so a
        # hostile id cannot be planted and then cited.
        return (
            f"`ceiling_test` row {receipt.raw!r}: `ref={receipt.ref}` is not shaped like a "
            f"`:L findings` lead id (`l-<alphanumeric>`)"
        )
    lead = _lead_by_id(companion, receipt.ref)
    if lead is None:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `ref={receipt.ref}` is not a lead in "
            f"`:L findings`"
        )
    if _lead_retrieval_came_back(lead):
        return (
            f"`ceiling_test` row {receipt.raw!r}: lead {receipt.ref} actually retrieved "
            f"something (an observation, an updated attribute) — a receipt cannot claim a "
            f"gap for a call that came back with data. An analytical CONCLUSION about the "
            f"lead (an authz/anchor/impact resolution) does not by itself disqualify it — "
            f"only retrieved data does; see `_lead_retrieval_came_back`"
        )
    outcome = lead.get("outcome")
    errored = isinstance(outcome, dict) and bool(outcome.get("failure_reason"))
    if receipt.state == CEILING_QUERY_FAILED and not errored:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=query-failed` but lead "
            f"{receipt.ref} records no `fail_reason` in `:L findings` — write "
            f"`state=query-empty` for a call that ran clean and came back with nothing, "
            f"or add the lead's `fail_reason`"
        )
    if receipt.state == CEILING_QUERY_EMPTY and errored:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=query-empty` but lead "
            f"{receipt.ref} records a `fail_reason` in `:L findings` — write "
            f"`state=query-failed` for a call that errored"
        )
    return None


def _check_nothing_to_try_receipt(receipt: CeilingReceipt) -> str | None:
    """The `nothing-to-try` half of `_check_ceiling_receipt`: `cap` must name a capability the
    closed verb roster does not declare."""
    if receipt.ref is not None:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=nothing-to-try` takes `cap=`, not "
            f"`ref=` — nothing was dispatched, so there is no lead to point at"
        )
    if not receipt.cap:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=nothing-to-try` needs "
            f"`cap=<system>` or `cap=<system.verb>` naming the missing capability"
        )
    if not _cap_is_identifier_shaped(receipt.cap):
        return (
            f"`ceiling_test` row {receipt.raw!r}: `cap={receipt.cap}` is not shaped like "
            f"`<system>` or `<system.verb>` — lowercase letters, digits and hyphens only, one "
            f"optional `.verb` segment. `cap` is checked by ABSENCE from the closed roster, "
            f"which cannot constrain an arbitrary string on its own; rewrite it as the "
            f"capability's actual system[.verb] name"
        )
    if _capability_exists(receipt.cap):
        return (
            f"`ceiling_test` row {receipt.raw!r}: `cap={receipt.cap}` names a capability this "
            f"deployment DOES provide — `nothing-to-try` is for a capability that does not "
            f"exist at all. If the call was made and failed or came back empty, use "
            f"`state=query-failed`/`state=query-empty` with `ref=<lead-id>` instead"
        )
    return None


def _check_ceiling_receipt(companion: CompanionBody, receipt: CeilingReceipt) -> str | None:
    """Is `receipt` consistent with this run's own transcript: a foreign-key and
    closed-vocabulary check, never a judgment of the note. Returns the refusal, or `None` when
    the receipt pays."""
    if receipt.state not in CEILING_STATES:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state={receipt.state}` is not one of "
            f"{CEILING_STATES}"
        )
    if _REPORT_CLOSE_DELIMITER in receipt.note:
        return (
            f"`ceiling_test` row {receipt.raw!r}: the `note` carries the literal "
            f"{_REPORT_CLOSE_DELIMITER!r}, which the committed report may not carry — "
            f"rewrite the note without it"
        )
    if receipt.state in _LEAD_ANCHORED_STATES:
        return _check_lead_anchored_receipt(companion, receipt)
    return _check_nothing_to_try_receipt(receipt)


@model(frozen=True)
class _CeilingWalk:
    """One walk of a `:T conclude.ceiling_test` list: the paying rows (document order, deduped)
    and every row-level complaint. Shared by the gate (`_check_inconclusive_gating`) and the
    report reader (`conclude_ceiling_test_rows`), so a row the gate refused never reaches
    `report.md` and one it accepted is never dropped."""

    paying: tuple[CeilingReceipt, ...]
    errors: tuple[str, ...]


def _walk_ceiling_rows(companion: CompanionBody, rows: Any) -> _CeilingWalk:
    paying: list[CeilingReceipt] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    # `isinstance(list)`, not `rows or []`: iterating a string would walk its characters.
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, str) or _row_renders_as_empty_marker(row):
            continue
        receipt = _parse_ceiling_row(row)
        if receipt is None:
            # Silent: a row not even shaped like a receipt states nothing to price. The
            # aggregate "no receipt pays" message carries the guidance if nothing else pays.
            continue
        identity = (
            receipt.state, receipt.ref if receipt.ref is not None else (receipt.cap or ""),
        )
        if identity in seen:
            errors.append(
                f"`ceiling_test` row {row!r} repeats an earlier gap — each row must name a "
                f"DISTINCT gap; repetition does not pay for a second one"
            )
            continue
        seen.add(identity)
        problem = _check_ceiling_receipt(companion, receipt)
        if problem is not None:
            errors.append(problem)
            continue
        paying.append(receipt)
    return _CeilingWalk(paying=tuple(paying), errors=tuple(errors))


#: Bound on the frontmatter receipt block (`ref`/`state`/`cap` only). Charged on the rendered
#: block (`ceiling_test_block`) because PyYAML quoting changes the size, and a measurement that
#: disagrees with the renderer can pass here what the commit refuses. Well under
#: `_artifact_schema.REPORT_FRONTMATTER_MAX` (512); it guards against an unreasonable number of
#: receipts rather than any one receipt's size.
_MAX_CEILING_FRONTMATTER_BYTES = 300

#: Bound on the rendered `ceiling_test` note lines in the report body (`ceiling_note_block`).
#: Without it a large note passes this gate and then strands the run at
#: `_artifact_schema.validate_report`'s whole-file cap, after the review has been spent. Sized
#: like `_MAX_RUNTIME_EVIDENCE_BODY_BYTES`: 300 + 2048 + 2048 stays well under
#: `_artifact_schema.REPORT_FILE_MAX` (8192).
_MAX_CEILING_NOTE_BYTES = 2048


def ceiling_note_block(receipts: Sequence[CeilingReceipt]) -> str:
    """The `report.md` body lines for the receipts' notes: one per receipt that has one, naming
    its state and its `ref` or `cap`, then the free text. The one renderer, so the bounding gate
    and `close_tool.render_report` measure the same bytes. Each line starts with a newline;
    empty when no receipt has a note."""
    return "".join(
        f"\nceiling_test ({r.state}, {r.ref or r.cap}): {r.note}" for r in receipts if r.note
    )


def _check_inconclusive_gating(companion: CompanionBody) -> list[str]:
    """`inconclusive` owes at least one `ceiling_test` row that is a valid receipt.

    A `query-failed`/`query-empty` receipt must `ref` a lead this run dispatched whose own
    retrieval is consistent with the state; a `nothing-to-try` receipt must `cap` a capability
    absent from the closed verb roster. Rows must be distinct, and the rendered frontmatter and
    note text are bounded. Collected at both the write gate and the close via
    `_DISPOSITION_GATES`."""
    conclude = companion.get("conclude") or {}
    walk = _walk_ceiling_rows(companion, conclude.get("ceiling_test"))
    errors = [f"disposition inconclusive blocked: {e}" for e in walk.errors]
    total_bytes = len(ceiling_test_block(walk.paying).encode("utf-8"))
    if total_bytes > _MAX_CEILING_FRONTMATTER_BYTES:
        errors.append(
            f"disposition inconclusive blocked: the accumulated `ceiling_test` receipts are "
            f"{total_bytes} bytes, over the {_MAX_CEILING_FRONTMATTER_BYTES}-byte bound — "
            f"name fewer, more specific gaps rather than every one in full"
        )
    note_bytes = len(ceiling_note_block(walk.paying).encode("utf-8"))
    if note_bytes > _MAX_CEILING_NOTE_BYTES:
        errors.append(
            f"disposition inconclusive blocked: the accumulated `ceiling_test` notes render "
            f"{note_bytes} bytes of `report.md` body, over the {_MAX_CEILING_NOTE_BYTES}-byte "
            f"bound — shorten the "
            f"notes; they are free text for the human analyst, never required to make a "
            f"receipt pay"
        )
    if not walk.paying:
        errors.append(
            "disposition inconclusive blocked: no `ceiling_test` row is a receipt that pays "
            "— write `state=query-failed ref=<lead-id> note=<text>` or "
            "`state=query-empty ref=<lead-id> note=<text>` naming a `:L findings` lead this "
            "run dispatched that failed or came back empty, or `state=nothing-to-try "
            "cap=<system[.verb]> note=<text>` naming a capability this deployment does not "
            "provide."
        )
    return errors


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


def conclude_ceiling_test_rows(companion: CompanionBody) -> tuple[CeilingReceipt, ...]:
    """The `:T conclude.ceiling_test` receipts that pay, in document order.

    Public because `report.md` is written from the close's disposition argument and never
    re-reads the companion, so the close carries these into the report itself. Uses the gate's
    own walk so the rows that ship are exactly the rows the gate priced and bounded.

    Takes the parsed companion: the close has already parsed it once, inside the guard that
    turns a parse fault into a refusal (`_refuse_if_entry_price_is_owed`)."""
    conclude = companion.get("conclude") or {}
    return _walk_ceiling_rows(companion, conclude.get("ceiling_test")).paying


@model(frozen=True)
class RuntimeEvidenceReceipt:
    """One parsed `:R consultations` baseline row.

    Split like `CeilingReceipt`: the structured half (`resolved_by_lead`/`anchor_kind`/
    `grounding_kind`/`anchor_id` and the window, verbatim and parsed) is checked mechanically;
    `result` and `reasoning` are free text for the analyst and never mined for numbers.

    @owns window_start

    The window is parsed once, here: the guard compares `window_end` with the alerted event and
    `close_tool.render_report` shows `window` as written. Frozen because it travels from the
    projection through the close into `report.md`.
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


def _parse_window(text: str) -> tuple[dt.datetime, dt.datetime] | None:
    """An `<start>/<end>` window as two aware UTC datetimes, or `None` if either half fails.

    A real parse, not a string comparison, since the guard must order instants. Through
    `_clock.parse_iso_utc`, which owns the naive-is-UTC rule (a local reading would vary by host,
    and comparing naive with aware raises). The caller fails closed on `None`.
    """
    start_text, sep, end_text = text.partition("/")
    if not sep:
        return None
    start = _clock.parse_iso_utc(start_text.strip())
    end = _clock.parse_iso_utc(end_text.strip())
    if start is None or end is None:
        return None
    return start, end


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


#: Bound on the report-body text baseline consultations render, charged on the rendered block
#: (as `_MAX_CEILING_FRONTMATTER_BYTES` is). `_artifact_schema.REPORT_FILE_MAX` caps the whole
#: report at 8192 bytes while the invlang write gate allows 65536, so consultations the write
#: gate accepted could otherwise render a report the close refuses permanently. Sized to leave
#: room for the frontmatter, the ceiling notes and the close's own text.
_MAX_RUNTIME_EVIDENCE_BODY_BYTES = 2048


def runtime_evidence_block(receipts: Sequence[RuntimeEvidenceReceipt]) -> str:
    """@owns runtime_evidence

    The `report.md` body lines for `receipts`: one per baseline, naming the grounding, entry,
    owning lead and window, then the model's free text. The one renderer, so the bounding gate
    and `close_tool.render_report` measure the same bytes. Each line starts with a newline;
    empty when there are no receipts.
    """
    out = ""
    for r in receipts:
        out += (
            f"\n{r.anchor_kind} ({r.grounding_kind}, {r.anchor_id}, {r.resolved_by_lead}, "
            f"{r.window}): {r.result}"
        )
        if r.reasoning:
            out += f" — {r.reasoning}"
    return out


#: Every cell `runtime_evidence_block` copies into `report.md`'s body; keep the two in step.
#: The delimiter guard covers all of them, not just the free-text ones: `anchor_id` is an open
#: column, and a `</report>` in any rendered cell would make the close refuse a report whose
#: append-only source row can never be withdrawn.
_RENDERED_BASELINE_CELLS: tuple[str, ...] = (
    "anchor_kind", "grounding_kind", "anchor_id", "resolved_by_lead",
    "effective_window", "result", "reasoning",
)


@model(frozen=True)
class _BaselineWalk:
    """One walk of the `:R consultations` baseline rows: the accepted receipts in document
    order and every row-level refusal. Shared by the guard and the report reader, as
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
        # Deduplicated as in `_walk_ceiling_rows`: a repeat renders twice and spends the body
        # budget twice. The identity is the whole rendered line, not the addressing cells:
        # `anchor_id` is optional, so two measurements by one lead over one window are legal.
        identity = tuple(_cell(row, cell) for cell in _RENDERED_BASELINE_CELLS)
        if identity in seen:
            errors.append(
                f"{where}: repeats an earlier baseline verbatim — a second copy measures "
                f"nothing further and renders the same line into the committed report twice. "
                f"Write one row per measurement"
            )
            continue
        seen.add(identity)
        # Every rendered cell is held to the `ceiling_test` note rule: a delimiter here would
        # make the close refuse the report, and the append-only row cannot be withdrawn.
        delimiter = _delimiter_bearing_cell(row, _RENDERED_BASELINE_CELLS)
        if delimiter is not None:
            errors.append(
                f"{where}: `{delimiter}` carries the literal {_REPORT_CLOSE_DELIMITER!r}, which "
                f"the committed report may not carry — this text rides into `report.md`'s body, "
                f"and a close that renders it is refused with no way left to repair the row. "
                f"Rewrite the cell without it"
            )
            continue
        parsed = _parse_window(window)
        if parsed is None:
            errors.append(
                f"{where}: `effective_window` {window!r} is not an "
                f"`<start>/<end>` pair of ISO-8601 instants — a baseline that cannot be placed "
                f"in time cannot be shown to PRECEDE the alerted event, which is the whole of "
                f"what makes it context rather than the incident describing itself"
            )
            continue
        start, end = parsed
        # Built first and judged on its own parsed fields, so the guard and the report read one
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
    body_bytes = len(runtime_evidence_block(tuple(receipts)).encode("utf-8"))
    if body_bytes > _MAX_RUNTIME_EVIDENCE_BODY_BYTES:
        errors.append(
            f"the accumulated `{RUNTIME_EVIDENCE}` consultations render "
            f"{body_bytes} bytes of `report.md` body, over the "
            f"{_MAX_RUNTIME_EVIDENCE_BODY_BYTES}-byte bound — state the recurrence and its "
            f"scope, not every occurrence in full"
        )
    return _BaselineWalk(receipts=tuple(receipts), errors=tuple(errors))


def _check_runtime_evidence_windows(companion: CompanionBody) -> list[str]:
    """The baseline-window guard at the write gate. The same walk's receipts are what
    `conclude_runtime_evidence_rows` hands the close."""
    return list(_walk_runtime_evidence_rows(companion).errors)


def conclude_runtime_evidence_rows(companion: CompanionBody) -> tuple[RuntimeEvidenceReceipt, ...]:
    """The `:R consultations` baseline receipts the guard accepted, in document order.

    Public for the reason `conclude_ceiling_test_rows` is: the close carries them into
    `report.md` itself. Uses the guard's own walk so only accepted rows ship, and takes the
    parsed companion the close already has.
    """
    return _walk_runtime_evidence_rows(companion).receipts


def disposition_entry_price(disposition: str, companion_text: str) -> EntryPrice:
    """What `disposition` still owes, read off an `investigation.md`; nothing for an unpriced
    keyword.

    A price must be collected at both boundaries: this module gates the `investigation.md`
    write, but `close_investigation` takes its disposition as an argument and never reads the
    companion. Without this, writing a cheaper keyword in `:T conclude` and passing the priced
    one to the close would bypass the price, and `report.md` is what the learning loop, evals
    and ticket lane read. Reads the same `_DISPOSITION_GATES` table as
    `_check_disposition_gating`.

    Normalized through `_rendered_disposition` so a zero-width character cannot turn a gate
    off. Typed `str` because an unrecognized value fails open (unpriced), and a wider type would
    let a caller swap the two `str` arguments unnoticed. Over an empty companion both priced
    keywords owe their full price (`false-positive` demands stated content, `benign` a prologue
    vertex).

    The text surface over `entry_price`.
    """
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
    """Two ways a `screen_result` can decide nothing.

    On a lead whose mode is not `screen`, it is a verdict about a screen that never ran, in the
    slot readers take for the fast-path answer. A `match` beside a `hypothesize` block claims
    both that no investigation was needed and that one happened; whichever half was written
    first, the other has a reachable repair (do not write the block, or record `no_match`).

    Known gap: a `match` on an earlier screen, followed by a later `no_match` screen and a `:H`
    block, is still refused over the committed `match`, which no write can withdraw. Fixing it
    needs the loop's last `screen_result` in `:L findings` order, which `companion["findings"]`
    (first-mention order) does not carry. For the same reason no rule refuses an intermediate
    screen's result: whether a screen is the last is unknowable when writing it, and by then
    the row cannot be withdrawn.

    Read off `findings[].screen_result`, where the column projects (never nested under
    `outcome`). Whether the verdict is right is not checked; nothing beneath the scalar is
    projected.
    """
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
    exactly like one never proposed.

    A close with no surviving table is out of scope: the table is optional by construction
    (benign gating computes survival from the resolution record), so its absence defers to that
    record. Requiring it would refuse most documents in the tree, both shipped goldens
    included; that is a spec decision. The table is read as the author's assertion, never as
    evidence.

    No other discharges: `termination.rationale`/`category` are unchecked free text, and
    `matched_archetype` resolves against a catalog that does not exist.
    """
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
    """A run terminating on `severity-ceiling` must name the check it could not make.

    It is the one category that ends a run by declaring the question unanswerable, so it most
    needs a receipt: without `ceiling_test`, a real tooling boundary is indistinguishable from
    stopping. The empty marker `none` projects as absence, and both are refused.

    Only half the spec rule: `ceiling_test` is not forbidden under other terminations. The
    shipped field lists checks the run could not make, lessons instruct writing it whenever a
    source was out of reach, and runs routinely name gaps while terminating on something else
    (`golden-v2sshd`: `data-ceiling`). Refusing those would discard runs for obeying lessons.

    The trigger is free text (see `SEVERITY_CEILING`); closing that vocabulary is a spec-owner
    decision.
    """
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
        f"`docs/dense-investigation-format.md` — the parser recognizes it and projects "
        f"nothing, so its rows never reach this rule; re-send them as flat rows. If nothing "
        f"was actually out of reach, this run did not hit a ceiling — terminate on the "
        f"category that describes what happened."
    ]
