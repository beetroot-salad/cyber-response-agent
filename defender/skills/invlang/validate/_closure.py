"""The three closure gates: every declared commitment is resolved, or deferred with a reason.

Each gate is only safe to run once its `deferred_*` table is projected, which is why
`diagnose` runs them together and last.
"""
from __future__ import annotations

from collections.abc import Container, Iterable, Iterator

from defender._model import model

from .. import _walkers, vocab
from ..parser import (
    _CONCLUDE_SUBTABLE_FIELDS,
    HYPOTHESIS_ID_RE,
)
from ..schema import (
    CompanionBody,
    DeferralRecord,
)
from ._diag import REFUTED_WEIGHT
from ._refs import _declared_prediction_ids, _leads
from ._predictions import _confirmed_and_standing, _settled_predictions
from ._structure import _cell, _declared_impact_predictions, _qualify
from ._state import _anchor_kind, _declarers_by_contract_id, outstanding_authz_contracts
from ._gating import _check_disposition_gating, _row_states_something


#: The `:T conclude.*` sub-table fields, which a block can write without the document having
#: written `:T conclude`. Subtracted in `_is_closing` so a mid-run sub-table write does not read
#: as a close. Derived from the parser's set so a new sub-table cannot be missed here.
_NON_CLOSING_FIELDS: frozenset[str] = _CONCLUDE_SUBTABLE_FIELDS


def _is_closing(companion: CompanionBody) -> bool:
    """Did this document write a `:T conclude` block (what the closure gates mean by "closing").

    Truthiness of `conclude` is wrong: a sub-table (a real deferral row, or
    `surviving_hypotheses`, which is opened eagerly because rule #24 reads key presence) makes
    it truthy mid-run. Arming the closure gates then would make the document unwritable, since
    append-only forbids removing the block. An empty `:T conclude` block is warned at parse
    time, so any remaining key means the close was written.
    """
    conclude = companion.get("conclude")
    return isinstance(conclude, dict) and bool(set(conclude) - _NON_CLOSING_FIELDS)


@model(frozen=True)
class _Commitment:
    """One declared commitment a close has to account for.

    `owner` is the declaring hypothesis or lead, since the local id is only unique under it.
    `ref` is the qualified spelling deferral tables and error messages use.
    """

    owner: str
    local_id: str

    @property
    def ref(self) -> str:
        return f"{self.owner}.{self.local_id}"


def _deferral_index(rows: Iterable[DeferralRecord]) -> dict[str, list[str]]:
    """`:T conclude.deferred_*` rationales keyed by the reference exactly as written.

    Not expanded: a qualified `h-001.ac1` discharges only that owner's `ac1`, while a bare
    `ac1` discharges every owner's (the document-wide reading `_check_benign_authz` gives a
    bare `fulfills_contract`). Erring toward acceptance is intended: over-refusing a deferral
    leaves the author no legal repair. A list per key because any one row with a reason
    suffices. Reads either reference column (`contract_ref` or `prediction_ref`).
    """
    out: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ref = (row.get("contract_ref") or row.get("prediction_ref") or "").strip()
        if ref:
            out.setdefault(ref, []).append(row.get("rationale") or "")
    return out


def _unclosed_commitments(
    declared: Iterable[_Commitment],
    *,
    resolved: Container[str],
    deferrals: Iterable[DeferralRecord],
) -> Iterator[tuple[_Commitment, bool]]:
    """Yield each declared commitment neither resolved nor deferred with a rationale.

    Paired with `True` when a deferral row names it but every rationale is blank (needs a
    sentence), `False` when nothing names it (needs a row). Shared by rules #26, #31 and #34 so
    their readings of references and rationales cannot drift; callers supply what is declared
    and what counts as resolved. A rationale must state something: `none` / `n/a` does not
    discharge.
    """
    index = _deferral_index(deferrals)
    for c in declared:
        if c.ref in resolved or c.local_id in resolved:
            continue
        rationales = index.get(c.ref, []) + index.get(c.local_id, [])
        if not rationales:
            yield c, False
        elif not any(_row_states_something(r) for r in rationales):
            yield c, True


def _closure_refusal(
    subject: str, table: str, ref: str, *, blank_rationale: bool, resolve: str
) -> str:
    """The two ways a closure rule refuses, worded once.

    `subject` names the commitment, `table` is the deferral sub-table, and `resolve` is the
    rule's non-deferral repair.
    """
    if blank_rationale:
        return (
            f"conclude: {subject} is deferred with an empty rationale — a "
            f"`:T conclude.{table}` row records WHY the commitment could not be settled, and a "
            f"blank cell records nothing while still discharging it. Write the reason, or "
            f"{resolve}."
        )
    return (
        f"conclude: {subject} is declared and then abandoned — nothing settles it and no "
        f"`:T conclude.{table}` row defers it. Either {resolve}, or add a "
        f"`:T conclude.{table}` row `{ref}|\"<why it could not be settled>\"`; a commitment "
        f"made and then dropped reads like one that was never made."
    )


def _declarer_kinds(
    c: _Commitment, declarers: dict[str, list[tuple[str, str]]]
) -> tuple[set[str], set[str]]:
    """This commitment's own anchor kinds, and those of competing declarers of the same id.

    Shared by `_discharged_by_row` and `_authz_closure_repair` so the advised repair always
    matches what the predicate accepts.
    """
    rows = declarers.get(c.local_id, [])
    return (
        {a for h, a in rows if h == c.owner},
        {a for h, a in rows if h != c.owner},
    )


def _discharged_by_row(
    c: _Commitment,
    declarers: dict[str, list[tuple[str, str]]],
    kinds_by_id: dict[str, set[str]],
) -> bool:
    """Does some `:R authz` row fulfil this contract, not merely one with the same id.

    When one `ac*` has several declarers, the anchor kind says which question a row answered.
    A competing declarer with the same anchor kind makes the row unattributable, so nothing is
    discharged; otherwise a live hypothesis's row could close a refuted one's unrelated
    question. Agrees with `_authz_contract_error` and `outstanding_authz_contracts`.
    """
    kinds = kinds_by_id.get(c.local_id)
    if not kinds:
        return False
    mine, competing = _declarer_kinds(c, declarers)
    if not competing:
        return True
    if mine & competing:
        return False
    return bool(mine & kinds)


def _authz_closure_repair(
    c: _Commitment, declarers: dict[str, list[tuple[str, str]]]
) -> str:
    """The non-deferral way out of a rule #26 refusal, worded for the case at hand.

    Advises the bare id in `fulfills`: `_check_benign_authz` matches only the bare `ac<n>`, so
    a qualified one would clear this rule and leave the benign gate blocked. A shared id also
    names the anchor kind, which `_discharged_by_row` requires.
    """
    plain = f"fulfil it with a `:R authz` row carrying `fulfills={c.local_id}`"
    mine, competing = _declarer_kinds(c, declarers)
    if not competing:
        return plain
    twins = sorted(mine & competing)
    if twins:
        # Same-kind twin: only the qualified spelling discharges it (`c.ref in qualified`), and
        # renumbering is impossible because `:H` rows are append-only.
        return (
            f"fulfil it with a `:R authz` row carrying `fulfills={c.ref}` — {c.local_id} is "
            f"also declared on another hypothesis under anchor kind {twins[0]!r}, so the bare "
            f"id names no one contract and only the qualified `h-NNN.ac<n>` form says which "
            f"question the row answered (`ac<n>` numbers across the DOCUMENT, so the durable "
            f"fix is not to share one)"
        )
    # `mine` is never empty: `c` and `declarers` come from the same walk.
    return (
        f"{plain} AND `anchor_kind={sorted(mine)[0]}` — {c.local_id} is declared on more than "
        f"one hypothesis, so the anchor kind is what says which question the row answered"
    )


def _check_authz_contract_closure(
    companion: CompanionBody, *, gated: set[str] | None = None
) -> list[str]:
    """Every declared `:H h-NNN.authz` contract is fulfilled by a `:R authz` row, or deferred
    in `:T conclude.deferred_authz` with a reason.

    Broader than `_check_benign_authz`: it runs under every disposition and covers contracts on
    refuted hypotheses too, since refutation is a deferral rationale the run should state, not
    an automatic discharge.

    Stands down on any contract the disposition gate is already refusing, matched on that
    gate's output (`gated`, handed in by `diagnose`): otherwise one missing row is reported
    twice, and this rule's "defer it" repair would leave the disposition gate still blocked.

    Fulfilment is read by id with no verdict condition; a shared `ac*` id is scoped by anchor
    kind (see `_discharged_by_row`). `resolved` is spelled qualified, because the shared walk
    also accepts a bare `local_id` and a bare set would reintroduce the cross-owner discharge.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    # `diagnose` passes the gate's output to avoid re-running it; the fallback keeps this
    # callable on its own.
    if gated is None:  # lint-default: ok — the standalone fallback; `diagnose` binds it
        gated = set(_check_disposition_gating(companion))
    # Skipped when `gated` is empty: `outstanding_authz_contracts` is expensive.
    spoken_for = {
        f"{hid}.{_cell(c, 'id')}"
        for hid, c, why in outstanding_authz_contracts(companion)
        if why in gated
    } if gated else set()
    declarers = _declarers_by_contract_id(companion)
    kinds_by_id: dict[str, set[str]] = {}
    #: Qualified `fulfills=h-001.ac1` rows, the spelling the spec allows. Kept apart from
    #: `kinds_by_id` because a qualified row names its own declarer and discharges only it.
    qualified: set[str] = set()
    for row in _walkers.iter_authz_resolutions(companion):
        # Through `_cell`, which unquotes, as the declared `id` is read: a quoted row must still
        # match.
        cid = _cell(row, "fulfills_contract")
        if not cid:
            continue
        owner, dot, local = cid.rpartition(".")
        if dot and local and HYPOTHESIS_ID_RE.fullmatch(owner):
            qualified.add(cid)
        else:
            kinds_by_id.setdefault(cid, set()).add(_anchor_kind(row))
    declared = [
        _Commitment(hid, _cell(c, "id"))
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        for c in hyp.get("authorization_contract") or []
        if isinstance(c, dict) and _cell(c, "id")
        and f"{hid}.{_cell(c, 'id')}" not in spoken_for
    ]
    resolved = {
        c.ref
        for c in declared
        if c.ref in qualified or _discharged_by_row(c, declarers, kinds_by_id)
    }
    return [
        _closure_refusal(
            f"authz contract {c.ref}", "deferred_authz", c.ref,
            blank_rationale=blank,
            resolve=_authz_closure_repair(c, declarers),
        )
        for c, blank in _unclosed_commitments(
            declared,
            resolved=resolved,
            deferrals=conclude.get("deferred_authorizations") or [],
        )
    ]


def _check_impact_closure(companion: CompanionBody) -> list[str]:
    """Every declared `ip*` is graded by a `:R impact` row or deferred in
    `:T conclude.deferred_impact` with a reason — and the roll-up over those grades is
    internally consistent.

    An ungraded predicate lets a run choose after the fact which threshold to be measured
    against. Applies across all leads, including failed ones: the deferral arm covers a query
    that errored.

    The roll-up check is presence only: `impact_severity` is required exactly when the verdict
    claims a consequence (`exceeds` / `indeterminate`) and forbidden otherwise. Not checked:
    either cell's vocabulary (the runtime SKILL never states it) and whether the roll-up is
    arithmetically right over the rows.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    resolved: set[str] = set()
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            # Same `_cell` + `_qualify` reading as `_check_impact_resolution_refs`, so the two
            # rules resolve a `pred_ref` identically.
            ref = _cell(row, "prediction_ref") if isinstance(row, dict) else ""
            if ref:
                resolved.add(_qualify(lid, ref))
    # The same index `_check_impact_resolution_refs` resolves against.
    declared = [
        _Commitment(*ref.rsplit(".", 1))
        for ref in _declared_impact_predictions(companion)
    ]
    errors = [
        _closure_refusal(
            f"impact prediction {c.ref}", "deferred_impact", c.ref,
            blank_rationale=blank,
            resolve=f"grade it with a `:R impact` row carrying `pred_ref={c.ref}`",
        )
        for c, blank in _unclosed_commitments(
            declared,
            resolved=resolved,
            deferrals=conclude.get("deferred_impact_predictions") or [],
        )
    ]

    # Neither `impact_verdict`'s nor `impact_severity`'s vocabulary is enforced: the runtime
    # SKILL states neither, and recorded e2e goldens (replayed through this gate) write values
    # outside the enum. Order: teach, re-record, then arm. The presence clause below does not
    # depend on membership: an unrecognized verdict simply owes no severity.
    verdict = conclude.get("impact_verdict")
    severity = conclude.get("impact_severity")
    # Normalized through `_cell` and case-folded: a scalar can arrive padded or capitalized.
    verdict_key = _cell(conclude, "impact_verdict").lower()
    # `null` (any case) means no severity.
    stated = (
        _row_states_something(severity)
        and _cell(conclude, "impact_severity").lower() != "null"
    )
    owed = verdict_key in _SEVERITY_OWING
    if owed and not stated:
        errors.append(
            f"conclude: `impact_verdict {verdict}` with no `impact_severity` — the verdict "
            f"says a registered threshold was crossed or could not be shown not to be, and "
            f"the severity is how far. Add `impact_severity` "
            f"({', '.join(v for v in vocab.IMPACT_SEVERITY if v != 'null')}), or roll up to "
            f"`within` if nothing was actually exceeded"
        )
    if stated and not owed:
        errors.append(
            f"conclude: `impact_severity {severity}` beside `impact_verdict "
            f"{verdict if verdict is not None else 'null'}` — severity is the magnitude of a "
            f"consequence the run is CLAIMING, and this verdict claims none. Write "
            f"`impact_severity null`, or say which predicate was exceeded and roll the "
            f"verdict up to match"
        )
    return errors


#: The `conclude.impact_verdict` values that claim a consequence and so owe an
#: `impact_severity`. Derived from the row-level enum; `within` is the one member claiming none.
_SEVERITY_OWING: frozenset[str] = frozenset(vocab.IMPACT_VERDICT) - {"within"}


def _check_prediction_closure(companion: CompanionBody) -> list[str]:
    """Every `p*`/`ap*` on a hypothesis the run is still carrying was settled by some
    resolution, or deferred in `:T conclude.deferred_preds` with a reason.

    PREDICT pre-commits predictions so grading cannot be chosen after the evidence lands; this
    stops the uncited ones from silently disappearing. `_check_prediction_completeness` (#6)
    covers a hypothesis standing at `++` at write time with no deferral; this covers every other
    live hypothesis at CONCLUDE, where "the tool was never available" is a final answer.

    Refutation is read from the resolution record (weight moved to `--`), not the `status`
    column, which append-only fixes at declaration. A citation counts only from a resolution
    with a non-null `after`, and only for the declaring hypothesis.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    # Same definition as rule #6 (`_settled_predictions`), so the two gates agree on which
    # citations count.
    resolved = {
        f"{hid}.{pid}"
        for hid, pids in _settled_predictions(companion).items()
        for pid in pids
    }
    weights = _walkers.final_weights(companion)
    # Stands down on hypotheses standing at `++`: rule #6 already refuses those, and offering a
    # deferral here would clear this rule while #6 still refuses.
    #
    # Known gap: `final_weights` is last-move-wins in lead-declaration order while the `++`
    # predicate is order-free, so they can disagree when `:T resolutions` blocks do not follow
    # their leads (see `_walkers.final_weights`).
    confirmed = _confirmed_and_standing(companion)
    declared = [
        _Commitment(hid, pid)
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        if weights.get(hid) != REFUTED_WEIGHT and hid not in confirmed
        for pid in sorted(_declared_prediction_ids(hyp))
    ]
    return [
        _closure_refusal(
            f"prediction {c.ref} on live hypothesis {c.owner}", "deferred_preds", c.ref,
            blank_rationale=blank,
            resolve=(
                f"cite {c.local_id} in a `:T resolutions` head that moves {c.owner}"
            ),
        )
        for c, blank in _unclosed_commitments(
            declared,
            resolved=resolved,
            deferrals=conclude.get("deferred_predictions") or [],
        )
    ]


def _check_loop_close(companion: CompanionBody) -> list[str]:
    closed = companion.get("closed_loops") or []
    if not closed:
        return []
    resolved_by_loop: dict[int, bool] = {}
    for f in companion.get("findings", []):
        loop = f.get("loop")
        if isinstance(loop, int):
            committed = bool(f.get("resolutions")) or bool(f.get("outcome"))
            resolved_by_loop[loop] = resolved_by_loop.get(loop, False) or committed
    errors: list[str] = []
    seen: set[int] = set()
    for n in closed:
        if n in seen:
            errors.append(f":T close blocked: loop {n} closed more than once")
        seen.add(n)
        if not resolved_by_loop.get(n, False):
            errors.append(
                f":T close blocked: loop {n} has no committed finding "
                f"— cannot close an empty/drafted loop"
            )
    return errors
