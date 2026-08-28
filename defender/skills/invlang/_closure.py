"""The three closure gates, which are one sentence over three namespaces.

The last family of `validate.py`'s rules, split out at 4038 lines, and the top of the
layering: every other family is imported from here. Each gate is only safe to run once
its `deferred_*` table is projected, which is why `diagnose` runs them together and last.
"""
from __future__ import annotations

from collections.abc import Container, Iterable, Iterator
from dataclasses import dataclass

from . import _walkers, vocab
from .parser import (
    _CONCLUDE_SUBTABLE_FIELDS,
    HYPOTHESIS_ID_RE,
)
from .schema import (
    CompanionBody,
    DeferralRecord,
)
from ._diag import REFUTED_WEIGHT
from ._refs import _declared_prediction_ids, _leads
from ._predictions import _confirmed_and_standing, _settled_predictions
from ._structure import _cell, _declared_impact_predictions, _qualify
from ._state import _anchor_kind, _declarers_by_contract_id, outstanding_authz_contracts
from ._gating import _check_disposition_gating, _row_states_something


#: Every `:T conclude.*` SUB-TABLE field — the fields a block writes without the document
#: having written `:T conclude` itself. Subtracted below so a mid-run write of one cannot read
#: as a close: `_project_deferral_block` opens its table lazily for the same reason, and
#: `_project_surviving_block` CANNOT (see `_is_closing`), which is why the subtraction is the
#: load-bearing half here rather than the belt.
#:
#: DERIVED from `parser._CONCLUDE_SUBTABLE_FIELDS`, never restated: that dict's own comment
#: invites "a fourth namespace should be a row here, not a fourth projector", and a
#: hand-written copy one module over is exactly what such a row leaves behind — after which a
#: mid-run `:T conclude.deferred_<new>` arms all three closure gates against every commitment
#: the run has not reached yet.
_NON_CLOSING_FIELDS: frozenset[str] = _CONCLUDE_SUBTABLE_FIELDS


def _is_closing(companion: CompanionBody) -> bool:
    """Did this document write a `:T conclude` block — the question the three closure gates
    actually mean by `if not conclude`.

    A truthiness test on the projected dict answers a different question and gets it wrong in
    both directions. A `:T conclude.deferred_preds` carrying a REAL row makes `conclude`
    truthy with no close in sight, so a mid-run write that defers one commitment would be
    refused for every commitment the run has not reached CONCLUDE on yet. And the
    other way, a `:T conclude` block is now guaranteed to record SOMETHING —
    `_project_conclude_scalars` warns when it recognizes no key at all — so an empty dict can
    only mean the close is not written.

    `surviving_hypotheses` does NOT count, though it is a claim ABOUT the close: being a claim
    about the close is not being the close, which is the question this asks.
    `_project_surviving_block` opens the key before it reads a row and must keep doing so —
    `_check_hypothesis_persistence` reads KEY PRESENCE to tell an absent table (defer to the
    resolution record) from one written as the `none` marker (a claim that NOTHING survived),
    so the lazy-open used for the deferral tables would silently disarm that rule. That leaves
    the subtraction as the only place to draw the line, and it costs nothing: rule #24 gates
    itself on its own key-presence test and never consults this function.

    Without the subtraction, a mid-run `:T conclude.surviving` with no `:T conclude` anywhere
    arms all three closure gates — and since append-only forbids removing the block and
    `fix_row` cannot reach it, the document is unwritable from then on.
    """
    conclude = companion.get("conclude")
    return isinstance(conclude, dict) and bool(set(conclude) - _NON_CLOSING_FIELDS)


@dataclass(frozen=True)
class _Commitment:
    """One thing the document DECLARED, which a close therefore has to account for.

    `owner` is the block that declared it — a hypothesis for a contract or a prediction, a lead
    for an impact prediction — because the local id is only unique under that owner. `ref` is
    the qualified spelling every deferral table and every error message uses.
    """

    owner: str
    local_id: str

    @property
    def ref(self) -> str:
        return f"{self.owner}.{self.local_id}"


def _deferral_index(rows: Iterable[DeferralRecord]) -> dict[str, list[str]]:
    """`:T conclude.deferred_*` rows keyed by the reference they name, EXACTLY as written.

    Never by an expanded alias. A row that writes the qualified `h-001.ac1` is registered under
    that alone, so it cannot also discharge `h-002.ac1`; a row that writes the bare `ac1`
    registers under the bare form and discharges every owner's `ac1`, which is the same
    document-wide reading `_check_benign_authz` gives a bare `fulfills_contract`. The
    asymmetry is deliberate: over-refusing a deferral leaves an author with no legal repair,
    while over-accepting one costs an orphan that a differently-spelled row would have
    excused anyway.

    A list per key, not one rationale: two rows may name the same commitment, and one of them
    carrying a reason is enough.

    EITHER spelling of the reference column. `:T conclude.deferred_authz` names its cell
    `contract_ref` and the other two `prediction_ref`; the parser keeps whichever the table
    used, because that is the name the spec gives the field, and one closure walk over three
    namespaces is a reason for ONE reader, not for one column name. A row carries exactly one
    of the two.
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
    """Every declared commitment a close neither resolved nor deferred WITH A RATIONALE, paired
    with which of the two it is — `True` when a deferral row names it and every rationale on it
    is blank, `False` when nothing names it at all.

    ONE walk for three rules. #26 (authorization contracts), #31 (impact predictions) and #34
    (predictions) are the same sentence over three namespaces — *every declared X is resolved,
    or deferred with a reason* — and #31's own text says it "mirrors rule #26's orphan gate".
    Written out three times they drift: the bare-vs-qualified reference reading, whether a
    blank rationale discharges, and whether a second deferral row can rescue the first are
    three judgment calls each, and nine places to disagree.

    What the callers keep is everything rule-specific: WHICH commitments are declared, what
    counts as resolved (a `:R authz` row, a `:R impact` row, a resolution head), and the prose.
    A blank rationale is a distinct outcome rather than "not deferred" because the two need
    different repairs — one needs a row, the other needs a sentence.

    "States something" rather than "is non-blank", the same test `_check_ceiling_test_scope`
    applies to `ceiling_test`. `none` / `n/a` is the format's own word for "nothing to say" and
    the SKILL teaches it two paragraphs from the deferral tables as the empty-TABLE marker, so
    a bare-truthiness test makes `h-001.p1|none` a discharge — one word that clears the only
    guard the escape hatch has, while the honest empty cell is refused.
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

    `subject` names the commitment as its own rule spells it, `resolve` is that rule's
    non-deferral repair, and `table` is the sub-table that carries the deferral. The wording is
    shared because the FAILURE is shared: a commitment made and then neither kept nor withdrawn
    reads, from outside, exactly like one that was never made.
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
    """This commitment's own anchor kinds, and the ones a COMPETING declarer of the same
    `ac<n>` carries.

    One walk for the two readers of it — `_discharged_by_row` decides the refusal and
    `_authz_closure_repair` words its repair — because they are a matched pair: a repair
    derived from a different split than the predicate advises a row the gate will reject
    again, on an append-only `:R authz` row the author cannot rewrite.
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
    """Does some `:R authz` row fulfil THIS contract — not merely one numbered the same.

    A `:R authz` row names only the contract id, so when one `ac*` has more than one declarer
    the anchor kind is the only column that says which question the row answered. Same
    discrimination `_authz_contract_error` makes, and made here rather than shared with it
    because that function's other job is to word a benign-gate refusal.

    TWINS — a competing declarer carrying the SAME anchor kind — discharge NOTHING, which is
    the arm `_authz_contract_error` states first: "a `:R authz` row names only the contract it
    fulfills, so no row can be attributed to this one and none discharges it". Reading the
    shared kind as a discharge instead makes one row answer two questions, and
    `_check_authz_contract_ids` deliberately exempts a collision whose other side is refuted —
    exactly the shape this rule covers and the benign gate does not — so the live hypothesis's
    row would silently close the refuted one's unrelated question. `outstanding_authz_contracts`
    names that second reading as the harmful one; the two now give the same answer.
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

    The BARE id in `fulfills`, the qualified one in the deferral row. That is not a cosmetic
    difference: `_check_benign_authz` matches `fulfills_contract` on the bare `ac<n>` alone, so
    advising `fulfills=h-001.ac1` would name a row that clears THIS rule and leaves the benign
    gate blocked.

    When the id is SHARED, the anchor kind is named too — `_discharged_by_row` requires it, and
    a repair that omits the discriminating column reads as already done to an author who has
    written the plain row. When it is shared with a declarer carrying the SAME kind, no row can
    be attributed at all, and saying so is the only honest repair besides the deferral the
    refusal already offers.
    """
    plain = f"fulfil it with a `:R authz` row carrying `fulfills={c.local_id}`"
    mine, competing = _declarer_kinds(c, declarers)
    if not competing:
        return plain
    twins = sorted(mine & competing)
    if twins:
        # The QUALIFIED spelling, because it is the one this rule actually accepts:
        # `_check_authz_contract_closure` resolves `c.ref in qualified`, so `fulfills={c.ref}`
        # discharges a twin that no bare id could. Advising "renumber it" alone would be a
        # repair the author cannot make — `:H` rows are append-only — on the one shape where a
        # legal repair exists. `_check_benign_authz` still matches the bare form, so the bare
        # row is named too; a document that owes both writes both.
        return (
            f"fulfil it with a `:R authz` row carrying `fulfills={c.ref}` — {c.local_id} is "
            f"also declared on another hypothesis under anchor kind {twins[0]!r}, so the bare "
            f"id names no one contract and only the qualified `h-NNN.ac<n>` form says which "
            f"question the row answered (`ac<n>` numbers across the DOCUMENT, so the durable "
            f"fix is not to share one)"
        )
    # `mine` cannot be empty here: `c` came from the same `all_hypotheses` walk that built
    # `declarers`, under the same guard, so its own `(owner, kind)` pair is always in it — an
    # empty anchor kind still contributes `{""}`.
    return (
        f"{plain} AND `anchor_kind={sorted(mine)[0]}` — {c.local_id} is declared on more than "
        f"one hypothesis, so the anchor kind is what says which question the row answered"
    )


def _check_authz_contract_closure(
    companion: CompanionBody, *, gated: set[str] | None = None
) -> list[str]:
    """Every declared `:H h-NNN.authz` contract is fulfilled by a `:R authz` row, or deferred
    in `:T conclude.deferred_authz` with a reason.

    The orphan-contract gate. `_check_benign_authz` already refuses an unresolved contract, but
    only on a LIVE hypothesis and only under `disposition: benign` — so every escalation path
    accepted orphans in silence, and in the pre-v2.10 corpus 59% of declared contracts had no
    resolution at all. A contract is a question the run committed to asking; dropping it
    quietly is how a legitimacy question stops existing.

    DELIBERATELY broader than `_check_benign_authz` in two directions, and both come from the
    spec text. It runs under every disposition, and it covers contracts on REFUTED hypotheses
    too — refutation is offered as a deferral RATIONALE ("superseded by mechanism refutation at
    lead l-007"), not as an automatic discharge, because "the mechanism was refuted so its
    authorization question is moot" is a claim about the case that a reader should be able to
    see the run make.

    DEFERS to the run's own disposition gate on any contract that gate is ALREADY refusing. The
    two would otherwise report one missing `:R authz` row twice, and the second report would be
    actively misleading: this rule offers "defer it with a rationale" as a repair, and on a
    `disposition: benign` document that repair clears this rule and leaves benign blocked —
    a fix that does not fix the document. The gate's refusal names the same contract with the
    sharper consequence and the only repair that works, so it is the one that speaks.

    Matched on the gate's OUTPUT, not on the disposition keyword. `outstanding_authz_contracts`
    is the shared definition of "still open" and hands back the exact string the gate emits, so
    a price added to `_DISPOSITION_GATES` that also refuses contracts is deferred to with no
    edit here — where a `== "benign"` test would leave the next one double-reporting. The
    gate's output is HANDED IN by `diagnose`, which already ran it this pass; the `gated=None`
    default re-runs it for a direct caller and is what every test in the tree reaches.

    Fulfilment is read by id, with no verdict condition: an `unauthorized` row settles the
    question, and what that verdict then costs the document is the benign gate's business. A
    SHARED `ac*` id is scoped by ANCHOR KIND, the same discrimination `_authz_contract_error`
    applies, and `outstanding_authz_contracts`' docstring names the alternative as the harmful
    one: "a second reading of 'discharged' — a bare `fulfills_contract` id set, say — silently
    disagrees with this one on every shared id". `_check_authz_contract_ids` refuses two LIVE
    declarers of one id but deliberately exempts a collision whose other side is refuted —
    which is exactly the shape this rule covers and the benign gate does not, so a bare-id
    reading would let the live hypothesis's `:R authz` row discharge the refuted one's
    unrelated question. That is the automatic discharge the paragraph above says the rule does
    not grant.

    `resolved` is spelled QUALIFIED for the same reason. The shared walk also accepts a bare
    `local_id`, which is right for the deferral table (the SKILL teaches the bare form there)
    and wrong here: `_check_benign_authz` matches `fulfills` bare only after scoping it, and
    handing the walk a bare set would reintroduce the cross-owner discharge one layer down.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    # HANDED IN by `diagnose`, which already ran the gate this pass — re-running it here made
    # this the most expensive check in the validator, and the re-run is by far the larger half
    # of its cost on a `benign` document (`_check_benign_grounding` + `_check_benign_open_slots`
    # + `_check_benign_authz`, itself three `all_hypotheses` rebuilds). The default keeps the
    # function callable on its own, which is how every test in the tree reaches it.
    if gated is None:  # lint-default: ok — the standalone fallback; `diagnose` binds it
        gated = set(_check_disposition_gating(companion))
    # Guarded on `gated`: only a priced disposition can put a contract in it, and
    # `outstanding_authz_contracts` is three `all_hypotheses` rebuilds plus two lead walks —
    # otherwise computed in full and then filtered away by an empty set on every other close.
    spoken_for = {
        f"{hid}.{_cell(c, 'id')}"
        for hid, c, why in outstanding_authz_contracts(companion)
        if why in gated
    } if gated else set()
    declarers = _declarers_by_contract_id(companion)
    kinds_by_id: dict[str, set[str]] = {}
    #: `fulfills=h-001.ac1` — spec rule #7's QUALIFIED spelling ("`fulfills_contract` of shape
    #: `h-{id}.ac{n}` points to a hypothesis whose `authorization_contract` declares that
    #: `ac{n}`"), which `docs/dense-investigation-format.md` also calls the correct shape. The
    #: SKILL teaches the bare form and `_check_benign_authz` matches only that, so the bare one
    #: is what this rule ADVISES — but refusing the qualified one would deny a close for a
    #: contract the run answered, in the spelling the spec blesses. Kept in its own set rather
    #: than folded into `kinds_by_id`: a qualified row names its own declarer, so it discharges
    #: that contract and never another hypothesis's `ac1`.
    qualified: set[str] = set()
    for row in _walkers.iter_authz_resolutions(companion):
        # Through `_cell`, which unquotes — the read every other cell this rule compares gets.
        # `_canonicalize_resolution_row` copies the `fulfills` cell verbatim, as
        # `_hyp_sub_authz_row` does the `id` it is matched against — BOTH sides are read
        # through `_cell` for that reason. Read raw, a uniformly quoted row keys `'"ac1"'`
        # here, matches no declared `ac1`, and the refusal tells the author to write the row
        # they just wrote. Before the closure gate that only cost a `benign` close
        # (`_check_benign_authz`); now it costs every close.
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

    Rule #26's orphan gate on the impact axis, and #31's own text says so. The failure is the
    same one: a predicate registered at PREDICT and never graded lets a run choose, after the
    fact, which of its own consequence thresholds to be measured against.

    ACROSS ALL LEADS, including a lead whose query failed. A predicate registered on a lead
    that never came back is exactly what the deferral arm is for ("the query errored before the
    measurement landed"), so the wider reading costs nothing and needs no concept the format
    does not already have — where exempting failed leads would need a rule about which
    `failure_reason` values excuse a predicate.

    The second half is the ROLL-UP PAIR, and only its PRESENCE. `impact_severity` is required
    exactly when the verdict is `exceeds` or `indeterminate` and forbidden otherwise, because
    severity is the magnitude of a consequence the run is CLAIMING: a severity beside `within`
    claims a magnitude for something that stayed inside its threshold, and a missing one beside
    `exceeds` escalates without saying how far. That is structural — it holds whatever the two
    cells say — which is why it ships while neither cell's VOCABULARY does.

    NOT checked, three times over, and all three for reasons at their sites. Neither conclude
    scalar's enum is enforced: `skills/invlang/SKILL.md` has never stated either vocabulary, so
    refusing on one refuses a run for a rule the model was never given — the failure spec rule
    #32 was struck for. And whether the roll-up is ARITHMETICALLY right — `exceeds` beside
    three `within` rows — needs the rows, and no document in the tree carries any; computing an
    aggregate from rows that do not exist yet is a check with no way to be wrong.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    resolved: set[str] = set()
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            # `_cell` + `_qualify`, both shared with `_check_impact_resolution_refs`, so the
            # two rules cannot resolve one `pred_ref` to two different strings and report a
            # predicate as graded and abandoned at once.
            ref = _cell(row, "prediction_ref") if isinstance(row, dict) else ""
            if ref:
                resolved.add(_qualify(lid, ref))
    # The SAME index `_check_impact_resolution_refs` resolves against, not a second walk with
    # the same guard written out again: what counts as a declared `ip*` is one question.
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

    # `conclude.impact_verdict`'s ENUM is measured and NOT armed. `vocab.CONCLUDE_IMPACT_VERDICT`
    # exists so the SKILL and this comment can name it, and nothing refuses on it yet. It fires on
    # BOTH shipped e2e goldens — `golden-v2sshd` writes `none-detected` and
    # `golden-sshpivot-ab3` writes `attempted-lateral-movement`, where the spec's roll-up over
    # zero `:R impact` rows is `none` in both cases. Those two are not authored fixtures whose
    # cell can be corrected: they are RECORDED runs replayed through this very gate from
    # `tool_trace.jsonl`, so arming this refuses the recorded write and takes seven e2e tests
    # with it, and "repairing" them means rewriting a trace of what a model actually wrote.
    #
    # The cause is upstream of the fixtures. `skills/invlang/SKILL.md` writes `impact_verdict
    # none` in one worked example and states no vocabulary, so both runs filled a
    # free-text-looking slot with prose and neither disobeyed anything. The order this has to
    # land in is teach, then re-record, then arm — and the first step ships here.
    #
    # `impact_severity`'s MEMBERSHIP is unenforced for the same reason and by the same rule:
    # `vocab.IMPACT_SEVERITY` is registered so `enum conclude.impact_severity` can teach it,
    # and no check refuses on it. It measures zero fires today — no document writes the cell at
    # all — but enforcing a vocabulary the runtime prompt has never stated is the same mistake
    # whether or not it happens to bite yet, and the two conclude scalars are one decision.
    #
    # The conditional-presence clause below does NOT depend on either membership test. An
    # unrecognized verdict is simply not in `_SEVERITY_OWING`, so a severity beside it is
    # forbidden and a missing one is not demanded — which is the correct reading of a run that
    # rolled up to something the enum does not name.
    verdict = conclude.get("impact_verdict")
    severity = conclude.get("impact_severity")
    # BOTH cells normalized the same way, and the verdict is the half that used to be read raw.
    # `_project_conclude_scalars` `_unquote`s a scalar without re-stripping, so
    # `impact_verdict "exceeds "` reaches here with its padding and `Exceeds` reaches here with
    # its case — and a raw membership test then reads either as a verdict claiming nothing,
    # refusing the run for the `impact_severity` the SKILL just told it to write. One reading
    # for the pair, because the pair is one clause.
    verdict_key = _cell(conclude, "impact_verdict").lower()
    # `null` is the format's own word for "no severity", so it is an ABSENT severity here and
    # not a present one — the same reading `_project_conclude_scalars` gives the bare token.
    # Case-FOLDED, like `is_conclude_empty_marker` beside it: a case-sensitive test makes
    # `impact_severity NULL` a present severity that satisfies `exceeds` while saying there is
    # none, so the one spelling that should be refused hardest is the one that validates clean.
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


#: The `conclude.impact_verdict` values that OWE an `impact_severity` — the ones where the run
#: is CLAIMING a consequence, so the severity says how large. Subtracted from the row-level
#: verdict enum rather than restated: `within` is the one member that claims none, and the
#: conclude-only `none` is not in that enum at all, so both fall out for the right reason
#: instead of by being left off a hand-written pair.
_SEVERITY_OWING: frozenset[str] = frozenset(vocab.IMPACT_VERDICT) - {"within"}


def _check_prediction_closure(companion: CompanionBody) -> list[str]:
    """Every `p*`/`ap*` on a hypothesis the run is still carrying was settled by some
    resolution, or deferred in `:T conclude.deferred_preds` with a reason.

    The contract ANALYZE owes PREDICT. PREDICT pre-commits a prediction set precisely so the
    grading cannot be chosen after the evidence lands; without a closure gate, ANALYZE cites
    the two predictions that came in and the other three are never heard from again, and no
    reader of the finished document can tell they existed.

    The late half of a pair. `_check_prediction_completeness` (spec #6) asks the same question
    at WRITE time and only of a hypothesis STANDING at `++` (`_confirmed_and_standing`, the one
    predicate that partitions the two), and offers no deferral — a standing `++` claims every
    prediction came in, so there is nothing outstanding to defer. This asks it of every weight, at
    CONCLUDE, and offers the deferral because at that point "the tool was never available" is a
    true and final answer.

    The discharge besides citation is read off the RESOLUTION RECORD rather than the `status`
    column the spec's wording names. `status` is a `:H` cell fixed at declaration time and
    append-only forbids updating it, so it can never carry a FINAL status; the run says
    "refuted" by moving the weight to `--`. That is the same translation
    `_check_hypothesis_persistence` applies to spec #24 — and since #933 retired `:T shelved`,
    the two rules read one word, not two.

    A citation only counts from a resolution with a non-null `after`. A row that cites `p1` and
    moves nowhere has recorded that the lead looked, not that the prediction settled — and
    `_walkers.final_weights` would read that row as the hypothesis's final position anyway.

    Scoped to the hypothesis that declared the prediction, never document-wide: a sibling's
    `p1` discharges nothing here, which is the cross-citation rule #25 refuses one level down
    and `_check_prediction_refs` enforces on the citing row.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    # ONE DEFINITION with rule #6's (`_settled_predictions`), so the write gate and the closure
    # gate cannot disagree about which citations count — a disagreement leaves the author
    # DEFERRING a prediction on a `++` that claims none is outstanding. Not one WALK: the two
    # rules run in separate passes and each folds it.
    resolved = {
        f"{hid}.{pid}"
        for hid, pids in _settled_predictions(companion).items()
        for pid in pids
    }
    weights = _walkers.final_weights(companion)
    # DEFERS to rule #6 on any hypothesis STANDING at `++`, the way
    # `_check_authz_contract_closure` defers to the disposition gate — and for the identical
    # reason. `_check_prediction_completeness` already refuses every uncited prediction on a
    # `++`, and offers no deferral because, as the docstring above says, "a `++` claims every
    # prediction came in, so there is nothing outstanding to defer". Reporting it here too
    # hands the author a repair (`:T conclude.deferred_preds`) that clears THIS rule and leaves
    # #6 refusing — a fix that does not fix the document, and one that then sits on disk as a
    # deferral contradicting the run's own `++`.
    #
    # TWO DIFFERENT READINGS, and the difference is a known gap rather than a design.
    # `weights` is `_walkers.final_weights`, last-move-wins by LEAD-DECLARATION order over the
    # raw `after` cell; the predicate counts `++` entries against exits per row and is
    # order-free. They agree on any document whose `:T resolutions` blocks follow their leads,
    # and disagree on one that does not — where this rule can call a hypothesis the document
    # refuted a "live" one, or skip as refuted one the document still carries. Fixing it wants
    # `final_weights` itself to fold in append order, which is eight readers wide; see the note
    # on `_walkers.final_weights`.
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
