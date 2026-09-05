"""History and weight: what the document already committed, and what a move is allowed to
say about it.

One family of `validate.py`'s rules, split out at 4038 lines: the append-only comparison
against the committed baseline, the provenance a strong move owes, and which of a
hypothesis' predictions the run actually settled.
"""
from __future__ import annotations

import re
from typing import Any

from .. import _walkers, vocab
from ..parser import (
    is_conclude_empty_marker,
    scan_fences,
)
from ..schema import (
    CompanionBody,
    EdgeRecord,
    HypothesisRecord,
    VertexRecord,
)
from ._diag import CONFIRMED_WEIGHT, STRONG_AUTH_KINDS, STRONG_WEIGHTS, _STRONG_AUTH_KINDS_STR
from ._refs import _declared_prediction_ids, _known_ids, _normalized_claim


def _vertex_core(v: VertexRecord) -> tuple:
    return (v.get("type"), v.get("classification"), v.get("identifier"))


def auth_kind_of(e: EdgeRecord) -> str | None:
    """An `:E` row's authority kind, or `None`. PUBLIC because `frontier._edge_index` keys the
    lesson EDGE axis on it and a second `e["authority"]["kind"]` spelling could drift."""
    auth = e.get("authority")
    return auth.get("kind") if auth else None


def _edge_core(e: EdgeRecord) -> tuple:
    return (
        e.get("relation"),
        e.get("source_vertex"),
        e.get("target_vertex"),
        auth_kind_of(e),
    )


def _by_id_first(records, core_fn) -> dict[str, tuple]:
    idx: dict[str, tuple] = {}
    for r in records:
        rid = r.get("id")
        if isinstance(rid, str) and rid not in idx:
            idx[rid] = core_fn(r)
    return idx


def _check_append_only(
    proposed_text: str,
    current_text: str | None,
    proposed: CompanionBody | None,
    current: CompanionBody | None,
) -> list[str]:
    if current_text is None:
        return []
    errors: list[str] = []

    cur_fences = len(scan_fences(current_text).bodies)
    new_fences = len(scan_fences(proposed_text).bodies)
    if new_fences < cur_fences:
        errors.append(
            f"append-only violation: proposed content has {new_fences} ```invlang "
            f"block(s) but the on-disk file has {cur_fences} — existing blocks must "
            f"not be removed (defender SKILL §Authoring discipline: append only)"
        )

    if not current:
        return errors

    proposed = proposed or CompanionBody()
    for label, records_cur, records_new, core_fn in (
        ("vertex", _walkers.all_vertices(current), _walkers.all_vertices(proposed), _vertex_core),
        ("edge", _walkers.all_edges(current), _walkers.all_edges(proposed), _edge_core),
    ):
        cur_idx = _by_id_first(records_cur, core_fn)
        new_idx = _by_id_first(records_new, core_fn)
        for rid, core in cur_idx.items():
            if rid not in new_idx:
                errors.append(
                    f"append-only violation: committed {label} {rid} present "
                    f"on-disk is missing from the proposed write — existing "
                    f"records must not be removed"
                )
            elif new_idx[rid] != core:
                errors.append(
                    # NAMES THE BLOCK. `_check_append_only` is in `structural_diagnostics`, so
                    # `record`'s round loop retries on this refusal and feeds it straight back
                    # to the clerk as "read this and fix it" — the clerk's only guidance for
                    # the retry. D15's verb purge took `:R attr_updates` out along with the
                    # verb names, leaving the one reader who acts on it unable to tell which
                    # block to emit. The block is a locus, not a verb: naming it is what D15
                    # permits and what the retry needs.
                    f"append-only violation: committed {label} {rid} was "
                    f"mutated in place ({core} → {new_idx[rid]}) — record the refinement as a "
                    f"new `:R attr_updates` observation row, never by rewriting the original "
                    f"declaration"
                )
    return errors




def _check_strong_move_provenance(companion: CompanionBody) -> list[str]:
    """Both halves of a strong move's provenance tuple, in one walk: WHICH observation it
    rests on, and WHICH pre-committed claim that observation settled. One walk so a row
    missing both reports both together.

    The citation half catches how the ids go missing in practice: the head is
    `[<lead> <ids…> <severity> ⟂ <edges>]` with severity positional-last, so a row that omits
    severity has its ids read as the severity and parses as citing nothing —
    `h-002 null → ++ [l-001 p1,p2,p3 ⟂ e-002]` writes three predictions and binds none.
    """
    auth_by_edge: dict[str, str] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        kind = auth_kind_of(e)
        if isinstance(eid, str) and isinstance(kind, str):
            auth_by_edge[eid] = kind

    errors: list[str] = []
    for lid, res in _walkers.iter_resolutions(companion):
        # Through `_resolution_move`, the one owner of "what did this row move the hypothesis
        # to". Read raw here and closed there, this gate and rule #6's would answer the same
        # question two ways — the disagreement `_resolution_move`'s docstring says it prevents.
        after = _resolution_move(res)
        if after not in STRONG_WEIGHTS:
            continue
        hyp = res.get("hypothesis", "?")
        if not (res.get("matched_prediction_ids") or res.get("matched_refutation_ids")):
            errors.append(
                f"lead {lid}: resolution of {hyp} to "
                f"{after!r} cites no prediction or refutation id — a strong (++/--) "
                f"move must name the `p*`/`ap*`/`r*` it turned on, in the "
                f"`[<lead> <ids> <severity> ⟂ <edges>]` head"
            )
        supporting = [s for s in (res.get("supporting_edges") or []) if isinstance(s, str)]
        if not supporting:
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites no "
                f"supporting edge — a strong (++/--) resolution must cite at "
                f"least one {_STRONG_AUTH_KINDS_STR} edge"
            )
            continue
        if not any(auth_by_edge.get(s) in STRONG_AUTH_KINDS for s in supporting):
            seen = sorted({auth_by_edge.get(s, "<unknown>") for s in supporting})
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites "
                f"{supporting} but none carry strong observational authority "
                f"(found: {seen}); ++/-- needs {_STRONG_AUTH_KINDS_STR}"
            )
    return errors




def _resolution_move(res: Any) -> str:
    """The bucket a `:T resolutions` row moved its hypothesis TO, or `""` for no move.

    Closed on `vocab.WEIGHT_BUCKETS` rather than open on "anything that is not a null
    spelling". The `after` cell is an unvalidated `\\S+` — `_RESOLUTION_LINE_RE` reads whatever
    token sits there and no check compares it to the bucket list — so an allow-by-default test
    makes an off-vocabulary token the CHEAPEST row in the language: `h-001 null → confirmed`
    settles every prediction it cites (rule #34), skips the strong-provenance gate (which fires
    on `STRONG_WEIGHTS`) and skips the `++` coverage gate (which fires on `CONFIRMED_WEIGHT`),
    where the honest `null` is refused for the predictions it leaves open. One typo, or one
    deliberate misspelling, is strictly better for the author than telling the truth.

    Both readers of "did this row move the hypothesis" take this answer, so the write gate
    (rule #6) and the closure gate (rule #34) cannot disagree about which citations count —
    the disagreement `_check_prediction_completeness` describes and nothing enforced.
    """
    if not isinstance(res, dict):
        return ""
    after = (res.get("after") or "").strip()
    return after if after in vocab.WEIGHT_BUCKETS else ""


#: A prediction id the row's own `⟺` annotation puts under a NEGATION — `¬p2`, or its ASCII
#: fallback `~p2`. `parser._extract_iff_literals` files it in `matched_prediction_ids` on
#: purpose: that field means "this lead TESTED the id", and polarity is attribution-neutral
#: (`test_invlang_parser.test_resolution_negated_iff_literal_still_attributes`). Rule #6 asks
#: a different question — did the prediction COME IN — and the two answers are opposite on
#: exactly this token, so the rule subtracts what the row says did not materialize rather than
#: the parser changing what the field means for everyone.
_NEGATED_LITERAL_RE = re.compile(r"[¬~]\s*(ap\d+|p\d+|r\d+)\b")


def _contradicted_predictions(res: Any) -> set[str]:
    """The `p*`/`ap*` a resolution's own annotation says did NOT materialize."""
    reasoning = res.get("reasoning") if isinstance(res, dict) else None
    if not isinstance(reasoning, str):
        return set()
    return {
        tok for tok in _NEGATED_LITERAL_RE.findall(reasoning.replace("<=>", "⟺"))
        if not tok.startswith("r")
    }


def _refutation_scopes(hyp: HypothesisRecord) -> dict[str, set[str]]:
    """Per `r*` this hypothesis declares, the `p*`/`ap*` its `refutes` cell names."""
    return {
        shape["id"]: {
            pid for pid in shape.get("refutes_predictions") or []
            if isinstance(pid, str) and pid and not is_conclude_empty_marker(pid)
        }
        for shape in hyp.get("refutation_shape") or []
        if isinstance(shape, dict) and isinstance(shape.get("id"), str)
    }


def _settled_predictions(companion: CompanionBody) -> dict[str, set[str]]:
    """Per hypothesis, the `p*`/`ap*` ids some resolution cited on a row that MOVED it.

    A `null → null` row that cites `p1` recorded that the lead looked, not that the prediction
    settled. See `_resolution_move` for why the move test is closed on the bucket vocabulary.

    A cited `r*` counts for the predictions IT names. `_check_strong_move_provenance` already
    reads `matched_refutation_ids` as the same half of a strong move's provenance tuple that
    `matched_prediction_ids` is — a refutation shape that was tested and failed to materialize
    settles the predictions it would have overturned — and reading only the `p*` side here
    leaves a `++` whose evidence is a dead refutation with exactly one spelling that clears
    the gate: citing the prediction as MATCHED, which is a claim the run did not make.

    A NEGATED literal does not settle its prediction. `matched_prediction_ids` means "this
    lead tested the id" and files `¬p2` alongside `p1`, which is right for attribution and
    inverted for this rule — so `⟺ p1 ∧ ¬p2` would otherwise clear a `++` on the strength of
    an annotation saying one of the two predictions did not come in.
    """
    matched: dict[str, set[str]] = {}
    hyps = _walkers.all_hypotheses(companion)
    scopes_by_hyp: dict[str, dict[str, set[str]]] = {}
    for _lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if not isinstance(hid, str) or not _resolution_move(res):
            continue
        hyp = hyps.get(hid)
        if hid not in scopes_by_hyp:
            scopes_by_hyp[hid] = _refutation_scopes(hyp) if hyp is not None else {}
        scopes = scopes_by_hyp[hid]
        row: set[str] = {
            p for p in res.get("matched_prediction_ids") or [] if isinstance(p, str) and p
        }
        for rid in res.get("matched_refutation_ids") or []:
            row |= scopes.get(rid, set()) if isinstance(rid, str) else set()
        # THIS row's negations against THIS row's citations, before the union. Subtracting from
        # the accumulated set instead would let a later row's `¬p1` un-settle a prediction an
        # earlier move settled — the union only grows, which is what keeps the rule repairable
        # on an append-only document.
        matched.setdefault(hid, set()).update(row - _contradicted_predictions(res))
    return matched


def _confirmed_and_standing(companion: CompanionBody) -> dict[str, str]:
    """Per hypothesis STANDING at `++`, the FIRST lead whose resolution moved it there.

    THE HANDOFF between rules #6 and #34, and one definition so the two cannot both stand down
    on the same hypothesis. #6 owns a hypothesis standing at `++` and refuses every uncited
    prediction on it; #34 owns everything else not refuted and offers a deferral. Split across
    two spellings — one on "stands at `++`" and one on "some row moved it to `++`" — a
    hypothesis confirmed and later withdrawn falls in the gap between them, and its uncited
    predictions are never asked about by either.

    STANDING, not EVER `++`, because the second is not a fact an append-only document can
    repair. A `++` is a claim about the predictions declared when it was written, and
    `:H h-NNN.preds` is appended: the moment a later block declares one more, a row committed
    to disk becomes a `++` that does not cover its own hypothesis, and no write can reach back
    into it. Reading the withdrawal makes the repair the message offers a real one — appending
    `h-NNN ++ → +` says the run is no longer claiming full coverage, which is what an author
    who has just declared an untested prediction means.

    STANDING IS COUNTED, NOT ORDERED, and the counting is the whole of why this is correct.
    Each row is read for whether it ENTERS `++` (`after` is `++`, `before` is not) or LEAVES it
    (`before` is `++`, `after` is not); the two are edge-triggered, so a `++ → ++` restatement
    is neither. On a chain whose rows join up — every `before` the previous row's `after` —
    entries and exits alternate, so the net is 1 exactly when the last row left the hypothesis
    at `++` and 0 otherwise. That is the same answer a last-move-wins fold gives, computed
    without needing an order the projection does not carry.

    NOT `_walkers.final_weights`, and not a SET of "was it ever withdrawn" either. The walker
    resolves last-move-wins by LEAD-DECLARATION order, not by append order — its own docstring
    says so — so on any document with more than one lead a withdrawal attributed to an
    earlier-declared lead loses to a `++` attributed to a later-declared one, and the write the
    refusal asks for is silently ignored. A withdrawal SET fixes that and breaks the other
    direction: `++ → +` followed by `+ → ++` re-asserts the claim, and a set that only records
    "withdrawn once" stands the rule down for the rest of the document — a two-row exemption
    from #6 on a hypothesis the document still grades `++`. Counting is the reading that
    survives both, because it is order-free AND it hears the re-confirmation.

    A NULL `after` leaves too. `++ → null` and `++ → ∅` are legal weight cells and both say the
    run stopped standing behind the grade, which is exactly what `++ → +` says with a number on
    it. What follows is rule #34's business at CONCLUDE, where a non-refuted hypothesis owes
    every declared prediction a citation or a deferral — so leaving `++` moves the question, it
    never discards it.

    BOTH CELLS READ CLOSED, on `vocab.WEIGHT_CELL_VALUES`. An off-vocabulary `after` — the
    `h-001 ++ → confirmd` typo `_resolution_move`'s docstring calls the cheapest row in the
    language — moves nothing, so it must not count as leaving `++` either; read open, one
    misspelling switched this rule off and left only `_check_vocab_weights` speaking. The
    ENTRY side goes through `_resolution_move`, which is this module's one owner of "what did
    this row move the hypothesis to".

    KNOWN AND NOT REFUSED: a `++` entered and left inside the block that wrote it (`null → ++`
    and `++ → +` in one `:T resolutions`) is a grade that never stood, and this counts it out
    like any other exit. #34 still asks for the predictions at CONCLUDE, so nothing escapes
    accounting; what does persist is a `++` row on disk that
    `runtime/review/projector.ablation_target` still counts as a strong move. Refusing it wants
    its own rule about rows that annihilate within a block, not a special case here.

    ALSO KNOWN: an exit whose `before` cell is a LIE. `_check_vocab_weights` is the only other
    reader of `before` and it checks the token, never whether it is the weight the previous row
    left — so `h-001 ++ → +` written when nothing ever graded h-001 `++` cancels the real `++`
    that follows it, and the count reads zero. Clamping the count at zero would close it and
    reopen the wedge: the clamp is order-sensitive, and a withdrawal attributed to an
    earlier-declared lead would be discarded again. The closable form is a CONTINUITY rule on
    `before` — a resolution starts where the last one on that hypothesis left off — which makes
    the cell trustworthy for every reader rather than for this count alone.

    ALSO OUTSIDE IT: a `:H` row DECLARED at `++` that no resolution ever moves. No row enters,
    so the count is zero and the hypothesis is invisible to #6 and handed to #34, which offers
    it a deferral for every prediction it declared — a deferral beside a standing `++`, which
    is the shape the partition exists to prevent. That is a gap, not a design; closing it wants
    the `:H` weight seeded as the starting position, which is a change to what "moved" means
    for every rule that reads a resolution row.
    """
    confirmed: dict[str, str] = {}
    net: dict[str, int] = {}
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if not isinstance(hid, str):
            continue
        entered = _resolution_move(res) == CONFIRMED_WEIGHT
        if entered:
            confirmed.setdefault(hid, lid)
        # RAW like `_resolution_move` and `_check_vocab_weights`, the other two readers of
        # these cells, so one quoting convention governs all three; and edge-triggered, so
        # `++ → ++` is a restatement rather than a move.
        before = (res.get("before") or "").strip()
        after = (res.get("after") or "").strip()
        if entered and before != CONFIRMED_WEIGHT:
            net[hid] = net.get(hid, 0) + 1
        elif (
            before == CONFIRMED_WEIGHT
            and after != CONFIRMED_WEIGHT
            and after in vocab.WEIGHT_CELL_VALUES
        ):
            net[hid] = net.get(hid, 0) - 1
    return {hid: lid for hid, lid in confirmed.items() if net.get(hid, 0) > 0}


def _check_prediction_completeness(companion: CompanionBody) -> list[str]:
    """A hypothesis graded `++` has settled every prediction it declared, not only the ones
    the confirming lead happened to look at.

    `_check_strong_move_provenance` stops one line short of this. It refuses a `++` that cites
    NOTHING and accepts one that cites `p1` out of five — so a hypothesis reaches "confirmed"
    on whichever fifth of its own pre-commitments the lead found convenient, and the four it
    never looked at are never heard from again. Partial coverage is what `+` is for.

    The union is taken over EVERY resolution on the hypothesis, not only the `++` row: a
    prediction an earlier `+` move already settled is settled.

    BOTH sides of the comparison grow, which is what the rule has to survive. The cited side
    growing is harmless — a write that clears the gate clears it for good. The DECLARED side
    growing is not: `:H h-NNN.preds` arrives by append, so declaring one more prediction on a
    hypothesis already carrying a committed `++` turns that row into a `++` that no longer
    covers its own hypothesis, and `:H` rows cannot be rewritten. `_confirmed_and_standing` is
    what makes that repairable — the rule asks whether the hypothesis STANDS at `++`, so
    appending `h-NNN ++ → +` withdraws the claim and clears the refusal. Reading "some row
    once said `++`" instead leaves a document with no legal next write.

    `ap*` counts toward the set. `_declared_prediction_ids` is this module's one answer to
    "what did the hypothesis declare", and its other two readers take the union; rule #34 — the
    late closure gate this is the early half of — enumerates `p*` and `ap*` alike. Reading only
    `p*` here would let an author take an observable out of the gate by declaring it under
    `.attr_preds`, which is a formatting choice and not an evidentiary one.

    NOT the closure gate. Rule #34 asks the same question of every weight at CONCLUDE and
    offers `conclude.deferred_predictions[]` as the answer to "that one could not be checked".
    This fires at write time on a hypothesis STANDING at `++` alone and offers nothing,
    because a standing `++` has no outstanding prediction to defer — the grade IS the claim
    that there is none. The two halves of that partition are one predicate
    (`_confirmed_and_standing`) so they cannot drift apart; the pre-v2.22 spelling was "any row
    ever wrote `++`", under which a confirmed-then-downgraded hypothesis belonged to #6 and now
    belongs to #34.
    """
    confirmed_at = _confirmed_and_standing(companion)
    if not confirmed_at:
        # Before the two document-wide folds below, which are the whole remaining cost of this
        # check. The predicate above is one `iter_resolutions` walk whatever the answer, so no
        # hypothesis standing at `++` — every in-flight document up to the confirming lead,
        # every run that never confirms, and every run that withdrew — stops here.
        return []
    hyps = _walkers.all_hypotheses(companion)
    matched = _settled_predictions(companion)

    errors: list[str] = []
    for hid, lid in confirmed_at.items():
        hyp = hyps.get(hid)
        if hyp is None:
            # `_check_hypothesis_refs` owns the undeclared-`h-*` defect. REACHED, not
            # defensive: `_confirmed_and_standing` walks resolution rows and keys on the `h-*`
            # each row names, with no test against the declared set — so `h-999 null → ++`
            # beside a `:H` block that never declares h-999 arrives here. A phantom declares no
            # predictions, so the coverage question is vacuous and its answer misleading.
            continue
        declared = _declared_prediction_ids(hyp)
        cited = matched.get(hid, set())
        unmet = declared - cited
        if unmet:
            errors.append(
                f"lead {lid}: resolution of {hid} to {CONFIRMED_WEIGHT!r} leaves "
                f"{_known_ids(unmet)} unmatched — {CONFIRMED_WEIGHT!r} says every prediction "
                f"the hypothesis declared came in, and the resolutions on {hid} cite "
                f"{_known_ids(cited & declared)} of {_known_ids(declared)}; cite the rest in "
                f"a resolution that moves {hid}, or withdraw the coverage claim by appending "
                f"`{hid}  {CONFIRMED_WEIGHT} → +   [{lid} <ids> <severity> ⟂ <edges>]` to a "
                f"`:T resolutions` block — head filled in from the row that graded it — to "
                f"grade it partial coverage"
            )
    return errors


_ATTR_PRED_TARGETS = vocab.ATTR_PRED_TARGETS
_ATTR_PRED_ID_RE = re.compile(r"ap\d+")


def _check_attribute_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:H h-NNN.attr_preds` rows, checked for the three things the parser does not check.

    `_hyp_sub_attr_pred_row` `_require`s `id`, `target` and `attribute` to be non-blank and
    stops there — whatever those cells SAY, the row is projected. So `a1|the parent|colour|`
    parses clean and lands an attribute prediction whose id is outside the namespace every
    citation site resolves against, whose target names no object the hypothesis has, and whose
    claim predicts nothing.

    The id shape is the load-bearing one. `matched_prediction_ids` and
    `refutation_shape[].refutes_predictions` both resolve against the union
    `_declared_prediction_ids` builds, so an id spelled `a1` can be cited by nobody.

    UNIQUENESS is not checked here, because it cannot be violated by the time this reads the
    record. Rule #33's "unique within the hypothesis" is already enforced one level up in two
    places: `_warn_repeated_ids` makes a repeat WITHIN one `.attr_preds` block a parse error,
    and `_extend_by_id` keys accumulation by id, so a repeat ACROSS blocks never reaches the
    projected list — and must not be refused either, since re-emitting a sub-block with one row
    added is the documented append shape (`test_invlang_hypothesis_accumulation`). A check here
    would be dead code that read as live.

    NOT checked: the one-observable-per-entry clause. "Compound `AND` / `OR` predicates split
    into separate entries" is a judgment about what a sentence asserts, not a property of the
    row — a lexical `" and "` test would refuse "the process and its parent share a cgroup",
    which is one observable. Rule #29 leaves the same clause to the author on
    `impact_predictions[]`, for the same reason.
    """
    errors: list[str] = []
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for ap in hyp.get("attribute_predictions") or []:
            if not isinstance(ap, dict):
                continue
            apid = ap.get("id") or "?"
            if not _ATTR_PRED_ID_RE.fullmatch(apid):
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: an attribute prediction is numbered "
                    f"`ap<n>` — `matched_prediction_ids` and `.refuts` resolve ids in that "
                    f"namespace, so one outside it can be cited by nothing"
                )
            # Lowercased, because `_predicted_observables` lowercases the same cell into rule
            # #23's fork key. Compared raw, `Proposed_Parent` is the canonical target to one
            # rule and an illegal one to the other, in the same pass over the same row.
            target = ap.get("target")
            if str(target).strip().lower() not in _ATTR_PRED_TARGETS:
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: target {target!r} is not one of "
                    f"{', '.join(_ATTR_PRED_TARGETS)} — the cell says which of the "
                    f"hypothesis's OWN objects carries the attribute, not which vertex id"
                )
            # `_normalized_claim`, not a bare `.strip()`: `"."` / `"..."` / `"''"` are
            # non-blank cells that carry no observable, and `_predicted_observables` already
            # drops them from rule #23's fork signature on that reading. Testing the RAW cell
            # here leaves a pair of siblings whose only predictions normalize to nothing
            # passing BOTH rules — this one because the cell is non-blank, #23 because the
            # signature is empty.
            if not _normalized_claim(ap.get("claim")):
                attribute = ap.get("attribute") or "?"
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: empty `claim` — the row pre-commits "
                    f"to what {attribute!r} will read as, and a blank cell commits to nothing "
                    f"while still counting as a prediction rules #6 and #34 require settled"
                )
    return errors


#: `:H h-NNN.preds`' id namespace, the sibling of `_ATTR_PRED_ID_RE`. Spelled here rather
#: than imported because `parser._REF_ID_RE` is the CITATION side's owner — it decides which
#: head tokens are ids at all — and this is the DECLARATION side; what the two must agree on
#: is the shape, which a shared regex would hide behind an alternation covering `r*` too.
_PRED_ID_RE = re.compile(r"p\d+")


def _check_prediction_id_namespace(companion: CompanionBody) -> list[str]:
    """A `:H h-NNN.preds` row is numbered `p<n>`, for the reason rule #33 gives for `ap<n>`.

    Rule #33 armed the id-shape check on `.attr_preds` and left its sibling block unchecked,
    and the closure gate turned that gap from harmless into a dead end. `_hyp_sub_pred_row`
    `_require`s `id` and never looks at what it says, so `x1|proposed_parent|"..."` declares a
    prediction; `parser._REF_ID_RE` then refuses to read `x1` as an id in a resolution head,
    so no citation can ever reach it — while rule #34 counts it as a declared commitment and
    refuses the close with "cite x1 in a `:T resolutions` head", a repair the grammar cannot
    express. The only exit is a deferral saying the prediction could not be settled, which is
    not what happened.
    """
    return [
        f"`:H {hid}.preds` row {pid!r}: a prediction is numbered `p<n>` — a resolution head "
        f"reads only `p*`/`ap*`/`r*` as ids, so one outside the namespace can be cited by "
        f"nothing and rule #34 then refuses the close for a prediction no row can settle"
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        for pred in hyp.get("predictions") or []
        if isinstance(pred, dict)
        for pid in [pred.get("id") or "?"]
        if not _PRED_ID_RE.fullmatch(pid)
    ]
