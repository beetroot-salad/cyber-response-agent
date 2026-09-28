"""History and weight rules: the append-only comparison against the committed baseline, the
provenance a strong move owes, and which of a hypothesis' predictions the run settled.
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
    """An `:E` row's authority kind, or `None`. Public so other modules share one reading."""
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
                    f"append-only violation: committed {label} {rid} was "
                    f"mutated in place ({core} → {new_idx[rid]}) — refine via a "
                    f"new :R attr_updates / observation row, never by rewriting "
                    f"the original declaration"
                )
    return errors




def _check_strong_move_provenance(companion: CompanionBody) -> list[str]:
    """A strong move must cite both the pre-committed claim it settled and a strongly
    authoritative edge it rests on.

    Commonly tripped by omitting severity: it is positional-last in the head, so the ids are
    read as the severity and the row cites nothing.
    """
    auth_by_edge: dict[str, str] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        kind = auth_kind_of(e)
        if isinstance(eid, str) and isinstance(kind, str):
            auth_by_edge[eid] = kind

    errors: list[str] = []
    for lid, res in _walkers.iter_resolutions(companion):
        # Through `_resolution_move` so every rule reads the move the same way.
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

    Closed on `vocab.WEIGHT_BUCKETS`: the `after` cell is unvalidated, and an open test would
    let an off-vocabulary token (`null → confirmed`) settle predictions while skipping the
    strong-move and `++` gates. Shared by rules #6 and #34 so they agree on what counts.
    """
    if not isinstance(res, dict):
        return ""
    after = (res.get("after") or "").strip()
    return after if after in vocab.WEIGHT_BUCKETS else ""


#: A prediction id negated in the row's `⟺` annotation (`¬p2` or `~p2`). The parser still
#: files it in `matched_prediction_ids` ("this lead tested it"); rule #6 asks whether it came
#: in, so it subtracts these.
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

    A row that cites `p1` without moving recorded that the lead looked, not that the
    prediction settled. A cited `r*` settles the predictions its `refutes` cell names (a tested
    refutation that failed to materialize). A negated literal (`¬p2`) settles nothing.
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
        # Subtract per row, before the union: a later row's `¬p1` must not un-settle an earlier
        # one, so the set only grows and stays repairable under append-only.
        matched.setdefault(hid, set()).update(row - _contradicted_predictions(res))
    return matched


def _confirmed_and_standing(companion: CompanionBody) -> dict[str, str]:
    """Per hypothesis STANDING at `++`, the FIRST lead whose resolution moved it there.

    The single predicate partitioning rules #6 (standing at `++`: every prediction must be
    cited) and #34 (everything else not refuted: cite or defer), so no hypothesis falls
    between them.

    Standing rather than "ever `++`", so appending `h-NNN ++ → +` withdraws a coverage claim
    that a later-declared prediction broke; otherwise the document has no legal next write.

    Counted, not ordered: each row entering `++` adds one and each leaving it (including to
    `null`) subtracts one, edge-triggered so `++ → ++` is neither. On a well-chained history
    that equals last-move-wins without needing an order. `_walkers.final_weights` is not used
    because it orders by lead declaration, which would ignore some withdrawals. Both cells are
    read closed on the weight vocabulary, so a typo does not count as leaving `++`.

    Known gaps: a `++` entered and left within one block is counted out (rule #34 still covers
    its predictions); a `before` cell that misstates the prior weight can cancel a real `++`
    (fixable by a continuity rule on `before`, not by clamping); and a hypothesis declared at
    `++` that no resolution moves is invisible here.
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
        # Read raw, like the other readers of these cells.
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

    Partial coverage is what `+` is for. Citations count from every moving resolution on the
    hypothesis, and `ap*` counts alongside `p*`. Applies only while the hypothesis stands at
    `++` (`_confirmed_and_standing`), so appending `++ → +` is always a legal repair after a
    new prediction is declared. Offers no deferral: a standing `++` claims nothing is
    outstanding. Rule #34 covers the other weights at CONCLUDE.
    """
    confirmed_at = _confirmed_and_standing(companion)
    if not confirmed_at:
        # Early exit before the two document-wide folds below.
        return []
    hyps = _walkers.all_hypotheses(companion)
    matched = _settled_predictions(companion)

    errors: list[str] = []
    for hid, lid in confirmed_at.items():
        hyp = hyps.get(hid)
        if hyp is None:
            # Reachable (resolution rows are not checked against declarations); an undeclared
            # `h-*` is `_check_hypothesis_refs`'s to report.
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

    The parser only requires the cells to be non-blank. Checked here: the id is `ap<n>` (or
    no citation can reach it), the target is a known object, and the claim says something.

    Uniqueness is already enforced by the parser. The one-observable-per-entry clause is not
    checked: it is a judgment about meaning that a lexical test would get wrong.
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
            # Lowercased, matching how rule #23's fork key reads the same cell.
            target = ap.get("target")
            if str(target).strip().lower() not in _ATTR_PRED_TARGETS:
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: target {target!r} is not one of "
                    f"{', '.join(_ATTR_PRED_TARGETS)} — the cell says which of the "
                    f"hypothesis's OWN objects carries the attribute, not which vertex id"
                )
            # `_normalized_claim`, as rule #23 reads it: a claim like `"..."` says nothing.
            if not _normalized_claim(ap.get("claim")):
                attribute = ap.get("attribute") or "?"
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: empty `claim` — the row pre-commits "
                    f"to what {attribute!r} will read as, and a blank cell commits to nothing "
                    f"while still counting as a prediction rules #6 and #34 require settled"
                )
    return errors


#: `:H h-NNN.preds`' id namespace (declaration side; `parser._REF_ID_RE` is the citation side).
_PRED_ID_RE = re.compile(r"p\d+")


def _check_prediction_id_namespace(companion: CompanionBody) -> list[str]:
    """A `:H h-NNN.preds` row is numbered `p<n>`.

    A resolution head reads only `p*`/`ap*`/`r*` as ids, so any other id can never be cited,
    yet rule #34 would still demand its citation at close.
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
