"""Structure rules: is a row filled in, and do its cells draw from their closed vocabularies?"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from defender._vocab import HOST_ONLY_DISPOSITION

from .. import _walkers, vocab
from .._cells import _unquote
from ..schema import (
    CompanionBody,
    ImpactPrediction,
)
from ._refs import _LEAD_PRED_ID_RE, _known_ids, _leads
from ._predictions import auth_kind_of


def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


def _cell(record: Mapping[str, object], key: str) -> str:
    """One cell of a projected row as stripped, unquoted text, by a variable column name.

    Unquoted because `:R` rows are projected verbatim while their declaring rows are
    unquoted, and comparisons must see through that. Stripped on both sides of the unquote so
    padding inside quotes does not survive.
    """
    value = record.get(key)
    return _unquote(value.strip()).strip() if isinstance(value, str) else ""


#: The two destinations an `advance_to` may name that are not a lead. `CONCLUDE` ends the run;
#: `HYPOTHESIZE` sends it back for a mechanism the plan did not have. One spelling each (spec
#: rule #18); aliases like `PREDICT` or `REPORT` are not accepted.
_ROUTE_SENTINELS: tuple[str, ...] = ("CONCLUDE", "HYPOTHESIZE")

#: `:L l-NNN.lead_preds`' three content cells as (projected key, column, cost of a blank).
_LEAD_PRED_CELLS: tuple[tuple[str, str, str], ...] = (
    (
        "condition", "if",
        "the row pre-commits to WHICH result sends the run down this branch, and a blank cell "
        "branches on nothing",
    ),
    (
        "read_as", "read_as",
        "the row says what that result MEANS, and a blank cell commits to no reading — which "
        "is the whole reason a route is registered before the data lands rather than chosen "
        "after it",
    ),
    (
        "advance_to", "advance_to",
        "the row names WHERE that reading routes, and a blank cell routes nowhere",
    ),
)


def _check_lead_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.lead_preds` rows: a lead's pre-committed route, checked for what makes it
    followable.

    A route fixes the interpretation before the data arrives, so it needs an `lp<n>` id, a
    condition, a reading, and a destination. `advance_to` must name a declared lead (by name,
    including the declaring lead itself, since names are not unique across loops) or a
    sentinel; a not-yet-declared destination is refused, as PLAN writes leads before routes.

    Not checked: uniqueness (enforced by the parser), and route compliance ("followed by
    another lead"), which would refuse a committed row based on what follows it and has no
    honest warning channel, since the rows involved must not be rewritten.
    """
    # Both sides through `_cell` so quoting or padding cannot make a correct destination miss.
    leads = _leads(companion)
    names = {
        _cell(f, "name") for f in leads
        if isinstance(f.get("name"), str) and f["name"]
    } - {""}
    destinations = names | set(_ROUTE_SENTINELS)
    errors: list[str] = []
    for lead in leads:
        lid = lead.get("id", "?")
        for lp in lead.get("predictions") or []:
            if not isinstance(lp, dict):
                continue
            lpid = lp.get("id") or "?"
            where = f"`:L {lid}.lead_preds` row {lpid!r}"
            if not _LEAD_PRED_ID_RE.fullmatch(lpid):
                errors.append(
                    f"{where}: a lead-level route is numbered `lp<n>` — the namespace is what "
                    f"keeps a route out of the `p*`/`ap*`/`r*` a resolution head and "
                    f"`:L findings`' `tests` column resolve against, so a route spelled `p1` "
                    f"collides with the hypothesis prediction of that name at both sites"
                )
            for key, column, cost in _LEAD_PRED_CELLS:
                if not _cell(lp, key):
                    errors.append(f"{where}: empty `{column}` — {cost}")
            dest = _cell(lp, "advance_to")
            if dest and dest not in destinations:
                errors.append(
                    f"{where}: `advance_to` names {dest!r}, which is neither a lead NAME this "
                    f"document declares ({_known_ids(names)}) nor one of "
                    f"{', '.join(_ROUTE_SENTINELS)} — the cell carries the lead's `name`, not "
                    f"its `l-*` id, and a route nobody can follow is not a plan"
                )
    return errors


_IMPACT_PRED_ID_RE = re.compile(r"ip\d+")

#: `:L l-NNN.impact_preds`' six required cells, by the canonical key the projector emits (the
#: name the spec uses), e.g. `dimension` rather than the column alias `dim`.
_IMPACT_PRED_CELLS: tuple[str, ...] = (
    "dimension", "claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on",
)


def _check_impact_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.impact_preds` rows — the impact predicate a lead registers at PREDICT, checked
    for the cells that make it gradeable.

    The threshold and every outcome must be written before the measurement lands, or ANALYZE
    can grade it whichever way the answer came out. `dimension` is closed because `:R impact`
    rows must match it. The one-observable-per-entry clause is left to the author.
    """
    errors: list[str] = []
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for ip in lead.get("impact_predictions") or []:
            if not isinstance(ip, dict):
                continue
            ipid = ip.get("id") or "?"
            where = f"`:L {lid}.impact_preds` row {ipid!r}"
            if not _IMPACT_PRED_ID_RE.fullmatch(ipid):
                errors.append(
                    f"{where}: an impact prediction is numbered `ip<n>` — a `:R impact` row's "
                    f"`pred_ref` resolves in that namespace, both bare and as the "
                    f"cross-lead `{lid}.ip<n>`, so an id outside it can be graded by nothing"
                )
            dimension = _cell(ip, "dimension")
            errors += _check_vocab(
                dimension, vocab.IMPACT_DIMENSION,
                f"{where}: dimension {dimension!r} is not one of "
                f"{', '.join(vocab.IMPACT_DIMENSION)} — the cell says which axis the "
                f"consequence is measured on, and `:R impact` grades against it",
            )
            # One error per row, not per column, so an under-filled row does not bury the rest.
            blank = [c for c in _IMPACT_PRED_CELLS if not _cell(ip, c)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"predicate registers its axis, its threshold AND every outcome before "
                    f"the measurement lands, so all of {', '.join(_IMPACT_PRED_CELLS)} are "
                    f"required; a blank cell lets ANALYZE decide that outcome after seeing "
                    f"the answer"
                )
    return errors


#: The `:R impact` cells rule #30 requires, by canonical field name (after
#: `_RESOLUTION_KEY_CANONICAL`), which is also the name the spec and refusals use.
_IMPACT_RESOLUTION_REQUIRED: tuple[str, ...] = (
    "prediction_ref",
    "dimension",
    "verdict",
    "grounding_kind",
    "authority_for_question",
    "as_of",
    "reasoning",
)


def _qualify(lid: str, ref: str) -> str:
    """A `pred_ref` under its cross-lead identity: a bare `ip<n>` is scoped to the lead the row
    landed on, a qualified `l-NNN.ip<n>` already names its own.

    Shared by rules #30 and #31 so they resolve the cell identically.
    """
    return ref if "." in ref else f"{lid}.{ref}"


def _declared_impact_predictions(
    companion: CompanionBody,
) -> dict[str, ImpactPrediction]:
    """Every `ip*` in the document under its CROSS-LEAD identity `l-{id}.ip{n}` — the one
    spelling both reference forms resolve to."""
    out: dict[str, ImpactPrediction] = {}
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for ip in lead.get("impact_predictions") or []:
            if isinstance(ip, dict) and isinstance(ip.get("id"), str) and ip["id"]:
                out.setdefault(f"{lid}.{ip['id']}", ip)
    return out


def _check_impact_resolution_refs(companion: CompanionBody) -> list[str]:
    """`:R impact` rows — what each grades, how it graded it, and on what authority.

    The impact analog of `_check_prediction_refs`: a verdict must resolve to a registered
    predicate, on the same dimension. `past-case` grounding is refused by name: impact is
    about what this event did, which a past case cannot establish. Whether the observation
    supports the verdict is ANALYZE's judgment, not checked here.
    """
    declared = _declared_impact_predictions(companion)
    errors: list[str] = []
    #: Every verdict each `ip*` was graded to, to refuse a predicate graded twice with
    #: different answers (which would let the close pick one after the fact).
    verdicts_by_ref: dict[str, set[str]] = {}
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            if not isinstance(row, dict):
                continue
            raw_ref = _cell(row, "prediction_ref")
            where = f"lead {lid}: `:R impact` row for {raw_ref or '<no prediction_ref>'}"
            # One error per row, not per column.
            blank = [key for key in _IMPACT_RESOLUTION_REQUIRED if not _cell(row, key)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"resolution carries a consequence verdict AND the provenance that makes "
                    f"it checkable, so all of "
                    f"{', '.join(_IMPACT_RESOLUTION_REQUIRED)} are required; a "
                    f"blank cell records the verdict without what it rests on"
                )
            verdict = _cell(row, "verdict")
            errors += _check_vocab(
                verdict, vocab.IMPACT_VERDICT,
                f"{where}: verdict {verdict!r} is not one of "
                f"{', '.join(vocab.IMPACT_VERDICT)} — the cell says whether the measurement "
                f"landed inside the registered threshold, not what was measured",
            )
            grounding = _cell(row, "grounding_kind")
            if grounding == "past-case":
                errors.append(
                    f"{where}: `grounding past-case` — impact is per-instance reasoning about "
                    f"what THIS event did, and a past case establishes only what a CATEGORY "
                    f"of event was permitted to do. Re-send this row grounded on "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}. Deferring the predicate in "
                    f"`:T conclude.deferred_impact` does NOT clear this: the refusal is on the "
                    f"`:R impact` row, and append-only leaves it on disk"
                )
            else:
                errors += _check_vocab(
                    grounding, vocab.IMPACT_GROUNDING,
                    f"{where}: grounding {grounding!r} is not one of "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}",
                )
            if not raw_ref:
                continue
            ref = _qualify(lid, raw_ref)
            pred = declared.get(ref)
            if pred is None:
                errors.append(
                    f"{where}: `prediction_ref` resolves to {ref!r}, which no "
                    f"`:L l-NNN.impact_preds` row declares (declared: "
                    f"{_known_ids(set(declared))}) — a bare `ip<n>` resolves within {lid} and "
                    f"a qualified `l-NNN.ip<n>` across leads; register the predicate before "
                    f"grading it"
                )
                continue
            if verdict:
                verdicts_by_ref.setdefault(ref, set()).add(verdict)
            # Both sides through `_cell`: the declaring cell may keep padding inside quotes.
            dim, pred_dim = _cell(row, "dimension"), _cell(pred, "dimension")
            if dim and pred_dim and dim != pred_dim:
                errors.append(
                    f"{where}: `dimension {dim}` but {ref} was registered on {pred_dim!r} — a "
                    f"resolution grades the predicate it names, so the two axes have to be "
                    f"the same one; fix the column, or point `pred_ref` at the predicate this "
                    f"row actually measured"
                )
    errors += [
        f"impact prediction {ref}: graded {', '.join(sorted(seen))} by different "
        f"`:R impact` rows — a predicate registers ONE threshold and the measurement lands "
        f"inside it or outside it, so two verdicts on one `ip<n>` let the close pick which of "
        f"its own answers to be measured against. Keep the grading that measured the "
        f"registered claim, or register a second predicate for the second measurement"
        for ref, seen in sorted(verdicts_by_ref.items())
        if len(seen) > 1
    ]
    return errors


def _check_vocab_vertices(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for v in _walkers.all_vertices(companion):
        t = v.get("type")
        errors += _check_vocab(
            t, vocab.TYPES,
            f"vertex {v.get('id', '?')}: type {t!r} is not a known vertex "
            f"type (`enum types`)",
        )
    return errors


def _check_vocab_edges(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for e in _walkers.all_edges(companion):
        rel = e.get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"edge {e.get('id', '?')}: rel {rel!r} is not a known relation "
            f"(`enum relations`)",
        )
        kind = auth_kind_of(e)
        errors += _check_vocab(
            kind, vocab.AUTH_KINDS,
            f"edge {e.get('id', '?')}: auth_kind {kind!r} is not a known "
            f"observational authority (`enum auth-kinds`)",
        )
    return errors


def _check_vocab_hypotheses(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        pv = (h.get("proposed_edge") or {}).get("parent_vertex") or {}
        pt = pv.get("type")
        errors += _check_vocab(
            pt, vocab.TYPES,
            f"hypothesis {h.get('id', '?')}: parent_type {pt!r} is not a "
            f"known vertex type (`enum types`)",
        )
        rel = (h.get("proposed_edge") or {}).get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"hypothesis {h.get('id', '?')}: rel {rel!r} is not a known "
            f"relation (`enum relations`)",
        )
    return errors


def _check_vocab_weights(companion: CompanionBody) -> list[str]:
    """The two cells that carry a weight, against the bucket list plus `null`.

    Every weight-keyed gate is a membership test, so an off-vocabulary token (`confirmed`)
    would skip them all at once. Checks both `:H` weights and resolution cells.
    """
    errors: list[str] = []
    for hid, h in _walkers.all_hypotheses(companion).items():
        errors += _check_vocab(
            h.get("weight"), vocab.WEIGHT_CELL_VALUES,
            f"hypothesis {hid}: weight {h.get('weight')!r} is not a weight — a `:H` row's "
            f"cell is one of {', '.join(vocab.WEIGHT_CELL_VALUES)}",
        )
    for lid, res in _walkers.iter_resolutions(companion):
        for cell in ("before", "after"):
            errors += _check_vocab(
                res.get(cell), vocab.WEIGHT_CELL_VALUES,
                f"lead {lid}: resolution of {res.get('hypothesis', '?')} has "
                f"{cell} {res.get(cell)!r}, which is not a weight — the cells either side of "
                f"the arrow are one of {', '.join(vocab.WEIGHT_CELL_VALUES)}; a token outside "
                f"the list moves nothing and skips every gate that reads the grade",
            )
    return errors


def _check_vocab_anchor_kinds(companion: CompanionBody) -> list[str]:
    """`anchor_kind` against `vocab.ANCHOR_KINDS`, on all three surfaces that carry one:
    `:H h-NNN.authz` contracts, `:R authz` rows, and `:R consultations` rows (which feed
    `report.md` and the anchor-id cross-check).
    """
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        for c in h.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            ak = c.get("anchor_kind")
            errors += _check_vocab(
                ak, vocab.ANCHOR_KINDS,
                f"hypothesis {h.get('id', '?')} contract "
                f"{c.get('id', '?')}: anchor_kind {ak!r} is not known "
                f"(`enum anchor-kinds`)",
            )
    for row in _walkers.iter_authz_resolutions(companion):
        row_ak = row.get("anchor_kind")
        errors += _check_vocab(
            row_ak, vocab.ANCHOR_KINDS,
            f"authz resolution for contract {row.get('fulfills_contract', '?')}: "
            f"anchor_kind {row_ak!r} is not known (`enum anchor-kinds`)",
        )
    for consult in _walkers.iter_anchor_consultations(companion):
        # Through `_cell`: `:R` cells are projected verbatim, quotes included.
        kind = _cell(consult, "anchor_kind")
        where = (
            f"lead {consult.get('resolved_by_lead', '?')}: `:R consultations` row for "
            f"{consult.get('anchor_id') or '<no anchor_id>'}"
        )
        errors += _check_vocab(
            kind, vocab.ANCHOR_KINDS,
            f"{where}: anchor_kind {kind!r} is not known (`enum anchor-kinds`)",
        )
        grounding = _cell(consult, "grounding_kind")
        errors += _check_vocab(
            grounding, vocab.CONSULTATION_GROUNDING,
            f"{where}: grounding {grounding!r} is not one of "
            f"{', '.join(vocab.CONSULTATION_GROUNDING)} (`enum consultation.grounding`) — a "
            f"consultation records what a system of record or a telemetry baseline SAYS, and "
            f"`past-case` in particular is excluded by name: grounding a baseline on a past "
            f"case is precedent-by-similarity, which this axis does not admit",
        )
    return errors

def _check_conclude_vocab(companion: CompanionBody) -> list[str]:
    """Check `conclude.disposition` against the vocabulary.

    An out-of-enum value would silently skip the disposition gating. The host-only disposition
    is a vocabulary member but is refused explicitly: only the host records it."""
    disposition = (companion.get("conclude") or {}).get("disposition")
    errors = _check_vocab(
        disposition, vocab.DISPOSITION,
        f"conclude: disposition {disposition!r} is not a known disposition "
        f"(`enum disposition`)",
    )
    if disposition == HOST_ONLY_DISPOSITION:
        errors.append(
            f"conclude: disposition {HOST_ONLY_DISPOSITION!r} is recorded by the host when a "
            f"run terminates without a settled finding — the investigating model reports what "
            f"it could not settle as `inconclusive` instead, naming the gap in `ceiling_test`; "
            f"it never concludes {HOST_ONLY_DISPOSITION!r} itself."
        )
    return errors
