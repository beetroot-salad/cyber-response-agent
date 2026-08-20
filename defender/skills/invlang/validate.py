
from __future__ import annotations

import re
from collections.abc import Callable, Container, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from defender._vocab import normalized_disposition
from . import _walkers, vocab
from ._cells import _row_dict
from ._types import RowError
from .parser import (
    COMMITMENT_ID_RE,
    HYPOTHESIS_ID_RE,
    INVLANG_FENCE_RE,
    ParseWarning,
    deferred_hypothesis_ids,
    is_conclude_empty_marker,
    iter_blocks,
    parse_dense_companion,
)
from .schema import (
    AuthorizationContract,
    CompanionBody,
    DeferralRecord,
    EdgeRecord,
    FindingRecord,
    HypothesisRecord,
    ImpactPrediction,
    VertexRecord,
)

STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS
CONFIRMED_WEIGHT = vocab.CONFIRMED_WEIGHT
REFUTED_WEIGHT = vocab.REFUTED_WEIGHT
_STRONG_AUTH_KINDS_STR = " / ".join(sorted(STRONG_AUTH_KINDS))

_YAML_FENCE_RE = re.compile(r"```ya?ml\b")

#: `Diagnostic.severity`'s closed set. Declared once, beside the type that carries it.
Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Locus:
    """Where a diagnostic's offending row actually is, when there is one row to point at.

    `row_text` is the row as the author WROTE it — never a reconstruction. Both families that
    populate a locus read it from the document: a parse warning carries its row, and the
    `:R attr_updates` check walks blocks rather than folded records. `row_index` is the ordinal
    WITHIN the block, not a file line number, and only the parse warnings have it."""

    block: str
    row_text: str
    row_index: int | None = None


@dataclass(frozen=True)
class Diagnostic:
    """One validation failure. `message` is the prose the model sees; `locus` and `fix` are
    optional structure alongside it.

    Only the families that can name a single offending row populate `locus` — parse warnings
    and `:R attr_updates`. The document-global checks (append-only, lead and prediction refs,
    strong-move provenance, benign gating, loop close, surface) have no row to point at and
    leave it `None`; so do the vocab sub-checks over `:V`/`:E`/`:H`, whose rows cannot be
    rebuilt without the block's declared column list."""

    message: str
    locus: Locus | None = None
    fix: tuple[str, ...] = field(default_factory=tuple)
    #: `"error"` (the write is refused and nothing is written) or `"warning"` (the write LANDS
    #: and the row gates the NEXT one until it is repaired). Assigned per check family at
    #: diagnose time, never document content — so no migration exists for older bytes.
    #: A closed `Literal`, not a bare `str`: the partition is read THREE ways across three
    #: modules (`== "warning"` here, `!= "warning"` in `validate_companion` and in
    #: `_artifact_schema.validate_investigation`), so a mistyped value would not fail — it
    #: would file silently as error severity at every one of them.
    severity: Severity = "error"


def _plain(messages: list[str]) -> list[Diagnostic]:
    """Lift the checks that carry no row into `Diagnostic`s. Those checks stay on `list[str]`
    deliberately: they gain nothing from the type."""
    return [Diagnostic(m) for m in messages]


def _parse_diagnostic(w: ParseWarning) -> Diagnostic:
    """A parse warning already knows its block, ordinal and raw row — `w.format()` folds them
    into prose. Keep the prose and carry the structure alongside it."""
    return Diagnostic(
        message=f"parse error: {w.format()}",
        locus=Locus(block=w.block, row_text=w.row, row_index=w.row_index),
    )


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")




def _check_surface(proposed_text: str) -> list[str]:
    if _YAML_FENCE_RE.search(proposed_text):
        return [
            "non-invlang surface: investigation.md contains a ```yaml/```yml "
            "fenced block, but the on-disk surface is ```invlang (defender "
            "SKILL §dense format). Rewrite the block(s) as ```invlang."
        ]
    return []




def _check_lead_refs(companion: CompanionBody) -> list[str]:
    """`:L findings` is the sole site that declares a lead; every other mention must resolve
    to one.

    The projector opens a bucket for any lead id it meets, so a typo, a forward reference, and
    a comma-joined pair of real ids (`l-004,l-005`) are indistinguishable from a declaration at
    projection time. Only a declared lead carries a name, so that is what separates the two.
    """
    findings = [f for f in (companion.get("findings") or []) if isinstance(f, dict)]
    declared = {
        f["id"] for f in findings
        if isinstance(f.get("id"), str) and f.get("name")
    }
    errors: list[str] = []
    for f in findings:
        fid = f.get("id")
        if not isinstance(fid, str) or fid in declared:
            continue
        hint = (
            " — a resolution is owned by exactly one lead; attribute it to one "
            "and name the others in `cites_leads`"
            if "," in fid else ""
        )
        errors.append(
            f"undeclared lead {fid!r}: referenced by a `:R` / `:T` row or a "
            f"lead sub-block, but no `:L findings` row declares it{hint}"
        )
    for row in _walkers.iter_grounded_resolutions(companion):
        owner = row.get("resolved_by_lead")
        for cited in row.get("cites_leads") or []:
            if cited not in declared:
                errors.append(
                    f"`cites_leads` on the resolution owned by "
                    f"{owner or '<unattributed>'} names {cited!r}, which no "
                    f"`:L findings` row declares"
                )
            elif cited == owner:
                errors.append(
                    f"`cites_leads` on {owner}'s resolution cites {owner} "
                    f"itself — it names the other leads the verdict rests on"
                )
    return errors


def _declared_prediction_ids(hyp: HypothesisRecord) -> set[str]:
    """Both PREDICT blocks: the `⟺` annotation form cites `ap*` next to `p*`, so
    `:H h-NNN.attr_preds` declares matched-prediction ids just as `.preds` does."""
    return {p["id"] for p in hyp.get("predictions") or []} | {
        ap["id"] for ap in hyp.get("attribute_predictions") or []
    }


def _unresolved(cited: list[str], declared: set[str]) -> list[str]:
    # Deduped: `[l-001 p1 + l-003 p1,p2 …]` cites p1 twice, and one undeclared id is one
    # defect however many times the head names it.
    return [c for c in dict.fromkeys(cited) if c not in declared]


def _known_ids(declared: set[str]) -> str:
    return ", ".join(sorted(declared)) or "none"


#: The two blocks that DECLARE a hypothesis. Named in every undeclared-`h-*` error, so the
#: author is told where the declaration goes rather than only that one is missing.
_HYPOTHESIS_DECLARING_BLOCKS = (
    "`:H hypothesize.hypotheses` or `:H l-NNN.new_hypotheses`"
)


def _undeclared_hypothesis(where: str, site: str, hid: str, declared: str) -> str:
    """`where` locates the row — `"lead l-001: "`, or empty for a document-level block —
    and `site` is the phrase naming the column that made the reference."""
    return (
        f"{where}{site} undeclared hypothesis {hid!r} — no "
        f"{_HYPOTHESIS_DECLARING_BLOCKS} row declares it (declared: {declared}); "
        f"a hypothesis born mid-run is declared by the lead that found it, "
        f"before anything references it"
    )


def _lead_prefix(lid: str) -> str:
    return f"lead {lid}: "


def _cited_hypothesis_ids(lead: FindingRecord) -> Iterator[tuple[str, list[str]]]:
    """Every `h-*` a LEAD names, per site, paired with the phrase that says where.

    Two sites, and both are lists the parser splits without ever looking the ids up:
    `:L findings`' `tests` column projects to `tests_hypotheses` through `_split_csv`, and
    `:T shelved`'s first cell appends to `shelved`.

    The shape gate applies at `tests` ONLY, because only `tests` is mixed: it lists the
    COMMITMENTS the lead was run for, which is three id kinds (`ac1` and `p2` alongside `h-*`).
    A `p2` resolves against `:H h-NNN.preds` and an `ac1` against `:H h-NNN.authz` — separate
    rules against separate declaring blocks — so reading the column as hypotheses-only would
    deny a correct document.

    `:T shelved`'s column is `hyp_id`: every value in it IS a hypothesis reference. Gating it
    on shape would exempt exactly the typo the rule exists to catch — `h_888`, `H-888`,
    `hyp-888` all shelve nothing and would pass in silence — so the gate is withheld there and
    an unrecognizable id is reported like any other undeclared one.
    """
    for site, ids, shaped in (
        ("`:L findings` tests", lead.get("tests_hypotheses"), True),
        ("`:T shelved` shelves", lead.get("shelved"), False),
    ):
        cited = [
            hid for hid in (ids or [])
            if isinstance(hid, str) and hid
            and (not shaped or HYPOTHESIS_ID_RE.fullmatch(hid))
        ]
        if cited:
            yield site, cited


def _hypothesis_references(
    companion: CompanionBody,
) -> Iterator[tuple[str, str, list[str]]]:
    """Every site that names an `h-*`, as `(where, site-phrase, ids-in-row-order)`.

    The census in one place, so "which sites reference a hypothesis" is a list to extend
    rather than a branch to remember to add.
    """
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if isinstance(hid, str):
            yield _lead_prefix(lid), "resolution moves", [hid]
    surviving = [
        row["hypothesis"]
        for row in (companion.get("conclude") or {}).get("surviving_hypotheses") or []
        if isinstance(row, dict) and isinstance(row.get("hypothesis"), str)
    ]
    if surviving:
        yield "", "`:T conclude.surviving` names", surviving
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        where = _lead_prefix(lead.get("id", "?"))
        for site, cited in _cited_hypothesis_ids(lead):
            yield where, site, cited


def _check_hypothesis_refs(
    companion: CompanionBody, *, deferred: frozenset[str] | None
) -> list[str]:
    """`:H hypothesize.hypotheses` and `:H l-NNN.new_hypotheses` are the sole sites that
    declare a hypothesis; every other mention of an `h-*` must resolve to one.

    `_check_lead_refs`'s analogue for the other id the projector opens no bucket for. A typo,
    a forward reference and a genuinely absent hypothesis are indistinguishable at projection
    time, so a phantom would move to `++` in silence and `_walkers.final_weights` would report
    it live.

    FOUR sites reference an `h-*` and this owns all four: a resolution, a lead's `tests`, a
    `:T shelved` row, and `:T conclude.surviving`. The middle two are the ones a run reaches
    first — a lead can claim to TEST a hypothesis nobody declared, and a shelve can retire one
    that never existed.

    `deferred` keeps the deference honest: a `:H` DECLARATION block the parser rejected (a
    stale header, an `attached_to` naming an edge) leaves every reference to it looking
    phantom, and the parse warning already names the cause. One defect, one error. It is keyed
    to the dropped IDS, not to the document, so an unrelated typo three leads away is still
    reported. `None` is the parser's "a dropped declaration could not be mapped to an id at
    all", and only that stands the rule down wholesale.
    """
    if deferred is None:
        return []
    declared = set(_walkers.all_hypotheses(companion))
    known = _known_ids(declared)
    # A dropped id is as good as a declared one HERE and only here: rule 1 already reported
    # the block that deleted it, and a second error would point away from the fix.
    resolvable = declared | deferred
    # `_unresolved` per site, the same dedup-then-filter the citation rule uses: one id
    # written twice in `tests` is one defect, not two.
    return [
        _undeclared_hypothesis(where, site, hid, known)
        for where, site, cited in _hypothesis_references(companion)
        for hid in _unresolved(cited, resolvable)
    ]


def _declared_commitments(hyp: HypothesisRecord) -> set[str]:
    """Every id a hypothesis's `:H h-NNN.<sub>` blocks declare, across all four namespaces."""
    return (
        _declared_prediction_ids(hyp)
        | {r["id"] for r in hyp.get("refutation_shape") or []}
        | {
            c["id"] for c in hyp.get("authorization_contract") or []
            if isinstance(c, dict) and c.get("id")
        }
    )


def _check_tested_commitment_refs(companion: CompanionBody) -> list[str]:
    """A `p*`/`ap*`/`r*`/`ac*` in `:L findings`' `tests` column resolves against a
    hypothesis that same row says it is testing.

    The other half of the mixed column: without it `tests=h-001,p9,ac9` names two commitments
    that do not exist and validates clean.

    Scoped to the hypotheses the SAME row names, not to the document. A `p2` means "h-001's
    p2" when the row tests h-001; resolving it against every hypothesis in the run would
    accept a sibling's `p2`, which is exactly the cross-citation `_check_prediction_refs`
    refuses one level down. A row naming no hypothesis at all has nothing to scope to, so it
    falls back to every declared hypothesis rather than inventing a stricter rule than the
    format states.

    NOT checked: an id in no recognized namespace. The one that reaches here is `lp*`, and it
    stays exempt after #933 projected `:L l-NNN.lead_preds` — for a better reason than "nothing
    declares it". An `lp*` is scoped to a LEAD and this column is scoped to a HYPOTHESIS, so
    there is no hypothesis whose declarations could resolve it; `_check_lead_prediction_structure`
    owns the `lp*` namespace where it lives. (`COMMITMENT_ID_RE` already excludes `lp1` — `p\\d+`
    is `fullmatch`ed — so the exemption is structural rather than a filter here.)
    """
    by_hyp = {
        hid: _declared_commitments(hyp)
        for hid, hyp in _walkers.all_hypotheses(companion).items()
    }
    errors: list[str] = []
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        tested = [t for t in lead.get("tests_hypotheses") or [] if isinstance(t, str)]
        named = [t for t in tested if HYPOTHESIS_ID_RE.fullmatch(t)]
        if any(h not in by_hyp for h in named):
            # An undeclared or dropped `h-*` on this row: `_check_hypothesis_refs` owns
            # that defect, and its commitments cannot be scoped until it is fixed.
            continue
        scope_ids = named or list(by_hyp)
        if not scope_ids:
            # Nothing to scope AGAINST — the row names no hypothesis and the document
            # declares none, which is the shape a rejected `:H` block leaves behind. Rule 1
            # already reported that block; reporting every commitment on top of it is the
            # second error for one defect the sibling rule's deference exists to prevent.
            continue
        scope: set[str] = set()
        for h in scope_ids:
            scope |= by_hyp[h]
        cited = [t for t in tested if COMMITMENT_ID_RE.fullmatch(t)]
        for cid in _unresolved(cited, scope):
            errors.append(
                f"{_lead_prefix(lead.get('id', '?'))}`:L findings` tests commitment "
                f"{cid!r}, which none of the hypotheses it tests declares "
                f"({_known_ids(set(scope_ids))}) — a `p*`/`ap*` is declared by "
                f"`:H h-NNN.preds` / `.attr_preds`, an `r*` by `.refuts` and an `ac*` by "
                f"`.authz` (declared: {_known_ids(scope)})"
            )
    return errors


def _check_prediction_refs(companion: CompanionBody) -> list[str]:
    """A resolution matches only the predictions and refutations its own hypothesis
    declared.

    The parser derives this reference by heuristic, not by lookup: `matched_prediction_ids` is
    just the id-shaped head tokens, never joined back to the declaring `:H h-NNN.preds` block.
    Unchecked, a typo, a forward reference and a *sibling's* `p1` all parse clean — a `++`
    could rest on a prediction that does not exist, or on one belonging to the hypothesis it is
    being weighed against.
    """
    errors: list[str] = []
    declared_by_hyp = {
        hid: (
            _declared_prediction_ids(hyp),
            {r["id"] for r in hyp.get("refutation_shape") or []},
        )
        for hid, hyp in _walkers.all_hypotheses(companion).items()
    }
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        entry = declared_by_hyp.get(hid) if isinstance(hid, str) else None
        if entry is None:
            # `_check_hypothesis_refs` owns the undeclared-`h-*` defect, and with no
            # declaring block there is nothing to resolve these citations against. One
            # defect stays one error rather than three piled on the same row.
            continue
        preds, refuts = entry
        for pid in _unresolved(res.get("matched_prediction_ids") or [], preds):
            errors.append(
                f"lead {lid}: resolution of {hid} cites prediction {pid!r}, "
                f"which {hid} does not declare (`:H {hid}.preds` / "
                f"`.attr_preds` declare: {_known_ids(preds)}) — a resolution "
                f"matches only its own hypothesis's predictions"
            )
        for rid in _unresolved(res.get("matched_refutation_ids") or [], refuts):
            errors.append(
                f"lead {lid}: resolution of {hid} cites refutation {rid!r}, "
                f"which {hid} does not declare (`:H {hid}.refuts` declares: "
                f"{_known_ids(refuts)})"
            )
    return errors


def _check_refutation_scope(companion: CompanionBody) -> list[str]:
    """A refutation shape overturns ITS OWN hypothesis's predictions, and only those.

    `:H h-NNN.refuts`'s `refutes` column is the third place a `p*`/`ap*` is named, and it was
    the one nothing resolved. `_check_prediction_refs` walks the resolution head — which ids a
    MOVE matched — and rule #5's half of it walks the `r*` a `--` cited. Neither reaches the
    other direction: what the refutation itself claims to overturn. So `r1|p9,ap9|"..."` on a
    hypothesis declaring neither parsed and validated clean, and the `--` that later cited `r1`
    rested on a scope nobody checked.

    The consequence is not confined to bookkeeping. A hypothesis reaches `refuted` through a
    `--`, and `_check_prediction_closure` exempts a refuted hypothesis from rule #34 — so a
    refutation with a phantom scope is a way to discharge every prediction on a hypothesis
    without settling any of them. The exemption is right; the hole was upstream of it.

    Scoped to the DECLARING hypothesis for the reason `_check_prediction_refs` is: a sibling's
    `p2` is not this hypothesis's evidence in either direction, and a document-wide lookup
    would accept it. Silent when the hypothesis declares no predictions at all — a refutation
    on a predictionless hypothesis has nothing to name, which is the lean shape rule #23
    exempts rather than a defect this rule owns.
    """
    errors: list[str] = []
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        shapes = hyp.get("refutation_shape") or []
        if not shapes:
            continue
        declared = _declared_prediction_ids(hyp)
        if not declared:
            continue
        for shape in shapes:
            rid = shape.get("id", "?")
            for pid in _unresolved(shape.get("refutes_predictions") or [], declared):
                errors.append(
                    f"`:H {hid}.refuts` row {rid!r} refutes prediction {pid!r}, which "
                    f"{hid} does not declare (`:H {hid}.preds` / `.attr_preds` declare: "
                    f"{_known_ids(declared)}) — a refutation overturns its own "
                    f"hypothesis's predictions, and a `--` citing it inherits that scope"
                )
    return errors


def _check_authz_contract_ids(companion: CompanionBody) -> list[str]:
    """An `ac*` id is declared by AT MOST ONE LIVE hypothesis.

    `:R authz` has no hypothesis column — the row names the contract it fulfills and nothing
    else — so the id carries the binding and every reader resolves it document-wide.
    `_check_benign_authz` discharges a contract by bare id, so two live hypotheses that each
    numbered their first contract `ac1` would BOTH be discharged by one row, failing a
    `disposition: benign` write gate open with no diagnostic.

    The rule is on the DECLARING side rather than a scoping rule on the resolving side, because
    scoping cannot be recovered from a row that never carried the hypothesis: the honest fix
    for an ambiguous id is to refuse it. Per-hypothesis numbering is the natural mistake here —
    `p*` and `r*` DO restart per hypothesis — so the error says which ids collide and that
    `ac*` numbers across the document.

    LIVE, not declared, and the scope is what makes the rule repairable. `investigation.md` is
    append-only and `:H` rows are immutable, so a collision already on disk cannot be edited
    away: under a declared-set reading every later write would be denied for a row the author
    may no longer touch, and `learning/core/persist.py` dead-letters the run. Refuting one of
    the two is an in-grammar, append-only move that ends the ambiguity honestly. Two live
    hypotheses is the case with no honest reading, and stays refused.

    Refuting does NOT make the id unambiguous — the `:R authz` row carries no hypothesis
    column, so the refuted declarer's row discharges the live declarer's same-numbered contract
    too. `_check_benign_authz` closes that by scoping a shared id to the ANCHOR KIND both sides
    carry; the exemption here leaves the author a repair and is not on its own sufficient.

    Only the cross-hypothesis collision reaches here: `_extend_by_id` keeps the first row per
    id when ONE `:H <h>.authz` block repeats an id, so the folded record carries one contract
    either way. That repeat is not silent — the projector warns on it, because keeping the
    first row DISCARDS the second contract's predicate.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    declared_by: dict[str, set[str]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        if hid not in live:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if isinstance(cid, str) and cid:
                declared_by.setdefault(cid, set()).add(hid)
    return [
        f"authz contract {cid!r} is declared by more than one live hypothesis "
        f"({', '.join(sorted(hids))}) — a `:R authz` row names only the contract it "
        f"fulfills, so one row would discharge all of them; number `ac*` across the "
        f"document, not per hypothesis (or refute one of them, if the evidence says so)"
        for cid, hids in declared_by.items()
        if len(hids) > 1
    ]


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

    cur_fences = len(INVLANG_FENCE_RE.findall(current_text))
    new_fences = len(INVLANG_FENCE_RE.findall(proposed_text))
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
        after = res.get("after")
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




def _check_prediction_completeness(companion: CompanionBody) -> list[str]:
    """A hypothesis graded `++` has settled every prediction it declared, not only the ones
    the confirming lead happened to look at.

    `_check_strong_move_provenance` stops one line short of this. It refuses a `++` that cites
    NOTHING and accepts one that cites `p1` out of five — so a hypothesis reaches "confirmed"
    on whichever fifth of its own pre-commitments the lead found convenient, and the four it
    never looked at are never heard from again. Partial coverage is what `+` is for.

    The union is taken over EVERY resolution on the hypothesis, not only the `++` row: a
    prediction an earlier `+` move already settled is settled. That is also what keeps the rule
    repairable on an append-only document — the union only grows, so a write that clears the
    gate clears it for good, and a later downgrade cannot re-open a row nobody can now edit.

    `ap*` counts toward the set. `_declared_prediction_ids` is this module's one answer to
    "what did the hypothesis declare", and its other two readers take the union; rule #34 — the
    late closure gate this is the early half of — enumerates `p*` and `ap*` alike. Reading only
    `p*` here would let an author take an observable out of the gate by declaring it under
    `.attr_preds`, which is a formatting choice and not an evidentiary one.

    NOT the closure gate. Rule #34 asks the same question of every weight at CONCLUDE and
    offers `conclude.deferred_predictions[]` as the answer to "that one could not be checked".
    This fires at write time on `++` alone and offers nothing, because a `++` has no
    outstanding prediction to defer — the grade IS the claim that there is none.
    """
    hyps = _walkers.all_hypotheses(companion)
    matched: dict[str, set[str]] = {}
    confirmed_at: dict[str, str] = {}
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if not isinstance(hid, str):
            continue
        matched.setdefault(hid, set()).update(
            p for p in res.get("matched_prediction_ids") or [] if isinstance(p, str)
        )
        if res.get("after") == CONFIRMED_WEIGHT:
            confirmed_at.setdefault(hid, lid)

    errors: list[str] = []
    for hid, lid in confirmed_at.items():
        hyp = hyps.get(hid)
        if hyp is None:
            # `_check_hypothesis_refs` owns the undeclared-`h-*` defect. A phantom declares no
            # predictions, so the coverage question is vacuous here and its answer misleading.
            continue
        declared = _declared_prediction_ids(hyp)
        cited = matched.get(hid, set())
        unmet = declared - cited
        if unmet:
            errors.append(
                f"lead {lid}: resolution of {hid} to {CONFIRMED_WEIGHT!r} leaves "
                f"{_known_ids(unmet)} unmatched — {CONFIRMED_WEIGHT!r} says every prediction "
                f"the hypothesis declared came in, and the resolutions on {hid} cite "
                f"{_known_ids(cited & declared)} of {_known_ids(declared)}; cite the rest, or "
                f"grade '+' for partial coverage"
            )
    return errors


#: `attribute_predictions[].target` names WHICH of the hypothesis's three objects carries the
#: predicted attribute. A closed set rather than a `v-*`/`e-*` id: the proposed parent and the
#: proposed edge do not exist yet, so there is no id to point at, and the attached vertex is
#: already named by the hypothesis's own `attached_to`.
_ATTR_PRED_TARGETS: tuple[str, ...] = (
    "proposed_parent", "attached_vertex", "proposed_edge",
)
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
            target = ap.get("target")
            if target not in _ATTR_PRED_TARGETS:
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: target {target!r} is not one of "
                    f"{', '.join(_ATTR_PRED_TARGETS)} — the cell says which of the "
                    f"hypothesis's OWN objects carries the attribute, not which vertex id"
                )
            if not (ap.get("claim") or "").strip():
                attribute = ap.get("attribute") or "?"
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: empty `claim` — the row pre-commits "
                    f"to what {attribute!r} will read as, and a blank cell commits to nothing "
                    f"while still counting as a prediction rules #6 and #34 require settled"
                )
    return errors


#: Rule #23's diagnostic identity — the opening of every message the sibling-fork check
#: emits, and the only stable handle a test has for picking those messages out of
#: `validate_companion`'s flat list. It is a NAMED CONSTANT rather than a phrase two files
#: happen to spell the same way: the message is built from it, so a test filtering on it
#: cannot silently stop matching when the prose around it is reworded. A filter that can
#: silently stop matching turns every `== []` assertion downstream of it into a pass the
#: suite earns by finding nothing, which is how a deleted rule looks from the outside.
_SIBLING_FORK_TAG = "sibling hypotheses"


def _sibling_key(hid: str, hyp: HypothesisRecord) -> tuple[str, str]:
    """The fork a hypothesis sits in: `(parent hypothesis, anchored vertex)`.

    There is no `parent_hypothesis_id` column. Hierarchy rides in the ID SHAPE —
    `h-{parent}-{nonce}`, the form rule #7 resolves — so the parent is read off the id, and a
    top-level `h-001` keys on the empty parent alongside every other top-level hypothesis on
    its anchor. `attached_to` projects to `anchor`; two hypotheses hung on different vertices
    are not competing for one cause and are not siblings.
    """
    parts = hid.split("-")
    parent = "-".join(parts[:-1]) if len(parts) > 2 else ""
    return parent, str(hyp.get("anchor") or "")


def _normalized_claim(claim: Any) -> str:
    """One claim, stripped of the differences that are not differences: case, inner
    whitespace, and the sentence punctuation the model varies freely.

    The trailing `.`/quote strip is load-bearing, not cosmetic: a full stop is the cheapest
    edit that defeats a textual floor, and a pair that differs only by one would otherwise be
    a fork the rule waves through.
    """
    if not isinstance(claim, str):
        return ""
    return " ".join(claim.lower().split()).strip(" .\"'")


def _claim_signature(hyp: HypothesisRecord) -> frozenset[str]:
    """Every observable a hypothesis pre-commits to, normalized for comparison with a sibling's.

    Both PREDICT blocks, because both declare an observable a lead can come back on. A SET,
    because order is not a fork axis and one claim written twice is one claim.

    The two blocks contribute DIFFERENTLY SHAPED keys, because their `claim` cells are
    different kinds of thing. A `.preds` claim is a sentence that carries its own subject
    ("failures arrive in bursts"), so the `subject` cell is deliberately NOT in the key: the
    same sentence filed once under `proposed_parent` and once under `proposed_edge` still
    leaves no lead able to split the two rows. An `.attr_preds` claim is a VALUE — `"UNSIGNED"`,
    `"none"`, `"partial"` — and means nothing without the `target` and `attribute` naming what
    the value is a value OF, so those join the key. Dropping them would fuse
    `proposed_parent.signing=UNSIGNED` with `attached_vertex.publisher=UNSIGNED` into one
    observable and refuse a pair a single lead splits by measuring two different things.
    """
    out = set()
    for pred in hyp.get("predictions") or []:
        if isinstance(pred, dict) and (claim := _normalized_claim(pred.get("claim"))):
            out.add(claim)
    for ap in hyp.get("attribute_predictions") or []:
        # A BLANK claim contributes nothing rather than an empty-valued key. Rule #33 already
        # refuses the row; counting it here would turn two separately-defective hypotheses
        # into a spurious third error saying they are one fork.
        if not isinstance(ap, dict) or not (claim := _normalized_claim(ap.get("claim"))):
            continue
        target = str(ap.get("target", "")).strip().lower()
        attribute = str(ap.get("attribute", "")).strip().lower()
        out.add(f"{target}.{attribute}={claim}")
    return frozenset(out)


def _check_sibling_fork_distinctness(companion: CompanionBody) -> list[str]:
    """Two siblings declaring the same claims are one hypothesis under two ids — no lead can
    move one without moving the other, so both sit at `null` until the run gives up on them.

    The sibling group is `(parent hypothesis, anchored vertex)` and the axis is the PREDICTED
    OBSERVABLE (#934). Explicitly NOT `proposed_edge.parent_vertex.classification`: an open
    tuple `??/??/??` is the canonical spelling for a fork whose parent the alert has not
    placed, so siblings legitimately share one, and a classification-keyed check would refuse
    exactly the shape SKILL §Sibling-fork uniqueness now asks for.
    `test_invlang_sibling_fork_934.py` is the guard on that.

    TEXTUAL, and only textual. The floor is a claim set identical after whitespace and case
    normalization; two claims saying the same thing in different words pass, and stay the
    author's discipline. Closing that is not this check's business — whether "failures arrive
    in bursts" and "failures are not evenly spaced" are one prediction is the judgment PREDICT
    exists to make. What is left is the pair that wrote the same sentence twice, which is
    always the defect and never a paraphrase.

    Empty-signature hypotheses are skipped: one declaring no prediction at all has no fork
    axis to compare, and the leanness and refutation-link rules own that shape. The convention
    was rule #35's while #35 was a rule; #934 merged #35 into #23 and this rule owns it now.
    The document is also written by APPEND — `:H hypothesize.hypotheses` and the `.preds`
    blocks arrive as separate writes — so a group is legally predictionless in between, and
    refusing it would deny the write on its way to satisfying the rule.

    LIVE only, for the reason `_check_authz_contract_ids` records: `:H` rows are immutable, so
    a collision already on disk is unrepairable under a declared-set reading and every later
    write would be denied for a row the author may no longer touch. Refuting one of the two is
    the in-grammar repair, and it has to stay reachable.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    groups: dict[tuple[str, str, frozenset[str]], list[str]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        if hid not in live:
            continue
        signature = _claim_signature(hyp)
        if not signature:
            continue
        groups.setdefault((*_sibling_key(hid, hyp), signature), []).append(hid)
    return [
        f"{_SIBLING_FORK_TAG} {', '.join(sorted(hids))} declare the same claims "
        f"({'; '.join(sorted(signature))}) on anchor {anchor or '?'} — a fork is a "
        f"disagreement about what will be observed, and a pair predicting the same observables "
        f"proposes one cause under two ids that no lead can split; give each a claim the "
        f"other's evidence would leave standing, or collapse them into one hypothesis. A "
        f"different `?name` or `parent_class` is not that difference: leave the slots the "
        f"alert has not settled `??` and write the difference as a prediction"
        for (_parent, anchor, signature), hids in groups.items()
        if len(hids) > 1
    ]


def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


def _leads(companion: CompanionBody) -> list[FindingRecord]:
    return [f for f in companion.get("findings") or [] if isinstance(f, dict)]


def _cell(record: Mapping[str, object], key: str) -> str:
    """One cell of a projected row as stripped TEXT, read by a column name held in a variable.

    A TypedDict `.get()` with a non-literal key is typed `object`, so a loop over a tuple of
    required columns cannot call `.strip()` on the result. Every projected cell is a `str`;
    stating that once here beats a cast at each of the sites that walk a column list.
    """
    value = record.get(key)
    return value.strip() if isinstance(value, str) else ""


_LEAD_PRED_ID_RE = re.compile(r"lp\d+")

#: The two destinations an `advance_to` may name that are not a lead. `CONCLUDE` ends the run;
#: `HYPOTHESIZE` sends it back for a mechanism the plan did not have.
#:
#: `docs/dense-investigation-format.md` §`:L` wrote `PREDICT` for the second in one worked
#: example. That is the PHASE name for the block `:H hypothesize.hypotheses` lives in, not a
#: third sentinel — spec rule #18 names these two, so the doc's example was corrected rather
#: than the enum widened. Widening it instead would have meant accepting two spellings of one
#: destination and, with `REPORT` beside `CONCLUDE` by the same argument, four.
_ROUTE_SENTINELS: tuple[str, ...] = ("CONCLUDE", "HYPOTHESIZE")

#: `:L l-NNN.lead_preds`' three content cells, each with what a BLANK one costs. The `if`
#: column projects as `condition` (`if` cannot be a TypedDict key); everything the author sees
#: uses the column spelling.
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
    """`:L l-NNN.lead_preds` rows — a lead's pre-committed ROUTE, checked for the four things
    that make a route followable.

    A route is not a prediction about the world; it is a prediction about the RUN. Nothing
    grades an `lp*`, no resolution head can cite one, and `_check_tested_commitment_refs`
    leaves an `lp*` alone. What it buys is that the interpretation was fixed before the data
    arrived — so the cells that matter are the ones that make it a commitment: a condition, the
    reading that condition licenses, and where that reading goes next. `_lead_pred_row`
    `_require`s only `id` and never looks at what any cell says, so `lp1|||` parses clean and
    lands a route committing to nothing.

    `advance_to` is a hard reference: a lead NAME some `:L findings` row declares, or a
    sentinel. Resolved against every declared lead INCLUDING the declaring one. The spec says
    "elsewhere in the companion", and the only ordering the dense surface carries is
    `:L findings` DOCUMENT ORDER — under which "elsewhere" can only mean "not this row", so
    enforcing it would refuse a self-route and nothing else. That is left alone deliberately:
    two loops may declare same-named leads under different ids, and there is no cell that says
    which one a name means, so a self-route test can be wrong where accepting one costs
    nothing. A destination that does not exist YET is refused, the way `_check_lead_refs`
    refuses a forward `l-*`: PLAN writes its `:L findings` rows before the routes that point
    at them, so the ordering the rule demands is the ordering PLAN already has.

    UNIQUENESS is not checked, for the reason `_check_attribute_prediction_structure` records
    at length: `_warn_repeated_ids` makes a repeat within one block a parse error and
    `_extend_by_id` keeps the first record per id across blocks, so a duplicate never reaches
    this list — and refusing the cross-block case would refuse the documented append shape.

    NOT checked: the ROUTE-COMPLIANCE clause. "Followed by another lead" would read as the
    next `:L findings` row in DOCUMENT ORDER, the same ordering `_check_screen_structure`
    already uses for "the final lead in a SCREEN sequence" — the reading is settled and it is
    not what blocks this. The CHANNEL is. Spec rule #18 asks for a WARNING, and there is no
    honest way to emit one here. A warn diagnostic without a `Locus` is dropped by
    `runtime/tools._addressable` and does nothing at all; a warn diagnostic WITH one FLAGS that
    row and blocks every later write until `fix_row` rewrites it — and both candidate rows must
    not be rewritten. The follower's `:L findings` row is a committed lead declaration, which
    the warn family has never been able to reach (`_tool_fix_row`: "the warn family walks
    `:R attr_updates` blocks and nothing else"). The `lead_preds` row is worse: letting a run
    edit its own pre-registration to match where it ended up destroys the only thing
    pre-registration is for. See the enforcement ramp for the deferral.
    """
    names = {
        f["name"] for f in _leads(companion)
        if isinstance(f.get("name"), str) and f["name"]
    }
    destinations = names | set(_ROUTE_SENTINELS)
    errors: list[str] = []
    for lead in _leads(companion):
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
            dest = (lp.get("advance_to") or "").strip()
            if dest and dest not in destinations:
                errors.append(
                    f"{where}: `advance_to` names {dest!r}, which is neither a lead NAME this "
                    f"document declares ({_known_ids(names)}) nor one of "
                    f"{', '.join(_ROUTE_SENTINELS)} — the cell carries the lead's `name`, not "
                    f"its `l-*` id, and a route nobody can follow is not a plan"
                )
    return errors


_IMPACT_PRED_ID_RE = re.compile(r"ip\d+")

#: `:L l-NNN.impact_preds`' five verdict-shaped cells. Grouped rather than spelled out one
#: branch apiece because they fail the same way and for the same reason: the row is a
#: PREDICATE, and a predicate missing one of its outcomes cannot be graded on that outcome.
_IMPACT_PRED_CELLS: tuple[str, ...] = (
    "claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on",
)


def _check_impact_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.impact_preds` rows — the impact predicate a lead registers at PREDICT, checked
    for the cells that make it gradeable.

    Impact is the third axis: an authorized, uncompromised action can still be
    escalation-worthy if its consequence exceeds a threshold. What makes that checkable rather
    than a post-hoc judgment is that the threshold and BOTH of its outcomes are written down
    before the measurement lands — so a row with a `claim` and no `on_mismatch` has registered
    a number without registering what exceeding it means, and ANALYZE grades it whichever way
    the answer came out.

    `_impact_pred_row` `_require`s only `id`, so every cell below is present-and-empty rather
    than missing: `ip1|confidentiality|||||` parses clean today.

    `dimension` is closed (`vocab.IMPACT_DIMENSION`) because `:R impact` rows must MATCH it —
    `_check_impact_resolution_refs` compares the two, and a free-text dimension makes that
    comparison a string coincidence.

    NOT checked: the one-observable-per-entry clause. "Compound `AND` / `OR` / semicolon
    predicates must be split across entries" is a judgment about what a sentence asserts, not a
    property of the row, and a lexical test would refuse "session bytes and connection count
    stay within baseline" written about one measurement. Rule #33 leaves the identical clause
    to the author on `attribute_predictions[]`, and
    `_check_attribute_prediction_structure` records why.
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
            errors += _check_vocab(
                ip.get("dimension"), vocab.IMPACT_DIMENSION,
                f"{where}: dimension {ip.get('dimension')!r} is not one of "
                f"{', '.join(vocab.IMPACT_DIMENSION)} — the cell says which axis the "
                f"consequence is measured on, and `:R impact` grades against it",
            )
            if not (ip.get("dimension") or "").strip():
                errors.append(
                    f"{where}: empty `dim` — a predicate with no dimension names no axis, and "
                    f"the `:R impact` row that grades it has nothing to match"
                )
            for cell in _IMPACT_PRED_CELLS:
                if not _cell(ip, cell):
                    errors.append(
                        f"{where}: empty `{cell}` — an impact predicate registers its "
                        f"threshold AND every outcome before the measurement lands; a blank "
                        f"cell lets ANALYZE decide that outcome after seeing the answer"
                    )
    return errors


#: The `:R impact` cells rule #30 requires, spelled as the CANONICAL key the projector emits
#: beside the COLUMN an author writes (`_RESOLUTION_KEY_CANONICAL` renames four of them).
_IMPACT_RESOLUTION_REQUIRED: tuple[tuple[str, str], ...] = (
    ("prediction_ref", "pred_ref"),
    ("dimension", "dim"),
    ("verdict", "verdict"),
    ("grounding_kind", "grounding"),
    ("authority_for_question", "authority"),
    ("as_of", "as_of"),
    ("reasoning", "reasoning"),
)


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

    The impact analog of `_check_prediction_refs`, and it exists for the same reason: nothing
    joins a `:R impact` row back to the `:L l-NNN.impact_preds` row it claims to grade. The
    projector canonicalizes `pred_ref` into a string and stops, so a typo, a forward reference
    and ANOTHER lead's `ip1` all land identically — and a verdict attached to no predicate is a
    consequence claim with no pre-registered threshold behind it, which is the one thing the
    impact axis exists to prevent.

    `dimension` is compared against the predicate's, not merely checked for membership. A row
    that grades an availability predicate under `confidentiality` has answered a question
    nobody asked, and the roll-up into `conclude.impact_verdict` cannot tell that from a real
    answer.

    `past-case` is refused by name rather than left to the enum's silence, because the omission
    is a judgment and not an oversight: impact is per-instance reasoning about what THIS event
    did, and a past case establishes what a CATEGORY of event was permitted to do. Rule #11
    excludes it from consultations for the neighbouring reason.

    NOT checked: whether the observation supports the verdict. `observed` is free text — "180GB
    (3σ above 60GB μ)" — and reading it against `claim` is the judgment ANALYZE is for. This
    checks that the row is ANSWERABLE, not that the answer is right.
    """
    declared = _declared_impact_predictions(companion)
    errors: list[str] = []
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            if not isinstance(row, dict):
                continue
            raw_ref = (row.get("prediction_ref") or "").strip()
            where = f"lead {lid}: `:R impact` row for {raw_ref or '<no pred_ref>'}"
            # ONE error per ROW, not per column: an under-filled row is one defect, and seven
            # near-identical refusals for one row would bury the six other checks below.
            blank = [column for key, column in _IMPACT_RESOLUTION_REQUIRED if not _cell(row, key)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"resolution carries a consequence verdict AND the provenance that makes "
                    f"it checkable, so all of "
                    f"{', '.join(c for _k, c in _IMPACT_RESOLUTION_REQUIRED)} are required; a "
                    f"blank cell records the verdict without what it rests on"
                )
            errors += _check_vocab(
                row.get("verdict"), vocab.IMPACT_VERDICT,
                f"{where}: verdict {row.get('verdict')!r} is not one of "
                f"{', '.join(vocab.IMPACT_VERDICT)} — the cell says whether the measurement "
                f"landed inside the registered threshold, not what was measured",
            )
            grounding = row.get("grounding_kind")
            if grounding == "past-case":
                errors.append(
                    f"{where}: `grounding past-case` — impact is per-instance reasoning about "
                    f"what THIS event did, and a past case establishes only what a CATEGORY "
                    f"of event was permitted to do. Ground it on "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}, or defer the prediction in "
                    f"`:T conclude.deferred_impact` with that as the rationale"
                )
            else:
                errors += _check_vocab(
                    grounding, vocab.IMPACT_GROUNDING,
                    f"{where}: grounding {grounding!r} is not one of "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}",
                )
            if not raw_ref:
                continue
            # Bare `ip{n}` is scoped to the lead the row landed on — the one the `resolved_by`
            # column named, which is the only lead that could have measured it.
            ref = raw_ref if "." in raw_ref else f"{lid}.{raw_ref}"
            pred = declared.get(ref)
            if pred is None:
                errors.append(
                    f"{where}: `pred_ref` resolves to {ref!r}, which no "
                    f"`:L l-NNN.impact_preds` row declares (declared: "
                    f"{_known_ids(set(declared))}) — a bare `ip<n>` resolves within {lid} and "
                    f"a qualified `l-NNN.ip<n>` across leads; register the predicate before "
                    f"grading it"
                )
                continue
            dim, pred_dim = row.get("dimension"), pred.get("dimension")
            if dim and pred_dim and dim != pred_dim:
                errors.append(
                    f"{where}: `dim {dim}` but {ref} was registered on {pred_dim!r} — a "
                    f"resolution grades the predicate it names, so the two axes have to be "
                    f"the same one; fix the column, or point `pred_ref` at the predicate this "
                    f"row actually measured"
                )
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


def _check_vocab_anchor_kinds(companion: CompanionBody) -> list[str]:
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
    return errors


def _swap_cell(cells: list[str], at: int, replacement: str) -> str:
    """One cell replaced, every other left exactly where the author put it."""
    swapped = list(cells)
    swapped[at] = replacement
    return "|".join(swapped)


#: The refinement keys `:R attr_updates` accepts. `class` sharpens the classification,
#: `attrs.<name>` an attribute, and `ident` the vertex's effective IDENTIFIER. `ident` lands in
#: a distinct top-level `identifier` slot, never in `attributes`: `_check_benign_open_slots`
#: refuses a benign close on any `??`-valued ATTRIBUTE, so routing it there would make
#: `ident=??` block a benign disposition.
#:
#: These three ARE the slot vocabulary `iter_vertex_cells` reports, and the one this module
#: uses to decide a refinement key is legal — one literal for both, so the spelling that CLOSES
#: a slot and the spelling that NAMES one in a `VertexCell` cannot drift apart INSIDE this file.
#:
#: They stop there. A lesson's `slot:` selector is free-form YAML compared by `!=`
#: (`lessons_frontier._node_match_score`), so nothing holds an AUTHOR to these spellings; the
#: prompt says so and `learning/author/lessons/prompt.md` warns that a typo matches nothing
#: forever. A corpus lint over `vocab` is what would close that, not another constant —
#: `frontier.py` deliberately does not re-export these (see its `__all__` note).
SLOT_CLASS = "class"
IDENT_REFINEMENT_KEY = "ident"
SLOT_IDENT = IDENT_REFINEMENT_KEY
ATTR_PREFIX = "attrs."


def _is_legal_refinement_key(key: str) -> bool:
    return key in (SLOT_CLASS, SLOT_IDENT) or key.startswith(ATTR_PREFIX)


def _check_attr_update_keys(proposed_text: str) -> list[Diagnostic]:
    """`:R attr_updates` refinement rows — the KEY, and the value that key promises to carry
    — checked over the ROWS rather than the folded records.

    Reads blocks straight from the document because this is the one check that quotes a row
    back and offers a corrected one. The fold keeps `{key: value}` per target and drops the
    header, so rebuilding a row from it means assuming the conventional
    `resolved_by|target|key|value` order — a convention `_row_dict` does not enforce, since it
    zips whatever header the block declares. Against `[…|value|key]` that yields a correction
    with its columns transposed: a "fix" that earns a second refusal.

    Here the `key` CELL is replaced in place and every other cell stays where the author put
    it. A block whose header names no `key` column has no cell to substitute and no row this
    can honestly point at, so it yields nothing — the row is not a refinement at all.

    The VALUE cell is the second family, and a REFUSAL rather than a warning. A present-but-
    blank value is not inert: `_apply_attr_updates` would assign it, and since neither
    `has_open_slot("")` nor `is_unresolved("")` reads `""` as open, the empty cell reads as a
    RESOLUTION — `l-001|v-001|class|` makes a benign-blocking error vanish. The truncated
    3-cell row is already refused by the cell-count rule, so the hole is exactly the cell that
    is present and says nothing. No `fix` is offered: the missing value is the one thing this
    check cannot supply."""
    out: list[Diagnostic] = []
    for block in iter_blocks(proposed_text):
        cols = block.columns or []
        if block.name != "attr_updates":
            continue
        for row in block.rows:
            try:
                rec = _row_dict(block, row)
            except RowError:
                continue  # already a parse warning; not this check's business
            key = rec.get("key")
            if not key:
                continue
            if _is_legal_refinement_key(key):
                value = rec.get("value")
                if "value" in cols and not (value or "").strip():
                    out.append(Diagnostic(
                        message=(
                            f":R attr_updates on {rec.get('target', '?')}: the `value` cell "
                            f"for key {key!r} is empty — a refinement settles a slot by "
                            f"naming the value the lead obtained, and an empty cell settles "
                            f"nothing. Write that value, or leave the `??` standing and "
                            f"escalate"
                        ),
                        locus=Locus(block=":R attr_updates", row_text=row),
                    ))
                continue
            # `rec`'s keys are the block's DECLARED columns, so a non-empty `key` is proof
            # the header names a `key` column to substitute into.
            at = cols.index("key")
            cells = [rec.get(c, "") for c in cols]
            out.append(Diagnostic(
                message=(
                    f":R attr_updates on {rec.get('target', '?')}: key {key!r} is not a "
                    f"valid refinement key — use `class` (class refinement), `ident` "
                    f"(identifier refinement) or `attrs.<name>` (attribute); a bare key "
                    f"is dropped silently"
                ),
                locus=Locus(block=":R attr_updates", row_text=row),
                fix=(
                    _swap_cell(cells, at, "class"),
                    _swap_cell(cells, at, f"attrs.{key}"),
                ),
                # THE one warn-severity family. The row is INERT — it changes no effective
                # vertex state — so the block it rides in is worth keeping, and the model
                # repairs the row with `fix_row` instead of re-emitting the whole block.
                # Every other family stays a refusal: nothing is written and the model
                # re-sends.
                severity="warning",
            ))
    return out


def _check_attr_update_targets(companion: CompanionBody) -> list[str]:
    """A `:R attr_updates` row must name a graph object the document DECLARES.

    Otherwise an undeclared target lands with zero diagnostics and `effective_vertex_state`
    fabricates the object out of the refinement alone — and since `ident` is writable, the
    fabricated vertex's identifier carries a value that flows from alert content.

    EDGES count as declared targets, not only vertices. `:R attr_updates` is the surface for
    recording facts learned about ANY existing graph object, and refining an edge is ordinary
    practice (`l-001|e-001|attrs.auth_method|password` appears in the checked-in goldens)."""
    declared = {
        r.get("id")
        for records in (_walkers.all_vertices(companion), _walkers.all_edges(companion))
        for r in records
        if isinstance(r.get("id"), str)
    }
    errors: list[str] = []
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target")
        if not isinstance(tgt, str) or not tgt or tgt in declared:
            continue
        errors.append(
            f":R attr_updates refines {tgt!r}, which no `:V` or `:E` block declares — declare "
            f"it before refining it (declared: {sorted(d for d in declared if d)})"
        )
    return errors


def _check_closed_vocab(companion: CompanionBody, proposed_text: str) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    out += _plain(_check_vocab_vertices(companion))
    out += _plain(_check_vocab_edges(companion))
    out += _plain(_check_vocab_hypotheses(companion))
    out += _plain(_check_conclude_vocab(companion))
    out += _plain(_check_vocab_anchor_kinds(companion))
    out += _check_attr_update_keys(proposed_text)
    return out




#: The whole-cell open marker, named once so the two predicates below and every reader of
#: theirs look for the same token rather than for a literal each spells for itself.
OPEN_MARKER = "??"


def is_unresolved(value: Any) -> bool:
    """Does this cell say "not settled yet" — the WHOLE of it, not a substring.

    The two markers SKILL.md §Open questions defines, and the three-state progression it
    documents (`??` → `{a, b, c}` → concrete) is why both count: a candidate set is an upgrade
    from `??`, not a resolution of it. No comma is required — `{internal}` is a one-member set
    that still has not picked.

    Anchored to the whole value on purpose: a "contains braces" test would refuse a benign
    close over a legitimate `attrs.cmdline` that happens to carry `{...}`.

    An OPENING brace with no close counts as open — otherwise a single dropped `}` reads as
    CONCRETE and closes benign over the class it was still enumerating (`role={internal, dmz`
    satisfies neither of the other two tests).

    That `count("{") > count("}")` test is load-bearing ON TOP of the whole-value anchor, not a
    replacement for it. The anchor alone reads any value that merely BEGINS with a brace as
    open, closed or not — `attrs.cmdline={ cd /x && ls; } >out` and a JSON-shaped attribute
    both start with `{` and carry their close. The anchor still narrows: a shell command
    carrying an unclosed `{` does not START with one, so it stays clean.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v == OPEN_MARKER:
        return True
    return v.startswith("{") and (v.endswith("}") or v.count("{") > v.count("}"))


def is_ident_open(value: Any) -> bool:
    """Does this `ident` cell still carry an open question — WHOLE-cell or EMBEDDED.

    Unlike a class slot or an attribute value, an identifier is routinely named IN PART, and
    the committed investigations do exactly that: `bash[pid=??]` and `??[pid=??]` for a process
    whose binary is known and whose pid is not, `dev-ws-??` for a host whose prefix is known
    and whose index is not.

    `is_unresolved` is anchored to the whole cell and calls every one of those SETTLED,
    which is the wrong answer for BOTH halves of the retrieval key (#919): a
    `frontier_nodes: {slot: ident}` lesson — "pin the pid before you attribute the process" —
    could never fire on the document that needs it, and an `observed_nodes: {slot: ident}`
    lesson fires instead, asserting the run HOLDS an identifier that literally reads `??`.

    SUBSTRING, deliberately, and only here. `is_unresolved` stays whole-cell anchored because
    an `attrs.cmdline` may legitimately carry braces or a literal `?`; an ident cell is a name
    the document CHOSE, and `??` inside one is the marker rather than data. Scope is retrieval
    only — `_check_benign_open_slots` passes `include_ident=False`, so widening this cannot
    move a disposition gate.

    A SUPERSET of `is_unresolved`, never a replacement for it. The embedded test alone loses
    the OTHER marker: SKILL.md's progression is `??` → `{a, b}` → concrete, so an ident cell
    reading `{dev-ws-1, dev-ws-2}` has not picked a name — and a substring test for `??` calls
    it SETTLED, which is the exact inversion this predicate exists to prevent for `??`. The
    class and attribute arms already read a candidate set as open; the ident arm has to agree.
    """
    return is_unresolved(value) or (isinstance(value, str) and OPEN_MARKER in value)


def class_slots(classification: str) -> list[str]:
    """A class cell's slots — the slash-tuple, minus an optional leading `<type>:` prefix.

    Brace-aware, because the primary candidate-set form enumerates whole triples
    (`{monitoring-agent/internal/known-corp, ip-only/internet/novel}`) and a plain
    `split("/")` would shred it into slots that are neither open nor concrete. Splitting at
    depth 0 only reads that cell as the ONE unresolved slot it is, and still reads the
    per-slot form (`role/{internal, dmz}/prov`) as three.

    The type prefix is stripped rather than tolerated: SKILL.md says the class cell carries
    the slash-tuple only, but `compute:{...}` is a spelling models reach for, and the prefix
    alone would otherwise hide the candidate set behind it.

    PUBLIC for the same reason `effective_vertex_state` below is: `has_open_slot` uses this
    split to decide a class cell is OPEN, and `scripts/lessons/lessons_frontier.py` re-splits
    the same cell to decide which selector matches it. A second, plainer `split("/")` there
    read the whole-triple candidate set as five fragments and kept the `compute:` prefix, so
    the two halves of one join disagreed about what a slot even is (#919).
    """
    c = classification.strip()
    head, sep, rest = c.partition(":")
    if sep and "{" not in head and "/" not in head:
        c = rest.strip()
    slots: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in c:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif ch == "/" and depth == 0:
            slots.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    slots.append("".join(cur))
    return [s.strip() for s in slots]


def is_open_slot(slot: str) -> bool:
    """Is this ONE ALREADY-SPLIT class slot unresolved.

    PUBLIC and separate from `has_open_slot` because `scripts/lessons/lessons_frontier.py`
    needs exactly this half: it has already run `class_slots` and holds the slots, and calling
    `has_open_slot` on one of them re-splits it and strips a leading `<head>:` prefix — so the
    cell that decided a slot was OPEN and the cell that wildcards it disagreed about the values
    the two exist to agree on (#919). One definition, two readers, rather than a copy per
    reader.

    A `{` the author never closed is an UNTERMINATED candidate set and counts as open: the
    depth-aware split in `class_slots` folds every slot after it into one cell that is neither
    `??` nor a closed `{...}`, so a single dropped `}` would read as CONCRETE. A stray `}` with
    no `{` is left alone — it splits like any other character and hides nothing.
    """
    return is_unresolved(slot) or slot.count("{") > slot.count("}")


def has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str):
        return False
    return any(is_open_slot(slot) for slot in class_slots(classification))


def _seed_vertex_state(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    for v in _walkers.all_vertices(companion):
        vid = v.get("id")
        if not isinstance(vid, str):
            continue
        cls = v.get("classification", "")
        cur = state.setdefault(
            vid,
            {
                "classification": cls,
                # Seeded from the DECLARED `:V` identifier. Both construction sites carry the
                # slot — one present at only one of them is a KeyError for the consumer on
                # every document that does not happen to exercise the other.
                "identifier": v.get("identifier", ""),
                "attributes": dict(v.get("attributes") or {}),
            },
        )
        # BLANK counts as unsettled here, exactly as it does on the ident arm below.
        # `classification` is not a required `:V` column, so `v-001|compute|||attrs` is
        # diagnostic-clean, and the pre-#919 test — `has_open_slot(cur["classification"])` —
        # is False for `""`, so the concrete class a later `observations.vertices` row
        # supplies was dropped. That only mattered once `iter_vertex_cells` stamped the class
        # tuple onto EVERY cell: a latched `""` makes `_class_pins` refuse every class-bearing
        # selector against the vertex's ident and attrs cells too, not just its class cell.
        #
        # Still one direction, and still never blank→OPEN: taking an unresolved class over an
        # empty one would newly BLOCK a benign close on a document the gate accepts today.
        held_cls = cur["classification"]
        if cls and not has_open_slot(cls) and (
            not (isinstance(held_cls, str) and held_cls.strip()) or has_open_slot(held_cls)
        ):
            cur["classification"] = cls
        # The IDENT half of the same rule, and it only started mattering when
        # `iter_vertex_cells(include_ident=True)` gave the slot a reader (#919). Re-observing a
        # vertex is how an append-only document NAMES the entity it opened with `ident=??`
        # (SKILL.md §Open questions now recommends that spelling over a guessed identifier), so
        # without this the frontier reports `ident=??` open on a vertex the run already named,
        # re-pushes the "name this entity" lesson forever, and withholds every
        # `observed_nodes: {slot: ident}` selector from the resolved value.
        #
        # UNSETTLED, not just `??`, and BLANK is one of the unsettled states: an empty ident
        # column is neither open nor held and no open predicate reads `""` (see
        # `_apply_attr_updates` on why none may), so without this arm a vertex declared with
        # an empty ident and later named in a lead's `observations.vertices` folds to `""`
        # and the run's answer to "which host is this IP" reaches NO lane at all.
        #
        # The INCOMING value is not required to be settled, only non-blank. `bash[pid=??]` is
        # the shape this arm was written for — a process whose binary the run has and whose
        # pid it has not — and demanding a settled value dropped it, leaving the cell `""`:
        # not an `OpenSlot` either, so the "pin the pid before you attribute the process"
        # lesson could not fire on the document that needs it.
        #
        # One direction only, like the class arm: the guard is on what is HELD, so a later row
        # can supersede a blank or still-open cell and can never re-open a settled name.
        ident = v.get("identifier", "")
        held = cur["identifier"]
        if isinstance(ident, str) and ident.strip() and (
            not (isinstance(held, str) and held.strip()) or is_ident_open(held)
        ):
            cur["identifier"] = ident
        if v.get("attributes"):
            cur["attributes"].update(v["attributes"])


def _apply_attr_updates(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target")
        updates = upd.get("updates") or {}
        if not isinstance(tgt, str) or not isinstance(updates, dict):
            continue
        st = state.setdefault(
            tgt, {"classification": "", "identifier": "", "attributes": {}}
        )
        for key, val in updates.items():
            # A refinement with nothing in its value cell resolves nothing. The parser defaults
            # an absent value to `""`, and `has_open_slot("")` / `is_unresolved("")` are both
            # False — so assigning it would read not as a downgrade but as a RESOLUTION, and
            # `l-001|v-001|class|` would clear the very `??` the row was meant to settle.
            # `_check_attr_update_keys` refuses the row outright; this keeps the read side
            # honest on a document that never went through the gate.
            if not isinstance(val, str) or not val.strip():
                continue
            if key == SLOT_CLASS:
                st["classification"] = val
            elif key == IDENT_REFINEMENT_KEY:
                # A DISTINCT top-level slot, never `attributes["ident"]` — see
                # IDENT_REFINEMENT_KEY. Last row in document order wins; the fold retains
                # no history, so a superseded value survives only as the rows on disk.
                st["identifier"] = val
            elif isinstance(key, str) and key.startswith(ATTR_PREFIX):
                st["attributes"][key[len(ATTR_PREFIX):]] = val


def effective_vertex_state(
    companion: CompanionBody,
) -> dict[str, dict[str, Any]]:
    """Every vertex as it stands NOW — declared `:V` state with every `:R attr_updates` row
    applied, last row winning.

    PUBLIC because it is the read-side answer to "what does the document currently say",
    which two independent consumers need: the benign-disposition gate below, and the
    frontier derivation `frontier.py` keys lesson retrieval on (#919). Both must see one
    fold of the document, not two that can drift.
    """
    state: dict[str, dict[str, Any]] = {}
    _seed_vertex_state(companion, state)
    _apply_attr_updates(companion, state)
    return state


#: The three states a vertex cell can be in. NOT a bool: open and held are not complements —
#: an absent cell is neither, and collapsing it into `held` would report every attribute a
#: vertex never carried as something the run KNOWS (`frontier.HeldFact`).
CELL_OPEN = "open"
CELL_HELD = "held"
CELL_EMPTY = "empty"


@dataclass(frozen=True)
class VertexCell:
    """One `(vertex, slot)` cell of the folded document, classified open / held / empty.

    THE node-axis walk. Two consumers read it, and they disagree about what to DO with a cell,
    never about what the cell IS: the benign-disposition gate (`_check_benign_open_slots`)
    blocks on the open ones, and `frontier._node_state` keys lesson retrieval on both populated
    halves (#919, PR-930). Before this they were two walks that agreed by inspection.
    """

    vertex_id: str
    #: The vertex's effective class tuple, carried on EVERY cell rather than only the `class`
    #: one, because a lesson selector matches `{type, class, slot}` as a triple — an
    #: `attrs.loginuid` cell still has to say what kind of vertex it sits on.
    classification: str
    slot: str
    value: str
    state: str

    @property
    def is_open(self) -> bool:
        return self.state == CELL_OPEN

    @property
    def is_held(self) -> bool:
        return self.state == CELL_HELD


def _cell_text(value: Any) -> str:
    """A cell as text. A non-`str` is read as ABSENT rather than crashing the walk.

    Both open tests already guard their input and answer False for a non-`str`, so this only
    restates their tolerance for the emptiness test below — which reaches for `.strip()` and
    would otherwise take down a whole document's frontier over one malformed attribute."""
    return value if isinstance(value, str) else ""


def _cell_state(value: str, *, open_test: Callable[[Any], bool]) -> str:
    """Classify one already-folded cell.

    `open_test` varies by slot and the variation is load-bearing: a class cell is open when ANY
    of its slash-slots is (`has_open_slot`), while `ident` and `attrs` cells are single values
    that `is_unresolved` reads whole. Running `is_unresolved` across a class tuple would read
    `a/??/c` as concrete — it is the WHOLE cell that is neither `??` nor a candidate set.

    Emptiness is tested FIRST and independently, because neither predicate reads `""` as open —
    see `_apply_attr_updates` on why a blank value must never read as a resolution."""
    if not value.strip():
        return CELL_EMPTY
    return CELL_OPEN if open_test(value) else CELL_HELD


def iter_vertex_cells(
    companion: CompanionBody, *, include_ident: bool
) -> Iterator[VertexCell]:
    """Every vertex cell the folded document holds, in document order, class → ident → attrs.

    `include_ident` is the first of the two divergences `frontier.py`'s module docstring
    records, hoisted out of a comment and into the signature. The gate passes False — an
    unresolved identifier must not block a benign close, which is the whole reason
    `IDENT_REFINEMENT_KEY` routes `ident` to its own top-level slot instead of into
    `attributes`. Retrieval passes True, because an unresolved identifier is the single most
    retrieval-worthy open slot there is.

    The second divergence is deliberately NOT a parameter. `effective_vertex_state` fabricates
    an entry for any `:R attr_updates` TARGET and the validator admits an `e-*` there, so some
    ids yielded here have no `:V` row at all. This walk reports them: the gate blocks on them
    today and must keep doing so, and dropping them here would narrow it silently. It is the
    CONSUMER that needs a vertex type to match a selector against, so that filter — and the
    limitation it creates — belongs in `frontier._node_state`, where it is recorded.
    """
    for vid, st in effective_vertex_state(companion).items():
        cls = _cell_text(st.get("classification"))
        yield VertexCell(
            vid, cls, SLOT_CLASS, cls, _cell_state(cls, open_test=has_open_slot)
        )
        if include_ident:
            ident = _cell_text(st.get("identifier"))
            yield VertexCell(
                vid, cls, SLOT_IDENT, ident, _cell_state(ident, open_test=is_ident_open)
            )
        for name, raw in (st.get("attributes") or {}).items():
            val = _cell_text(raw)
            yield VertexCell(
                vid,
                cls,
                f"{ATTR_PREFIX}{name}",
                val,
                _cell_state(val, open_test=is_unresolved),
            )


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
    """The open cells that block a benign close, over the one shared walk.

    `include_ident=False`: see `IDENT_REFINEMENT_KEY`. An unresolved identifier does not block —
    routing `ident` where this check can see it is the exact mistake that key exists to prevent.
    """
    errors: list[str] = []
    for cell in iter_vertex_cells(companion, include_ident=False):
        if not cell.is_open:
            continue
        if cell.slot == SLOT_CLASS:
            errors.append(
                f"disposition benign blocked: vertex {cell.vertex_id} still has an "
                f"unresolved class ({cell.value!r}) — resolve via "
                f":R attr_updates or escalate"
            )
        elif cell.slot.startswith(ATTR_PREFIX):
            errors.append(
                f"disposition benign blocked: vertex {cell.vertex_id} attribute "
                f"{cell.slot[len(ATTR_PREFIX):]!r} is still unresolved ({cell.value!r}) — "
                f"resolve via :R attr_updates or escalate"
            )
        # No `else`. The two arms above are the two slot kinds `include_ident=False` yields
        # today, but the walk is SHARED and takes a knob — a bare `else` would render an
        # `ident` cell as `attribute ''` (`"ident"[len("attrs."):]` is `""`), a nonsense refusal
        # naming an attribute that does not exist, and one that contradicts the whole reason
        # `IDENT_REFINEMENT_KEY` routes `ident` out of `attributes`. A fourth slot kind reaching
        # here should be a visible gap, not a mislabelled attribute.
    return errors


def _anchor_kind(record: Any) -> str:
    return (record.get("anchor_kind") or "").strip() if isinstance(record, dict) else ""


def _declarers_by_contract_id(
    companion: CompanionBody,
) -> dict[str, list[tuple[str, str]]]:
    """Every `(hypothesis, anchor kind)` that declares each `ac*` id — LIVE OR NOT.

    A different question from the one `_check_authz_contract_ids` indexes, which is why the
    live filter is not shared. That check asks "is this collision still repairable"; this one
    asks "which contract does a `:R authz` row naming this id answer", and a refuted declarer
    competes for the row exactly as a live one does — the row carries no hypothesis column.
    """
    declared_by: dict[str, list[tuple[str, str]]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if isinstance(cid, str) and cid:
                declared_by.setdefault(cid, []).append((hid, _anchor_kind(c)))
    return declared_by


def _authz_contract_error(
    hid: str,
    contract: AuthorizationContract,
    declarers: dict[str, list[tuple[str, str]]],
    verdicts: dict[str, list[tuple[str, str]]],
) -> str | None:
    """Why this ONE contract on this LIVE hypothesis does not close benign — or `None`."""
    cid = contract.get("id", "?")
    anchor = _anchor_kind(contract)
    competing = [(h, a) for h, a in declarers.get(cid, []) if h != hid]
    candidates = verdicts.get(cid) or []

    if competing:
        # The anchor kind is always present: `_hyp_sub_authz_row` `_require`s it, so a
        # `:H <h>.authz` row without one is a parse error and the contract never reaches the
        # companion. That is what makes the kind a usable discriminator here.
        twins = sorted(h for h, a in competing if a == anchor)
        if twins:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} shares BOTH its id and its anchor kind {anchor!r} with a contract "
                f"on {', '.join(twins)} — a `:R authz` row names only the contract it "
                f"fulfills, so no row can be attributed to this one and none discharges "
                f"it; number `ac*` across the document, not per hypothesis"
            )
        rows = [v for v, a in candidates if a == anchor]
        if not rows:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} asks an {anchor!r} question, and {cid} is also declared by "
                f"{', '.join(sorted(h for h, _a in competing))} — so only a `:R authz` row "
                f"carrying anchor kind {anchor!r} discharges it, and the document has none"
            )
    else:
        rows = [v for v, _a in candidates]

    if not rows:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved 'no fulfilling :R authz "
            f"row', not 'authorized' — benign requires every contract "
            f"authorized"
        )
    # The LIST, not `next(..., None)`: `None` is a verdict a row can carry, so the sentinel
    # and the value would be the same object and a `None` verdict would discharge the contract
    # it is the strongest evidence against. Emptiness is the only test that cannot collide.
    bad = [v for v in rows if v != "authorized"]
    if bad:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved {bad[0]!r}, not 'authorized' "
            f"— benign requires every contract authorized"
        )
    return None


def outstanding_authz_contracts(
    companion: CompanionBody,
) -> list[tuple[str, AuthorizationContract, str]]:
    """Every `(hypothesis, contract, why)` on a LIVE hypothesis that no `:R authz` row
    discharges — THE definition of "this authorization question is still open".

    PUBLIC, and published for the same reason `effective_vertex_state` is: two consumers need
    one answer. `_check_benign_authz` below turns each `why` into a benign-close refusal, and
    `frontier._open_contracts` puts each contract on the retrieval frontier (#919). A second
    reading of "discharged" — a bare `fulfills_contract` id set, say — silently disagrees with
    this one on every shared id, and disagrees in the harmful direction: the frontier drops
    the contract that is actually wedging the close, so the lessons about what that anchor can
    conclude are withheld exactly when the run is stuck on it.

    See `_authz_contract_error` for why a shared id is scoped by anchor kind.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)
    declarers = _declarers_by_contract_id(companion)

    verdicts: dict[str, list[tuple[str, str]]] = {}
    for row in _walkers.iter_authz_resolutions(companion):
        cid = row.get("fulfills_contract")
        if isinstance(cid, str):
            verdicts.setdefault(cid, []).append(
                (row.get("verdict", "indeterminate"), _anchor_kind(row))
            )

    out: list[tuple[str, AuthorizationContract, str]] = []
    for hid in sorted(live):
        hyp = hyps.get(hid)
        if hyp is None:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            found = _authz_contract_error(hid, c, declarers, verdicts)
            if found is not None:
                out.append((hid, c, found))
    return out


def _check_benign_authz(companion: CompanionBody) -> list[str]:
    """Every authz contract on a LIVE hypothesis is discharged by an `authorized` row.

    The row that discharges it has to be attributable to it, and a bare `fulfills_contract` id
    is not always enough. `_check_authz_contract_ids` exempts a collision whose other side is
    REFUTED, because on an append-only document refuting is the only repair left once the rows
    are on disk. That exemption is sound about the CONTRACT and false about the ROW: a
    `:R authz` row written against the refuted declarer's `ac1` would discharge the LIVE
    declarer's `ac1` too, landing a benign close over a question nobody ever asked.

    So a shared id is scoped by ANCHOR KIND — the one column both sides carry, and the one that
    says which question the row answers. Scoping rather than refusing outright keeps the rule
    repairable: `:H` rows are immutable, so a live contract holding a shared `ac1` can never be
    renumbered, and "an ambiguous id discharges nothing" would make `disposition: benign`
    unreachable for the rest of that document's life. Writing the `:R authz` row that carries
    THIS contract's anchor kind is an ordinary append, and it discharges it.

    Two declarers sharing an id AND an anchor kind has no honest reading left and is refused:
    no row can be attributed, so none discharges.

    The scoping applies only where the id is shared. A contract nobody competes for is
    discharged by its id alone; making the anchor kind load-bearing document-wide would refuse
    every document that left the cell empty.
    """
    return [why for _hid, _c, why in outstanding_authz_contracts(companion)]


def _check_conclude_vocab(companion: CompanionBody) -> list[str]:
    """`conclude`'s disposition is the run's headline, so it carries a vocabulary check like
    every other conclude field: an out-of-enum value silently skips the benign gating below,
    and a typo would buy a document past the checks a `benign` conclusion has to pass."""
    disposition = (companion.get("conclude") or {}).get("disposition")
    return _check_vocab(
        disposition, vocab.DISPOSITION,
        f"conclude: disposition {disposition!r} is not a known disposition "
        f"(`enum disposition`)",
    )


def _row_states_something(value: Any) -> bool:
    """A `:T conclude` scalar that actually SAYS something — present, non-blank, and not the
    format's own "nothing to say" marker, which only the parser gets to define."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not is_conclude_empty_marker(value)
    )


def _lead_returned_a_result(lead: FindingRecord) -> bool:
    """Did this lead come back with a RESULT — not merely with a record that it ran.

    Deliberately stricter than `_check_loop_close`'s committed test, which counts ANY outcome:
    `:L findings`' `fail_reason` column projects into `outcome` as `failure_reason`, so a lead
    whose only recorded outcome is "the query errored" reads as committed there. For closing a
    loop that is right — the loop was worked. Here it is the shape the gate exists to reject:
    a failed query tested the alerted entity for nothing.
    """
    if lead.get("resolutions"):
        return True
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(set(outcome) - {"failure_reason"})


def _check_false_positive_gating(companion: CompanionBody) -> list[str]:
    """`false-positive` is the one disposition that closes a case on a claim about the RULE, so
    it is the one that has to prove it also looked at the entity.

    Three things are checked, each a way the exit could otherwise be faked:

      * `detection_notes` — an FP close with no stated defect is a close with no reason, and
        `none` is not a defect: the format's empty marker is rejected here, not read as prose;
      * `entity_check` names a lead that EXISTS and RETURNED A RESULT — a planned-but-never-
        dispatched lead is the shape of an investigation that stopped at the plan, and a lead
        carrying only a `fail_reason` is the shape of one whose query never landed;
      * that lead targets a vertex the PROLOGUE carried — an entity the ALERT named, not one
        the refutation introduced.

    TWO things it does NOT check, both about the QUESTION the named lead asked:

      * whether it was a good one. Distinguishing "read authorized_keys for the service account"
        from "…for root" is a question about query parameters, which never reach this layer;
      * whether it was INDEPENDENT of the alert's claim. Nothing here separates the lead that
        tested the host for its own suspicion from the lead that refuted the correlation, so a
        run can satisfy this gate with work it had already done before the refutation landed.

    Closing either gap means a fixed indicator set the runtime executes rather than the model
    choosing; this gate is the structural half, and its limits are recorded here so the next
    author does not read a passing gate as a swept host.
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

    lead = next(
        (f for f in companion.get("findings") or [] if f.get("id") == lead_id), None
    )
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
    """`benign` needs a log that recorded WHAT THE ALERT WAS ABOUT.

    The other two benign checks refuse CONTRADICTIONS — an unresolved slot, an unfulfilled
    contract — which is the right shape for a log that did the work, and vacuous for one that
    did not: a document with no vertices has no slot to be open and no hypothesis to carry a
    contract, so it clears a price it never paid. Absent, empty, whitespace-only and fence-less
    `investigation.md` files all reach the close that way.

    So the prologue has to carry a vertex, and the point is what that does to the two checks
    beside it: once a vertex is guaranteed, `_check_benign_open_slots` has something to check
    on every benign close, and "the classification is resolved" stops being a claim a document
    can satisfy by staying silent. ORIENT writes this block before PLAN runs, so every real run
    clears it long before it can conclude anything.

    Deliberately NOT a demand for leads, committed or declared. How much measurement a
    disposition needs is a judgment about the case, which the review gate makes; this is the
    structural floor beneath it, and a trivially-benign alert closed off the payload alone is a
    run this must not refuse.
    """
    if not (companion.get("prologue") or {}).get("vertices"):
        return [
            "disposition benign blocked: no `:V prologue.vertices` row — benign says the "
            "alerted activity was accounted for, so the log has to name the entity the "
            "alert was about. An `investigation.md` that records no vertex records no "
            "investigation; conclude `inconclusive` instead."
        ]
    return []


def _check_benign_gating(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    errors += _check_benign_grounding(companion)
    errors += _check_benign_open_slots(companion)
    errors += _check_benign_authz(companion)
    return errors


@dataclass(frozen=True)
class _Price:
    """What a keyword costs, and why it costs it.

    Two columns because the price has two audiences. `check` answers whether THIS document has
    paid, and its strings name the blocking vertex, contract or row. `rationale` answers why
    the price exists at all — what a refused model needs in order to choose between paying it
    and concluding in another vocabulary. The rationale is a property of the KEYWORD, equally
    true at either boundary, so it belongs beside the check rather than in a second
    keyword-keyed table at whichever boundary happens to print it.
    """

    check: Callable[[CompanionBody], list[str]]
    rationale: str


#: The structural price of a keyword, keyed by the keyword. Two dispositions carry one; the
#: rest carry none. A table rather than a guard clause inside each gate, so a third priced
#: keyword is a row here and not a third copy of the "is this my disposition" preamble that
#: has to get the keyword normalization right every time.
#:
#: Two readers dispatch on it and both must, because a price owed by the document alone is not
#: owed at all: `_check_disposition_gating` on what `:T conclude` says, and
#: `disposition_entry_price` on what the close is about to commit. Adding a row arms both.
#:
#: The rationale rides in the row so a new keyword cannot be collected but left unexplained —
#: `lint_half_read_table`'s documented blind spot is a consumer that enumerates EVERY key, so
#: a second `{keyword: prose}` table elsewhere would not be caught drifting.
#:
#: Each row is BOUND TO A NAME rather than built inline, and that is load-bearing:
#: `lint_half_read_table` recognizes a keyed gate table only when every value is a
#: `Name`/`Attribute`/`Lambda`, so writing these as `_Price(...)` calls in the literal makes
#: the table invisible to the gate that watches it and drops its other findings too.
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

_DISPOSITION_GATES: dict[str, _Price] = {
    "benign": _BENIGN_PRICE,
    "false-positive": _FALSE_POSITIVE_PRICE,
}


@dataclass(frozen=True)
class EntryPrice:
    """What a close still owes for its keyword, and why that keyword owes anything.

    Both halves come back from ONE dispatch so a caller cannot look the second up on a
    differently-normalized value than the first — which would lose the refusal's explanation on
    exactly the zero-width-laced keyword normalization exists for.
    """

    owed: tuple[str, ...]
    rationale: str

    def __bool__(self) -> bool:
        """Truthy when something is owed, so `if price:` reads as "is anything outstanding".
        An unpriced keyword and a paid document are both falsy — the caller does not care
        which, and neither blocks a close."""
        return bool(self.owed)


def disposition_entry_price(disposition: str, companion_text: str) -> EntryPrice:
    """What `disposition` still owes, read off an `investigation.md` — nothing owed when it
    owes nothing, and nothing owed for the keywords `_DISPOSITION_GATES` prices at nothing.

    Public because a price has to be collected at BOTH boundaries. This module gates the
    `investigation.md` write; `report.md` is written by `close_investigation`, which takes its
    disposition as a tool argument and never reads the companion. Without a second reader an
    entry price is bypassable by writing `:T conclude` with a cheaper keyword — or none — and
    passing the priced one to the close, which is the artifact the learning loop, the evals and
    the ticket lane all actually read.

    The mirror of `_check_disposition_gating`, and deliberately the same table read: that one
    dispatches on the disposition the DOCUMENT wrote, this one on the disposition the CALLER is
    about to commit, so a row added to `_DISPOSITION_GATES` is collected at both.

    `disposition` is normalized through `normalized_disposition` for the same reason the
    write-side dispatch is: a keyword is judged on what it RENDERS as, so a zero-width
    character cannot turn a gate off. Typed `str` rather than `object` even though the
    normalizer accepts anything: an unrecognized value takes the unpriced branch, so this
    dispatch fails OPEN on a wrong one, and `object` would let the type checker pass a caller
    that swapped these two arguments — both are `str` — and silently waive the price. (The
    write-side dispatch reads a value off a parsed DOCUMENT and keeps the wider type honestly.)

    What each price means about an ABSENT companion is the gate's own business, and both priced
    ones answer it the same way for different reasons: `false-positive` demands stated content,
    so nothing written owes everything, and `benign` demands a prologue vertex beneath its
    contradiction checks (`_check_benign_grounding`), which are vacuous over a document with no
    vertices.
    """
    priced = normalized_disposition(disposition)
    price = _DISPOSITION_GATES.get(priced) if priced else None
    if price is None:
        return EntryPrice(owed=(), rationale="")
    companion, _ = parse_dense_companion(companion_text)
    return EntryPrice(owed=tuple(price.check(companion)), rationale=price.rationale)


def _check_disposition_gating(companion: CompanionBody) -> list[str]:
    """Run the structural checks this run's disposition is priced at, and only those.

    Dispatched on what the value RENDERS as. This is the ONE branch that decides whether a
    disposition's structural checks run at all, so a zero-width character clinging to the
    keyword would turn them all off — a gate failing open on an invisible character in
    model-authored text. `_check_conclude_vocab` denies the laced spelling separately, and the
    two rules stay independent on purpose: either alone would leave a hole.
    """
    disposition = normalized_disposition(
        (companion.get("conclude") or {}).get("disposition")
    )
    price = _DISPOSITION_GATES.get(disposition) if disposition else None
    return price.check(companion) if price is not None else []




#: `:L findings`' `mode` cell for a fast-path screen lead, and the `screen_result` that says
#: the screen HIT. The only two cell values the SCREEN rule turns on — every other mode and
#: every other result passes through it untouched.
SCREEN_MODE = "screen"
SCREEN_MATCH = "match"


def _check_screen_structure(companion: CompanionBody) -> list[str]:
    """A `screen_result` is a SCREEN lead's verdict, and three ways a document can carry one
    that decides nothing.

    On a lead with no `mode: screen` it is a verdict about a screen that never ran, written in
    the slot every reader takes for the run's fast-path answer. On an INTERMEDIATE screen lead
    it is a partial answer in that same slot: a screen sequence narrows across leads and only
    the last of them has seen every indicator, so an earlier `no_match` reads as the sequence's
    result while the sequence is still running. A `match` beside a `hypothesize` block is the
    third, and the only one with a disposition behind it — a matched screen ENDS the run on the
    fast path, so a companion that then enumerates hypotheses claims both that no investigation
    was needed and that one happened.

    "Intermediate" is read as "the next lead in `:L findings` order also screens", which lets a
    second screen phase later in the run be its own sequence rather than folding into the first.

    Read off `findings[].screen_result`, which is where the `:L findings` column projects. The
    spec spells the field `outcome.screen_result`, from the pre-dense envelope; the projection
    has never nested it.

    NOT checked: whether the verdict is the right one, or whether the indicators it claims to
    rest on were retrieved. `screen_result` is a scalar the model writes and nothing beneath it
    is projected — the same limit `_check_false_positive_gating` records for `entity_check`.
    """
    leads = [f for f in companion.get("findings") or [] if isinstance(f, dict)]
    errors: list[str] = []
    for i, lead in enumerate(leads):
        result = lead.get("screen_result")
        if not (isinstance(result, str) and result.strip()):
            continue
        lid = lead.get("id", "?")
        mode = lead.get("mode") or ""
        if mode != SCREEN_MODE:
            errors.append(
                f"lead {lid}: `screen_result: {result}` on a lead whose mode is {mode!r} — "
                f"the column records a SCREEN's verdict; set `mode: screen` on the lead that "
                f"ran the screen, or drop the cell"
            )
        elif i + 1 < len(leads) and leads[i + 1].get("mode") == SCREEN_MODE:
            errors.append(
                f"lead {lid}: `screen_result: {result}` on an intermediate screen lead — "
                f"{leads[i + 1].get('id', '?')} screens after it, so the sequence has not "
                f"answered yet; only its final lead carries the result"
            )
    matched = [
        f.get("id", "?") for f in leads
        if isinstance(f.get("screen_result"), str)
        and f["screen_result"].strip() == SCREEN_MATCH
    ]
    if matched and (companion.get("hypothesize") or {}).get("hypotheses"):
        errors.append(
            f"lead {matched[0]}: `screen_result: {SCREEN_MATCH}` closes the run on the fast "
            f"path, but `:H hypothesize.hypotheses` enumerates hypotheses — a matched screen "
            f"and an investigation are two different runs; drop the block, or record the "
            f"screen as `no_match` and keep investigating"
        )
    return errors


def _check_hypothesis_persistence(companion: CompanionBody) -> list[str]:
    """A close that ENUMERATES its survivors enumerates all of them. A hypothesis the run
    neither refuted nor listed was dropped, and nothing else on disk says so.

    The failure is grading blindness papered over by silence: a hypothesis declared in loop 1,
    never moved off `null`, never shelved, and left out of the close reads exactly like one
    that was never proposed. The document then concludes over a smaller mechanism set than it
    opened with, and no reader can tell which one went missing.

    Two discharges. Final effective weight `--` — the run refuted it — or a
    `:T conclude.surviving` row naming it. What was not refuted is what the run is still
    carrying, and naming it is the whole price.

    A close that writes NO surviving table is out of scope, and that is a measured concession
    rather than an oversight. The table is omittable by construction — `_project_surviving_block`
    projects it "checkable, not authoritative" and benign gating computes survival from the
    resolution record precisely so a run may leave it out — so an absent table is read as the
    document deferring to that record, under which every non-refuted hypothesis IS surviving and
    nothing is dropped. Reading an absent table as an empty one instead would refuse seven of
    the eight ```invlang documents in the tree, both shipped goldens among them; making the
    table mandatory is a spec decision about what ANALYZE must write, not a validator decision
    about what this document says. The rule bites where the author made the claim: writing the
    table and leaving a live hypothesis out of it.

    NOT a claim that the table is TRUE. It is read as an ASSERTION the author made, never as
    evidence — which is what lets this demand the row without the row buying anything, and what
    keeps benign gating's independent computation of survival independent.

    v2.17: the spec's other two discharge arms are excised. `termination.rationale` is free text
    and `termination.category` an unchecked scalar, so "cited as the termination target" was
    never a projected hypothesis reference; and `matched_archetype` — "the matched archetype's
    mechanism" — is a `schema.Conclude` scalar no production code reads, resolved against an
    archetype catalog that does not exist. Neither was checkable, and an escape hatch that
    cannot be checked is one every document holds open.
    """
    conclude = companion.get("conclude") or {}
    # KEY presence, not row count. `_project_surviving_block` opens the bucket before it reads
    # a row, so an absent `:T conclude.surviving` block leaves the key off entirely while a
    # table written as the empty-array marker (`none`) leaves it present and empty — and the
    # second is a claim that NOTHING survived, which a live hypothesis contradicts.
    if "surviving_hypotheses" not in conclude:
        return []
    surviving = {
        row["hypothesis"] for row in conclude["surviving_hypotheses"]
        if isinstance(row, dict) and isinstance(row.get("hypothesis"), str)
    }
    return [
        f"conclude: hypothesis {hid} is neither refuted nor carried into the close — its "
        f"final weight is {weight!r} and the `:T conclude.surviving` table, which names "
        f"{_known_ids(surviving)}, omits it. Resolve it to {REFUTED_WEIGHT!r}, or add its "
        f"row; a hypothesis declared and then dropped reads like one that was never proposed"
        for hid, weight in _walkers.final_weights(companion).items()
        if weight != REFUTED_WEIGHT and hid not in surviving
    ]


#: The `termination.category` that makes rule #13 engage. A free-text scalar with NO closed
#: vocabulary anywhere in the system — `_check_vocab` has nothing to hand for it, and the
#: four-value enum the spec states (`trust-root`, `adversarial-refuted`, `severity-ceiling`,
#: `exhaustion-escalation`) is contradicted on disk by `data-ceiling` and
#: `adversarial-confirmed` in the two shipped e2e goldens. See
#: `_check_ceiling_test_scope` for what that costs the rule and why the vocabulary was not
#: closed here.
SEVERITY_CEILING = "severity-ceiling"


def _check_ceiling_test_scope(companion: CompanionBody) -> list[str]:
    """A run that terminates on a SEVERITY CEILING names the check it could not make.

    `severity-ceiling` is the strongest termination the language has that is not a refutation:
    live hypotheses remain and their critical edges cannot be tested with available tools. It
    is the one category that ends a run by declaring the question unanswerable, so it is the
    one that most needs a receipt — without `ceiling_test`, "severity ceiling" is a phrase, and
    the reader cannot tell a run that hit a real tooling boundary from one that stopped.

    The receipt is `ceiling_test`: one row per unreachable check, naming the host and the data
    source (`skills/invlang/SKILL.md` §`:T conclude`). The empty marker `none` projects as
    absence, so "wrote the row and said there was no ceiling" and "wrote no row" are the same
    document here, which is right — both claim no gap while the termination claims one.

    HALF the spec rule, deliberately. #13 also says `ceiling_test` is FORBIDDEN under any other
    termination, and that half is not implemented and should not be:

      * The field it forbids is not the field the spec was written about. The pilot spec's
        `ceiling_test` was `{kind, subject}` — THE out-of-band step that would resolve the
        ceiling, so "only under a ceiling" follows. The shipped field is the list of checks the
        run could not make, and eleven checked-in lessons instruct writing it whenever a source
        was out of reach ("name them by host and source type in `ceiling_test`"). Forbidding it
        elsewhere would refuse a run for obeying a lesson, which is the one failure
        `learning/core/persist.py` turns into a discarded run.
      * Measured: it would fire on the runs that name a telemetry gap and terminate on
        something else, which is the ordinary shape — `golden-v2sshd` names two such gaps in
        its prose and terminates `data-ceiling`.

    The TRIGGER is unbacked and this rule fails silent because of it. `termination.category` is
    free text with no vocabulary, so `severity_ceiling` or `severity-celing` disables this
    check with nothing said. That direction is the safe one — a typo costs a miss, never a
    wrongful refusal — but it is a real limit and not a rounding error. Closing the vocabulary
    would fix it and was NOT done here: the spec's four values are contradicted by both shipped
    e2e goldens (`data-ceiling`, `adversarial-confirmed`) and by three test corpora
    (`exhaustion`, `adversarial-confirmed`, `natural`), so closing it is a spec-owner decision
    with its own measurement, filed in the enforcement ramp rather than taken here.
    """
    conclude = companion.get("conclude") or {}
    category = (conclude.get("termination") or {}).get("category")
    if category != SEVERITY_CEILING or conclude.get("ceiling_test"):
        return []
    return [
        f"conclude: `termination.category {SEVERITY_CEILING}` with no `ceiling_test` — the "
        f"category says live hypotheses remain and their critical edges cannot be tested, so "
        f"the close owes the specific check it could not make. Add one "
        f"`ceiling_test  \"<host> <data source> not retrieved\"` row per gap to `:T conclude` "
        f"(repeat the key; the SKILL's §`:T conclude` has the shape), naming the source rather "
        f"than the shape of the question. If nothing was actually out of reach, this run did "
        f"not hit a ceiling — terminate on the category that describes what happened."
    ]


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
    """
    out: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ref = (row.get("ref") or "").strip()
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
    """
    index = _deferral_index(deferrals)
    for c in declared:
        if c.ref in resolved or c.local_id in resolved:
            continue
        rationales = index.get(c.ref, []) + index.get(c.local_id, [])
        if not rationales:
            yield c, False
        elif not any(r.strip() for r in rationales):
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


def _check_authz_contract_closure(companion: CompanionBody) -> list[str]:
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
    edit here — where a `== "benign"` test would leave the next one double-reporting. It costs
    a second `_check_disposition_gating` pass over an in-memory dict.

    Fulfilment is read by id exactly as `_check_benign_authz` reads it, with no verdict
    condition: an `unauthorized` row settles the question, and what that verdict then costs the
    document is the benign gate's business.
    """
    conclude = companion.get("conclude")
    if not conclude:
        return []
    gated = set(_check_disposition_gating(companion))
    spoken_for = {
        f"{hid}.{c.get('id')}"
        for hid, c, why in outstanding_authz_contracts(companion)
        if why in gated
    }
    resolved = {
        row["fulfills_contract"]
        for row in _walkers.iter_authz_resolutions(companion)
        if isinstance(row.get("fulfills_contract"), str) and row["fulfills_contract"]
    }
    declared = [
        _Commitment(hid, c["id"])
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        for c in hyp.get("authorization_contract") or []
        if isinstance(c, dict) and isinstance(c.get("id"), str) and c["id"]
        and f"{hid}.{c['id']}" not in spoken_for
    ]
    return [
        _closure_refusal(
            f"authz contract {c.ref}", "deferred_authz", c.ref,
            blank_rationale=blank,
            # The BARE id in `fulfills`, the qualified one in the deferral row. That is not a
            # cosmetic difference: `_check_benign_authz` matches `fulfills_contract` on the
            # bare `ac<n>` alone, so advising `fulfills=h-001.ac1` here would name a row that
            # clears THIS rule and leaves the benign gate blocked.
            resolve=f"fulfil it with a `:R authz` row carrying `fulfills={c.local_id}`",
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
    conclude = companion.get("conclude")
    if not conclude:
        return []
    resolved: set[str] = set()
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            ref = (row.get("prediction_ref") or "").strip() if isinstance(row, dict) else ""
            if ref:
                resolved.add(ref if "." in ref else f"{lid}.{ref}")
    declared = [
        _Commitment(lead.get("id", "?"), ip["id"])
        for lead in _leads(companion)
        for ip in lead.get("impact_predictions") or []
        if isinstance(ip, dict) and isinstance(ip.get("id"), str) and ip["id"]
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
    # `null` is the format's own word for "no severity", so it is an ABSENT severity here and
    # not a present one — the same reading `_project_conclude_scalars` gives the bare token.
    stated = _row_states_something(severity) and severity != "null"
    owed = verdict in _SEVERITY_OWING
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


def _shelved_hypothesis_ids(companion: CompanionBody) -> set[str]:
    """Every `h-*` a `:T shelved` row retired, across every lead — the hypotheses a run set
    aside rather than answered, which is one of the two ways #34 lets a prediction go."""
    return {
        hid
        for lead in _leads(companion)
        for hid in lead.get("shelved") or []
        if isinstance(hid, str)
    }


def _check_prediction_closure(companion: CompanionBody) -> list[str]:
    """Every `p*`/`ap*` on a hypothesis the run is still carrying was settled by some
    resolution, or deferred in `:T conclude.deferred_preds` with a reason.

    The contract ANALYZE owes PREDICT. PREDICT pre-commits a prediction set precisely so the
    grading cannot be chosen after the evidence lands; without a closure gate, ANALYZE cites
    the two predictions that came in and the other three are never heard from again, and no
    reader of the finished document can tell they existed.

    The late half of a pair. `_check_prediction_completeness` (spec #6) asks the same question
    at WRITE time and only of a `++`, and offers no deferral — a `++` claims every prediction
    came in, so there is nothing outstanding to defer. This asks it of every weight, at
    CONCLUDE, and offers the deferral because at that point "the tool was never available" is a
    true and final answer.

    Two discharges besides citation, and both are read off the RESOLUTION RECORD rather than
    the `status` column the spec's wording names. `status` is a `:H` cell fixed at declaration
    time and append-only forbids updating it, so it can never carry a FINAL status; the run
    says "refuted" by moving the weight to `--` and "shelved" with a `:T shelved` row. That is
    the same translation `_check_hypothesis_persistence` applies to spec #24.

    A citation only counts from a resolution with a non-null `after`. A row that cites `p1` and
    moves nowhere has recorded that the lead looked, not that the prediction settled — and
    `_walkers.final_weights` would read that row as the hypothesis's final position anyway.

    Scoped to the hypothesis that declared the prediction, never document-wide: a sibling's
    `p1` discharges nothing here, which is the cross-citation rule #25 refuses one level down
    and `_check_prediction_refs` enforces on the citing row.
    """
    conclude = companion.get("conclude")
    if not conclude:
        return []
    resolved: set[str] = set()
    for _lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        after = (res.get("after") or "").strip()
        if not isinstance(hid, str) or not after or after in vocab.NULL_WEIGHTS:
            continue
        for pid in res.get("matched_prediction_ids") or []:
            if isinstance(pid, str) and pid:
                resolved.add(f"{hid}.{pid}")
    shelved = _shelved_hypothesis_ids(companion)
    weights = _walkers.final_weights(companion)
    declared = [
        _Commitment(hid, pid)
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        if weights.get(hid) != REFUTED_WEIGHT and hid not in shelved
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




def diagnose(
    proposed_text: str, current_text: str | None = None
) -> list[Diagnostic]:
    """The validator proper. Failures arrive as `Diagnostic`s so a caller that wants to point
    at the offending row can. `validate_companion` is the string surface over this and is what
    nearly everything calls."""
    proposed_text = _normalize_newlines(proposed_text)
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    found: list[Diagnostic] = []
    found.extend(_plain(_check_surface(proposed_text)))

    companion, warnings = parse_dense_companion(proposed_text)
    current_companion: CompanionBody | None = None
    if current_text is not None:
        current_companion, _ = parse_dense_companion(current_text)

    found.extend(_plain(
        _check_append_only(proposed_text, current_text, companion, current_companion)
    ))

    found.extend(_parse_diagnostic(w) for w in warnings)

    if not companion:
        return found

    found.extend(_plain(_check_lead_refs(companion)))
    found.extend(_plain(_check_attr_update_targets(companion)))
    found.extend(_plain(_check_hypothesis_refs(
        companion, deferred=deferred_hypothesis_ids(warnings),
    )))
    found.extend(_plain(_check_prediction_refs(companion)))
    found.extend(_plain(_check_refutation_scope(companion)))
    found.extend(_plain(_check_authz_contract_ids(companion)))
    found.extend(_plain(_check_tested_commitment_refs(companion)))
    found.extend(_plain(_check_strong_move_provenance(companion)))
    found.extend(_plain(_check_prediction_completeness(companion)))
    found.extend(_plain(_check_attribute_prediction_structure(companion)))
    found.extend(_plain(_check_sibling_fork_distinctness(companion)))
    found.extend(_plain(_check_lead_prediction_structure(companion)))
    found.extend(_plain(_check_impact_prediction_structure(companion)))
    found.extend(_plain(_check_impact_resolution_refs(companion)))
    found.extend(_check_closed_vocab(companion, proposed_text))
    found.extend(_plain(_check_screen_structure(companion)))
    found.extend(_plain(_check_disposition_gating(companion)))
    found.extend(_plain(_check_ceiling_test_scope(companion)))
    found.extend(_plain(_check_hypothesis_persistence(companion)))
    # The three closure gates, together and last: they are one sentence over three namespaces
    # (`_unclosed_commitments`), and each is only safe to run because its `deferred_*` table is
    # now projected.
    found.extend(_plain(_check_authz_contract_closure(companion)))
    found.extend(_plain(_check_impact_closure(companion)))
    found.extend(_plain(_check_prediction_closure(companion)))
    found.extend(_plain(_check_loop_close(companion)))
    return found


def warn_diagnostics(text: str) -> tuple[Diagnostic, ...]:
    """The REPAIR WINDOW, derived from a document's current bytes and stored nowhere.

    Not state anything records: it is `diagnose`'s warn-severity findings over whatever is on
    disk right now, so it cannot go stale, cannot disagree with the file, and survives a
    freshly constructed deps object. Each finding's `locus.row_text` is how `fix_row` addresses
    the row — the row as PARSED (the tokenizer strips it), which is also the text the warning
    prints, so the model's copy-paste round trip closes.

    No baseline: append-only is judged against history, but a warning is a property of the
    document as it stands."""
    return tuple(d for d in diagnose(text) if d.severity == "warning")


def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    """The string surface over `diagnose`, which is what the validator's callers are written
    against. `_artifact_schema` is the one caller that wants the structure and calls `diagnose`
    directly.

    ERROR severity only. Its production caller reads this list as "reasons to refuse the
    document" — persist dead-letters a run on any element — and a warn-family row is explicitly
    not that: the run reaches the learning loop with it."""
    return [
        d.message for d in diagnose(proposed_text, current_text) if d.severity != "warning"
    ]
