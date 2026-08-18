
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
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
    EdgeRecord,
    FindingRecord,
    HypothesisRecord,
    VertexRecord,
)

STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS
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

    NOT checked: an id in no recognized namespace. `:L l-NNN.lead_preds` is a documented block
    the parser does not project, so its `lp*` would resolve against nothing — reporting those
    would deny a document the format permits.
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




def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


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
IDENT_REFINEMENT_KEY = "ident"


def _is_legal_refinement_key(key: str) -> bool:
    return key == "class" or key == IDENT_REFINEMENT_KEY or key.startswith("attrs.")


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
    if v == "??":
        return True
    return v.startswith("{") and (v.endswith("}") or v.count("{") > v.count("}"))


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


def has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str):
        return False
    slots = class_slots(classification)
    # A `{` the author never closed is an UNTERMINATED candidate set and counts as open: the
    # depth-aware split above folds every slot after it into one cell that is neither `??` nor
    # a closed `{...}`, so a single dropped `}` would read as CONCRETE. A stray `}` with no
    # `{` is left alone — it splits like any other character and hides nothing.
    if any(s.count("{") > s.count("}") for s in slots):
        return True
    return any(is_unresolved(slot) for slot in slots)


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
        if cls and has_open_slot(cur["classification"]) and not has_open_slot(cls):
            cur["classification"] = cls
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
            if key == "class":
                st["classification"] = val
            elif key == IDENT_REFINEMENT_KEY:
                # A DISTINCT top-level slot, never `attributes["ident"]` — see
                # IDENT_REFINEMENT_KEY. Last row in document order wins; the fold retains
                # no history, so a superseded value survives only as the rows on disk.
                st["identifier"] = val
            elif isinstance(key, str) and key.startswith("attrs."):
                st["attributes"][key[len("attrs."):]] = val


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


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for vid, st in effective_vertex_state(companion).items():
        if has_open_slot(st["classification"]):
            errors.append(
                f"disposition benign blocked: vertex {vid} still has an "
                f"unresolved class ({st['classification']!r}) — resolve via "
                f":R attr_updates or escalate"
            )
        for name, val in st["attributes"].items():
            if is_unresolved(val):
                errors.append(
                    f"disposition benign blocked: vertex {vid} attribute "
                    f"{name!r} is still unresolved ({val!r}) — resolve via "
                    f":R attr_updates or escalate"
                )
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
    found.extend(_plain(_check_authz_contract_ids(companion)))
    found.extend(_plain(_check_tested_commitment_refs(companion)))
    found.extend(_plain(_check_strong_move_provenance(companion)))
    found.extend(_check_closed_vocab(companion, proposed_text))
    found.extend(_plain(_check_disposition_gating(companion)))
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
