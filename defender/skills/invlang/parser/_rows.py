"""One row of one block type, projected into one typed record.

Every function here is pure: `(Block, row) -> record`, raising `RowError` for a row it
cannot read. Split out of `parser.py` (#god-file); imports the tokenizer, never the
projector."""


from __future__ import annotations

import contextlib
import re
from typing import Any, cast

from .._cells import (
    _parse_attrs,
    _require,
    _row_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _row_dict,
    _split_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_csv,
    _split_csv_or_semi,
    _split_quoted,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_subcells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _unquote,
    is_conclude_empty_marker,  # noqa: F401 — re-export: parser is this name's public home
)
from .._types import Block, RowError
from ..vocab import UNOBSERVED_EDGE_REF
from ..schema import (
    AttrPredictionRecord,
    AuthorityRef,
    AuthorizationContract,
    Conclude,
    EdgeRecord,
    HypothesisRecord,
    ImpactPrediction,
    LeadPrediction,
    ParentVertex,
    PredictionRecord,
    ProposedEdge,
    RefutationRecord,
    ResolutionRecord,
    ResolutionRow,
    VertexRecord,
)



from ._tokenize import ParseWarning


def _parse_auth(cell: str) -> AuthorityRef:
    if ":" not in cell:
        return {"kind": cell.strip(), "source": ""}
    kind, source = cell.split(":", 1)
    return {"kind": kind.strip(), "source": source.strip()}

_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]
_SURVIVING_COLS = ["hyp_id", "final_weight"]




def _vertex_record(block: Block, row: str) -> VertexRecord:
    rec = _row_dict(block, row, _VERTEX_COLS)
    _require(rec, "id", "type", msg="vertex missing id/type")
    out: VertexRecord = {
        "id": rec["id"],
        "type": rec["type"],
        "classification": rec.get("class", ""),
        "identifier": rec.get("ident", ""),
    }
    if rec.get("attrs"):
        out["attributes"] = _parse_attrs(rec["attrs"])
    return out


def _edge_record(block: Block, row: str) -> EdgeRecord:
    cols = block.columns or _EDGE_COLS
    rec = _row_dict(block, row, _EDGE_COLS)
    _require(rec, "id", "rel", msg="edge missing id/rel")
    out: EdgeRecord = {
        "id": rec["id"],
        "relation": rec["rel"],
        "source_vertex": rec.get("src", ""),
        "target_vertex": rec.get("tgt", ""),
    }
    if rec.get("when"):
        out["when"] = {"timestamp": rec["when"]}
    auth_col = next((c for c in cols if c.startswith("auth_kind")), None)
    if auth_col and rec.get(auth_col):
        out["authority"] = _parse_auth(rec[auth_col])
    if rec.get("attrs"):
        out["attributes"] = _parse_attrs(rec["attrs"])
    return out


_HYP_HEADER_COLS = {
    "id", "name", "attached_to", "rel",
    "parent_type", "parent_class",
    "integrity_waived", "weight", "status",
}


#: The two block names that DECLARE a hypothesis, spelled as `ParseWarning.block` renders them
#: (`:H <name>`). One owner: `_project_block`'s dispatch, the validator's "did a declaration get
#: dropped?" test, and the SKILL/parser grammar pin all read the declaration sites from here.
HYP_DECLARATION_BLOCK_RE = re.compile(
    r"^:H (?:hypothesize\.hypotheses|l-[A-Za-z0-9]+\.new_hypotheses)$"
)

#: An `h-*` id, including the hierarchical child form: when a lean hypothesis refines into
#: sub-cases the language allocates `h-{parent}-{ordinal}` (`h-001` → `h-001-001`) and writes
#: the children into the lead's `new_hypotheses` (`docs/investigation-language.md` §Refinement
#: via hierarchical IDs); the parent is retired by resolving it, #933 having retired the
#: `:T shelved` row that used to do it in the same block. One owner: the validator reads
#: which tokens are hypothesis references from here, and
#: `deferred_hypothesis_ids` reads which dropped rows it can map back to one.
HYPOTHESIS_ID_RE = re.compile(r"h-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")


def _row_first_cell(row: str) -> str:
    # Through `_split_cells` rather than `row.split("|")`, so an escaped `\|` or a quoted
    # cell is read the same way every other cell extraction in this module reads it.
    return _split_cells(row)[0]


def deferred_hypothesis_ids(
    warnings: list[ParseWarning],
) -> frozenset[str] | None:
    """Which `h-*` ids a parse warning DELETED — the set the undeclared-hypothesis rule
    must stay quiet about, because the parse error already names the cause.

    A rejected header or a bad row on a hypothesis DECLARATION block deletes ids the document
    goes on referring to, so every reference to them looks phantom — the one case where the
    undeclared-hypothesis error would point away from the defect. A warning from anywhere ELSE
    (an unknown block, an unattributed `:R` row, a malformed vertex) drops no declaration and
    must not stand the rule down.

    Per ID, not per DOCUMENT, so one malformed `:H` row does not silence the rule for the whole
    file. The id is recoverable in both failure modes: a whole-block rejection carries
    `dropped_ids`, and a row-level failure carries its row, whose first cell IS the id.

    `None` means "stand down everywhere" — the honest answer when a dropped declaration cannot
    be mapped to an id at all (a row so malformed its first cell is not id-shaped). Reporting
    references then would give two errors for one defect.

    `dropped_ids` is the authoritative channel and is consulted whatever block carries it,
    because a declaration is deleted from more than the two DECLARING names: the singular typo
    `:H l-NNN.new_hypothesis` drops its rows too.

    A warning that names NO id is skipped rather than deferred: a header rejected on a block
    with no rows deleted nothing, so standing the rule down for the document would hide every
    unrelated phantom. It is also why the catch-all `:H l-NNN.<sub>` warning filters its
    `dropped_ids` down to `h-*` cells before they get here: a stray `:H l-001.preds`
    contributes `p9`, which is neither usable as a hypothesis id nor evidence that a
    declaration went missing.
    """
    deferred: set[str] = set()
    for w in warnings:
        if w.dropped_ids:
            named: tuple[str, ...] = w.dropped_ids
        elif HYP_DECLARATION_BLOCK_RE.match(w.block) and w.row:
            named = (_row_first_cell(w.row),)
        else:
            continue
        # lint-selection: ok — the complement CHANGES THE ANSWER rather than vanishing:
        # an empty selection means a dropped declaration could not be mapped to an id,
        # and `return None` then stands the undeclared-hypothesis rule down document-wide
        # instead of reporting references the parse error already explains.
        usable = [  # lint-selection: ok — empty selection returns None; see above
            i for i in named if HYPOTHESIS_ID_RE.fullmatch(i)
        ]
        if not usable:
            return None
        deferred.update(usable)
    return frozenset(deferred)


def _is_current_hyp_header(cols: list[str] | None) -> bool:
    if not cols:
        return False
    return set(cols) == _HYP_HEADER_COLS


#: The `:H` header cells a CHECK compares against something, rather than carries as text:
#: `attached_to` is half of rule #23's sibling-group key, `weight` and `status` are closed
#: cells, `rel`/`parent_type`/`parent_class` are closed vocabularies, and `id` is resolved by
#: equality at four sites. Read raw, a uniformly quoted row anchors on `'"v-001"'` — which
#: equals no other sibling's anchor, so the pair drops out of the fork group in silence — and
#: a quoted `"--"` is not `REFUTED_WEIGHT`, so the hypothesis the run refuted reads as live.
_HYP_COMPARED_CELLS = (
    "id", "name", "attached_to", "rel", "parent_type", "parent_class", "weight", "status",
)


def _hypothesis_record(block: Block, row: str) -> HypothesisRecord:
    rec = _row_dict(block, row)
    for key in _HYP_COMPARED_CELLS:
        if key in rec:
            rec[key] = _unquote(rec[key]).strip()
    _require(rec, "id", "name", msg="hypothesis missing id/name")
    out: HypothesisRecord = {"id": rec["id"], "name": rec["name"]}
    if rec.get("attached_to"):
        anchor = rec["attached_to"]
        if anchor.startswith("e-"):
            raise RowError(
                f"hypothesis {rec['id']!r} attached_to={anchor!r} names an edge; "
                f":H is discovery-only (propose a new parent vertex+edge anchored "
                f"to a v-* id). For class refinement of an existing vertex, use "
                f"`??` / `{{...}}` notation on the prologue entry instead."
            )
        out["anchor"] = anchor
    proposed_edge = _build_proposed_edge(rec)
    if proposed_edge:
        out["proposed_edge"] = proposed_edge
    if rec.get("integrity_waived"):
        out["integrity_waived"] = rec["integrity_waived"]
    if rec.get("weight"):
        out["weight"] = None if rec["weight"] == "null" else rec["weight"]
    if rec.get("status"):
        out["status"] = rec["status"]
    return out


def _build_proposed_edge(rec: dict[str, str]) -> ProposedEdge:
    edge: ProposedEdge = {}
    if rec.get("rel"):
        edge["relation"] = rec["rel"]
    if rec.get("parent_type") or rec.get("parent_class"):
        pv: ParentVertex = {}
        if rec.get("parent_type"):
            pv["type"] = rec["parent_type"]
        if rec.get("parent_class"):
            pv["classification"] = rec["parent_class"]
        edge["parent_vertex"] = pv
    return edge




#: The DECLARING side of `HYPOTHESIS_ID_RE`, built from it rather than restating it, so the
#: hierarchical child form the reference sites accept can also declare `:H h-001-001.preds`.
#: (A narrower restatement here sends that block to the generic "unknown block" warning and
#: denies the write, leaving a committed child unable to declare the prediction
#: `_check_strong_move_provenance` demands before a `++`/`--` move.) With one owner, a typoed
#: child id lands on `_project_hyp_subblock`'s "sub-block references unknown hypothesis"
#: warning, which names the actual cause.
_HYP_PREFIX_RE = re.compile(
    rf"^(?P<hyp>{HYPOTHESIS_ID_RE.pattern})"
    rf"\.(?P<sub>preds|attr_preds|refuts|authz|parent_attrs)$"
)

#: Every `:<TAG> l-NNN.<sub>` block name a lead carries, per tag — what the "unknown lead
#: sub-block" warning names as the alternatives, and the reason that warning can exist at all.
#:
#: PROSE ONLY. The projector's own branches decide what lands, so this list steers nothing: a
#: name added here without a branch is still dropped, and a branch added without a name here
#: still projects — it just goes unlisted in the message that tells an author what to write
#: instead. Keep the two in step by hand; the alternative is a dispatch table that cannot carry
#: the per-branch typing (`_attach_hyp_sub_rows` records why).
_LEAD_SUBBLOCKS: dict[str, tuple[str, ...]] = {
    "V": ("observations.vertices",),
    "E": ("observations.edges",),
    "H": ("new_hypotheses",),
    "L": ("lead_preds", "impact_preds", "substitutions"),
}

_LEAD_PRED_COLS = ["id", "if", "read_as", "advance_to"]
_IMPACT_PRED_COLS = [
    "id", "dim", "claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on",
]

_HYP_PRED_COLS = ["id", "subject", "claim"]
_HYP_ATTR_PRED_COLS = ["id", "target", "attribute", "claim"]
_HYP_REFUT_COLS = ["id", "refutes", "claim"]
_HYP_AUTHZ_COLS = ["id", "edge_ref", "anchor_kind", "predicate", "on_unauth", "on_indet"]


def _lead_pred_row(block: Block, row: str) -> LeadPrediction:
    """`:L l-NNN.lead_preds [id|if|read_as|advance_to]` — one pre-committed route.

    Only `id` is `_require`d, where `:H h-NNN.preds` also requires `subject`. The difference is
    which layer can say something useful about the blank cell: rule #18 owns `if` / `read_as` /
    `advance_to` and its error names the column and the repair, while a `RowError` here would
    delete the row and report only that it was deleted — taking the rest of the route plan's
    numbering with it.
    """
    rec = _row_dict(block, row, _LEAD_PRED_COLS)
    _require(rec, "id", msg="lead_preds row missing id")
    return {
        # `_unquote`d like every cell beside it. `_check_lead_prediction_structure` matches this
        # against `_LEAD_PRED_ID_RE` and names it in every refusal, so a uniformly quoted row
        # is refused for not being numbered `lp<n>` when it is, on an append-only block.
        "id": _unquote(rec["id"]),
        # `if` is a Python keyword and cannot be a class-syntax TypedDict key; see
        # `schema.LeadPrediction`.
        "condition": _unquote(rec.get("if", "")),
        "read_as": _unquote(rec.get("read_as", "")),
        # `_unquote`d like its neighbours: `_check_lead_prediction_structure` compares this
        # cell against `_ROUTE_SENTINELS` and against the declared lead names, so a row that
        # quotes all four cells uniformly would be refused for a destination it names
        # correctly.
        "advance_to": _unquote(rec.get("advance_to", "")),
    }


def _impact_pred_row(block: Block, row: str) -> ImpactPrediction:
    """`:L l-NNN.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|
    escalation_on]` — one pre-registered impact predicate.

    `_require`s `id` alone, for the same reason `_lead_pred_row` does: rule #29 checks the six
    remaining cells and can say what each is for.
    """
    rec = _row_dict(block, row, _IMPACT_PRED_COLS)
    _require(rec, "id", msg="impact_preds row missing id")
    # Every cell `_unquote`d, `id` included. `_declared_impact_predictions` keys on the raw id
    # while `_check_impact_resolution_refs` reads the grading side through `_cell`, so a quoted
    # `"ip1"` is reported undeclared by a message that lists it among the declared — and the
    # repair it offers (`pred_ref=l-002."ip1"`) is not a cell any author can write.
    # Keys written out rather than looped, for the reason `_attach_hyp_sub_rows` gives: a
    # TypedDict write needs a LITERAL key, and the loop form only type-checks by widening the
    # record back to `dict[str, Any]`.
    return {
        "id": _unquote(rec["id"]),
        # `_unquote`d because `dim` is a CLOSED vocabulary two checks compare against
        # (`_check_impact_prediction_structure`, `_check_impact_resolution_refs`); a quoted
        # cell would be refused for naming an axis it names correctly.
        "dimension": _unquote(rec.get("dim", "")),
        "claim": _unquote(rec.get("claim", "")),
        # The four outcome cells `_unquote`d with their neighbours: they are the record the
        # review projector renders and the shape `IMPACT_VERDICT` will be closed on, and a
        # projected `'"exceeds"'` is a value that spells itself correctly and matches nothing.
        "on_match": _unquote(rec.get("on_match", "")),
        "on_mismatch": _unquote(rec.get("on_mismatch", "")),
        "on_indeterminate": _unquote(rec.get("on_indeterminate", "")),
        "escalation_on": _unquote(rec.get("escalation_on", "")),
    }


def _hyp_sub_pred_row(block: Block, row: str) -> PredictionRecord:
    rec = _row_dict(block, row, _HYP_PRED_COLS)
    # Unquoted, STRIPPED, and BEFORE `_require` — the same three things `_hyp_sub_attr_pred_row`
    # does, for the same three reasons. `_check_prediction_id_namespace` compares `id` against
    # a closed namespace, so `" p1 "` is a legal `p<n>` refused for its padding on a `:H` row
    # that is immutable; and an id cell of `""` is truthy before the unquote, so `_require`
    # passes it and the refusal downstream names row `'?'` — a row the author cannot find.
    for key in ("id", "subject"):
        rec[key] = _unquote(rec.get(key, "")).strip()
    _require(rec, "id", "subject", msg="preds row missing id/subject")
    return {
        "id": rec["id"],
        "subject": rec["subject"],
        "claim": _unquote(rec.get("claim", "")),
    }


def _hyp_sub_attr_pred_row(block: Block, row: str) -> AttrPredictionRecord:
    rec = _row_dict(block, row, _HYP_ATTR_PRED_COLS)
    # EVERY cell, not just `target`. Each of the four is read by a check that compares it
    # against something: `id` against the `ap<n>` namespace (rule #33), `target` against
    # `_ATTR_PRED_TARGETS`, and `attribute` and `claim` as two thirds of rule #23's fork key.
    # Unquoting one and leaving the next raw is how a uniformly quoted row gets refused for a
    # legal target (`id`) or slips past the fork rule with a signature no sibling can collide
    # with (`attribute`).
    #
    # And BEFORE `_require`, which is what makes rule #33's stated reason for not checking
    # `attribute` itself ("already a parse error — `_require` tests truthiness") true: a
    # quoted run of spaces reaches `_require` as `'"  "'`, which is truthy, and lands an
    # attribute predicting nothing whose fork key degrades to `proposed_parent.=unsigned`.
    for key in ("id", "target", "attribute"):
        rec[key] = _unquote(rec.get(key, "")).strip()
    _require(
        rec, "id", "target", "attribute",
        msg="attr_preds row missing id/target/attribute",
    )
    return {
        "id": rec["id"],
        "target": rec["target"],
        "attribute": rec["attribute"],
        "claim": _unquote(rec.get("claim", "")),
    }


def _hyp_sub_refut_row(block: Block, row: str) -> RefutationRecord:
    rec = _row_dict(block, row, _HYP_REFUT_COLS)
    # Stripped before `_require`, like `.preds` and `.attr_preds`. Rule #5 resolves a `--`'s
    # cited `r*` against this cell by equality, so a padded `"r1 "` parses clean and then
    # refuses the citation with "cites refutation 'r1', which h-001 does not declare
    # (declares: r1 )" — an error whose own text lists the id it says is missing.
    rec["id"] = _unquote(rec.get("id", "")).strip()
    _require(rec, "id", msg="refuts row missing id")
    out: RefutationRecord = {
        "id": rec["id"],
        "claim": _unquote(rec.get("claim", "")),
    }
    if rec.get("refutes"):
        # Unquoted BEFORE the split: `_check_refutation_scope` resolves these tokens against
        # the declared ids by equality, and a quoted whole cell (`"p1,p2"`) otherwise splits
        # the quote characters INTO the ids, yielding `'"p1'` and `'p2"'` — two refusals
        # whose own text lists both ids as declared.
        out["refutes_predictions"] = _split_csv(_unquote(rec["refutes"]))
    return out


def _hyp_sub_authz_row(block: Block, row: str) -> AuthorizationContract:
    rec = _row_dict(block, row, _HYP_AUTHZ_COLS)
    _require(rec, "id", "anchor_kind", msg="authz row missing id/anchor_kind")
    return {
        "id": rec["id"],
        "edge_ref": rec.get("edge_ref", UNOBSERVED_EDGE_REF) or UNOBSERVED_EDGE_REF,
        "anchor_kind": rec["anchor_kind"],
        "predicate": _unquote(rec.get("predicate", "")),
        "on_unauthorized": rec.get("on_unauth", "escalate") or "escalate",
        "on_indeterminate": rec.get("on_indet", "escalate") or "escalate",
    }


def _lead_header_record(
    rec: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Split a `:L findings` row into (identity, outcome, query_details).

    The outcome fields are returned separately rather than nested inside `identity` so the
    caller cannot merge them with a plain `dict.update`, which would overwrite the lead's whole
    outcome and discard resolution buckets an earlier `:R` block already projected onto it.
    """
    identity: dict[str, Any] = {
        "id": rec["id"], "name": rec["name"], "target": rec.get("target", ""),
    }
    for k_in, k_out in (
        ("loop", "loop"),
        ("mode", "mode"),
        ("trust_root", "trust_root_reached"),
        ("screen_result", "screen_result"),
        ("status", "status"),
    ):
        if rec.get(k_in):
            # UNQUOTED, and before the `loop` coercion. Every one of these five is read by a
            # check that compares it to something — `mode` and `screen_result` against rule
            # #17's closed cells, `loop` against `:T close`'s loop numbers in
            # `_check_loop_close` (rule #17's own `loop` reading went with the
            # intermediate-screen arm at v2.22) — so a uniformly quoted row is refused for a
            # `mode` it spells correctly, or (worse) has its quoted `"1"` survive `int()` as a
            # string that matches no closed loop, and a legal close is refused for a finding
            # it committed.
            v: Any = _unquote(rec[k_in])
            if k_in == "loop":
                with contextlib.suppress(ValueError):
                    v = int(v)
            identity[k_out] = v
    if rec.get("tests"):
        # Unquoted BEFORE the split, exactly as `.refuts`' `refutes` is. Read raw, a quoted
        # whole cell (`"h-001,p1"`) splits the quote characters INTO the ids, and this column
        # fails OPEN where `refutes` failed closed: `_cited_hypothesis_ids` filters `tests` on
        # `HYPOTHESIS_ID_RE` and `_check_tested_commitment_refs` on `COMMITMENT_ID_RE`, so
        # `'"h-999'` matches neither and both references vanish with no diagnostic.
        identity["tests_hypotheses"] = _split_csv(_unquote(rec["tests"]))
    outcome: dict[str, Any] = {}
    if rec.get("fail_reason"):
        outcome["failure_reason"] = rec["fail_reason"]
    query_details: dict[str, Any] = {}
    for k_in, k_out in (
        ("system", "system"),
        ("template", "template"),
        ("query", "query"),
        ("window", "time_window"),
    ):
        if rec.get(k_in):
            query_details[k_out] = rec[k_in]
    return identity, outcome, query_details


_RESOLUTION_LINE_RE = re.compile(
    r"^(?P<hyp>[^\s]+)\s+(?P<before>\S+)\s*→\s*(?P<after>\S+)\s+"
    r"\[(?P<inner>.*)\]\s*$"
)


# What a prediction / refutation citation looks like, on either side of the row. One owner:
# the head tokenizer `fullmatch`es it, the `⟺` scanner searches for it word-bounded. A
# `startswith` test instead would let any head word beginning `p`, `ap` or `r` (`partial`,
# `approved`, `refuted`) parse as a cited id, which `_check_prediction_refs` then blocks on.
_REF_ID_RE = re.compile(r"ap\d+|p\d+|r\d+")
_IFF_LITERAL_RE = re.compile(rf"\b(?:{_REF_ID_RE.pattern})\b")

#: A COMMITMENT id in any of the four namespaces a hypothesis declares — `_REF_ID_RE`'s three
#: plus `ac*` authorization contracts, which no resolution head ever cites and which only
#: `:L findings`' `tests` column can name. Composed from `_REF_ID_RE` so the namespaces keep
#: one owner.
COMMITMENT_ID_RE = re.compile(rf"(?:{_REF_ID_RE.pattern})|ac\d+")


def _dedup(ids: list[str]) -> list[str]:
    return list(dict.fromkeys(ids))


def _extract_iff_literals(annotation: str) -> tuple[list[str], list[str]]:
    if not annotation:
        return [], []
    pred_ids: list[str] = []
    refut_ids: list[str] = []
    seen_pred: set[str] = set()
    seen_refut: set[str] = set()
    normalized = annotation.replace("<=>", "⟺")
    for clause in normalized.split(";"):
        if "⟺" not in clause:
            continue
        _lhs, rhs = clause.split("⟺", 1)
        for token in _IFF_LITERAL_RE.findall(rhs):
            if token.startswith("r"):
                if token not in seen_refut:
                    seen_refut.add(token)
                    refut_ids.append(token)
            else:
                if token not in seen_pred:
                    seen_pred.add(token)
                    pred_ids.append(token)
    return pred_ids, refut_ids


#: An edge id in the `⟂` cell. WORD-BOUNDED, because the cell is free text and its non-id
#: spelling lands in `supporting_marker`: unanchored, `⟂ inference-only` yields a phantom
#: `e-only` and `⟂ none-observed` an `e-observed`. A phantom is worse than none — it makes
#: `_check_strong_provenance` answer "cites e-only but it carries no strong authority" instead
#: of "cites no supporting edge", and it can win `projector.ablation_target` as the
#: narrowest-supported edge, whereupon `_drop_edge` removes nothing and the ablation lens
#: reads the FULL world while the composer is told that edge was withheld.
_SUPPORTING_EDGE_RE = re.compile(r"\be-[A-Za-z0-9]+\b")


def _resolution_record(row: str) -> tuple[str | None, ResolutionRecord]:
    m = _RESOLUTION_LINE_RE.match(row)
    if not m:
        raise RowError("resolution head doesn't match `<hyp> <before> → <after> [...]`")
    inner = m.group("inner")
    annotation = ""
    if "::" in inner:
        bracketed, annotation = inner.split("::", 1)
        annotation = annotation.strip()
    else:
        bracketed = inner
    if "⟂" not in bracketed:
        raise RowError("resolution missing `⟂` supporting-edges separator")
    head, supp = bracketed.split("⟂", 1)
    head_tokens = head.split()
    if len(head_tokens) < 2:
        raise RowError("resolution head needs lead-id + severity")
    lead_id = head_tokens[0]
    severity = head_tokens[-1]
    head_refs: list[str] = []
    for tok in head_tokens[1:-1]:
        head_refs.extend(t.strip() for t in tok.split(",") if t.strip())
    supp_text = supp.strip()
    iff_pred_ids, iff_refut_ids = _extract_iff_literals(annotation)
    # Same split as the `⟺` side: an id-shaped token that is not `r*` is a prediction, so
    # `ap*` files under predictions in both spellings. A bare `startswith("p")` drops `ap1`.
    # lint-selection: ok — PARTIALLY covered downstream, and the gap is recorded rather
    # than claimed closed. A head whose ids ALL drop cites nothing, which
    # `_check_strong_move_provenance` refuses; a head that keeps one good id and drops a
    # malformed sibling passes, and an `ac1` written here drops silently because `ac*` is
    # discharged by a `:R authz` row and `_REF_ID_RE` does not admit it
    # (`experiments/oracle-telemetry-fidelity/runs/defender-run-snapshot` does exactly
    # that). Whether an `ac*` is legal in a resolution head is a spec question, not a
    # mechanical one, so it is not decided here.
    head_ids = [  # lint-selection: ok — partially covered downstream; see above
        t for t in head_refs if _REF_ID_RE.fullmatch(t)
    ]
    # UNION, not `iff_ids or head_ids`. The `⟺` form exists for the row that cites nothing in
    # its head, and replacing meant one iff literal in a `::` segment — which is otherwise free
    # prose — DISCARDED the head's own list: a `++` whose head cites `p1,p2` and whose
    # annotation reads `⟺ p1` was refused by rule #6 for leaving p2 unmatched, with advice
    # ("cite the rest") the row already followed.
    matched_pred_ids = _dedup(
        [t for t in head_ids if not t.startswith("r")] + iff_pred_ids
    )
    matched_refut_ids = _dedup([t for t in head_ids if t.startswith("r")] + iff_refut_ids)
    record: ResolutionRecord = {
        "hypothesis": m.group("hyp"),
        "hypothesis_id": m.group("hyp"),
        "before": m.group("before"),
        "after": m.group("after"),
        "severity_of_test": severity,
        # `_dedup`, like the two sibling id lists above it — this was the one id list on the
        # record that skipped it. The `⟂` cell is free text, so `findall` returns every
        # MENTION: a row citing `⟂ e-001 e-002 e-001` yields `e-001` twice. Every reader
        # means the edges CITED, never how often the cell named them — `ablation_target`
        # counts "how many strong resolutions cite it" to pick the narrowest-supported edge
        # to withhold from the ablation lens, so a repeat made one resolution look like two,
        # withheld a different edge, and reported the inflated count to the composer (#969).
        "supporting_edges": _dedup(_SUPPORTING_EDGE_RE.findall(supp_text)),
        "matched_prediction_ids": matched_pred_ids,
        "matched_refutation_ids": matched_refut_ids,
    }
    if supp_text and not supp_text.startswith("e-"):
        record["supporting_marker"] = supp_text
    if annotation:
        record["reasoning"] = annotation
    return lead_id, record


_RESOLUTION_KEY_CANONICAL = {
    "conditioning": "conditioning_context",
    "grounding": "grounding_kind",
    "authority": "authority_for_question",
    "fulfills": "fulfills_contract",
    "resolved_by": "resolved_by_lead",
    "lead": "resolved_by_lead",
    "pred_ref": "prediction_ref",
    "dim": "dimension",
    "matched_pred": "matched_prediction",
}
# Canonical names, so a header that already spells the canonical key
# (`conditioning_context`) splits the same way its alias (`conditioning`) does.
_RESOLUTION_LIST_KEYS = {"conditioning_context", "concerns", "cites_leads"}


def _canonicalize_resolution_row(rec: dict[str, str]) -> ResolutionRow:
    # Built as a plain dict and cast: the header names the keys at runtime, so there is no
    # literal-key form for mypy to check the writes against. The return type is the shared
    # base — each bucket narrows it on the read side; see the `:R` note in schema.py.
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if not v:
            continue
        canonical = _RESOLUTION_KEY_CANONICAL.get(k, k)
        if canonical in _RESOLUTION_LIST_KEYS:
            out[canonical] = _split_csv_or_semi(v)
        else:
            out[canonical] = v
    return cast(ResolutionRow, out)


#: Conclude rows that REPEAT — one row per item, accumulated in order. `ceiling_test` names one
#: unreachable check each, so a run with three coverage gaps writes three rows and the duplicate
#: guard below must not read the second and third as a key being overwritten.
_CONCLUDE_LISTS: frozenset[str] = frozenset({"ceiling_test"})

#: `:T conclude.deferred_*` — the sub-table name an author writes, the `Conclude` field its
#: rows land in, and the column naming the deferred commitment. One entry per closure rule
#: (#26 authorization contracts, #31 impact predictions, #34 predictions), because those three
#: are one rule over three namespaces: a fourth namespace should be a row here, not a fourth
#: projector. THE owner of the three field names — every set below is derived from it, so the
#: row this comment invites cannot leave one of them behind.
_DEFERRAL_BLOCKS: dict[str, tuple[str, str]] = {
    "conclude.deferred_authz": ("deferred_authorizations", "contract_ref"),
    "conclude.deferred_impact": ("deferred_impact_predictions", "prediction_ref"),
    "conclude.deferred_preds": ("deferred_predictions", "prediction_ref"),
}

#: The `Conclude` fields a `:T conclude.<sub>` block writes — everything else under `conclude`
#: came from a flat `<key> <value>` row in `:T conclude` itself. Derived from
#: `_DEFERRAL_BLOCKS` rather than restated. `validate._NON_CLOSING_FIELDS` IMPORTS this set
#: whole rather than restating it: none of these fields means the document wrote `:T conclude`,
#: so none of them may arm the closure gates.
_CONCLUDE_SUBTABLE_FIELDS: frozenset[str] = frozenset(
    {"surviving_hypotheses", *(field for field, _col in _DEFERRAL_BLOCKS.values())}
)

#: `Conclude` fields that are their OWN `:T conclude.*` sub-table, never a flat
#: `<key> <value>` row. They must be subtracted because `_CONCLUDE_SCALARS` is read off
#: `Conclude.__annotations__`: a sub-table field left in is otherwise advertised in
#: `_CONCLUDE_KEYS_HINT` as a legal flat key AND projected as a STRING over the list the
#: sub-table built, making `_project_surviving_block`'s `setdefault(...).append(...)` raise.
#:
#: `_CONCLUDE_SUBTABLE_FIELDS` plus `termination`, which is a sub-table of the flat block
#: rather than a block of its own (`termination.category` / `.rationale` rows fold into one
#: nested dict). Derived rather than hand-listed: this is the set whose staleness produces the
#: `AttributeError` the paragraph above describes, so it must not be the one copy nobody
#: updates.
#:
#: `ceiling_test` is deliberately NOT here. The dense-format proposal spells it as a
#: `[kind|subject]` sub-table; the shipped surface — `skills/invlang/SKILL.md`, eleven checked-in
#: lessons, and every `:T conclude` block on disk — writes it as a REPEATED FLAT ROW, one gap
#: per row, which is what `_CONCLUDE_LISTS` above carries. The flat row is the real one; see
#: `_project_t_block` for what happens to a block written under the retired spelling.
_CONCLUDE_SUBTABLES: frozenset[str] = frozenset({
    "termination", *_CONCLUDE_SUBTABLE_FIELDS,
})

#: The scalar rows `:T conclude` projects, and the CLOSED set an unrecognized row is judged
#: against. One owner: `Conclude` is the type the projection has to satisfy, so the set is read
#: off it rather than restated here, where the two could drift a field apart.
_CONCLUDE_SCALARS: frozenset[str] = (
    frozenset(Conclude.__annotations__) - _CONCLUDE_SUBTABLES - _CONCLUDE_LISTS
)
_CONCLUDE_KEYS_HINT = ", ".join(
    sorted(_CONCLUDE_SCALARS | _CONCLUDE_LISTS)
    + ["termination.category", "termination.rationale"]
)

#: The two rows that fold into the nested `termination` dict rather than landing as flat keys.
#: Written out because they are the only `:T conclude` rows whose KEY is not the field it lands
#: in, which is exactly what kept them out of the cross-block guard below.
_TERMINATION_ROWS: dict[str, str] = {
    "termination.category": "category",
    "termination.rationale": "rationale",
}

#: The keys the cross-block "a later row replaces an earlier value" warning is asked about —
#: every row `:T conclude` PROJECTS as a single value. `_CONCLUDE_LISTS` is excluded because
#: repetition is how a list row carries more than one item; the `termination.*` pair is
#: INCLUDED, because a second block restating one of them is the same loss on the one field
#: `validate._check_ceiling_test_scope` reads.
_CROSS_BLOCK_GUARDED: frozenset[str] = _CONCLUDE_SCALARS | frozenset(_TERMINATION_ROWS)

#: "This key is not set yet", distinct from `None` — which is what the projection stores for a
#: row whose value is the literal `null`, and therefore a value the guard has to be able to see
#: being replaced.
_MISSING = object()


def _conclude_value(conclude: dict[str, Any], key: str) -> Any:
    """What the projection has already recorded under this ROW key, or `_MISSING`.

    One lookup for two shapes: a flat scalar sits under its own key, while `termination.category`
    and `.rationale` sit one level down inside `termination`.
    """
    sub = _TERMINATION_ROWS.get(key)
    if sub is not None:
        nested = conclude.get("termination")
        return nested.get(sub, _MISSING) if isinstance(nested, dict) else _MISSING
    return conclude.get(key, _MISSING)


#: The `:T conclude.ceiling_test [kind|subject]` sub-table of the dense-format PROPOSAL, kept
#: recognized-and-ignored rather than projected or refused.
#:
#: `ceiling_test` has two spellings and only one of them is real. The shipped authoring surface
#: (`skills/invlang/SKILL.md` §`:T conclude`), eleven checked-in lessons, and every `:T conclude`
#: block on disk write it as a REPEATED FLAT ROW naming one unreachable check each — the shape
#: `_CONCLUDE_LISTS` carries and `render_synthesis` puts in front of the judge. The sub-table is
#: from `docs/dense-investigation-format.md`, a document whose own status line reads "Not
#: implemented", and its `kind` enum appears in no vocabulary and no document.
#:
#: Silence rather than a warning because refusing it buys nothing: the flat row is where the
#: content actually goes, so a run reaching here has written its gaps somewhere the projection
#: does not read either way, and denying the write would cost a run for following a stale
#: format note. The format doc is reconciled to the flat spelling in the same change.
#:
#: The silence has ONE cost, and `validate._check_ceiling_test_scope` pays it rather than this
#: arm: a `severity-ceiling` close whose gaps went into this block is refused by rule #13 for a
#: receipt the author can see in their own document. Refusing the block here would say so
#: earlier, and was not done because the block is legal-looking content a stale format note
#: teaches — so #13's refusal names the retired spelling instead.
_RETIRED_CEILING_TEST_BLOCK = "conclude.ceiling_test"


def _close_loop(rows: list[str]) -> int | None:
    for row in rows:
        m = re.match(r"^loop\s+(\S+)", row.strip())
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    return None




_RESOLUTION_BUCKET_KEY = {
    "authz": "authorization_resolutions",
    "consultations": "anchor_consultations",
    "impact": "impact_resolutions",
    "attr_updates": "attribute_updates",
}


def _two_site_reason(hid: str) -> str:
    return (
        f"hypothesis {hid!r} is declared both by `:H hypothesize.hypotheses` and "
        f"by a lead's `:H l-NNN.new_hypotheses` — declare it at exactly one site. "
        f"Its `:H {hid}.<sub>` blocks attach to whichever record the parser met "
        f"first, while every reader takes the table's, so a contract or "
        f"prediction can land on a record nothing reads."
    )


def _extend_by_id(dest: list[Any], rows: list[Any]) -> None:
    """Append the rows whose id the destination does not already carry.

    Accumulation has to be by id, not blind: re-emitting a whole `:H hypothesize.hypotheses`
    table with one new row appended is the natural reading of a table block, and a blind
    `extend` turns that into duplicate rows. `runtime/review/projector.py` maps the raw list
    straight to the review lenses without the dedup `_walkers.all_hypotheses` applies, so every
    lens would see the same hypothesis twice.

    First declaration wins, so the raw list holds exactly what the walkers dedup to. A row with
    no id is always appended; nothing can key it.
    """
    seen = {r["id"] for r in dest if isinstance(r, dict) and r.get("id")}
    for r in rows:
        rid = r.get("id") if isinstance(r, dict) else None
        if rid and rid in seen:
            continue
        if rid:
            seen.add(rid)
        dest.append(r)