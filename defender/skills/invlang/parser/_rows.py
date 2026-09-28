"""One row of one block type, projected into one typed record.

Every function here is pure: `(Block, row) -> record`, raising `RowError` for a row it
cannot read."""


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


#: The two block names that declare a hypothesis, spelled as `ParseWarning.block` renders them
#: (`:H <name>`).
HYP_DECLARATION_BLOCK_RE = re.compile(
    r"^:H (?:hypothesize\.hypotheses|l-[A-Za-z0-9]+\.new_hypotheses)$"
)

#: An `h-*` id, including the hierarchical child form `h-{parent}-{ordinal}` (`h-001-001`)
#: used when a hypothesis refines into sub-cases.
HYPOTHESIS_ID_RE = re.compile(r"h-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")


def _row_first_cell(row: str) -> str:
    # `_split_cells`, not `row.split("|")`, so escaped `\|` and quoted cells are honoured.
    return _split_cells(row)[0]


def deferred_hypothesis_ids(
    warnings: list[ParseWarning],
) -> frozenset[str] | None:
    """Which `h-*` ids parse warnings dropped, so the undeclared-hypothesis rule stays quiet
    about references to them (the parse warning already names the cause).

    Per id, so one bad `:H` row does not silence the rule for the whole document. Ids come
    from a warning's `dropped_ids` (whatever block carries it, e.g. the `new_hypothesis` typo)
    or from the first cell of a rejected declaration row. Returns `None`, standing the rule
    down everywhere, when a dropped declaration cannot be mapped to an id.
    """
    deferred: set[str] = set()
    for w in warnings:
        if w.dropped_ids:
            named: tuple[str, ...] = w.dropped_ids
        elif HYP_DECLARATION_BLOCK_RE.match(w.block) and w.row:
            named = (_row_first_cell(w.row),)
        else:
            continue
        usable = [  # lint-selection: ok — an empty selection returns None (rule stands down)
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


#: The `:H` header cells checks compare by equality or vocabulary, so they are unquoted: a
#: quoted `"--"` would otherwise not equal `REFUTED_WEIGHT` and a refuted hypothesis would read
#: as live.
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




#: `:H h-NNN.<sub>` block names. Built from `HYPOTHESIS_ID_RE` so hierarchical children
#: (`h-001-001.preds`) can declare sub-blocks too.
_HYP_PREFIX_RE = re.compile(
    rf"^(?P<hyp>{HYPOTHESIS_ID_RE.pattern})"
    rf"\.(?P<sub>preds|attr_preds|refuts|authz|parent_attrs)$"
)

#: Every `:<TAG> l-NNN.<sub>` block name a lead carries, per tag, as listed in the "unknown
#: lead sub-block" warning. Used for messages only: the projector's branches decide what lands,
#: so keep the two in step by hand.
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

    Only `id` is required: rule #18 checks the other cells and can name the column and repair,
    where a `RowError` here would just drop the row. Cells are unquoted because checks compare
    them by equality.
    """
    rec = _row_dict(block, row, _LEAD_PRED_COLS)
    _require(rec, "id", msg="lead_preds row missing id")
    return {
        "id": _unquote(rec["id"]),
        # `if` is a Python keyword, so the TypedDict key is `condition`.
        "condition": _unquote(rec.get("if", "")),
        "read_as": _unquote(rec.get("read_as", "")),
        "advance_to": _unquote(rec.get("advance_to", "")),
    }


def _impact_pred_row(block: Block, row: str) -> ImpactPrediction:
    """`:L l-NNN.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|
    escalation_on]` — one pre-registered impact predicate.

    Only `id` is required, as in `_lead_pred_row` (rule #29 checks the rest). Every cell is
    unquoted because checks compare them by equality. Keys are written out, not looped,
    because a TypedDict write needs a literal key.
    """
    rec = _row_dict(block, row, _IMPACT_PRED_COLS)
    _require(rec, "id", msg="impact_preds row missing id")
    return {
        "id": _unquote(rec["id"]),
        "dimension": _unquote(rec.get("dim", "")),
        "claim": _unquote(rec.get("claim", "")),
        "on_match": _unquote(rec.get("on_match", "")),
        "on_mismatch": _unquote(rec.get("on_mismatch", "")),
        "on_indeterminate": _unquote(rec.get("on_indeterminate", "")),
        "escalation_on": _unquote(rec.get("escalation_on", "")),
    }


def _hyp_sub_pred_row(block: Block, row: str) -> PredictionRecord:
    rec = _row_dict(block, row, _HYP_PRED_COLS)
    # Unquoted and stripped before `_require`: ids are compared by equality, and a quoted empty
    # cell `""` would otherwise pass `_require` as truthy.
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
    # Every compared cell is unquoted and stripped before `_require`, so a quoted blank cell
    # is refused here (rule #33 relies on that) and equality checks see the real value.
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
    # Unquoted and stripped before `_require`: rule #5 matches cited `r*` ids by equality.
    rec["id"] = _unquote(rec.get("id", "")).strip()
    _require(rec, "id", msg="refuts row missing id")
    out: RefutationRecord = {
        "id": rec["id"],
        "claim": _unquote(rec.get("claim", "")),
    }
    if rec.get("refutes"):
        # Unquoted before the split, or a quoted cell leaves quote characters in the ids.
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
            # Unquoted before the `loop` coercion: these cells are compared by equality, and a
            # quoted `"1"` would otherwise stay a string that matches no closed loop.
            v: Any = _unquote(rec[k_in])
            if k_in == "loop":
                with contextlib.suppress(ValueError):
                    v = int(v)
            identity[k_out] = v
    if rec.get("tests"):
        # Unquoted before the split, or a quoted cell leaves quote characters in the ids.
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


# A prediction / refutation citation. A regex rather than `startswith`, so head words like
# `partial` or `refuted` are not read as cited ids.
_REF_ID_RE = re.compile(r"ap\d+|p\d+|r\d+")
_IFF_LITERAL_RE = re.compile(rf"\b(?:{_REF_ID_RE.pattern})\b")

#: A commitment id in any of the four namespaces a hypothesis declares: `_REF_ID_RE`'s three
#: plus `ac*` authorization contracts (only nameable in `:L findings`' `tests` column).
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


#: An edge id in the free-text `⟂` cell. Word-bounded so `inference-only` does not yield a
#: phantom `e-only`, which would mislead provenance checks and the ablation lens.
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
    # An id-shaped token that is not `r*` is a prediction (`p*` or `ap*`), as on the `⟺` side.
    # Known gap: a head whose ids all drop is refused downstream by
    # `_check_strong_move_provenance`, but one malformed id beside a good one, or an `ac1`,
    # drops silently. Whether `ac*` is legal in a head is an open spec question.
    head_ids = [  # lint-selection: ok — partially covered downstream; gap noted above
        t for t in head_refs if _REF_ID_RE.fullmatch(t)
    ]
    # Union of head and `⟺` ids: an annotation literal must not discard the head's own list.
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
        # Deduped: readers count citing resolutions (e.g. `ablation_target`), not mentions.
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
    # A plain dict cast at the end: the header names the keys at runtime. Each bucket narrows
    # the shared base type on the read side.
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


#: Conclude rows that repeat, one row per item (e.g. one `ceiling_test` per coverage gap), so
#: the duplicate-key guard must not treat a repeat as an overwrite.
_CONCLUDE_LISTS: frozenset[str] = frozenset({"ceiling_test"})

#: `:T conclude.deferred_*` sub-table name -> (`Conclude` field, column naming the deferred
#: commitment). One entry per closure rule (#26, #31, #34); the sets below derive from it, so a
#: new namespace should be a new row here.
_DEFERRAL_BLOCKS: dict[str, tuple[str, str]] = {
    "conclude.deferred_authz": ("deferred_authorizations", "contract_ref"),
    "conclude.deferred_impact": ("deferred_impact_predictions", "prediction_ref"),
    "conclude.deferred_preds": ("deferred_predictions", "prediction_ref"),
}

#: The `Conclude` fields written by a `:T conclude.<sub>` block rather than a flat row in
#: `:T conclude`. None of them means the document wrote `:T conclude`, so none may arm the
#: closure gates (`validate._NON_CLOSING_FIELDS` imports this set).
_CONCLUDE_SUBTABLE_FIELDS: frozenset[str] = frozenset(
    {"surviving_hypotheses", *(field for field, _col in _DEFERRAL_BLOCKS.values())}
)

#: `Conclude` fields that are not flat `<key> <value>` rows: the sub-table fields plus the
#: nested `termination` dict. Subtracted from `_CONCLUDE_SCALARS`, or a flat row could overwrite
#: a sub-table's list with a string. `ceiling_test` is a repeated flat row, not a sub-table.
_CONCLUDE_SUBTABLES: frozenset[str] = frozenset({
    "termination", *_CONCLUDE_SUBTABLE_FIELDS,
})

#: The scalar rows `:T conclude` projects, read off the `Conclude` type so the two cannot drift.
_CONCLUDE_SCALARS: frozenset[str] = (
    frozenset(Conclude.__annotations__) - _CONCLUDE_SUBTABLES - _CONCLUDE_LISTS
)
_CONCLUDE_KEYS_HINT = ", ".join(
    sorted(_CONCLUDE_SCALARS | _CONCLUDE_LISTS)
    + ["termination.category", "termination.rationale"]
)

#: The two rows that fold into the nested `termination` dict rather than landing as flat keys.
_TERMINATION_ROWS: dict[str, str] = {
    "termination.category": "category",
    "termination.rationale": "rationale",
}

#: Keys the cross-block "a later row replaces an earlier value" warning covers: every
#: single-valued `:T conclude` row, including `termination.*`.
_CROSS_BLOCK_GUARDED: frozenset[str] = _CONCLUDE_SCALARS | frozenset(_TERMINATION_ROWS)

#: "Not set yet", distinct from `None` (the projection of a literal `null`).
_MISSING = object()


def _conclude_value(conclude: dict[str, Any], key: str) -> Any:
    """What the projection has already recorded under this row key, or `_MISSING`.

    `termination.*` rows are looked up inside the nested `termination` dict.
    """
    sub = _TERMINATION_ROWS.get(key)
    if sub is not None:
        nested = conclude.get("termination")
        return nested.get(sub, _MISSING) if isinstance(nested, dict) else _MISSING
    return conclude.get(key, _MISSING)


#: A sub-table spelling of `ceiling_test` from an unimplemented format proposal, accepted and
#: ignored. The real spelling is the repeated flat row in `:T conclude`. Not refused, because a
#: stale format note teaches it; rule #13 names this spelling if a `severity-ceiling` close
#: relied on it.
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

    Authors often re-emit a whole table with one new row appended; a blind `extend` would
    duplicate rows, and some readers (e.g. `runtime/review/projector.py`) use the raw list
    without deduping. First declaration wins. A row with no id is always appended.
    """
    seen = {r["id"] for r in dest if isinstance(r, dict) and r.get("id")}
    for r in rows:
        rid = r.get("id") if isinstance(r, dict) else None
        if rid and rid in seen:
            continue
        if rid:
            seen.add(rid)
        dest.append(r)