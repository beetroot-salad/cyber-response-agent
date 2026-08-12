
from __future__ import annotations

import contextlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, cast

from ._cells import (
    _has_unbalanced_quote,
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
)
from ._types import Block, RowError
from .vocab import UNOBSERVED_EDGE_REF
from .schema import (
    AttributeUpdate,
    AttrPredictionRecord,
    AuthorityRef,
    AuthorizationContract,
    CompanionBody,
    Conclude,
    EdgeRecord,
    HypothesisRecord,
    ParentVertex,
    PredictionRecord,
    ProposedEdge,
    RefutationRecord,
    ResolutionRecord,
    ResolutionRow,
    VertexRecord,
)

INVLANG_FENCE_RE = re.compile(r"```invlang\n(.*?)\n```", re.DOTALL)
HEADER_RE = re.compile(
    r"^:(?P<tag>[A-Z])\s+(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\s*\[(?P<cols>[^\]]*)\])?\s*$"
)
_STORY_HEADER_RE = re.compile(r"^###\s+story\s+(h-[\w\-]+)\s*$")
_LEAD_PREFIX_RE = re.compile(r"^l-(?P<id>[A-Za-z0-9]+)\.(?P<sub>.+)$")


@dataclass
class ParseWarning:
    block: str
    row_index: int
    row: str
    reason: str
    file_path: str = ""
    #: The ids this warning DELETED from the companion, when it deleted any and the rows
    #: were still readable enough to name them. Structure carried alongside the prose, the
    #: same way `Diagnostic` carries a `Locus`: the message is unchanged, and a consumer
    #: that needs to know *which* ids went missing no longer has to re-parse it back out.
    #: The whole-block rejections populate it — a row-level failure already carries its
    #: row, and the id is that row's first cell.
    dropped_ids: tuple[str, ...] = ()

    def format(self) -> str:
        loc = self.file_path or "(unknown file)"
        return (
            f"{loc}: {self.block} row {self.row_index}: {self.reason} "
            f"| row={self.row[:200]!r}"
        )


def _parse_auth(cell: str) -> AuthorityRef:
    if ":" not in cell:
        return {"kind": cell.strip(), "source": ""}
    kind, source = cell.split(":", 1)
    return {"kind": kind.strip(), "source": source.strip()}




def _tokenize_fence(body: str) -> list[Block]:
    blocks: list[Block] = []
    cur: Block | None = None
    in_story = False

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if _STORY_HEADER_RE.match(stripped):
            in_story = True
            cur = None
            continue

        m = HEADER_RE.match(stripped)
        if m:
            in_story = False
            cols_raw = m.group("cols")
            cols = (
                [c.strip().rstrip("?") for c in cols_raw.split("|")]
                if cols_raw is not None
                else None
            )
            cur = Block(
                tag=m.group("tag"),
                name=m.group("name"),
                columns=cols,
            )
            blocks.append(cur)
            continue

        if in_story or cur is None:
            continue
        cur.rows.append(stripped)
    return blocks




_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]
_SURVIVING_COLS = ["hyp_id", "final_weight"]


def iter_blocks(text: str) -> Iterator[Block]:
    """Every invlang `Block` in `text`, in document order, with its DECLARED header and its
    rows as the author wrote them.

    The projection that `parse_dense_companion` builds is lossy on purpose — it folds rows
    into records and drops the header — which is right for every consumer that asks "what
    does this investigation say". A check that has to quote a row back, or substitute one
    cell of it, needs the layer underneath, and rebuilding a row from the folded record
    means assuming a column order the grammar does not enforce (#825).

    Kept out of the companion deliberately: carrying per-row provenance on the records
    inflated the parsed body by up to 25%, and that body is projected into the review lens
    prompts."""
    for fence in INVLANG_FENCE_RE.finditer(text):
        yield from _tokenize_fence(fence.group(1))


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


#: The two block names that DECLARE a hypothesis, spelled as `ParseWarning.block`
#: renders them (`:H <name>`). One owner: `_project_block`'s dispatch, the
#: validator's "did a declaration get dropped?" test, and the SKILL/parser
#: grammar pin all read which names are declaration sites from here, so they
#: cannot drift into disagreeing about it.
HYP_DECLARATION_BLOCK_RE = re.compile(
    r"^:H (?:hypothesize\.hypotheses|l-[A-Za-z0-9]+\.new_hypotheses)$"
)

#: An `h-*` id, including the hierarchical child form: when a lean hypothesis refines into
#: sub-cases the language allocates `h-{parent}-{ordinal}` (`h-001` → `h-001-001`) and
#: writes the children into the lead's `new_hypotheses` with the parent shelved in the same
#: block (`docs/investigation-language.md` §Refinement via hierarchical IDs). One owner:
#: the validator reads which tokens are hypothesis references from here, and
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

    A rejected header or a bad row on a hypothesis DECLARATION block deletes ids the
    document goes on referring to, so every reference to them looks phantom — the one case
    where the undeclared-hypothesis error would point away from the defect. A warning from
    anywhere ELSE (an unknown block, an unattributed `:R` row, a malformed vertex) drops no
    declaration and must not stand the rule down.

    Per ID, not per DOCUMENT. The predecessor answered only "did any declaration get
    dropped?", so one malformed `:H` row anywhere silenced the rule for the whole file and
    an unrelated typo three leads away went unreported behind it. The id is recoverable in
    both failure modes: a whole-block rejection carries `dropped_ids`, and a row-level
    failure carries its row, whose first cell IS the id.

    `None` means "stand down everywhere" and is the honest answer when a dropped
    declaration cannot be mapped to an id at all — a row so malformed its first cell is not
    id-shaped. Reporting references then would give two errors for one defect, which is the
    whole reason this deference exists; the caller treats `None` exactly as the predecessor
    treated `True`.

    `dropped_ids` is the authoritative channel and is consulted whatever block carries it,
    because a declaration is deleted from more than the two DECLARING names: the singular
    typo `:H l-NNN.new_hypothesis` drops its rows too, and matching on the name alone left
    that one warning to be followed by one error per reference site.

    A warning that names NO id is skipped rather than deferred: a header rejected on a block
    with no rows deleted nothing, so standing the rule down for the document would hide
    every unrelated phantom behind a warning that dropped no declaration at all.
    """
    deferred: set[str] = set()
    for w in warnings:
        if w.dropped_ids:
            named: tuple[str, ...] = w.dropped_ids
        elif HYP_DECLARATION_BLOCK_RE.match(w.block) and w.row:
            named = (_row_first_cell(w.row),)
        else:
            continue
        usable = [i for i in named if HYPOTHESIS_ID_RE.fullmatch(i)]
        if not usable:
            return None
        deferred.update(usable)
    return frozenset(deferred)


def _is_current_hyp_header(cols: list[str] | None) -> bool:
    if not cols:
        return False
    return set(cols) == _HYP_HEADER_COLS


def _hypothesis_record(block: Block, row: str) -> HypothesisRecord:
    rec = _row_dict(block, row)
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




#: The DECLARING side of `HYPOTHESIS_ID_RE`, built from it rather than restating it. The
#: restatement was narrower — single-segment only — so a hierarchical child that the four
#: reference sites accept (#821/#828) could not declare `:H h-001-001.preds`: the block fell
#: through to the generic "unknown block" warning and the write was denied, leaving a
#: committed child unable to declare the prediction `_check_strong_move_provenance` then
#: demands before it can be moved `++`/`--` (#853/F-27). One owner means the two cannot
#: drift again, and a typoed child id now lands on `_project_hyp_subblock`'s "sub-block
#: references unknown hypothesis" warning, which names the actual cause.
_HYP_PREFIX_RE = re.compile(
    rf"^(?P<hyp>{HYPOTHESIS_ID_RE.pattern})"
    rf"\.(?P<sub>preds|attr_preds|refuts|authz|parent_attrs)$"
)

_HYP_PRED_COLS = ["id", "subject", "claim"]
_HYP_ATTR_PRED_COLS = ["id", "target", "attribute", "claim"]
_HYP_REFUT_COLS = ["id", "refutes", "claim"]
_HYP_AUTHZ_COLS = ["id", "edge_ref", "anchor_kind", "predicate", "on_unauth", "on_indet"]


def _hyp_sub_pred_row(block: Block, row: str) -> PredictionRecord:
    rec = _row_dict(block, row, _HYP_PRED_COLS)
    _require(rec, "id", "subject", msg="preds row missing id/subject")
    return {
        "id": rec["id"],
        "subject": rec["subject"],
        "claim": _unquote(rec.get("claim", "")),
    }


def _hyp_sub_attr_pred_row(block: Block, row: str) -> AttrPredictionRecord:
    rec = _row_dict(block, row, _HYP_ATTR_PRED_COLS)
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
    _require(rec, "id", msg="refuts row missing id")
    out: RefutationRecord = {
        "id": rec["id"],
        "claim": _unquote(rec.get("claim", "")),
    }
    if rec.get("refutes"):
        out["refutes_predictions"] = _split_csv(rec["refutes"])
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

    The outcome fields are returned separately rather than nested inside
    `identity` so the caller cannot merge them with a plain `dict.update` —
    that overwrote the lead's whole outcome, discarding resolution buckets
    already projected onto it by an earlier `:R` block.
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
            v: Any = rec[k_in]
            if k_in == "loop":
                with contextlib.suppress(ValueError):
                    v = int(v)
            identity[k_out] = v
    if rec.get("tests"):
        identity["tests_hypotheses"] = _split_csv(rec["tests"])
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


# What a prediction / refutation citation looks like, on either side of the row.
# One owner: the head tokenizer `fullmatch`es it, the `⟺` scanner searches for it
# word-bounded. A `startswith` test here instead let any head word beginning `p`,
# `ap` or `r` (`partial`, `approved`, `refuted`) parse as a cited id — harmless
# while nothing joined the list back to the declaring `:H` block, a blocked write
# once `_check_prediction_refs` did.
_REF_ID_RE = re.compile(r"ap\d+|p\d+|r\d+")
_IFF_LITERAL_RE = re.compile(rf"\b(?:{_REF_ID_RE.pattern})\b")

#: A COMMITMENT id in any of the four namespaces a hypothesis declares — `_REF_ID_RE`'s three
#: plus `ac*` authorization contracts, which no resolution head ever cites and which only
#: `:L findings`' `tests` column can name. Composed from `_REF_ID_RE` rather than restating
#: it, the same way `_IFF_LITERAL_RE` is, so the namespaces keep one owner.
COMMITMENT_ID_RE = re.compile(rf"(?:{_REF_ID_RE.pattern})|ac\d+")


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
    # Same split as the `⟺` side: an id-shaped token that is not `r*` is a
    # prediction, so `ap*` files under predictions in both spellings. A bare
    # `startswith("p")` dropped `ap1` on the floor — the head spelling the
    # validator's own error message asks for parsed as citing nothing at all.
    head_ids = [t for t in head_refs if _REF_ID_RE.fullmatch(t)]
    matched_pred_ids = iff_pred_ids or [t for t in head_ids if not t.startswith("r")]
    matched_refut_ids = iff_refut_ids or [t for t in head_ids if t.startswith("r")]
    record: ResolutionRecord = {
        "hypothesis": m.group("hyp"),
        "hypothesis_id": m.group("hyp"),
        "before": m.group("before"),
        "after": m.group("after"),
        "severity_of_test": severity,
        "supporting_edges": re.findall(r"e-[A-Za-z0-9]+", supp_text),
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
    # Built as a plain dict and cast: the header names the keys at runtime, so
    # there is no literal-key form for mypy to check the writes against. The
    # return type is the shared base — each bucket narrows it on the read side;
    # see the `:R` note in schema.py.
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

#: `Conclude` fields that are their OWN `:T conclude.*` sub-table, never a flat
#: `<key> <value>` row. They must be subtracted for the same reason `termination` always was:
#: `_CONCLUDE_SCALARS` is read off `Conclude.__annotations__`, so a field added to carry a
#: sub-table is otherwise advertised in `_CONCLUDE_KEYS_HINT` as a legal flat key AND
#: projected as a STRING over the list the sub-table built — which then makes
#: `_project_surviving_block`'s `setdefault(...).append(...)` raise on a str (#821).
_CONCLUDE_SUBTABLES: frozenset[str] = frozenset({"termination", "surviving_hypotheses"})

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

#: What the format writes where a conclude row has nothing to say (`docs/dense-investigation-
#: format.md`: these "carry `none` / `n/a`" unless the run terminated on a ceiling). A list row
#: holding it projects as absence, so a reader tests `conclude.get("ceiling_test")` rather than
#: filtering a sentinel back out.
_CONCLUDE_EMPTY_MARKERS: frozenset[str] = frozenset({"none", "n/a"})


def is_conclude_empty_marker(value: object) -> bool:
    """Does this conclude row value spell "nothing to say"? THE membership test for the
    vocabulary above, beside the vocabulary.

    A SCALAR row keeps the marker — only the list branch below drops it — so a gate that asks
    "did the run state a defect" has to ask this rather than `value.strip()`: `detection_notes
    none` is the row that explicitly says there is no defect, and it is not blank.
    """
    return isinstance(value, str) and value.strip().lower() in _CONCLUDE_EMPTY_MARKERS


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

    Accumulation has to be by id, not blind: re-emitting a whole `:H
    hypothesize.hypotheses` table with one new row appended is the natural
    reading of a table block, and it was CORRECT under the old replace
    semantics. Blind `extend` turned that pattern into duplicate rows, and
    `runtime/review/projector.py` maps the raw list straight to the review
    lenses without the dedup `_walkers.all_hypotheses` applies — so every lens
    would have seen the same hypothesis twice.

    First declaration wins, so the raw list holds exactly what the walkers
    dedup to. A row with no id is always appended; nothing can key it.
    """
    seen = {r["id"] for r in dest if isinstance(r, dict) and r.get("id")}
    for r in rows:
        rid = r.get("id") if isinstance(r, dict) else None
        if rid and rid in seen:
            continue
        if rid:
            seen.add(rid)
        dest.append(r)


@dataclass
class _Projector:

    out: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    hypotheses_by_id: dict[str, HypothesisRecord] = field(default_factory=dict)
    #: Ids the `:H hypothesize.hypotheses` table declares. The table outranks a
    #: lead's `new_hypotheses` in `hypotheses_by_id` regardless of document
    #: order, because that is the precedence `_walkers.all_hypotheses` applies
    #: on the read side.
    prologue_hypothesis_ids: set[str] = field(default_factory=set)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)

    # No "current lead" state, deliberately. Attribution used to fall back to
    # whichever lead a preceding block happened to mention last, which silently
    # filed one lead's grounding evidence under another. Every row that lands on
    # a lead now names it.

    def lead_bucket(self, lead_id: str) -> dict[str, Any]:
        lead = self.findings.setdefault(lead_id, {"id": lead_id})
        lead.setdefault("outcome", {})
        lead.setdefault("query_details", {})
        lead.setdefault("resolutions", [])
        return lead

    def _warn(
        self,
        block: Block,
        row_index: int,
        row: str,
        reason: str,
        dropped_ids: tuple[str, ...] = (),
    ) -> None:
        self.warnings.append(ParseWarning(
            block=f":{block.tag} {block.name}",
            row_index=row_index,
            row=row,
            reason=reason,
            dropped_ids=dropped_ids,
        ))

    def _project_rows(self, block: Block, project_one) -> list[Any]:
        projected: list[Any] = []
        for idx, row in enumerate(block.rows):
            try:
                projected.append(project_one(block, row))
            except RowError as e:
                self._warn(block, idx, row, str(e))
        return projected

    def _for_each_row(
        self, block: Block, default_cols: list[str] | None = None
    ) -> Iterator[tuple[int, str, dict[str, str]]]:
        for idx, row in enumerate(block.rows):
            try:
                rec = _row_dict(block, row, default_cols)
            except RowError as e:
                self._warn(block, idx, row, str(e))
                continue
            yield idx, row, rec


    def _check_one_line_rows(self, block: Block) -> None:
        """Every invlang row is ONE line, in every block.

        `_tokenize_fence` makes a row per line, so a value written across two lines keeps line
        one with its quote dangling and reparses the rest as fresh rows — dropped, or worse,
        landing on whatever key the continuation's first word happens to name. That used to be
        silent, which is how #806's refuted-correlation finding could be authored and lost.
        The guard is here rather than inside one block's projector because the truncation is a
        property of the line-oriented surface, not of `:T conclude`: a two-line `:L findings`
        name loses the lead's target, loop and system just as quietly.
        """
        for idx, row in enumerate(block.rows):
            if _has_unbalanced_quote(row):
                self._warn(
                    block, idx, row,
                    "row opens a quoted value that does not close on this row — invlang rows "
                    "are ONE line each, so the lines below it are parsed as separate rows and "
                    "the rest of the value is dropped. Write it as ONE line (long is fine — "
                    "`summary` routinely is).",
                )

    def project_block(self, block: Block) -> None:
        tag, name = block.tag, block.name
        self._check_one_line_rows(block)

        # Extend, never assign — same reason as `:H` (#816). Append-only forbids
        # rewriting a committed block, so a second `:V prologue.vertices` is the
        # only legal way to add one, and assignment deleted every vertex the
        # first block declared.
        if tag == "V" and name == "prologue.vertices":
            _extend_by_id(
                self.out.setdefault("prologue", {}).setdefault("vertices", []),
                self._project_rows(block, _vertex_record),
            )
            return
        if tag == "E" and name == "prologue.edges":
            _extend_by_id(
                self.out.setdefault("prologue", {}).setdefault("edges", []),
                self._project_rows(block, _edge_record),
            )
            return
        if tag == "H" and name == "hypothesize.hypotheses":
            self._project_hypothesize_block(block)
            return

        m_hyp_sub = _HYP_PREFIX_RE.match(name) if tag == "H" else None
        if m_hyp_sub:
            self._project_hyp_subblock(
                block, m_hyp_sub.group("hyp"), m_hyp_sub.group("sub"),
            )
            return

        if tag == "L" and name == "findings":
            self._project_findings_block(block)
            return

        m = _LEAD_PREFIX_RE.match(name)
        if m:
            lead_id = "l-" + m.group("id")
            sub = m.group("sub")
            self._project_lead_subblock(tag, sub, block, self.lead_bucket(lead_id))
            return

        if tag == "R" and name in _RESOLUTION_BUCKET_KEY:
            self._project_resolution_block(block)
            return

        if tag == "T" and self._project_t_block(block):
            return

        self._warn(block, -1, "", "unknown block — no projection rule")

    def _project_conclude_scalars(self, block: Block) -> None:
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        termination: dict[str, Any] = {}
        seen: set[str] = set()
        for index, row in enumerate(block.rows):
            m = re.match(r"^(\S+)\s+(.*)$", row)
            if not m:
                self._warn(
                    block, index, row,
                    f"conclude: row records nothing — every row is `<key> <value>` on one "
                    f"line, keyed by one of {_CONCLUDE_KEYS_HINT}. If this is the "
                    f"continuation of a value from the row above, join it onto one line.",
                )
                continue
            key = m.group(1)
            raw = m.group(2).strip()
            value: Any = None if raw == "null" else _unquote(raw)
            if key in seen and key not in _CONCLUDE_LISTS:
                # The continuation of a two-line value lands on whatever key its first word
                # names, so this fires on the row that silently overwrote a real conclusion —
                # `summary` clobbered by the tail of a `termination.rationale`, say. A list key
                # is exempt: repetition is how it carries more than one item.
                self._warn(
                    block, index, row,
                    f"conclude: {key!r} is set twice in this block; the later row wins and "
                    f"the earlier value is lost. Keep one row per key, and join a value that "
                    f"spilled onto a second line back into one line.",
                )
            if key == "termination.category":
                seen.add(key)
                termination["category"] = value
            elif key == "termination.rationale":
                seen.add(key)
                termination["rationale"] = value
            elif key in _CONCLUDE_LISTS:
                seen.add(key)
                if is_conclude_empty_marker(value):
                    continue
                cast(list[str], conclude.setdefault(key, [])).append(value)
            elif key in _CONCLUDE_SCALARS:
                seen.add(key)
                conclude[key] = value
            # An unrecognized key is IGNORED, not warned. It reads like the obvious place to
            # catch an unquoted value that spilled onto a second line, and it cannot be: the
            # lessons corpus can instruct conclude rows this projection does not carry, and
            # `learning/core/persist.py` dead-letters a run whose investigation.md fails
            # validation rather than learning from it — so a warning here turns "the model
            # obeyed a lesson" into a discarded run. `ceiling_test` was exactly that case until
            # this commit recorded it. The truncation this block guards against is caught
            # upstream by `_check_one_line_rows` on quote parity, which fires on both halves of
            # a spilled quoted value without needing to know which keys are real. An unquoted
            # spill stays undetected; that is the price of not denying instructed content.
        if termination:
            conclude["termination"] = termination

    def _project_t_block(self, block: Block) -> bool:
        name = block.name
        if name == "conclude":
            self._project_conclude_scalars(block)
            return True
        if name == "conclude.surviving":
            self._project_surviving_block(block)
            return True
        if name.startswith("conclude."):
            return True
        if name == "close":
            loop = _close_loop(block.rows)
            if loop is None:
                self._warn(
                    block, -1, "\n".join(block.rows)[:200],
                    "`:T close` needs a `loop N` (integer) row",
                )
            else:
                self.out.setdefault("closed_loops", []).append(loop)
            return True
        if name == "resolutions":
            self._project_resolutions_block(block)
            return True
        if name == "shelved":
            self._project_shelved_block(block)
            return True
        return False

    def _stale_hyp_header(self, block: Block) -> bool:
        """True (and warned) when a `:H` DECLARATION block's header is off-schema.

        One owner for both declaration sites. `:H l-NNN.new_hypotheses` used to
        skip the check that `:H hypothesize.hypotheses` enforces, so a lead could
        project a hypothesis off a stale header — and since a lead-born record is
        now indexed for sub-block attachment, that record reaches every consumer
        of `_walkers.all_hypotheses`.
        """
        if _is_current_hyp_header(block.columns):
            return False
        self._warn(
            block, -1, "",
            (
                f"column header {block.columns!r} does not match the "
                f"current schema (id|name|attached_to|rel|parent_type|"
                f"parent_class|integrity_waived?|weight|status); whole "
                f"block rejected"
            ),
            # The rows are readable even though the header is not, and their first cell is
            # the id. Naming them here is what lets the undeclared-hypothesis rule defer
            # for exactly these ids instead of for the whole document.
            dropped_ids=tuple(_row_first_cell(r) for r in block.rows),
        )
        return True

    def _project_hypothesize_block(self, block: Block) -> None:
        if self._stale_hyp_header(block):
            return
        hyps = self._project_rows(block, _hypothesis_record)
        # Extend, never assign. Append-only forbids rewriting the loop-1 block, so
        # a loop that forks a hypothesis writes a SECOND `:H
        # hypothesize.hypotheses` — which used to REPLACE the list, deleting every
        # earlier loop's hypothesis from the companion with no parse warning, and
        # with them the `:H h-NNN.preds` a later resolution resolves against and
        # the `:H h-NNN.authz` contracts benign-gating has to find (#816).
        _extend_by_id(
            self.out.setdefault("hypothesize", {}).setdefault("hypotheses", []), hyps
        )
        self._register_hypotheses(block, hyps, prologue=True)

    def _register_hypotheses(
        self, block: Block, hyps: list[HypothesisRecord], *, prologue: bool
    ) -> None:
        """Index the records a `:H h-NNN.<sub>` sub-block attaches to.

        Re-declaring an id at the SAME site is a re-emission: the first
        declaration stands, silently, because that is what `_extend_by_id` does
        to the list and what `_walkers.all_hypotheses` does on the read side.
        Re-declaring it at the OTHER site is not recoverable and is warned.

        The two sites disagree on order — `_walkers.all_hypotheses` walks the
        `:H hypothesize.hypotheses` table before any lead's `new_hypotheses`,
        not the document — so an id declared in a lead and then promoted into
        the table indexed the LEAD record here and the TABLE record there. A
        `:H h-NNN.authz` between the two landed on a record no consumer reads,
        and `disposition: benign` passed on an unfulfilled contract. `prologue`
        realigns the precedence; the warning covers what precedence cannot,
        since a sub-block already attached to the loser cannot be moved.
        """
        for h in hyps:
            hid = h.get("id")
            if not isinstance(hid, str):
                continue
            if prologue:
                if hid in self.prologue_hypothesis_ids:
                    continue
                if hid in self.hypotheses_by_id:
                    self._warn(block, -1, "", _two_site_reason(hid))
                self.prologue_hypothesis_ids.add(hid)
                self.hypotheses_by_id[hid] = h
                continue
            if hid in self.prologue_hypothesis_ids:
                self._warn(block, -1, "", _two_site_reason(hid))
            elif hid not in self.hypotheses_by_id:
                self.hypotheses_by_id[hid] = h

    def _project_hyp_subblock(self, block: Block, hyp_id: str, sub: str) -> None:
        hyp = self.hypotheses_by_id.get(hyp_id)
        if hyp is None:
            self._warn(
                block, -1, "",
                f"sub-block references unknown hypothesis {hyp_id!r}",
            )
            return
        if sub == "parent_attrs":
            attrs: dict[str, str] = {}
            for _idx, _row, rec in self._for_each_row(block, ["key", "value"]):
                key = rec.get("key")
                if not key:
                    self._warn(block, _idx, _row, "parent_attrs row missing key")
                    continue
                attrs[key] = _unquote(rec.get("value", ""))
            if attrs:
                hyp.setdefault("proposed_edge", {}).setdefault(
                    "parent_vertex", {}
                ).setdefault("attributes", {}).update(attrs)
            return
        self._attach_hyp_sub_rows(block, hyp, sub)

    def _attach_hyp_sub_rows(
        self, block: Block, hyp: HypothesisRecord, sub: str
    ) -> None:
        """Project a `:H h-NNN.<sub>` block onto the field it declares.

        The destination is named at each branch rather than looked up in a
        `{sub: field_name}` table: a TypedDict write needs a LITERAL key, so the
        table form can only type-check by widening the record back to
        `dict[str, Any]` — which is how a hypothesis record stopped being a
        `HypothesisRecord` to everything downstream of the projector. Same reason
        `_walkers._iter_outcome_rows` takes a selector instead of a field name.

        Each branch EXTENDS, for the same reason `:H hypothesize.hypotheses`
        does (#816): append-only forbids rewriting a committed sub-block, so a
        loop that adds a prediction — or, worse, an authz contract the benign
        gate has to find — writes a SECOND `:H h-NNN.<sub>`, and assignment
        dropped everything the first one declared with no parse warning.
        """
        if sub == "preds":
            if preds := self._project_rows(block, _hyp_sub_pred_row):
                _extend_by_id(hyp.setdefault("predictions", []), preds)
            return
        if sub == "attr_preds":
            if attr_preds := self._project_rows(block, _hyp_sub_attr_pred_row):
                _extend_by_id(hyp.setdefault("attribute_predictions", []), attr_preds)
            return
        if sub == "refuts":
            if refuts := self._project_rows(block, _hyp_sub_refut_row):
                _extend_by_id(hyp.setdefault("refutation_shape", []), refuts)
            return
        if sub == "authz":
            if authz := self._project_rows(block, _hyp_sub_authz_row):
                _extend_by_id(hyp.setdefault("authorization_contract", []), authz)
            return

    def _project_lead_subblock(
        self, tag: str, sub: str, block: Block, lead: dict[str, Any]
    ) -> None:
        # Extend, never assign — a lead whose results arrive as two `:V
        # l-NNN.observations.vertices` blocks kept only the last one, and
        # append-only leaves no way to write them as one (#816).
        if tag == "V" and sub == "observations.vertices":
            _extend_by_id(
                lead.setdefault("outcome", {}).setdefault(
                    "observations", {}
                ).setdefault("vertices", []),
                self._project_rows(block, _vertex_record),
            )
            return
        if tag == "E" and sub == "observations.edges":
            _extend_by_id(
                lead.setdefault("outcome", {}).setdefault(
                    "observations", {}
                ).setdefault("edges", []),
                self._project_rows(block, _edge_record),
            )
            return
        if tag == "H" and sub == "new_hypotheses":
            if self._stale_hyp_header(block):
                return
            hyps = self._project_rows(block, _hypothesis_record)
            _extend_by_id(lead.setdefault("new_hypotheses", []), hyps)
            # A hypothesis born inside a lead declares its predictions the way a
            # prologue one does — in a `:H h-NNN.preds` sub-block. Unregistered,
            # that sub-block was rejected as "unknown hypothesis", so a mid-run
            # hypothesis could never carry a prediction for a resolution to cite.
            self._register_hypotheses(block, hyps, prologue=False)
            return
        if tag == "H":
            # `new_hypotheses` is the ONLY `:H` sub-block a lead carries, and it
            # is now a documented authoring surface — so the singular typo is
            # reachable. Silently dropping it left the fork vanished with zero
            # warnings, and `_check_prediction_refs` then blamed the (correct)
            # resolution row for moving an undeclared hypothesis. The other tags
            # stay silent: `:L l-NNN.lead_preds` and friends are documented but
            # unprojected, and warning on them needs the allowlist (#820).
            self._warn(
                block, -1, "",
                f"unknown lead sub-block `:H l-NNN.{sub}` — the only `:H` block "
                f"a lead carries is `:H l-NNN.new_hypotheses`; its rows were "
                f"dropped",
                # Same reason as the stale-header rejection: the rows are readable and
                # their first cell is the id, so `deferred_hypothesis_ids` can defer for
                # exactly these instead of letting one typo here raise one undeclared-`h-*`
                # error at every site that then references them.
                dropped_ids=tuple(_row_first_cell(r) for r in block.rows),
            )

    def _project_findings_block(self, block: Block) -> None:
        for idx, row, rec in self._for_each_row(block):
            if not rec.get("id") or not rec.get("name"):
                self._warn(block, idx, row, "findings row missing id/name")
                continue
            identity, outcome, query_details = _lead_header_record(rec)
            lead = self.lead_bucket(identity["id"])
            lead.update(identity)
            if outcome:
                lead.setdefault("outcome", {}).update(outcome)
            if query_details:
                lead.setdefault("query_details", {}).update(query_details)

    def _project_resolution_block(self, block: Block) -> None:
        name = block.name
        bucket_key = _RESOLUTION_BUCKET_KEY[name]
        for idx, row, rec in self._for_each_row(block):
            lead_id = rec.get("resolved_by") or rec.get("lead")
            if not lead_id:
                self._warn(block, idx, row, "row has no lead attribution")
                continue
            lead = self.lead_bucket(lead_id)
            if name == "attr_updates":
                self._apply_attr_update(lead, rec, block, idx, row)
            else:
                lead.setdefault("outcome", {}).setdefault(bucket_key, []).append(
                    _canonicalize_resolution_row(rec)
                )

    def _apply_attr_update(
        self, lead: dict[str, Any], rec: dict[str, str], block: Block,
        idx: int, row: str,
    ) -> None:
        tgt = rec.get("target")
        key = rec.get("key")
        val = rec.get("value", "")
        if not tgt or not key:
            self._warn(block, idx, row, "attr_updates missing target/key")
            return
        au = lead.setdefault("outcome", {}).setdefault("attribute_updates", [])
        for entry in au:
            if entry.get("target") == tgt and isinstance(entry.get("updates"), dict):
                entry["updates"][key] = val
                return
        # Literally constructed so the type gate actually checks both keys —
        # this is the only writer, and `AttributeUpdate` is total on the strength
        # of it.
        entry_new: AttributeUpdate = {"target": tgt, "updates": {key: val}}
        au.append(entry_new)

    def _project_resolutions_block(self, block: Block) -> None:
        for idx, row in enumerate(block.rows):
            try:
                lead_id, record = _resolution_record(row)
            except RowError as e:
                self._warn(block, idx, row, str(e))
                continue
            if not lead_id:
                self._warn(block, idx, row, "resolution has no lead attribution")
                continue
            self.lead_bucket(lead_id).setdefault("resolutions", []).append(record)

    def _project_surviving_block(self, block: Block) -> None:
        """`:T conclude.surviving [hyp_id|final_weight]` — the run's own list of what it
        thinks is still standing.

        Projected, where every other `conclude.*` sub-block is still discarded, for one
        reason: it is the FOURTH site that names an `h-*`, and the only one of the four the
        parser threw away. A conclude naming a hypothesis nothing declares passed the
        parser and the validator in silence, while the rule against exactly that was
        written three sites over (#821).

        Deliberately NOT wired into benign-gating. Survival there is computed from the
        resolution record precisely because this table is omittable and self-reported
        (enforcement ramp rule 5); projecting it makes the claim checkable, and must not
        make it authoritative.
        """
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        rows: list[dict[str, str]] = conclude.setdefault("surviving_hypotheses", [])
        for _idx, _row, rec in self._for_each_row(block, _SURVIVING_COLS):
            hid = rec.get("hyp_id")
            # `none` / `n/a` is how an EMPTY array is written here, not a hypothesis id
            # (`docs/dense-investigation-format.md`: "Empty arrays render as a single `none`
            # row", `surviving_hypotheses` named among them). Projecting the marker made the
            # undeclared-`h-*` rule refuse a run whose hypotheses were all refuted.
            if not hid or is_conclude_empty_marker(hid):
                continue
            # Keyed `hypothesis`, the name `:T resolutions` records already use for the
            # same reference — a reader that knows one shape reads the other.
            entry = {"hypothesis": hid}
            if rec.get("final_weight"):
                entry["final_weight"] = rec["final_weight"]
            rows.append(entry)

    def _project_shelved_block(self, block: Block) -> None:
        for idx, row, rec in self._for_each_row(block):
            hyp = rec.get("hyp_id")
            if not hyp:
                continue
            lid = rec.get("by_lead")
            if not lid:
                self._warn(block, idx, row, "shelved row has no lead attribution")
                continue
            lead = self.lead_bucket(lid)
            lead.setdefault("shelved", []).append(hyp)
            if rec.get("rationale"):
                lead.setdefault("shelved_rationales", {})[hyp] = _unquote(rec["rationale"])


def companion_from_blocks(
    blocks: list[Block],
) -> tuple[CompanionBody, list[ParseWarning]]:
    proj = _Projector()
    for block in blocks:
        proj.project_block(block)
    if proj.findings:
        proj.out["findings"] = list(proj.findings.values())
    return cast(CompanionBody, proj.out), proj.warnings


def parse_dense_companion(
    text: str,
) -> tuple[CompanionBody, list[ParseWarning]]:
    blocks: list[Block] = []
    for match in INVLANG_FENCE_RE.finditer(text):
        blocks.extend(_tokenize_fence(match.group(1)))
    if not blocks:
        return cast(CompanionBody, {}), []
    return companion_from_blocks(blocks)
