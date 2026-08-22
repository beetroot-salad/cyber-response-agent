
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
    is_conclude_empty_marker,  # noqa: F401 — re-export: parser is this name's public home
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

INVLANG_FENCE_RE = re.compile(r"```invlang\n(.*?)\n```", re.DOTALL)
HEADER_RE = re.compile(
    r"^:(?P<tag>[A-Z])\s+(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\s*\[(?P<cols>[^\]]*)\])?\s*$"
)
_STORY_HEADER_RE = re.compile(r"^###\s+story\s+(h-[\w\-]+)\s*$")
#: A line the author MEANT as a block header — the `:<TAG>` opening of `HEADER_RE`, whether or
#: not the rest of the line is one `HEADER_RE` accepts. The FIRST TOKEN of the same grammar,
#: which is what makes "the author was opening a block here" decidable on a line the header
#: rule rejects. Two arms of `_tokenize_fence` read it, both to bound a silent drop: prose in a
#: `### story h-NNN` section is discarded without a warning, and a run of orphan lines would
#: otherwise be bounded only by the next ACCEPTED header.
_HEADER_ATTEMPT_RE = re.compile(r"^:[A-Z]")
_LEAD_PREFIX_RE = re.compile(r"^l-(?P<id>[A-Za-z0-9]+)\.(?P<sub>.+)$")


@dataclass
class ParseWarning:
    block: str
    row_index: int
    row: str
    reason: str
    file_path: str = ""
    #: The ids this warning DELETED from the companion, when it deleted any and the rows
    #: were still readable enough to name them — so a consumer need not re-parse the prose.
    #: Populated by whole-block rejections; a row-level failure already carries its row,
    #: and the id is that row's first cell.
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




#: `ParseWarning.block` for a line the tokenizer could file under no block at all — the absence
#: of a `Block` IS the defect. Deliberately not header-shaped: `deferred_hypothesis_ids`
#: matches declaration blocks by name, and a warning that dropped no declaration must not be
#: mistaken for one that did.
NO_OPEN_BLOCK = "(no open block)"


def _orphan_warning(lines: list[str]) -> ParseWarning:
    """The lines a rejected header takes down with it, as ONE warning naming the header.

    `HEADER_RE` anchors `\\s*$` immediately after the optional `[cols]`, so ANYTHING trailing a
    header makes the match fail — a `# loop 2 wrap-up` comment, a `(loop 3)` note, a dropped
    `]`, a missing space after the tag. The line then reads as a row, and with no block open it
    would be discarded together with every row beneath it in silence, against this module's
    rule that every drop earns a `ParseWarning`. (A fence headed `:T conclude   # loop 2` then
    parses to an EMPTY companion with `warnings == []`, so the benign write gate never runs.)

    Reached whenever no block is OPEN: the first header of a fence (the ordinary authoring
    path — `append_block` carries one block per fence), a header under a `### story h-NNN`
    section, and every rejected header after the first. With a block still open the same line
    lands as a ROW and draws a cell-count error instead.

    ONE warning per RUN of orphan lines: repairing the rejected header repairs the rows under
    it, so a seven-row `:T conclude` would otherwise cost eight errors for one trailing
    comment. The count of what followed is carried in the message, so nothing vanishes unnamed.

    A run ends at the next header ATTEMPT, not only at the next ACCEPTED header — otherwise two
    rejected headers fold into one warning naming only the first, and repairing that one does
    not repair the second (it opens a block, and the second lands in it as a bad ROW).
    """
    head, rest = lines[0], lines[1:]
    tail = (
        f", and with it the {len(rest)} line(s) under it, which had no block to land in"
        if rest
        else ""
    )
    return ParseWarning(
        block=NO_OPEN_BLOCK,
        row_index=-1,
        row=head,
        reason=(
            f"this line is not a block header and no block is open, so it was dropped{tail}. "
            f"A header is `:<TAG> <name>` with an optional `[col|col]` and NOTHING after it — "
            f"no trailing comment, note or stray bracket. Re-send the block with its header on "
            f"a line of its own."
        ),
    )


def _header_block(m: re.Match[str]) -> Block:
    """The empty `Block` a matched header opens — its declared columns, and how many of them a
    row has to carry. This is where a trailing `?` stops being a character and becomes
    `required_cells`."""
    cols_raw = m.group("cols")
    declared = (
        [c.strip() for c in cols_raw.split("|")] if cols_raw is not None else None
    )
    return Block(
        tag=m.group("tag"),
        name=m.group("name"),
        columns=[c.rstrip("?") for c in declared] if declared is not None else None,
        required_cells=(
            max(
                (i + 1 for i, c in enumerate(declared) if not c.endswith("?")),
                default=0,
            )
            if declared is not None
            else 0
        ),
    )


def _flush_orphans(orphans: list[str], warnings: list[ParseWarning]) -> None:
    """Discharge the run of orphan lines in hand as ONE warning, and reset the run.

    Module-level rather than a closure so the four call sites can be read for WHERE a run ends:
    a story heading, an accepted header, the next rejected one, end of fence."""
    if orphans:
        warnings.append(_orphan_warning(orphans))
        orphans.clear()


def _tokenize_fence(body: str) -> tuple[list[Block], list[ParseWarning]]:
    blocks: list[Block] = []
    warnings: list[ParseWarning] = []
    cur: Block | None = None
    in_story = False
    # Lines reached with no block open. They LAND here rather than being dropped, and
    # `_flush_orphans` turns each run of them into one warning.
    orphans: list[str] = []

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if _STORY_HEADER_RE.match(stripped):
            _flush_orphans(orphans, warnings)
            in_story = True
            cur = None
            # A state transition, not a row: the line consumed IS the heading, so there is
            # nothing here to land and nothing a warning could name. (The flush above
            # discharges the run that ENDED here; it says nothing about this line.)
            continue  # lint-row-drop: ok — the story heading itself, not a row

        m = HEADER_RE.match(stripped)
        if m:
            _flush_orphans(orphans, warnings)
            in_story = False
            cur = _header_block(m)
            blocks.append(cur)
            continue

        if in_story and not _HEADER_ATTEMPT_RE.match(stripped):
            # A `### story h-NNN` section is narrative by construction, so there is no row
            # here to land and nothing a warning could name.
            continue  # lint-row-drop: ok — prose inside a story section, not a row

        if in_story or cur is None:
            if _HEADER_ATTEMPT_RE.match(stripped):
                # A header the header RULE rejected does two things. It ENDS any story section
                # above it — otherwise `### story h-001` over a `:T conclude  # loop 2`
                # swallows the header and every row beneath it in silence. And it opens its OWN
                # orphan run, because repairing the PREVIOUS run's header does not repair this
                # one; see `_orphan_warning`.
                _flush_orphans(orphans, warnings)
                in_story = False
            orphans.append(stripped)
            continue
        cur.rows.append(stripped)
    _flush_orphans(orphans, warnings)
    return blocks, warnings




_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]
_SURVIVING_COLS = ["hyp_id", "final_weight"]


def iter_blocks(text: str) -> Iterator[Block]:
    """Every invlang `Block` in `text`, in document order, with its DECLARED header and its
    rows as the author wrote them.

    The projection `parse_dense_companion` builds is lossy on purpose — it folds rows into
    records and drops the header. A check that has to quote a row back, or substitute one cell
    of it, needs this layer underneath: rebuilding a row from the folded record means assuming
    a column order the grammar does not enforce.

    Kept out of the companion deliberately: carrying per-row provenance on the records inflated
    the parsed body by up to 25%, and that body is projected into the review lens prompts."""
    for fence in INVLANG_FENCE_RE.finditer(text):
        # Blocks only. A caller at this layer is quoting a ROW back under its block, and a
        # line that reached no block has no block to quote it under; `parse_dense_companion`
        # is where the tokenizer's warnings are collected and refused on.
        yield from _tokenize_fence(fence.group(1))[0]


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
        usable = [i for i in named if HYPOTHESIS_ID_RE.fullmatch(i)]
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
            # #17's closed cells, `loop` against the next lead's — so a uniformly quoted row
            # is refused for a `mode` it spells correctly, or (worse, failing open) has its
            # quoted `"1"` survive `int()` as a string that equals no other lead's loop.
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
    head_ids = [t for t in head_refs if _REF_ID_RE.fullmatch(t)]
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


@dataclass
class _Projector:

    out: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    hypotheses_by_id: dict[str, HypothesisRecord] = field(default_factory=dict)
    #: Ids the `:H hypothesize.hypotheses` table declares. The table outranks a lead's
    #: `new_hypotheses` in `hypotheses_by_id` regardless of document order, because that is
    #: the precedence `_walkers.all_hypotheses` applies on the read side.
    prologue_hypothesis_ids: set[str] = field(default_factory=set)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)

    # No "current lead" state, deliberately: a fallback to whichever lead a preceding block
    # mentioned last silently files one lead's grounding evidence under another. Every row
    # that lands on a lead names it.

    #: `:T conclude` blocks that recorded nothing, pending the whole-document verdict
    #: `flush_deferred_warnings` reaches. A list rather than a flag: two such blocks are two
    #: defects, and each names its own locus.
    empty_conclude_blocks: list[Block] = field(default_factory=list)

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

    def _marked_rows(self, block: Block, project_one) -> list[Any]:
        """`_project_rows`, minus the empty-TABLE marker.

        A lone `none` / `n/a` row says the table is empty; `_row_cells` pads it to the block
        width so it reaches `project_one` as a real record with `id == "none"`. The two `:L`
        plan blocks are the callers. `_project_surviving_block` and `_project_deferral_block`
        drop the same marker INLINE rather than through here, because they warn per row and so
        need the `idx`/`row` this generator has already spent — the shared piece between all
        four is `is_conclude_empty_marker`, which is where the rule lives.
        """
        return [
            rec for rec in self._project_rows(block, project_one)
            # lint-row-drop: ok — the empty-TABLE marker, not a row
            if not is_conclude_empty_marker(rec.get("id"))
        ]

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
        landing on whatever key the continuation's first word happens to name. The guard is
        here rather than inside one block's projector because the truncation is a property of
        the line-oriented surface, not of `:T conclude`: a two-line `:L findings` name loses
        the lead's target, loop and system just as quietly.
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

        # Extend, never assign — same reason as `:H`. Append-only forbids rewriting a
        # committed block, so a second `:V prologue.vertices` is the only legal way to add
        # one, and assignment would delete every vertex the first block declared.
        if tag == "V" and name == "prologue.vertices":
            vertices = self._project_rows(block, _vertex_record)
            self._warn_repeated_ids(block, vertices)
            _extend_by_id(
                self.out.setdefault("prologue", {}).setdefault("vertices", []),
                vertices,
            )
            return
        if tag == "E" and name == "prologue.edges":
            edges = self._project_rows(block, _edge_record)
            self._warn_repeated_ids(block, edges)
            _extend_by_id(
                self.out.setdefault("prologue", {}).setdefault("edges", []),
                edges,
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

    def _land_conclude_row(
        self,
        key: str,
        value: Any,
        conclude: dict[str, Any],
        termination: dict[str, Any],
        seen: set[str],
    ) -> bool:
        """Put ONE recognized `:T conclude` row where it goes. True when something landed.

        Split out of `_project_conclude_scalars` so the caller stays under the complexity gate;
        it is also where "recognized" and "recorded something" come apart. `seen` marks a key
        the projection KNOWS (the duplicate-row warning's question), and the return value marks
        a key that recorded a VALUE — a lone `ceiling_test  none` is the first and not the
        second, which is why `_warn_conclude_recorded_nothing` cannot read `seen`.

        An unrecognized key falls through to `False` and is not warned; the caller records why.
        """
        if key == "termination.category":
            seen.add(key)
            termination["category"] = value
            return True
        if key == "termination.rationale":
            seen.add(key)
            termination["rationale"] = value
            return True
        if key in _CONCLUDE_LISTS:
            seen.add(key)
            # `value is None` is the caller's mapping of the literal `null`, which the format
            # spells beside `none` for the same "nothing to say" — `is_conclude_empty_marker`
            # cannot see it, because by here the string is already gone. Without this arm
            # `ceiling_test  null` appends `None` into a declared `list[str]` AND makes
            # `conclude` truthy, so `validate._is_closing` reads a mid-run block as a close
            # and the three closure gates refuse every commitment the run has not reached.
            if value is None or is_conclude_empty_marker(value):
                return False  # lint-row-drop: ok — the empty-ARRAY marker, not a row
            cast(list[str], conclude.setdefault(key, [])).append(value)
            return True
        if key in _CONCLUDE_SCALARS:
            seen.add(key)
            conclude[key] = value
            return True
        return False

    def _project_conclude_scalars(self, block: Block) -> None:
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        termination: dict[str, Any] = {}
        seen: set[str] = set()
        #: Did any row of THIS block reach the projection? Not `seen` — a lone
        #: `ceiling_test  none` is a recognized key that lands nothing — and not `conclude`
        #: emptiness either, since a `:T conclude.surviving` block earlier in the document
        #: already opened that dict.
        landed = False
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
                # names, so this fires on the row that silently overwrote a real conclusion.
                # A list key is exempt: repetition is how it carries more than one item.
                self._warn(
                    block, index, row,
                    f"conclude: {key!r} is set twice in this block; the later row wins and "
                    f"the earlier value is lost. Keep one row per key, and join a value that "
                    f"spilled onto a second line back into one line.",
                )
            elif (
                key in _CROSS_BLOCK_GUARDED
                and _conclude_value(conclude, key) is not _MISSING
                and _conclude_value(conclude, key) != value
            ):
                # The SAME loss one block over. `seen` is per-block while `conclude` is
                # document-wide, so a close that arrives as two `:T conclude` blocks — the
                # shape `_warn_conclude_recorded_nothing` is written around — could restate
                # `disposition` and silently replace it, with every downstream gate
                # (`_check_disposition_gating`, `_check_benign_authz`, `spoken_for`) then
                # running against a keyword the run only half wrote. Narrowed to a CHANGED
                # value: re-stating a key with the same value loses nothing, and append-only
                # means a document already carrying that shape must stay writable.
                self._warn(
                    block, index, row,
                    f"conclude: {key!r} is already set to "
                    f"{_conclude_value(conclude, key)!r} by an earlier "
                    f"`:T conclude` block, and this row replaces it — append-only means the "
                    f"first value cannot be withdrawn, so the two rows are a disagreement "
                    f"rather than a correction. Drop this row, or restate the value the "
                    f"close is actually making everywhere it appears.",
                )
            landed |= self._land_conclude_row(key, value, conclude, termination, seen)
            # An unrecognized key is IGNORED, not warned. It reads like the obvious place to
            # catch an unquoted value that spilled onto a second line, and it cannot be: the
            # lessons corpus can instruct conclude rows this projection does not carry, and
            # `learning/core/persist.py` dead-letters a run whose investigation.md fails
            # validation rather than learning from it — so a warning here turns "the model
            # obeyed a lesson" into a discarded run. The truncation is caught upstream by
            # `_check_one_line_rows` on quote parity, which fires on both halves of a spilled
            # quoted value without needing to know which keys are real. An unquoted spill
            # stays undetected; that is the price of not denying instructed content.
        if termination:
            # MERGED, never assigned. `termination` is a per-BLOCK local while `conclude` is
            # document-wide, so an assignment lets a second `:T conclude` block that restates
            # one of the two rows delete the other — `termination.rationale` alone wipes the
            # `category` `_check_ceiling_test_scope` (#13) reads, and the rule then stands down
            # on a document that named its ceiling. The guard above now warns when a row
            # CHANGES a value; this is what stops a row it does not name from erasing one.
            cast(dict[str, Any], conclude.setdefault("termination", {})).update(termination)
        if not landed:
            # Not `block.rows and not landed`: a `:T conclude` block written with no rows under
            # it — a truncated or interrupted REPORT write — is the plainest case of a close
            # that records nothing, and gating on `block.rows` was the one shape that reached
            # `_is_closing` with `conclude == {}` and no diagnostic anywhere.
            #
            # DEFERRED to `flush_deferred_warnings`, never decided here. See that method.
            self.empty_conclude_blocks.append(block)

    def flush_deferred_warnings(self) -> None:
        """The warnings that can only be decided once EVERY block has been projected.

        `companion_from_blocks` calls this after its loop. A judgement made mid-loop is scoped
        to the blocks projected SO FAR, which for an append-only document means it is scoped to
        a PREFIX — and a prefix-scoped verdict is order-dependent in a format where a close may
        legally arrive as two `:T conclude` blocks in either order.
        """
        for block in self.empty_conclude_blocks:
            self._warn_conclude_recorded_nothing(block)
        self.empty_conclude_blocks.clear()

    def _warn_conclude_recorded_nothing(self, block: Block) -> None:
        """A `:T conclude` block not one of whose rows reached the projection.

        NOT the "unrecognized key" warning `_project_conclude_scalars` deliberately refuses —
        this fires only when the WHOLE block recognized nothing, which is a close that records
        nothing rather than a lesson-instructed row the projection has yet to carry. It has to
        be loud, because the three closure gates read "is this document closing" off a
        non-empty `conclude` (`validate._is_closing`), and a block that projects to `{}` would
        otherwise stand all of them down in silence — a close with every commitment abandoned
        and no diagnostic anywhere.

        Asked of the WHOLE DOCUMENT, which is why the caller defers it to
        `flush_deferred_warnings` instead of deciding inline. Append-only means a close can
        arrive as two `:T conclude` blocks, and one of them may legally carry nothing but keys
        this projection does not name — the lesson-instructed rows `_project_conclude_scalars`
        refuses to warn on, because "`learning/core/persist.py` dead-letters a run whose
        investigation.md fails validation rather than learning from it". A verdict reached
        inline sees only the blocks projected BEFORE this one, so it protects that pair in one
        order and refuses it in the other — and on a document already carrying such a block,
        every later append re-derives the refusal against a block nobody may edit.

        The sub-table fields do not count: neither `:T conclude.surviving` nor a `deferred_*`
        table is a flat close.
        """
        if set(self.out.get("conclude") or {}) - _CONCLUDE_SUBTABLE_FIELDS:
            return
        self._warn(
            block, -1, "",
            f"`:T conclude` recorded nothing — not one row keyed on a field this projection "
            f"carries, so the close projects empty and the CONCLUDE rules (#13, #24, #26, "
            f"#31, #34) all stand down. Key at least `disposition`; the fields are "
            f"{_CONCLUDE_KEYS_HINT}.",
        )

    def _project_t_block(self, block: Block) -> bool:
        name = block.name
        if name == "conclude":
            self._project_conclude_scalars(block)
            return True
        if name == "conclude.surviving":
            self._project_surviving_block(block)
            return True
        deferral = _DEFERRAL_BLOCKS.get(name)
        if deferral is not None:
            self._project_deferral_block(block, *deferral)
            return True
        if name.startswith("conclude."):
            self._warn_unknown_conclude_subblock(block)
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
            self._warn_retired_shelved(block)
            return True
        return False

    def _warn_retired_shelved(self, block: Block) -> None:
        """`:T shelved` is retired, and says so by name rather than as "unknown block".

        The generic fallthrough is an error pointing away from its cause — the same defect
        `_warn_unknown_conclude_subblock` exists to prevent one tag over. A run that writes the
        row is not guessing at a block tag; it is using a spelling every version of the format
        docs taught, so the refusal owes it the replacement rather than a shrug.

        Retired because no investigation on record ever wrote one, while it stayed a discharge
        arm on rules #23, #24 and #34 and two fields on the shipped document — a retirement
        route the validator honoured and the injected SKILL.md never taught, so the only runs
        that could reach it were the ones that guessed the grammar right.
        """
        self._warn(
            block, -1, "",
            "`:T shelved` is retired — a hypothesis leaves the live frontier by being "
            "RESOLVED: move its final weight to `--` in a `:T resolutions` row when the run "
            "refuted it, or NAME it in `:T conclude.surviving` when the run is still carrying "
            "it. Omitting it from a written `:T conclude.surviving` table is not a "
            "retirement — rule #24 refuses exactly that. Neither this block nor its rows are "
            "projected, so nothing here reaches the close.",
        )

    def _stale_hyp_header(self, block: Block) -> bool:
        """True (and warned) when a `:H` DECLARATION block's header is off-schema.

        One owner for both declaration sites: a lead-born record is indexed for sub-block
        attachment, so a hypothesis projected off a stale header would reach every consumer of
        `_walkers.all_hypotheses`.
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
        self._warn_repeated_ids(block, hyps)
        # Extend, never assign. Append-only forbids rewriting the loop-1 block, so a loop that
        # forks a hypothesis writes a SECOND `:H hypothesize.hypotheses`; assignment would
        # delete every earlier loop's hypothesis with no parse warning, and with them the
        # `:H h-NNN.preds` a later resolution resolves against and the `:H h-NNN.authz`
        # contracts benign-gating has to find.
        _extend_by_id(
            self.out.setdefault("hypothesize", {}).setdefault("hypotheses", []), hyps
        )
        self._register_hypotheses(block, hyps, prologue=True)

    def _register_hypotheses(
        self, block: Block, hyps: list[HypothesisRecord], *, prologue: bool
    ) -> None:
        """Index the records a `:H h-NNN.<sub>` sub-block attaches to.

        Re-declaring an id at the SAME site is a re-emission: the first declaration stands,
        silently, matching `_extend_by_id` and `_walkers.all_hypotheses`. Re-declaring it at
        the OTHER site is not recoverable and is warned.

        The two sites disagree on order — `_walkers.all_hypotheses` walks the
        `:H hypothesize.hypotheses` table before any lead's `new_hypotheses`, not the
        document — so an id declared in a lead and then promoted into the table would index the
        LEAD record here and the TABLE record there, landing a `:H h-NNN.authz` between the two
        on a record no consumer reads (and passing `disposition: benign` on an unfulfilled
        contract). `prologue` realigns the precedence; the warning covers what precedence
        cannot, since a sub-block already attached to the loser cannot be moved.
        """
        for h in hyps:
            hid = h.get("id")
            if not isinstance(hid, str):
                # NOT a dropped row, which is why this warns nothing: `_hypothesis_record`
                # `_require`s `id`, so a `:H` row with an empty id cell raises `RowError` and
                # is warned by `_project_rows` before any record exists. Nothing reaching here
                # can fail this test; it narrows the type, and a warning would double-report a
                # defect already named.
                continue  # lint-row-drop: ok — no row here; a bad id was refused upstream
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

        The destination is named at each branch rather than looked up in a `{sub: field_name}`
        table: a TypedDict write needs a LITERAL key, so the table form can only type-check by
        widening the record back to `dict[str, Any]`, which loses `HypothesisRecord` for
        everything downstream of the projector. Same reason `_walkers._iter_outcome_rows` takes
        a selector instead of a field name.

        Each branch EXTENDS, for the same reason `:H hypothesize.hypotheses` does: append-only
        forbids rewriting a committed sub-block, so a loop that adds a prediction — or an authz
        contract the benign gate has to find — writes a SECOND `:H h-NNN.<sub>`, and assignment
        would drop everything the first one declared with no parse warning.
        """
        if sub == "preds":
            if preds := self._project_rows(block, _hyp_sub_pred_row):
                self._warn_repeated_ids(block, preds)
                _extend_by_id(hyp.setdefault("predictions", []), preds)
            return
        if sub == "attr_preds":
            if attr_preds := self._project_rows(block, _hyp_sub_attr_pred_row):
                self._warn_repeated_ids(block, attr_preds)
                _extend_by_id(hyp.setdefault("attribute_predictions", []), attr_preds)
            return
        if sub == "refuts":
            if refuts := self._project_rows(block, _hyp_sub_refut_row):
                self._warn_repeated_ids(block, refuts)
                _extend_by_id(hyp.setdefault("refutation_shape", []), refuts)
            return
        if sub == "authz":
            if authz := self._project_rows(block, _hyp_sub_authz_row):
                self._warn_repeated_ids(block, authz)
                _extend_by_id(hyp.setdefault("authorization_contract", []), authz)
            return

    def _warn_repeated_ids(self, block: Block, rows: list[Any]) -> None:
        """An id written twice in ONE sub-block DELETES the second row, so say so.

        `_extend_by_id` keeps the first record per id — correct against the re-emission it
        exists for, which is a whole block sent again as a SECOND block — but WITHIN one block
        a repeated id is never a re-emission, and the row it drops carries content nothing else
        does. A second `ac1` with a different predicate simply vanishes, and
        `_check_benign_authz` then discharges the surviving contract and closes benign over a
        legitimacy question no lead ever asked. Same shape for a second `p1`/`r1`: the
        prediction is gone while `:T resolutions` goes on citing the id.

        The four GRAPH-row sites are here for the same reason, and the benign open-slot gate
        reads them: a second `:V prologue.vertices` row repeating `v-001` by an ordinal typo
        deletes the row carrying `integrity=??`, and the document then closes benign over an
        open slot still on the page. Append-only makes that unrecoverable — the committed row
        cannot be rewritten, and a second block with the corrected id declares a DIFFERENT
        vertex — so the drop has to be loud at write time.

        The two `:H` DECLARATION sites carry the sharpest case: a repeated `h-001` in one
        `:H hypothesize.hypotheses` block deletes a whole hypothesis, and every
        `:H h-001.authz` contract then attaches to the SURVIVING row, so the benign gate
        discharges a contract the deleted hypothesis never got to state. `_register_hypotheses`
        cannot see it — it is written against the cross-BLOCK re-emission, where the first
        declaration standing silently is the sanctioned append-only shape.

        Only the rows of the block in hand are compared, which keeps that legal cross-block
        repeat silent.
        """
        seen: set[str] = set()
        for r in rows:
            rid = r.get("id") if isinstance(r, dict) else None
            if not isinstance(rid, str) or not rid:
                # A row with no readable id cannot be checked for a repeated one, and the
                # caller still projects it — so nothing is dropped here.
                continue  # lint-row-drop: ok — no id to compare; the caller still lands it
            if rid in seen:
                self._warn(
                    block, -1, "",
                    f"{rid!r} is declared twice in this block; only the FIRST row is kept "
                    f"and the later one is discarded with everything it declares. Give each "
                    f"row its own id, or send the added rows as a second block.",
                )
            seen.add(rid)

    def _off_schema_plan_header(self, block: Block, cols: list[str]) -> bool:
        """True (and warned) when a `:L` plan block's header names a column this projection
        does not read.

        The guard `_project_deferral_block` already carries, for the same defect one block over.
        `_row_dict` keys on the AUTHOR's header, so a column spelled anything else lands its
        cell EMPTY — and rules #18 / #29 then refuse the row for a cell the author filled in,
        naming the very column the header declares. The canonical field names are the reachable
        typo, because they are what `schema.py` and every refusal message use: a header written
        `[id|dimension|claim|…]` or `[id|condition|read_as|advance_to]` blanks the cell whose
        name it spells.

        A SUBSET header is left alone — rules #18 and #29 name each missing cell and what it is
        for, which is the better message. Only a column nothing reads is a block-level defect.
        """
        unread = [c for c in block.columns or () if c not in cols]
        if not unread:
            return False
        self._warn(
            block, -1, "",
            f"column header {block.columns!r} names {', '.join(repr(c) for c in unread)}, "
            f"which `:L l-NNN.{block.name.split('.', 1)[-1]}` does not read — the columns are "
            f"[{'|'.join(cols)}], so a cell under any other name is dropped and the row is then "
            f"refused for a value you wrote; whole block rejected",
        )
        return True

    def _project_lead_plan_subblock(
        self, sub: str, block: Block, lead: dict[str, Any]
    ) -> bool:
        """The `:L l-NNN.<sub>` blocks — a lead's PLAN, as opposed to its results. True when
        this arm owns the name, so the caller can warn on the ones nothing owns.

        `lead_preds` and `impact_preds` were documented and unprojected until #933 (tracked as
        #820): the parser recognized them, consumed them and dropped every row, so rules #18,
        #29, #30 and #31 had nothing to read and the plan they record reached no consumer.
        Projecting them is what makes those rules possible at all — and it is also what gives
        `:L` an allowlist, which is what lets the caller warn on a misspelled sub-block instead
        of staying silent for want of one.

        Both EXTEND, for the reason every sibling does: append-only forbids rewriting a
        committed block, so a loop that adds a route or a predicate writes a SECOND block and
        assignment would delete the first one's rows with no warning.

        Both drop the empty-TABLE marker, the way `_project_surviving_block` and
        `_project_deferral_block` do. `_row_cells` pads a lone `none` to the block width, so
        without the filter it lands as a record whose id IS
        `none` — and rules #18 / #29 then emit four and two refusals respectively, none of
        which says the author wrote the marker (#29 groups its blank cells into ONE message;
        see `_check_impact_prediction_structure`).
        """
        if sub == "lead_preds":
            if self._off_schema_plan_header(block, _LEAD_PRED_COLS):
                return True
            if lead_preds := self._marked_rows(block, _lead_pred_row):
                self._warn_repeated_ids(block, lead_preds)
                _extend_by_id(lead.setdefault("predictions", []), lead_preds)
            return True
        if sub == "impact_preds":
            if self._off_schema_plan_header(block, _IMPACT_PRED_COLS):
                return True
            if impact_preds := self._marked_rows(block, _impact_pred_row):
                self._warn_repeated_ids(block, impact_preds)
                _extend_by_id(lead.setdefault("impact_predictions", []), impact_preds)
            return True
        # `substitutions` is the one `:L` sub-block still documented and unprojected.
        # Allowlisted rather than projected: `query_details.substitutions` has no reader — no
        # rule resolves against it and no prompt renders it — so projecting it would invent a
        # field to hold rows nothing asks for. Allowlisted rather than WARNED because the block
        # is legal (`docs/dense-investigation-format.md` §`:L`), and refusing a legal block is
        # the one outcome worse than dropping it.
        return sub == "substitutions"  # lint-row-drop: ok — no reader; see #820

    def _project_lead_subblock(
        self, tag: str, sub: str, block: Block, lead: dict[str, Any]
    ) -> None:
        # Extend, never assign — a lead whose results arrive as two
        # `:V l-NNN.observations.vertices` blocks would keep only the last one, and
        # append-only leaves no way to write them as one.
        if tag == "V" and sub == "observations.vertices":
            vertices = self._project_rows(block, _vertex_record)
            self._warn_repeated_ids(block, vertices)
            _extend_by_id(
                lead.setdefault("outcome", {}).setdefault(
                    "observations", {}
                ).setdefault("vertices", []),
                vertices,
            )
            return
        if tag == "E" and sub == "observations.edges":
            edges = self._project_rows(block, _edge_record)
            self._warn_repeated_ids(block, edges)
            _extend_by_id(
                lead.setdefault("outcome", {}).setdefault(
                    "observations", {}
                ).setdefault("edges", []),
                edges,
            )
            return
        if tag == "H" and sub == "new_hypotheses":
            if self._stale_hyp_header(block):
                return
            hyps = self._project_rows(block, _hypothesis_record)
            self._warn_repeated_ids(block, hyps)
            _extend_by_id(lead.setdefault("new_hypotheses", []), hyps)
            # A hypothesis born inside a lead declares its predictions the way a prologue one
            # does — in a `:H h-NNN.preds` sub-block. Unregistered, that sub-block is rejected
            # as "unknown hypothesis" and a mid-run hypothesis can carry no prediction for a
            # resolution to cite.
            self._register_hypotheses(block, hyps, prologue=False)
            return
        if tag == "L" and self._project_lead_plan_subblock(sub, block, lead):
            return
        if tag == "H":
            # `new_hypotheses` is the ONLY `:H` sub-block a lead carries, so the singular typo
            # is reachable. Dropping it silently vanishes the fork with zero warnings, and
            # `_check_prediction_refs` then blames the (correct) resolution row for moving an
            # undeclared hypothesis. Its own arm, ahead of the shared one below, because it is
            # the only tag whose dropped rows can name a HYPOTHESIS.
            self._warn(
                block, -1, "",
                f"unknown lead sub-block `:H l-NNN.{sub}` — the only `:H` block "
                f"a lead carries is "
                f"{', '.join(f'`:H l-NNN.{s}`' for s in _LEAD_SUBBLOCKS['H'])}; its rows "
                f"were dropped",
                # Same reason as the stale-header rejection: the rows are readable and their
                # first cell is the id, so `deferred_hypothesis_ids` can defer for exactly
                # these instead of raising one undeclared-`h-*` error at every reference site.
                # Filtered to `h-*` cells, because "these cells are hypothesis ids" holds only
                # for the singular `new_hypothesis` typo this branch was written for. Any
                # OTHER sub-name contributes its own row ids — `:H l-001.preds` contributes
                # `p9` — and `deferred_hypothesis_ids` would then find no id-shaped name,
                # return `None`, and stand the undeclared-hypothesis rule down for the WHOLE
                # DOCUMENT. The typo case is unaffected: its ids ARE `h-*`.
                dropped_ids=tuple(
                    cell
                    for cell in (_row_first_cell(r) for r in block.rows)
                    if HYPOTHESIS_ID_RE.fullmatch(cell)
                ),
            )
            return
        # Every OTHER tag, now that `:L` has an allowlist. Before it, warning here needed one
        # and the comment above said so; `lead_preds` / `impact_preds` were the reason. What
        # this catches is the tag whose typo used to be free: `:V l-001.observations.vertex`
        # drops a lead's whole observed graph in silence, and the resolutions citing those
        # edges then fail `_check_strong_move_provenance` for having no supporting edge — an
        # error naming the resolution rather than the block that deleted its evidence.
        #
        # No `dropped_ids`: only the `:H` arm above can be sure its rows name hypotheses, and
        # a non-`h-*` id reaching `deferred_hypothesis_ids` stands the undeclared-hypothesis
        # rule down for the whole document.
        if tag == "T" and sub == "shelved":
            # `:T l-{id}.shelved` is the OTHER spelling the format docs taught for the block
            # #933 retired, and it reaches here rather than `_project_t_block`. Routed to the
            # retirement message: an author writing it needs the replacement, not a lecture on
            # where a `:T` row names its lead.
            self._warn_retired_shelved(block)
            return
        legal = ", ".join(f"`:{tag} l-NNN.{s}`" for s in _LEAD_SUBBLOCKS.get(tag, ()))
        self._warn(
            block, -1, "",
            f"unknown lead sub-block `:{tag} l-NNN.{sub}` — its rows were dropped. "
            + (
                f"The lead-scoped `:{tag}` blocks are {legal}."
                if legal
                else f"`:{tag}` carries no `l-NNN.`-prefixed block at all; a lead's `:{tag}` "
                     f"rows name their lead in the row itself — a `resolved_by` COLUMN on "
                     f"every `:R` block, the leading `[l-NNN …]` head on a "
                     f"`:T resolutions` row."
            ),
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
        # Literally constructed so the type gate actually checks both keys — this is the only
        # writer, and `AttributeUpdate` is total on the strength of it.
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

        Projected, where every other `conclude.*` sub-block is discarded, for one reason: it is
        the FOURTH site that names an `h-*`, so discarding it lets a conclude naming an
        undeclared hypothesis pass parser and validator in silence.

        Deliberately NOT wired into benign-gating. Survival there is computed from the
        resolution record precisely because this table is omittable and self-reported
        (enforcement ramp rule 5); projecting it makes the claim checkable, and must not make
        it authoritative.
        """
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        rows: list[dict[str, str]] = conclude.setdefault("surviving_hypotheses", [])
        for idx, row, rec in self._for_each_row(block, _SURVIVING_COLS):
            # Unquoted for the reason the `:T shelved` cell is: rule #24 asks whether the table
            # NAMES a hypothesis, by equality, and a quoted row otherwise earns the refusal
            # "the `:T conclude.surviving` table, which names \"h-001\", omits it".
            hid = _unquote(rec.get("hyp_id") or "")
            # `none` / `n/a` is how an EMPTY array is written here, not a hypothesis id
            # (`docs/dense-investigation-format.md`: "Empty arrays render as a single `none`
            # row"). Projecting the marker makes the undeclared-`h-*` rule refuse a run whose
            # hypotheses were all refuted.
            if is_conclude_empty_marker(hid):
                continue  # lint-row-drop: ok — the empty-TABLE marker, not a row
            # An empty `hyp_id` cell is a different case, and a DROP: the row would vanish
            # from `conclude.surviving_hypotheses` with nothing raised, and the close would
            # reason over a shortened survivor set no reader could tell from an honest one.
            if not hid:
                self._warn(
                    block, idx, row,
                    "surviving row has no hypothesis id — the row records WHICH hypothesis "
                    "is still standing, so an empty `hyp_id` cell records nothing. Name the "
                    "`h-*`, or write the whole table as one `none` row if none survived.",
                )
                continue
            # Keyed `hypothesis`, the name `:T resolutions` records already use for the
            # same reference — a reader that knows one shape reads the other.
            entry = {"hypothesis": hid}
            if rec.get("final_weight"):
                entry["final_weight"] = _unquote(rec["final_weight"])
            rows.append(entry)

    def _warn_unknown_conclude_subblock(self, block: Block) -> None:
        """A `:T conclude.<sub>` block name this projection does not carry.

        Loud, where an unrecognized flat `<key> <value>` row in `:T conclude` is deliberately
        silent, and the asymmetry is the point. A flat key can be lesson-instructed content the
        projection has yet to carry, so denying it would dead-letter a run for obeying a lesson
        (see `_project_conclude_scalars`). A sub-block name is GRAMMAR — no lesson names one,
        and the whole grammar is four projected spellings plus the one retired below. Dropping
        a misspelled one in silence has a sharp cost now that the closure rules are armed:
        `:T conclude.deferred_authorizations`
        (the FIELD name, which the spec also uses) drops the whole deferral table, and rule #26
        then refuses the document for an unresolved contract the author DID account for — an
        error pointing away from its cause, which is the failure `deferred_hypothesis_ids`
        exists to prevent one namespace over.

        The write is refused and nothing lands, so the retry costs a re-send and not a run.
        """
        if block.name == _RETIRED_CEILING_TEST_BLOCK:
            # The one spelling let through in silence; see `_RETIRED_CEILING_TEST_BLOCK`.
            return
        legal = ", ".join(sorted({"conclude.surviving", *_DEFERRAL_BLOCKS}))
        self._warn(
            block, -1, "",
            f"unknown conclude sub-block `:T {block.name}` — the sub-tables `:T conclude` "
            f"carries are {legal}; its rows were dropped. Everything else `conclude` records "
            f"is a flat `<key> <value>` row in `:T conclude` itself, keyed by one of "
            f"{_CONCLUDE_KEYS_HINT}.",
        )

    def _project_deferral_block(
        self, block: Block, field: str, ref_col: str
    ) -> None:
        """`:T conclude.deferred_* [<ref>|rationale]` — the commitments this close is NOT
        closing, and why.

        Projected in the same change that arms rules #26, #31 and #34, and not before: each of
        those rules refuses a declared commitment that is neither resolved nor deferred, and
        this table is the ONLY spelling of "deferred". Arming the strict half over an
        unprojected escape hatch refuses documents whose author already wrote the answer.

        Both empty-cell cases are handled the way `:T conclude.surviving` handles them. A lone
        `none` row is the empty-ARRAY marker — the run deferred nothing — and projects as an
        absent table rather than as a deferral of a commitment named "none". An empty ref CELL
        is a drop: the row would vanish and the closure rule would then refuse a commitment the
        author was reaching for.

        A blank RATIONALE is not a drop and is not warned here. The row lands, and the closure
        rule refuses it by name — that check can say what a rationale is for, where a parse
        warning could only say the row was discarded.

        `conclude` and the table are opened LAZILY — on the first row that lands, never on
        entry. Opening them eagerly makes a table whose only row is the empty-ARRAY marker
        project as `conclude = {"deferred_predictions": []}`, and every reader that asks "did
        this run conclude" by presence or truthiness then answers yes for a document that
        recorded nothing: `corpus._load_one` admits the case as complete, `render_synthesis`
        puts `deferred_predictions: []` in front of the judge as the conclusion, and
        `validate._is_closing` needs a bespoke subtraction to say otherwise. `:T
        conclude.surviving` is the deliberate exception one method up — present-and-empty
        there is the CLAIM that nothing survived, and `_check_hypothesis_persistence` reads it
        as one. There is no such claim to make here: "deferred nothing" is what an absent
        table already says.
        """
        # A DECLARED header that names neither cell by the name this projection reads is the
        # one shape whose damage is silent. `_row_dict` keys on the author's header, so
        # `[contract_ref|reason]` lands every row with a blank `rationale` — and the closure
        # rule then refuses the commitment for "an empty rationale" the author DID write,
        # naming the cell rather than the header that discarded it. Refused as a block, the
        # way `_stale_hyp_header` refuses an off-schema `:H` declaration.
        if block.columns and not {ref_col, "rationale"}.issubset(block.columns):
            self._warn(
                block, -1, "",
                f"column header {block.columns!r} does not match `:T {block.name} "
                f"[{ref_col}|rationale]` — this projection reads those two names, so a cell "
                f"under any other one is dropped and the closure rule then refuses the "
                f"commitment for a rationale you wrote; whole block rejected",
            )
            return
        for idx, row, rec in self._for_each_row(block, [ref_col, "rationale"]):
            # `_unquote`d like the rationale beside it. The three closure rules match this
            # cell against `h-001.ac1` / `h-001.p2` / `l-002.ip1` verbatim, so a quoted cell
            # defers nothing while looking exactly like a row that does — and the refusal
            # then tells the author to add a row they already wrote.
            ref = _unquote(rec.get(ref_col, "")).strip() or None
            if is_conclude_empty_marker(ref):
                continue  # lint-row-drop: ok — the empty-TABLE marker, not a row
            if not ref:
                self._warn(
                    block, idx, row,
                    f"deferral row has no `{ref_col}` — the row records WHICH commitment the "
                    f"close is leaving open, so an empty cell defers nothing and the closure "
                    f"rule will still refuse the commitment. Name it, or write the whole "
                    f"table as one `none` row if nothing was deferred.",
                )
                continue
            entry = {ref_col: ref}
            rationale = _unquote(rec.get("rationale", ""))
            if rationale:
                entry["rationale"] = rationale
            conclude: dict[str, Any] = self.out.setdefault("conclude", {})
            rows: list[dict[str, str]] = conclude.setdefault(field, [])
            rows.append(entry)


def companion_from_blocks(
    blocks: list[Block],
) -> tuple[CompanionBody, list[ParseWarning]]:
    proj = _Projector()
    for block in blocks:
        proj.project_block(block)
    proj.flush_deferred_warnings()
    if proj.findings:
        proj.out["findings"] = list(proj.findings.values())
    return cast(CompanionBody, proj.out), proj.warnings


def parse_dense_companion(
    text: str,
) -> tuple[CompanionBody, list[ParseWarning]]:
    blocks: list[Block] = []
    warnings: list[ParseWarning] = []
    for match in INVLANG_FENCE_RE.finditer(text):
        fence_blocks, fence_warnings = _tokenize_fence(match.group(1))
        blocks.extend(fence_blocks)
        warnings.extend(fence_warnings)
    # Return the warnings, not `[]`. A fence whose FIRST header was rejected opens no block at
    # all, and dropping them here would let that document parse to a clean, empty companion.
    if not blocks:
        return cast(CompanionBody, {}), warnings
    companion, projected = companion_from_blocks(blocks)
    return companion, warnings + projected
