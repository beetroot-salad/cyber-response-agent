
from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, cast

from ._cells import (
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


def dropped_a_hypothesis_declaration(warnings: list[ParseWarning]) -> bool:
    """True when a parse warning came off a hypothesis DECLARATION block.

    A rejected header or a bad row there deletes ids the document goes on
    referring to, so every resolution against them looks phantom — the one case
    where the undeclared-hypothesis error would point away from the defect. A
    warning from anywhere ELSE (an unknown block, an unattributed `:R` row, a
    malformed vertex) drops no declaration, so it must not stand that check
    down: gating on "no warnings at all" hid a real phantom behind any unrelated
    parse defect, and would have hidden more with every warning added since.
    """
    return any(HYP_DECLARATION_BLOCK_RE.match(w.block) for w in warnings)


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




_HYP_PREFIX_RE = re.compile(
    r"^(?P<hyp>h-[A-Za-z0-9]+)\.(?P<sub>preds|attr_preds|refuts|authz|parent_attrs)$"
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


#: The scalar rows `:T conclude` projects, and the CLOSED set an unrecognized row is judged
#: against. Rows here are one-per-line by construction — the block is line-oriented, so a value
#: spanning two lines is TWO rows to this loop, the second of which lands in no key. That used to
#: be dropped in silence, which is how #806's refuted-correlation finding could be authored and
#: lost: the model writes a note across three lines, line one survives with its opening quote
#: dangling, and nothing anywhere says the rest is gone. A conclusion that quietly loses half of
#: itself is worse than one that was never written, so an unrecognized row now WARNS — and
#: `validate_companion` turns every parse warning into a write-gate denial the author can act on.
_CONCLUDE_SCALARS: frozenset[str] = frozenset({
    "disposition", "impact_verdict", "impact_severity", "confidence",
    "matched_archetype", "ceiling_rationale", "summary", "detection_notes",
})


def _project_conclude_scalars(
    conclude: dict[str, Any], rows: list[str], warn: Callable[[int, str, str], None]
) -> None:
    termination: dict[str, Any] = {}
    for index, row in enumerate(rows):
        m = re.match(r"^(\S+)\s+(.*)$", row)
        if not m:
            continue
        key = m.group(1)
        raw = m.group(2).strip()
        value: Any = None if raw == "null" else _unquote(raw)
        if key == "termination.category":
            termination["category"] = value
        elif key == "termination.rationale":
            termination["rationale"] = value
        elif key in _CONCLUDE_SCALARS:
            conclude[key] = value
            # An opened quote that never closes on its own row is the multi-line author's
            # signature: `_unquote` leaves the leading `"` in place because it found no partner,
            # so the stored value is a fragment wearing a quote. Warn on the row that OPENED it
            # rather than only on the orphaned continuations, so the reason names the field.
            if isinstance(value, str) and value.startswith('"'):
                warn(
                    index, row,
                    f"conclude: {key} opens a quoted value that does not close on this row — "
                    "invlang rows are one line each, so the rest of the value is dropped. "
                    "Write it as ONE line (long is fine — `summary` routinely is).",
                )
        else:
            warn(
                index, row,
                f"conclude: unrecognized row {key!r} — the block projects "
                f"{sorted(_CONCLUDE_SCALARS)} plus termination.category / "
                "termination.rationale. A row outside that set records nothing. If this is the "
                "continuation of a value from the row above, join it onto one line.",
            )
    if termination:
        conclude["termination"] = termination


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

    def _warn(self, block: Block, row_index: int, row: str, reason: str) -> None:
        self.warnings.append(ParseWarning(
            block=f":{block.tag} {block.name}",
            row_index=row_index,
            row=row,
            reason=reason,
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


    def project_block(self, block: Block) -> None:
        tag, name = block.tag, block.name

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

    def _project_t_block(self, block: Block) -> bool:
        name = block.name
        if name == "conclude":
            _project_conclude_scalars(
                self.out.setdefault("conclude", {}), block.rows,
                lambda i, row, reason: self._warn(block, i, row, reason),
            )
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
