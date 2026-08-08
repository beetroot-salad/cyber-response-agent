
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


_HYP_SUB_DISPATCH = {
    "preds": ("predictions", _hyp_sub_pred_row),
    "attr_preds": ("attribute_predictions", _hyp_sub_attr_pred_row),
    "refuts": ("refutation_shape", _hyp_sub_refut_row),
    "authz": ("authorization_contract", _hyp_sub_authz_row),
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


_IFF_LITERAL_RE = re.compile(r"\b(ap\d+|p\d+|r\d+)\b")


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
    matched_pred_ids = iff_pred_ids or [t for t in head_refs if t.startswith("p")]
    matched_refut_ids = iff_refut_ids or [t for t in head_refs if t.startswith("r")]
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

#: The scalar rows `:T conclude` projects, and the CLOSED set an unrecognized row is judged
#: against. One owner: `Conclude` is the type the projection has to satisfy, so the set is read
#: off it rather than restated here, where the two could drift a field apart.
_CONCLUDE_SCALARS: frozenset[str] = (
    frozenset(Conclude.__annotations__) - {"termination"} - _CONCLUDE_LISTS
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


@dataclass
class _Projector:

    out: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    hypotheses_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
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

        if tag == "V" and name == "prologue.vertices":
            self.out.setdefault("prologue", {})["vertices"] = (
                self._project_rows(block, _vertex_record)
            )
            return
        if tag == "E" and name == "prologue.edges":
            self.out.setdefault("prologue", {})["edges"] = (
                self._project_rows(block, _edge_record)
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
                if isinstance(value, str) and value.strip().lower() in _CONCLUDE_EMPTY_MARKERS:
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

    def _project_hypothesize_block(self, block: Block) -> None:
        if not _is_current_hyp_header(block.columns):
            self._warn(
                block, -1, "",
                (
                    f"column header {block.columns!r} does not match the "
                    f"current schema (id|name|attached_to|rel|parent_type|"
                    f"parent_class|integrity_waived?|weight|status); whole "
                    f"block rejected"
                ),
            )
            return
        hyps = self._project_rows(block, _hypothesis_record)
        self.out.setdefault("hypothesize", {})["hypotheses"] = hyps
        for h in hyps:
            hid = h.get("id")
            if isinstance(hid, str):
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
                )["attributes"] = attrs
            return
        if sub not in _HYP_SUB_DISPATCH:
            return
        out_key, row_proj = _HYP_SUB_DISPATCH[sub]
        rows = self._project_rows(block, row_proj)
        if rows:
            hyp[out_key] = rows

    def _project_lead_subblock(
        self, tag: str, sub: str, block: Block, lead: dict[str, Any]
    ) -> None:
        if tag == "V" and sub == "observations.vertices":
            lead.setdefault("outcome", {}).setdefault("observations", {})["vertices"] = (
                self._project_rows(block, _vertex_record)
            )
            return
        if tag == "E" and sub == "observations.edges":
            lead.setdefault("outcome", {}).setdefault("observations", {})["edges"] = (
                self._project_rows(block, _edge_record)
            )
            return
        if tag == "H" and sub == "new_hypotheses":
            lead["new_hypotheses"] = self._project_rows(block, _hypothesis_record)
            return

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
