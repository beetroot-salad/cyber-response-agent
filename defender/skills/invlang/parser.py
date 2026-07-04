"""Strict ```invlang parser aligned with the current defender schema.

Source of truth: `defender/skills/invlang/SKILL.md`.

Schema highlights
-----------------
- `:V prologue.vertices`, `:E prologue.edges` — unchanged 5/7-col rows.
- `:H hypothesize.hypotheses` — slim 9-col header (identity only).
  Multi-row optional content (predictions, refutations, authorization
  contracts, parent attributes) lives in namespaced sub-blocks under
  the same `:H` tag:

      :H h-NNN.preds        [id|subject|claim]
      :H h-NNN.attr_preds   [id|target|attribute|claim]
      :H h-NNN.refuts       [id|refutes|claim]      # `refutes` is csv of pred ids
      :H h-NNN.authz        [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
      :H h-NNN.parent_attrs [key|value]

  This mirrors the lead-scoped sub-block pattern (`:V l-NNN.observations.vertices`).
  No new top-level concept; scoping is in the block name.

- Cell values containing a literal `|` must be wrapped in double quotes
  (`flags="EXE_WRITABLE|EXE_LOWER_LAYER"`). The row tokenizer skips
  `|` inside a quoted span.

What we don't do
----------------
- No tolerance for old-format `:H` rows (the wide 14-col surface or
  the alternate 11-col surface). Both are rejected at the column-
  header check with a clear warning.
- No tolerance for `:T resolutions` without the `⟂` supporting-edges
  separator.

What we surface
---------------
Per-row failures land in a `ParseWarning` list returned alongside
the parsed body. The corpus loader threads these into each
`Companion.parse_warnings` and aggregates them in `LoadReport` so
post-mortem debugging always has a paper trail.

Module layout
-------------
The schema-free cell/row tokenizer lives in `_cells.py`; the shared
`Block`/`RowError` value types in `_types.py`. Both are re-exported from
here (production consumers and the invlang tests import them from
`parser`). This module keeps the schema-aware projection: record
projectors (`:V`/`:E`/`:H`/`:R`/`:T`/`:L` rows → canonical companion
dict) and the `_Projector` that drives blocks onto it.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterator
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
from .schema import (
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
    """One row or block we couldn't project, with enough context to
    diagnose later (which file, which block, which row, why).
    `file_path` is filled in by the corpus loader since the parser
    itself only sees text."""
    block: str           # ":H hypothesize.hypotheses", ":T resolutions", ...
    row_index: int       # 0-based row index within the block
    row: str             # the raw row text (truncated to 200 chars)
    reason: str          # the RowError message
    file_path: str = ""  # set by the corpus loader

    def format(self) -> str:
        loc = self.file_path or "(unknown file)"
        return (
            f"{loc}: {self.block} row {self.row_index}: {self.reason} "
            f"| row={self.row[:200]!r}"
        )


# The one schema-aware cell helper: it returns a `schema.AuthorityRef`, so it
# stays here rather than in the schema-free `_cells.py` tokenizer.
def _parse_auth(cell: str) -> AuthorityRef:
    if ":" not in cell:
        return {"kind": cell.strip(), "source": ""}
    kind, source = cell.split(":", 1)
    return {"kind": kind.strip(), "source": source.strip()}


# ---------------------------------------------------------------------------
# Block tokenization
# ---------------------------------------------------------------------------


def _tokenize_fence(body: str) -> list[Block]:
    blocks: list[Block] = []
    cur: Block | None = None
    in_story = False

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if _STORY_HEADER_RE.match(stripped):
            # Defender SKILL doesn't use `### story` blocks today; tolerate
            # the header (consume following lines until next block) but
            # don't project. Soc-agent uses it for hypothesis prose.
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


# ---------------------------------------------------------------------------
# Row → record projections
# ---------------------------------------------------------------------------


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


# Current `:H hypothesize.hypotheses` schema: 9-col identity row.
# Multi-row optional content (preds/refuts/authz/parent_attrs) lives
# in `:H h-NNN.<sub>` sub-blocks; legacy packed-cell forms are rejected
# at the column-header check, not silently mis-projected.
_HYP_HEADER_COLS = {
    "id", "name", "attached_to", "rel",
    "parent_type", "parent_class",
    "integrity_waived", "weight", "status",
}


def _is_current_hyp_header(cols: list[str] | None) -> bool:
    """Return True iff `cols` looks like the current 9-col :H header.

    The check is tolerant of column order and accepts the optional
    `integrity_waived?` column (the `?` is stripped at tokenization).
    Rows from legacy 14-col or 11-col headers fail this and the block
    is rejected wholesale with one warning instead of N-row noise.
    """
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


# ---------------------------------------------------------------------------
# `:H h-NNN.<sub>` sub-block projections
# ---------------------------------------------------------------------------


_HYP_PREFIX_RE = re.compile(
    r"^(?P<hyp>h-[A-Za-z0-9]+)\.(?P<sub>preds|attr_preds|refuts|authz|parent_attrs)$"
)

# Column grammars for the `:H h-NNN.<sub>` sub-blocks. Named (not inline
# literals) so the SKILL.md grammar pin (`tests/test_invlang_grammar_pin.py`)
# can assert the documented headers match what the parser actually reads.
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
        "edge_ref": rec.get("edge_ref", "proposed") or "proposed",
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project a findings (`:L`) record dict onto (identity, query_details).
    The id/name guard lives in the caller so the whole loop shares the
    `_for_each_row` recovery path."""
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
    if rec.get("fail_reason"):
        identity.setdefault("outcome", {})["failure_reason"] = rec["fail_reason"]
    query_details: dict[str, Any] = {}
    for k_in, k_out in (
        ("system", "system"),
        ("template", "template"),
        ("query", "query"),
        ("window", "time_window"),
    ):
        if rec.get(k_in):
            query_details[k_out] = rec[k_in]
    return identity, query_details


_RESOLUTION_LINE_RE = re.compile(
    r"^(?P<hyp>[^\s]+)\s+(?P<before>\S+)\s*→\s*(?P<after>\S+)\s+"
    r"\[(?P<inner>.*)\]\s*$"
)


# Matches `p\d+`, `ap\d+`, `r\d+` literals inside the iff annotation RHS.
_IFF_LITERAL_RE = re.compile(r"\b(ap\d+|p\d+|r\d+)\b")


def _extract_iff_literals(annotation: str) -> tuple[list[str], list[str]]:
    """Pull (pred_ids, refut_ids) from the iff RHS literal set.

    Multiple iffs separated by `;`. For each iff (`⟺` or ASCII
    fallback `<=>`), only the RHS contributes literals — LHS tokens
    name the *current* observation, RHS names the predictions /
    refutations the resolution matched. Polarity (`p1` vs `¬p1`) is
    reasoning prose; both count as "p1 was tested by this resolution".
    """
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
    """Parse `<hyp> <before> → <after> [<lead> <pred-refs> <sev> ⟂ <edges> :: <ann>]`.

    The `⟂` separator is required by the current schema. Rows that omit
    it raise RowError and are dropped with a warning.

    Matched prediction/refutation ids are derived from the iff RHS
    literal set in the annotation (`p1 ⟺ ¬r1; ...`). Pre-iff tokens
    in the head (between lead-id and severity, e.g. `r1,r2` in
    `[l-001 r1,r2 severe ⟂ ...]`) are accepted as a fallback so
    rows that elide the iff annotation still attribute correctly.
    `hypothesis_id` is emitted as an alias of `hypothesis` for
    consumers that index on the soc-agent name.
    """
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
    # Pre-iff positional tokens between lead-id and severity. Split
    # each on `,` so `r1,r2` lands as two ids.
    head_refs: list[str] = []
    for tok in head_tokens[1:-1]:
        head_refs.extend(t.strip() for t in tok.split(",") if t.strip())
    supp_text = supp.strip()
    iff_pred_ids, iff_refut_ids = _extract_iff_literals(annotation)
    matched_pred_ids = iff_pred_ids or [t for t in head_refs if t.startswith("p")]
    matched_refut_ids = iff_refut_ids or [t for t in head_refs if t.startswith("r")]
    record: ResolutionRecord = {
        "hypothesis": m.group("hyp"),
        "hypothesis_id": m.group("hyp"),  # alias, matches soc-agent shape
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


# Maps dense `:R` column names to the canonical companion-dict field
# names downstream consumers (and soc-agent corpus queries) expect.
# Dense column headers use short forms (`grounding`, `authority`,
# `fulfills`, `resolved_by`); canonical companion uses long forms.
# Lives next to `_resolution_record` / `_Projector._project_resolution_block`
# (its only consumer), out of the schema-free lexer neighborhood.
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
# Resolution columns whose values are semicolon-packed lists, projected
# to list[str] on the canonical record.
_RESOLUTION_LIST_KEYS = {"conditioning", "concerns"}


def _canonicalize_resolution_row(rec: dict[str, str]) -> dict[str, Any]:
    """Project a dense `:R` row dict onto canonical field names.

    Empty cells are dropped (no point carrying `verdict: ""` around).
    Semicolon-packed columns (`conditioning`, `concerns`) become lists.
    """
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if not v:
            continue
        canonical = _RESOLUTION_KEY_CANONICAL.get(k, k)
        if k in _RESOLUTION_LIST_KEYS:
            out[canonical] = _split_csv_or_semi(v)
        else:
            out[canonical] = v
    return out


def _project_conclude_scalars(conclude: dict[str, Any], rows: list[str]) -> None:
    termination: dict[str, Any] = {}
    for row in rows:
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
        elif key in (
            "disposition", "impact_verdict", "impact_severity",
            "confidence", "matched_archetype", "ceiling_rationale", "summary",
        ):
            conclude[key] = value
    if termination:
        conclude["termination"] = termination


def _close_loop(rows: list[str]) -> int | None:
    """The integer loop number from a `:T close` block's `loop N` scalar row.

    `:T close` is the per-loop completion marker (the loop-boundary signal
    compaction folds on — see `runtime/compaction.fold_boundary`). Minimal,
    scalar-shaped like its sibling `:T conclude`:

        :T close
        loop  1

    Returns None when no parseable `loop N` row is present; the parser stays
    lenient (records a warning via the caller) and the validator rejects the
    malformed marker (rule 6) so a bogus close can't reach the fold."""
    for row in rows:
        m = re.match(r"^loop\s+(\S+)", row.strip())
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
# Top-level projection
# ---------------------------------------------------------------------------


_RESOLUTION_BUCKET_KEY = {
    "authz": "authorization_resolutions",
    "consultations": "anchor_consultations",
    "impact": "impact_resolutions",
    "attr_updates": "attribute_updates",
}


@dataclass
class _Projector:
    """Mutable projection state for one companion parse.

    Holds the four accumulators every `:X` block writes into (`out`,
    `warnings`, `hypotheses_by_id`, `findings`) plus the running
    `current_lead` pointer that `:R` / `:T resolutions` / `:T shelved`
    rows fall back on for attribution. These used to be threaded by hand
    through every `_project_*`, with `_project_block`/`_project_t_block`
    even *returning* `current_lead` just to pass the pointer back up the
    stack; here they are fields and the projectors are methods, so the
    pointer mutates in place and the return-threading is gone.
    """

    out: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    hypotheses_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)
    current_lead: str | None = None

    # -- shared helpers -----------------------------------------------------

    def lead_bucket(self, lead_id: str) -> dict[str, Any]:
        lead = self.findings.setdefault(lead_id, {"id": lead_id})
        lead.setdefault("outcome", {})
        lead.setdefault("query_details", {})
        lead.setdefault("resolutions", [])
        return lead

    def _warn(self, block: Block, row_index: int, row: str, reason: str) -> None:
        """Record one ParseWarning for `block`. The `:{tag} {name}` label
        was hand-built at ~12 sites with identical boilerplate; this is the
        single source of it."""
        self.warnings.append(ParseWarning(
            block=f":{block.tag} {block.name}",
            row_index=row_index,
            row=row,
            reason=reason,
        ))

    def _project_rows(self, block: Block, project_one) -> list[Any]:
        """Drive a row-projection function across `block.rows`. Each row
        failure becomes a ParseWarning; the rest of the block continues."""
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
        """Yield `(idx, row, rec)` for each row, projecting cells to a record
        dict via `_row_dict`. A malformed row (cell-count overflow) is recorded
        as a ParseWarning and skipped — the same per-row recovery `_project_rows`
        gives, but for consumers that need the raw `rec` plus side effects rather
        than a returned list. `default_cols` is the headerless-block fallback
        passed through to `_row_dict` (e.g. parent_attrs' `[key, value]`)."""
        for idx, row in enumerate(block.rows):
            try:
                rec = _row_dict(block, row, default_cols)
            except RowError as e:
                self._warn(block, idx, row, str(e))
                continue
            yield idx, row, rec

    # -- block dispatch -----------------------------------------------------

    def project_block(self, block: Block) -> None:
        """Project one block, updating `self.current_lead` in place."""
        tag, name = block.tag, block.name

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
            self.current_lead = lead_id
            return

        if tag == "R" and name in _RESOLUTION_BUCKET_KEY:
            self._project_resolution_block(block)
            return

        if tag == "T" and self._project_t_block(block):
            return

        self._warn(block, -1, "", "unknown block — no projection rule")

    def _project_t_block(self, block: Block) -> bool:
        """Project a `:T` block. Returns whether it was handled."""
        name = block.name
        if name == "conclude":
            _project_conclude_scalars(self.out.setdefault("conclude", {}), block.rows)
            return True
        if name.startswith("conclude."):
            # `conclude.*` sub-tables (surviving / ceiling_test / deferred_*) have
            # no machine consumer in defender — the closure rules that read them in
            # soc-agent (#13/#26/#31/#34) were never ported, and benign-gating is
            # computed from the resolution record. Accept-and-ignore: a stray
            # sub-block is tolerated rather than rejected, so the agent never
            # format-fights an undocumented surface against the validator.
            return True
        if name == "close":
            # Per-loop completion marker. Records the closed loop number for
            # `fold_boundary`; a malformed close (no `loop N`) warns → rule 1
            # blocks the write rather than silently dropping the marker.
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
        """Route a `:H h-NNN.<sub>` sub-block onto its parent hypothesis."""
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
        # Other lead-scoped variants (substitutions, lead_preds, impact_preds)
        # are not part of the advisory-retrieval surface.

    def _project_findings_block(self, block: Block) -> None:
        last_lead_id: str | None = None
        for idx, row, rec in self._for_each_row(block):
            if not rec.get("id") or not rec.get("name"):
                self._warn(block, idx, row, "findings row missing id/name")
                continue
            identity, query_details = _lead_header_record(rec)
            lead = self.lead_bucket(identity["id"])
            lead.update(identity)
            if query_details:
                lead.setdefault("query_details", {}).update(query_details)
            last_lead_id = identity["id"]
        self.current_lead = last_lead_id or self.current_lead

    def _project_resolution_block(self, block: Block) -> None:
        name = block.name
        bucket_key = _RESOLUTION_BUCKET_KEY[name]
        for idx, row, rec in self._for_each_row(block):
            # `resolved_by` / `lead` are the dense column names for the
            # back-pointer; look them up *before* canonicalization so
            # attribution still works.
            lead_id = rec.get("resolved_by") or rec.get("lead") or self.current_lead
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
        self, lead: dict[str, Any], rec: dict, block: Block, idx: int, row: str
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
        au.append({"target": tgt, "updates": {key: val}})

    def _project_resolutions_block(self, block: Block) -> None:
        for idx, row in enumerate(block.rows):
            try:
                lead_id, record = _resolution_record(row)
            except RowError as e:
                self._warn(block, idx, row, str(e))
                continue
            lid = lead_id or self.current_lead
            if not lid:
                self._warn(block, idx, row, "resolution has no lead attribution")
                continue
            self.lead_bucket(lid).setdefault("resolutions", []).append(record)
            self.current_lead = lid

    def _project_shelved_block(self, block: Block) -> None:
        for _idx, _row, rec in self._for_each_row(block):
            hyp = rec.get("hyp_id")
            if not hyp:
                continue
            lid = rec.get("by_lead") or self.current_lead
            if not lid:
                continue
            lead = self.lead_bucket(lid)
            lead.setdefault("shelved", []).append(hyp)
            if rec.get("rationale"):
                lead.setdefault("shelved_rationales", {})[hyp] = _unquote(rec["rationale"])


def companion_from_blocks(
    blocks: list[Block],
) -> tuple[CompanionBody, list[ParseWarning]]:
    """Project blocks → canonical companion dict + per-row warnings."""
    proj = _Projector()
    for block in blocks:
        proj.project_block(block)
    if proj.findings:
        proj.out["findings"] = list(proj.findings.values())
    return cast(CompanionBody, proj.out), proj.warnings


def parse_dense_companion(
    text: str,
) -> tuple[CompanionBody, list[ParseWarning]]:
    """Walk every ```invlang fence in `text` and project to companion dict.
    Returns (companion_body, parse_warnings)."""
    blocks: list[Block] = []
    for match in INVLANG_FENCE_RE.finditer(text):
        blocks.extend(_tokenize_fence(match.group(1)))
    if not blocks:
        return cast(CompanionBody, {}), []
    return companion_from_blocks(blocks)
