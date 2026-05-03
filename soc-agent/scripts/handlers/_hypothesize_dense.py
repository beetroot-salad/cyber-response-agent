"""Dense-format emitters for hypothesis state.

Two surfaces exist side-by-side:

- `emit_hypothesize_dense(...)` keeps the historical packed `:H
  hypothesize.hypotheses` row block used by older fixtures and compatibility
  readers.
- `emit_hypothesize_state_dense(...)` renders the same canonical hypothesis
  list as an expanded full-state block: metadata rows plus per-hypothesis
  story / prediction / refutation / authz sub-blocks. That fuller surface is
  what the predict handler now writes back to `investigation.md` and what the
  prompt renderer shows to the LLM.

The expanded surface preserves queryability because the metadata spine stays
in `:H hypothesize.hypotheses`; the extra `:P h-...` blocks simply carry the
detail that the packed row form used to discard.
"""

from __future__ import annotations

from typing import Any

from scripts.handlers._dense_emit_common import cell, serialize_attrs


class HypothesizeDenseEmitError(ValueError):
    """Raised on a malformed input dict to the hypothesize emitter."""


_COLS = [
    "id", "name", "attached_to", "rel",
    "parent_type", "parent_class", "parent_attrs",
    "preds", "attr_preds", "refuts", "authz",
    "integrity_waived", "weight", "status",
]

_STATE_COLS = [
    "id", "name", "attached_to", "rel",
    "parent_type", "parent_class", "parent_attrs",
    "integrity_waived", "weight", "status",
]


def emit_hypothesize_dense(hypotheses: list[dict[str, Any]]) -> str:
    """Render `result.invlang_delta['hypotheses']` as a dense `:H` block body.

    Returns the block text (no fence). Empty input → empty string; the
    caller should skip the on-disk write entirely (matches the legacy
    behavior in `_compose_section`).
    """
    if not hypotheses:
        return ""
    if not isinstance(hypotheses, list):
        raise HypothesizeDenseEmitError(
            f"emit_hypothesize_dense: expected list, got "
            f"{type(hypotheses).__name__}"
        )
    rows = [_render_row(h) for h in hypotheses]
    return "\n".join([
        ":H hypothesize.hypotheses [" + "|".join(_COLS) + "]",
        *rows,
    ])


def emit_hypothesize_state_dense(
    hypotheses: list[dict[str, Any]],
    *,
    block_name: str = "hypothesize.hypotheses",
) -> str:
    """Render hypotheses as an expanded full-state surface.

    Layout:
      - one metadata `:H` block covering all hypotheses
      - optional `### story h-...` prose blocks
      - optional per-hypothesis `:P h-...` sub-blocks

    The emitted rows are tolerant of legacy hypotheses that were persisted
    before `kind`, `from_story_link`, `comparison`, or `story` were stored:
    missing fields are emitted as empty cells or omitted blocks rather than
    raising.
    """
    if not hypotheses:
        return ""
    if not isinstance(hypotheses, list):
        raise HypothesizeDenseEmitError(
            f"emit_hypothesize_state_dense: expected list, got "
            f"{type(hypotheses).__name__}"
        )

    parts = [
        "\n".join([
            ":H " + block_name + " [" + "|".join(_STATE_COLS) + "]",
            *[_render_state_row(h) for h in hypotheses],
        ])
    ]
    for h in hypotheses:
        story = _render_story_block(h)
        if story:
            parts.append(story)
        parts.extend(_render_state_subblocks(h))
    return "\n\n".join(parts)


def _render_row(h: dict[str, Any]) -> str:
    if not isinstance(h, dict):
        raise HypothesizeDenseEmitError(
            f"hypothesis entry must be a dict, got {type(h).__name__}"
        )
    if not h.get("id") or not h.get("name"):
        raise HypothesizeDenseEmitError(
            f"hypothesis row missing id/name: {h!r}"
        )
    hid = h["id"]
    proposed = h.get("proposed_edge") or {}
    if not isinstance(proposed, dict):
        raise HypothesizeDenseEmitError(
            f"hypothesis {hid!r}.proposed_edge must be a dict (got "
            f"{type(proposed).__name__})"
        )
    # Canonical companion shape: `proposed_edge.parent_vertex.{type,
    # classification, attributes}` (nested). Project to the dense cells.
    parent_vertex = proposed.get("parent_vertex") or {}
    if not isinstance(parent_vertex, dict):
        parent_vertex = {}
    cells = {
        "id":               hid,
        "name":             h["name"],
        "attached_to":      h.get("attached_to_vertex", ""),
        "rel":              proposed.get("relation", ""),
        "parent_type":      parent_vertex.get("type", ""),
        "parent_class":     parent_vertex.get("classification", ""),
        "parent_attrs":     serialize_attrs(parent_vertex.get("attributes") or {}),
        "preds":            _pack_preds(hid, _require_list(hid, "predictions", h.get("predictions"))),
        "attr_preds":       _pack_attr_preds(hid, _require_list(hid, "attribute_predictions", h.get("attribute_predictions"))),
        "refuts":           _pack_refuts(hid, _require_list(hid, "refutation_shape", h.get("refutation_shape"))),
        "authz":            _pack_authz(hid, _require_list(hid, "authorization_contract", h.get("authorization_contract"))),
        "integrity_waived": h.get("integrity_waived", ""),
        "weight":           _weight_cell(h.get("weight", "")),
        "status":           h.get("status", ""),
    }
    return "|".join(cell(cells[c]) for c in _COLS)


def _render_state_row(h: dict[str, Any]) -> str:
    if not isinstance(h, dict):
        raise HypothesizeDenseEmitError(
            f"hypothesis entry must be a dict, got {type(h).__name__}"
        )
    if not h.get("id") or not h.get("name"):
        raise HypothesizeDenseEmitError(
            f"hypothesis row missing id/name: {h!r}"
        )
    hid = h["id"]
    proposed = h.get("proposed_edge") or {}
    if not isinstance(proposed, dict):
        raise HypothesizeDenseEmitError(
            f"hypothesis {hid!r}.proposed_edge must be a dict (got "
            f"{type(proposed).__name__})"
        )
    parent_vertex = proposed.get("parent_vertex") or {}
    if not isinstance(parent_vertex, dict):
        parent_vertex = {}
    cells = {
        "id": hid,
        "name": h["name"],
        "attached_to": h.get("attached_to_vertex", ""),
        "rel": proposed.get("relation", ""),
        "parent_type": parent_vertex.get("type", ""),
        "parent_class": parent_vertex.get("classification", ""),
        "parent_attrs": serialize_attrs(parent_vertex.get("attributes") or {}),
        "integrity_waived": h.get("integrity_waived", ""),
        "weight": _weight_cell(h.get("weight", "")),
        "status": h.get("status", ""),
    }
    return "|".join(cell(cells[c]) for c in _STATE_COLS)


def _require_list(hid: str, field: str, value: Any) -> list[Any]:
    """Coerce a missing/None field to []; reject non-list scalars loudly so
    a stray string doesn't get iterated character-by-character.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise HypothesizeDenseEmitError(
            f"hypothesis {hid!r}.{field} must be a list (got "
            f"{type(value).__name__})"
        )
    return value


def _weight_cell(w: Any) -> str:
    # `null` is the explicit sentinel the dense parser maps back to None
    # for the weight column (see test_project_hypothesis_with_authz_contract
    # fixture). An empty cell would round-trip as "" rather than None.
    if w is None:
        return "null"
    return str(w)


def _quote_claim(claim: Any) -> str:
    """Wrap a claim in `"..."`, escaping embedded `"` as `\\"` so
    `_dense_primitives.split_subcells` keeps the sub-cell intact through
    `;` boundaries.
    """
    if claim is None:
        return '""'
    s = str(claim).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _render_story_block(h: dict[str, Any]) -> str:
    story = h.get("story")
    hid = h.get("id", "")
    if not isinstance(story, str) or not story.strip() or not hid:
        return ""
    return "\n".join([f"### story {hid}", story.strip()])


def _render_state_subblocks(h: dict[str, Any]) -> list[str]:
    hid = h.get("id")
    if not isinstance(hid, str) or not hid:
        raise HypothesizeDenseEmitError(
            f"hypothesis row missing id/name: {h!r}"
        )
    out: list[str] = []

    preds = _require_list(hid, "predictions", h.get("predictions"))
    if preds:
        rows: list[str] = []
        for p in preds:
            rows.append("|".join([
                cell(p.get("id", "")),
                cell(p.get("subject", "")),
                cell(p.get("kind", "")),
                cell(p.get("from_story_link", "")),
                cell(_quote_claim(p.get("claim"))),
            ]))
        out.append("\n".join([
            f":P {hid}.preds [id|subject|kind|from_story|claim]",
            *rows,
        ]))

    attr_preds = _require_list(
        hid, "attribute_predictions", h.get("attribute_predictions")
    )
    if attr_preds:
        rows = []
        for p in attr_preds:
            rows.append("|".join([
                cell(p.get("id", "")),
                cell(p.get("target", "")),
                cell(p.get("attribute", "")),
                cell(p.get("kind", "")),
                cell(_quote_claim(p.get("claim"))),
            ]))
        out.append("\n".join([
            f":P {hid}.attr_preds [id|target|attribute|kind|claim]",
            *rows,
        ]))

    refuts = _require_list(hid, "refutation_shape", h.get("refutation_shape"))
    if refuts:
        rows = []
        for r in refuts:
            rows.append("|".join([
                cell(r.get("id", "")),
                cell(",".join(str(x) for x in (r.get("refutes_predictions") or []))),
                cell(r.get("kind", "")),
                cell(_quote_claim(r.get("claim"))),
            ]))
        out.append("\n".join([
            f":P {hid}.refuts [id|refutes|kind|claim]",
            *rows,
        ]))

    authz = _require_list(
        hid, "authorization_contract", h.get("authorization_contract")
    )
    if authz:
        rows = []
        for c in authz:
            rows.append("|".join([
                cell(c.get("id", "")),
                cell(c.get("edge_ref", "proposed") or "proposed"),
                cell(c.get("anchor_kind", "")),
                cell(_quote_claim(c.get("predicate"))),
                cell(c.get("on_unauthorized", "esc") or "esc"),
                cell(c.get("on_indeterminate", "esc") or "esc"),
            ]))
        out.append("\n".join([
            f":P {hid}.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]",
            *rows,
        ]))

    comparison_rows = _render_comparison_rows(hid, preds, refuts)
    if comparison_rows:
        out.append("\n".join([
            f":P {hid}.comparisons [pred_ref|selector_kind|selector|dimension]",
            *comparison_rows,
        ]))

    return out


def _render_comparison_rows(
    hid: str,
    preds: list[dict[str, Any]],
    refuts: list[dict[str, Any]],
) -> list[str]:
    rows: list[str] = []
    for bucket in (preds, refuts):
        for entry in bucket:
            comp = entry.get("comparison")
            if not isinstance(comp, dict) or not comp:
                continue
            pred_ref = entry.get("id")
            if not pred_ref:
                raise HypothesizeDenseEmitError(
                    f"hypothesis {hid!r} comparison row missing pred/ref id: {entry!r}"
                )
            rows.append("|".join([
                cell(pred_ref),
                cell(comp.get("selector_kind", "")),
                cell(_quote_claim(comp.get("selector"))),
                cell(comp.get("dimension", "")),
            ]))
    return rows


def _pack_preds(hid: str, preds: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for p in preds:
        pid = p.get("id")
        if not pid:
            raise HypothesizeDenseEmitError(
                f"hypothesis {hid!r} prediction missing id: {p!r}"
            )
        parts.append(f"{pid}:{p.get('subject', '')}:{_quote_claim(p.get('claim'))}")
    return ";".join(parts)


def _pack_attr_preds(hid: str, preds: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for p in preds:
        pid = p.get("id")
        if not pid:
            raise HypothesizeDenseEmitError(
                f"hypothesis {hid!r} attribute_prediction missing id: {p!r}"
            )
        parts.append(
            f"{pid}:{p.get('target', '')}:{p.get('attribute', '')}:"
            f"{_quote_claim(p.get('claim'))}"
        )
    return ";".join(parts)


def _pack_refuts(hid: str, refuts: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for r in refuts:
        rid = r.get("id")
        if not rid:
            raise HypothesizeDenseEmitError(
                f"hypothesis {hid!r} refutation missing id: {r!r}"
            )
        refs = r.get("refutes_predictions") or []
        ref_token = ""
        if refs:
            ref_token = "[" + ",".join(str(x) for x in refs) + "]"
        parts.append(f"{rid}{ref_token}:{_quote_claim(r.get('claim'))}")
    return ";".join(parts)


def _pack_authz(hid: str, contracts: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for c in contracts:
        cid = c.get("id")
        if not cid:
            raise HypothesizeDenseEmitError(
                f"hypothesis {hid!r} authorization_contract missing id: {c!r}"
            )
        parts.append(
            f"{cid}:{c.get('edge_ref', 'proposed') or 'proposed'}:"
            f"{c.get('anchor_kind', '')}:"
            f"{_quote_claim(c.get('predicate'))}:"
            f"{c.get('on_unauthorized', 'esc') or 'esc'}/"
            f"{c.get('on_indeterminate', 'esc') or 'esc'}"
        )
    return ";".join(parts)
