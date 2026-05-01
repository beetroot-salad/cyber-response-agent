"""Dense-format emitter for the on-disk PREDICT `hypothesize:` block.

Parallel to `_gather_dense.py` / `_analyze_dense.py` / `_conclude_dense.py`.
The on-disk surface produced by `emit_hypothesize_dense(hypotheses)` is a
single `:H hypothesize.hypotheses` row block plus packed sub-cells per
hypothesis — exactly the shape that `scripts.handlers._dense_parser` reads
back via `_hypothesis_record`.

Surface produced:

    :H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs|preds|attr_preds|refuts|authz|integrity_waived|weight|status]
    h-001|?monitoring-probe|v-001|attempted_auth|endpoint|monitoring-host||p1:proposed_parent:"…";p2:…|...|r1[p1]:"…"|ac1:proposed:approved-monitoring-sources:"is on approved list":esc/esc|||active

Sub-cell grammars (semicolon-separated, quote-aware via
`_dense_primitives.split_subcells`):

    preds:      `<id>:<subject>:"<claim>"`
    attr_preds: `<id>:<target>:<attribute>:"<claim>"`
    refuts:     `<id>[refs?]:"<claim>"`        (refs = comma-joined prediction ids)
    authz:      `<id>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>`

Lossy with respect to subagent-side prediction `kind` and `from_story_link`
slots — those live in `:P h-<id>.preds` sub-blocks consumed by
`_predict_dense.parse_predict_dense` for envelope validation only, and no
downstream phase or validator rule reads them off-disk (verified: only
`scripts/invlang/queries.py` touches `kind`, and only at the lead level).
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


def _render_row(h: dict[str, Any]) -> str:
    if not isinstance(h, dict):
        raise HypothesizeDenseEmitError(
            f"hypothesis entry must be a dict, got {type(h).__name__}"
        )
    if not h.get("id") or not h.get("name"):
        raise HypothesizeDenseEmitError(
            f"hypothesis row missing id/name: {h!r}"
        )
    proposed = h.get("proposed_edge") or {}
    if not isinstance(proposed, dict):
        raise HypothesizeDenseEmitError(
            f"hypothesis {h.get('id')!r}.proposed_edge must be a dict (got "
            f"{type(proposed).__name__})"
        )
    cells = {
        "id":               h["id"],
        "name":             h["name"],
        "attached_to":      h.get("attached_to_vertex", ""),
        "rel":              proposed.get("relation", ""),
        "parent_type":      proposed.get("parent_type", ""),
        "parent_class":     proposed.get("parent_class", ""),
        "parent_attrs":     serialize_attrs(proposed.get("parent_attributes") or {}),
        "preds":            _pack_preds(h.get("predictions") or []),
        "attr_preds":       _pack_attr_preds(h.get("attribute_predictions") or []),
        "refuts":           _pack_refuts(h.get("refutation_shape") or []),
        "authz":            _pack_authz(h.get("authorization_contract") or []),
        "integrity_waived": h.get("integrity_waived", ""),
        "weight":           _weight_cell(h.get("weight", "")),
        "status":           h.get("status", ""),
    }
    return "|".join(cell(cells[c]) for c in _COLS)


def _weight_cell(w: Any) -> str:
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


def _pack_preds(preds: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for p in preds:
        pid = p.get("id")
        if not pid:
            raise HypothesizeDenseEmitError(
                f"prediction missing id: {p!r}"
            )
        parts.append(f"{pid}:{p.get('subject', '')}:{_quote_claim(p.get('claim'))}")
    return ";".join(parts)


def _pack_attr_preds(preds: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for p in preds:
        pid = p.get("id")
        if not pid:
            raise HypothesizeDenseEmitError(
                f"attribute_prediction missing id: {p!r}"
            )
        parts.append(
            f"{pid}:{p.get('target', '')}:{p.get('attribute', '')}:"
            f"{_quote_claim(p.get('claim'))}"
        )
    return ";".join(parts)


def _pack_refuts(refuts: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for r in refuts:
        rid = r.get("id")
        if not rid:
            raise HypothesizeDenseEmitError(
                f"refutation missing id: {r!r}"
            )
        refs = r.get("refutes_predictions") or []
        ref_token = ""
        if refs:
            ref_token = "[" + ",".join(str(x) for x in refs) + "]"
        parts.append(f"{rid}{ref_token}:{_quote_claim(r.get('claim'))}")
    return ";".join(parts)


def _pack_authz(contracts: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for c in contracts:
        cid = c.get("id")
        if not cid:
            raise HypothesizeDenseEmitError(
                f"authorization_contract missing id: {c!r}"
            )
        parts.append(
            f"{cid}:{c.get('edge_ref', 'proposed') or 'proposed'}:"
            f"{c.get('anchor_kind', '')}:"
            f"{_quote_claim(c.get('predicate'))}:"
            f"{c.get('on_unauthorized', 'esc') or 'esc'}/"
            f"{c.get('on_indeterminate', 'esc') or 'esc'}"
        )
    return ";".join(parts)
