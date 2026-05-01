"""Dense-format emitter for the ANALYZE phase `findings:` block.

Parallel to `_gather_dense.py`. Replaces the YAML synthesis path in
`analyze.py` (`_synthesize_findings_block` → `:::yaml ... :::`) with a
dense-block author so the ANALYZE write lands as ```` ```invlang ````.

The ANALYZE subagent already emits dense (see `parse_analyze_envelope_dense`
in `_output_parser.py`); this module only handles the *handler-side*
write of the merged gather+analyze findings block.

Surface produced (per `docs/dense-investigation-format.md` §Findings,
§Resolutions, §Authority blocks):

    :L findings [id|name|loop|target|mode|system|template|query|window|status]
    l-001|enrich-source|2|v-001|graded|wazuh|tpl-x|"<query>"|24h|active

    :V l-001.observations.vertices [id|type|class|ident|attrs]    (when present)
    :E l-001.observations.edges    [id|rel|src|tgt|when|auth_kind:source|attrs]

    :R authz [resolved_by|edge|verdict|fulfills|anchor_kind|anchor_id|grounding|authority|as_of|reasoning]
    :R consultations [resolved_by|verdict|grounding|anchor_kind|anchor_id|authority|as_of|reasoning]
    :R impact [resolved_by|pred_ref|dim|verdict|grounding|authority|as_of|reasoning]
    :R attr_updates [resolved_by|target|key|value]

    :T resolutions
    h-001  ∅ → ++   [l-001 p1,p2 severe ⟂ e-010 :: <annotation>]

Resolution row form: `<hyp> <before> → <after> [<lead> <pred-tokens>
<severity> ⟂ <supp-edges|marker> :: <annotation>]`. Severity defaults to
`severe` for ++/-- (validator S1) and `moderate` otherwise; the ANALYZE
envelope carries the parser-internal `severity` and `before_weight` keys
on each resolution (see `_parse_resolution_row` in `_output_parser.py`)
when available.
"""

from __future__ import annotations

from typing import Any


class AnalyzeDenseEmitError(ValueError):
    """Raised on a malformed input dict to the analyze emitter."""


_LEAD_COLS = [
    "id", "name", "loop", "target", "mode",
    "system", "template", "query", "window", "status",
]
_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]

_AUTHZ_COLS = [
    "resolved_by", "edge", "verdict", "fulfills",
    "anchor_kind", "anchor_id", "grounding", "authority", "as_of", "reasoning",
]
_CONSULT_COLS = [
    "resolved_by", "verdict", "grounding",
    "anchor_kind", "anchor_id", "authority", "as_of", "reasoning",
]
_IMPACT_COLS = [
    "resolved_by", "pred_ref", "dim", "verdict",
    "grounding", "authority", "as_of", "reasoning",
]
_ATTR_UPD_COLS = ["resolved_by", "target", "key", "value"]


def emit_analyze_findings_dense(findings: list[dict[str, Any]]) -> str:
    """Render an analyze findings list as one or more dense blocks.

    Returns the concatenated block text (no fence). Empty input → empty
    string. The caller wraps the returned text in a ```invlang fence.
    """
    if not findings:
        return ""
    if not isinstance(findings, list):
        raise AnalyzeDenseEmitError(
            f"emit_analyze_findings_dense: expected list, got "
            f"{type(findings).__name__}"
        )

    lead_rows: list[str] = []
    sub_blocks: list[str] = []

    authz_rows: list[str] = []
    consult_rows: list[str] = []
    impact_rows: list[str] = []
    attr_upd_rows: list[str] = []
    resolution_rows: list[str] = []

    for entry in findings:
        if not isinstance(entry, dict):
            raise AnalyzeDenseEmitError(
                f"findings entry must be a dict, got {type(entry).__name__}"
            )
        lid = entry.get("id")
        if not isinstance(lid, str):
            raise AnalyzeDenseEmitError(
                f"findings entry missing id (or non-string): {entry!r}"
            )
        lead_rows.append(_render_lead_row(entry))
        sub_blocks.extend(_render_observation_subblocks(lid, entry))

        outcome = entry.get("outcome") or {}
        if not isinstance(outcome, dict):
            raise AnalyzeDenseEmitError(
                f"findings[{lid!r}].outcome must be a dict"
            )
        for r in outcome.get("authorization_resolutions") or []:
            authz_rows.append(_render_authz_row(lid, r))
        for r in outcome.get("anchor_consultations") or []:
            consult_rows.append(_render_consult_row(lid, r))
        for r in outcome.get("impact_resolutions") or []:
            impact_rows.append(_render_impact_row(lid, r))
        for r in outcome.get("attribute_updates") or []:
            attr_upd_rows.extend(_render_attr_upd_rows(lid, r))

        for res in entry.get("resolutions") or []:
            resolution_rows.append(_render_resolution_line(lid, res))

    out: list[str] = []
    out.append(":L findings [" + "|".join(_LEAD_COLS) + "]")
    out.extend(lead_rows)
    for block in sub_blocks:
        out.append("")
        out.append(block)

    if authz_rows:
        out.append("")
        out.append(":R authz [" + "|".join(_AUTHZ_COLS) + "]")
        out.extend(authz_rows)
    if consult_rows:
        out.append("")
        out.append(":R consultations [" + "|".join(_CONSULT_COLS) + "]")
        out.extend(consult_rows)
    if impact_rows:
        out.append("")
        out.append(":R impact [" + "|".join(_IMPACT_COLS) + "]")
        out.extend(impact_rows)
    if attr_upd_rows:
        out.append("")
        out.append(":R attr_updates [" + "|".join(_ATTR_UPD_COLS) + "]")
        out.extend(attr_upd_rows)
    if resolution_rows:
        out.append("")
        out.append(":T resolutions")
        out.extend(resolution_rows)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Lead row + observations
# ---------------------------------------------------------------------------


def _render_lead_row(entry: dict[str, Any]) -> str:
    qd = entry.get("query_details") or {}
    if not isinstance(qd, dict):
        raise AnalyzeDenseEmitError(
            f"findings[{entry.get('id')!r}].query_details must be a dict"
        )
    cells = {
        "id":       entry.get("id", ""),
        "name":     entry.get("name", ""),
        "loop":     entry.get("loop", ""),
        "target":   entry.get("target", ""),
        "mode":     entry.get("mode", "graded"),
        "system":   qd.get("system", ""),
        "template": qd.get("template", ""),
        "query":    qd.get("query", ""),
        "window":   _flatten_window(qd.get("time_window", "")),
        "status":   entry.get("status", "active"),
    }
    if not cells["id"] or not cells["name"]:
        raise AnalyzeDenseEmitError(
            f"analyze findings row missing id/name: {entry!r}"
        )
    return "|".join(_cell(cells[c]) for c in _LEAD_COLS)


def _render_observation_subblocks(
    lid: str, entry: dict[str, Any]
) -> list[str]:
    out: list[str] = []
    qd = entry.get("query_details") or {}
    subs = qd.get("substitutions") if isinstance(qd, dict) else None
    if isinstance(subs, dict) and subs:
        rows = [f"{_cell(k)}|{_cell(v)}" for k, v in subs.items()]
        out.append(_block(f":L {lid}.substitutions [key|value]", rows))

    outcome = entry.get("outcome") or {}
    obs = outcome.get("observations") if isinstance(outcome, dict) else None
    if isinstance(obs, dict):
        verts = obs.get("vertices") or []
        edges = obs.get("edges") or []
        if verts:
            out.append(_block(
                f":V {lid}.observations.vertices [" + "|".join(_VERTEX_COLS) + "]",
                [_render_vertex_row(v) for v in verts],
            ))
        if edges:
            out.append(_block(
                f":E {lid}.observations.edges [" + "|".join(_EDGE_COLS) + "]",
                [_render_edge_row(e) for e in edges],
            ))
    return out


def _render_vertex_row(v: dict[str, Any]) -> str:
    cells = [
        v.get("id", ""),
        v.get("type", ""),
        v.get("classification", ""),
        v.get("identifier", ""),
        _serialize_attrs(v.get("attributes") or {}),
    ]
    return "|".join(_cell(c) for c in cells)


def _render_edge_row(e: dict[str, Any]) -> str:
    when = e.get("when") or {}
    timestamp = when.get("timestamp", "") if isinstance(when, dict) else ""
    auth = e.get("authority") or {}
    if not isinstance(auth, dict) or not auth.get("kind") or not auth.get("source"):
        raise AnalyzeDenseEmitError(
            f"observation edge {e.get('id')!r} missing authority kind/source"
        )
    cells = [
        e.get("id", ""),
        e.get("relation", ""),
        e.get("source_vertex", ""),
        e.get("target_vertex", ""),
        timestamp,
        f"{auth['kind']}:{auth['source']}",
        _serialize_attrs(e.get("attributes") or {}),
    ]
    return "|".join(_cell(c) for c in cells)


# ---------------------------------------------------------------------------
# :R rows
# ---------------------------------------------------------------------------


def _render_authz_row(lid: str, r: dict[str, Any]) -> str:
    cells = [
        lid,
        r.get("edge_id") or r.get("edge", ""),
        r.get("verdict", ""),
        r.get("fulfills_contract") or r.get("contract_id", ""),
        r.get("anchor_kind", ""),
        r.get("anchor_id", ""),
        r.get("grounding_kind") or r.get("grounding", ""),
        r.get("authority_for_question") or r.get("authority", ""),
        r.get("as_of", ""),
        r.get("reasoning", ""),
    ]
    return "|".join(_cell(c) for c in cells)


def _render_consult_row(lid: str, r: dict[str, Any]) -> str:
    asks = r.get("asks") or []
    anchor_id = asks[0] if asks else r.get("anchor_id", "")
    cells = [
        lid,
        r.get("verdict", ""),
        r.get("grounding_kind") or r.get("grounding", ""),
        r.get("anchor_kind", ""),
        anchor_id,
        r.get("authority_for_question") or r.get("authority", ""),
        r.get("as_of", ""),
        r.get("reasoning", ""),
    ]
    return "|".join(_cell(c) for c in cells)


def _render_impact_row(lid: str, r: dict[str, Any]) -> str:
    cells = [
        lid,
        r.get("prediction_ref") or r.get("pred_ref", ""),
        r.get("dimension") or r.get("dim", ""),
        r.get("verdict", ""),
        r.get("grounding_kind") or r.get("grounding", ""),
        r.get("authority_for_question") or r.get("authority", ""),
        r.get("as_of", ""),
        r.get("reasoning", ""),
    ]
    return "|".join(_cell(c) for c in cells)


def _render_attr_upd_rows(
    lid: str, upd: dict[str, Any]
) -> list[str]:
    """An attribute_update entry has shape `{target, updates: {k: v, ...}}`.
    The dense `:R attr_updates` table is one row per (target, key, value).
    Lists/dicts collapse to a comma-joined string for the cell — the parser
    accepts this surface and the validator doesn't differentiate.
    """
    target = upd.get("target", "")
    updates = upd.get("updates") or {}
    if not isinstance(updates, dict):
        raise AnalyzeDenseEmitError(
            f"attribute_updates entry on {target!r} has non-dict updates"
        )
    rows: list[str] = []
    for k, v in updates.items():
        rows.append("|".join(_cell(c) for c in [lid, target, k, _flatten_value(v)]))
    return rows


# ---------------------------------------------------------------------------
# :T resolutions
# ---------------------------------------------------------------------------


def _render_resolution_line(lid: str, res: dict[str, Any]) -> str:
    """`<hyp> <before> → <after> [<lead> <pred-tokens> <severity> ⟂ <supp> :: <ann>]`"""
    hyp = res.get("hypothesis") or res.get("hypothesis_id", "")
    if not hyp:
        raise AnalyzeDenseEmitError(
            f"resolution missing hypothesis id: {res!r}"
        )
    before = res.get("before") or res.get("before_weight") or "∅"
    after = res.get("after") or res.get("weight", "")
    if after not in {"++", "+", "-", "--"}:
        raise AnalyzeDenseEmitError(
            f"resolution {hyp!r}: invalid `after` weight {after!r}"
        )

    severity = res.get("severity_of_test") or res.get("severity")
    if not severity:
        severity = "severe" if after in {"++", "--"} else "moderate"

    pred_tokens = list(res.get("matched_prediction_ids") or [])
    refut_tokens = list(res.get("matched_refutation_ids") or [])
    tokens = [str(t) for t in pred_tokens + refut_tokens if t]

    supp_edges = res.get("supporting_edges") or []
    supp_marker = res.get("supporting_marker") or res.get("supporting_edges_marker")
    if supp_edges:
        supp = " ".join(str(e) for e in supp_edges)
    elif supp_marker:
        supp = str(supp_marker)
    else:
        supp = "no-authority"

    annotation = res.get("reasoning", "") or ""

    inner = f"{lid} {' '.join(tokens)} {severity} ⟂ {supp}".replace("  ", " ").strip()
    if annotation:
        inner = f"{inner} :: {annotation}"
    return f"{hyp}  {before} → {after}    [{inner}]"


# ---------------------------------------------------------------------------
# Cell helpers
# ---------------------------------------------------------------------------


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    s = str(value)
    return s.replace("|", "\\|")


def _serialize_attrs(attrs: dict[str, Any]) -> str:
    if not attrs:
        return ""
    parts: list[str] = []
    for k, v in attrs.items():
        if v is None:
            continue
        parts.append(f"{k}={v}")
    return ";".join(parts)


def _flatten_window(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, dict):
        return ";".join(f"{k}={v}" for k, v in value.items() if v is not None)
    return str(value)


def _flatten_value(v: Any) -> str:
    if isinstance(v, list):
        return ",".join(_flatten_value(x) for x in v)
    if isinstance(v, dict):
        return ";".join(f"{k}={_flatten_value(val)}" for k, val in v.items())
    if v is None:
        return ""
    return str(v)


def _block(header: str, rows: list[str]) -> str:
    return "\n".join([header, *rows])
