"""Dense-format emitter for the ANALYZE phase `findings:` block.

Replaces the YAML synthesis path in `analyze.py`
(`_synthesize_findings_block` → `:::yaml ... :::`) with a dense-block
author so the ANALYZE write lands as ```` ```invlang ````.

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
    :R consultations [resolved_by|result|grounding|anchor_kind|anchor_id|authority|as_of|reasoning]
    :R impact [resolved_by|pred_ref|dim|verdict|grounding|authority|as_of|reasoning]
    :R attr_updates [resolved_by|target|key|value]

    :T resolutions
    h-001  ∅ → ++   [l-001 p1,p2 severe ⟂ e-010 :: <annotation>]

Resolution row form: `<hyp> <before> → <after> [<lead> <pred-tokens>
<severity> ⟂ <supp-edges|marker> :: <annotation>]`. The handler upstream
(`analyze.py:_synthesize_findings_block`) sets every required key on each
resolution dict (`hypothesis`, `before_weight`, `after`, `severity`); we
read those keys directly and fail loud if they're missing.
"""

from __future__ import annotations

from typing import Any

from scripts.handlers._dense_emit_common import (
    block,
    cell,
    flatten_value,
    flatten_window,
    render_observation_subblocks,
    render_substitutions_subblock,
)


class AnalyzeDenseEmitError(ValueError):
    """Raised on a malformed input dict to the analyze emitter."""


_LEAD_COLS = [
    "id", "name", "loop", "target", "mode",
    "system", "template", "query", "window", "status",
]

_AUTHZ_COLS = [
    "resolved_by", "edge", "verdict", "fulfills",
    "anchor_kind", "anchor_id", "grounding", "authority", "as_of", "reasoning",
]
_CONSULT_COLS = [
    "resolved_by", "result", "grounding",
    "anchor_kind", "anchor_id", "authority", "as_of", "reasoning",
]
_IMPACT_COLS = [
    "resolved_by", "pred_ref", "dim", "verdict",
    "grounding", "authority", "as_of", "reasoning",
]
_ATTR_UPD_COLS = ["resolved_by", "target", "key", "value"]

_VALID_WEIGHTS = {"++", "+", "-", "--"}


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
        if not isinstance(lid, str) or not lid:
            raise AnalyzeDenseEmitError(
                f"findings entry missing id (or non-string): {entry!r}"
            )
        lead_rows.append(_render_lead_row(entry))

        qd = entry.get("query_details") or {}
        subs = render_substitutions_subblock(lid, qd) if isinstance(qd, dict) else None
        if subs:
            sub_blocks.append(subs)

        outcome = entry.get("outcome") or {}
        if not isinstance(outcome, dict):
            raise AnalyzeDenseEmitError(
                f"findings[{lid!r}].outcome must be a dict"
            )
        sub_blocks.extend(
            render_observation_subblocks(lid, outcome, AnalyzeDenseEmitError)
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
    for b in sub_blocks:
        out.append("")
        out.append(b)

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
# Lead row
# ---------------------------------------------------------------------------


def _render_lead_row(entry: dict[str, Any]) -> str:
    qd = entry.get("query_details") or {}
    if not isinstance(qd, dict):
        raise AnalyzeDenseEmitError(
            f"findings[{entry.get('id')!r}].query_details must be a dict"
        )
    if not entry.get("name"):
        raise AnalyzeDenseEmitError(
            f"analyze findings row missing name: {entry!r}"
        )
    cells = {
        "id":       entry["id"],
        "name":     entry["name"],
        "loop":     entry.get("loop", ""),
        "target":   entry.get("target", ""),
        "mode":     entry.get("mode", "graded"),
        "system":   qd.get("system", ""),
        "template": qd.get("template", ""),
        "query":    qd.get("query", ""),
        "window":   flatten_window(qd.get("time_window", "")),
        "status":   entry.get("status", "active"),
    }
    return "|".join(cell(cells[c]) for c in _LEAD_COLS)


# ---------------------------------------------------------------------------
# :R rows — handler builds these dicts with canonical long-form keys
# (see `analyze.py:_synthesize_findings_block`); we read them directly.
# ---------------------------------------------------------------------------


def _render_authz_row(lid: str, r: dict[str, Any]) -> str:
    cells = [
        lid,
        r.get("edge", ""),
        r.get("verdict", ""),
        r.get("fulfills_contract", ""),
        r.get("anchor_kind", ""),
        r.get("anchor_id", ""),
        r.get("grounding_kind", ""),
        r.get("authority_for_question", ""),
        r.get("as_of", ""),
        _scrub_inline(r.get("reasoning", "")),
    ]
    return "|".join(cell(c) for c in cells)


def _render_consult_row(lid: str, r: dict[str, Any]) -> str:
    asks = r.get("asks")
    if isinstance(asks, list) and len(asks) > 1:
        raise AnalyzeDenseEmitError(
            f"consultation on lead {lid!r} carries multiple `asks` "
            f"({asks!r}); the dense surface holds a single anchor_id per row"
        )
    cells = [
        lid,
        r.get("result", ""),
        r.get("grounding_kind", ""),
        r.get("anchor_kind", ""),
        r.get("anchor_id", ""),
        r.get("authority_for_question", ""),
        r.get("as_of", ""),
        _scrub_inline(r.get("reasoning", "")),
    ]
    return "|".join(cell(c) for c in cells)


def _render_impact_row(lid: str, r: dict[str, Any]) -> str:
    cells = [
        lid,
        r.get("prediction_ref", ""),
        r.get("dimension", ""),
        r.get("verdict", ""),
        r.get("grounding_kind", ""),
        r.get("authority_for_question", ""),
        r.get("as_of", ""),
        _scrub_inline(r.get("reasoning", "")),
    ]
    return "|".join(cell(c) for c in cells)


def _render_attr_upd_rows(
    lid: str, upd: dict[str, Any]
) -> list[str]:
    """An attribute_update entry has shape `{target, updates: {k: v, ...}}`.
    The dense `:R attr_updates` table is one row per (target, key, value).
    Lists/dicts collapse to a comma-joined string for the cell.
    """
    target = upd.get("target")
    if not isinstance(target, str) or not target:
        raise AnalyzeDenseEmitError(
            f"attribute_updates entry missing target: {upd!r}"
        )
    updates = upd.get("updates")
    if not isinstance(updates, dict):
        raise AnalyzeDenseEmitError(
            f"attribute_updates entry on {target!r} has non-dict updates"
        )
    return [
        "|".join(cell(c) for c in [lid, target, k, flatten_value(v)])
        for k, v in updates.items()
    ]


# ---------------------------------------------------------------------------
# :T resolutions
# ---------------------------------------------------------------------------


def _render_resolution_line(lid: str, res: dict[str, Any]) -> str:
    """`<hyp> <before> → <after> [<lead> <pred-tokens> <severity> ⟂ <supp> :: <ann>]`

    Required keys (set by `analyze.py:_synthesize_findings_block`):
    `hypothesis`, `before_weight`, `after`, `severity`. Optional:
    `matched_prediction_ids`, `matched_refutation_ids`, `supporting_edges`,
    `supporting_marker`, `reasoning`.
    """
    hyp = res.get("hypothesis")
    if not hyp:
        raise AnalyzeDenseEmitError(
            f"resolution missing `hypothesis`: {res!r}"
        )
    before = res.get("before_weight")
    if not before:
        raise AnalyzeDenseEmitError(
            f"resolution {hyp!r} missing `before_weight`: {res!r}"
        )
    after = res.get("after")
    if after not in _VALID_WEIGHTS:
        raise AnalyzeDenseEmitError(
            f"resolution {hyp!r}: invalid `after` weight {after!r}"
        )
    severity = res.get("severity")
    if not severity:
        raise AnalyzeDenseEmitError(
            f"resolution {hyp!r} missing `severity`: {res!r}"
        )

    pred_tokens = list(res.get("matched_prediction_ids") or [])
    refut_tokens = list(res.get("matched_refutation_ids") or [])
    tokens = [str(t) for t in pred_tokens + refut_tokens if t]

    supp_edges = res.get("supporting_edges") or []
    if supp_edges:
        supp = " ".join(str(e) for e in supp_edges)
    else:
        supp = str(res.get("supporting_marker") or "no-authority")

    head_parts = [str(lid)]
    if tokens:
        head_parts.append(" ".join(tokens))
    head_parts.append(str(severity))
    inner = f"{' '.join(head_parts)} ⟂ {supp}"

    annotation = _scrub_inline(res.get("reasoning", ""))
    if annotation:
        inner = f"{inner} :: {annotation}"
    return f"{hyp}  {before} → {after}    [{inner}]"


def _scrub_inline(value: Any) -> str:
    """Collapse newlines/tabs to spaces — every emit cell and the resolution
    annotation must stay on one line so the line-grammar parser can frame
    the row.
    """
    if value is None:
        return ""
    return " ".join(str(value).split())
