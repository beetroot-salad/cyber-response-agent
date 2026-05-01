"""Dense-format emitter for the SCREEN phase `findings:` block.

Parallel to `_gather_dense.py` and `_analyze_dense.py`. SCREEN findings are
the simplest of the three:

- `mode: screen` on every lead row
- `loop: 0` (pre-PREDICT)
- `resolutions: []` always (no hypotheses exist yet)
- `outcome` is exactly one of `attribute_updates`, `anchor_consultations`, or
  `observations` per lead (never authz / impact / hypothesis resolutions)
- the LAST lead may carry `outcome.screen_result: match | no_match` — promoted
  to the lead row's `screen_result` cell so it round-trips through the dense
  parser's lead-identity projection (see `_dense_parser._lead_header_record`).

Surface produced:

    :L findings [id|name|loop|target|mode|system|template|screen_result]
    l-001|source-classification|0|v-001|screen|classification-lookup||
    l-004|authentication-history|0|v-001|screen|wazuh-indexer|auth-history-cluster-stats|match

Optional sub-blocks per lead, only when populated:

    :V l-001.observations.vertices [...]
    :E l-001.observations.edges    [...]

    :R consultations [resolved_by|result|grounding|anchor_kind|anchor_id|
                      authority|as_of|anchor_query]
    :R attr_updates  [resolved_by|target|key|value]

The consultations column header is `result` (not `verdict`) per schema rule
#11 — the canonical anchor-consultation field is `result`. The dense parser
preserves both names by passthrough; emitting `result` keeps the validator
happy without a translation hop.
"""

from __future__ import annotations

from typing import Any

from scripts.handlers._dense_emit_common import (
    cell,
    render_observation_subblocks,
)


class ScreenDenseEmitError(ValueError):
    """Raised on a malformed input dict to the screen emitter."""


_LEAD_COLS = [
    "id", "name", "loop", "target", "mode",
    "system", "template", "screen_result",
]

_CONSULT_COLS = [
    "resolved_by", "result", "grounding",
    "anchor_kind", "anchor_id", "authority", "as_of", "anchor_query",
]

_ATTR_UPD_COLS = ["resolved_by", "target", "key", "value"]


def emit_screen_findings_dense(findings: list[dict[str, Any]]) -> str:
    """Render screen's findings list as one or more dense blocks.

    Returns the concatenated block text (no fence). Returns an empty string
    when `findings` is empty — caller should skip the write.
    """
    if not findings:
        return ""
    if not isinstance(findings, list):
        raise ScreenDenseEmitError(
            f"emit_screen_findings_dense: expected list, got "
            f"{type(findings).__name__}"
        )

    lead_rows: list[str] = []
    sub_blocks: list[str] = []
    consult_rows: list[str] = []
    attr_upd_rows: list[str] = []

    for entry in findings:
        if not isinstance(entry, dict):
            raise ScreenDenseEmitError(
                f"findings entry must be a dict, got {type(entry).__name__}"
            )
        if entry.get("resolutions"):
            raise ScreenDenseEmitError(
                f"screen findings entry {entry.get('id')!r} carries "
                f"non-empty resolutions; screen runs pre-PREDICT"
            )
        lid = entry.get("id")
        if not isinstance(lid, str) or not lid:
            raise ScreenDenseEmitError(
                f"findings entry missing id (or non-string): {entry!r}"
            )

        outcome = entry.get("outcome") or {}
        if not isinstance(outcome, dict):
            raise ScreenDenseEmitError(
                f"findings[{lid!r}].outcome must be a dict"
            )

        lead_rows.append(_render_lead_row(entry, outcome))

        sub_blocks.extend(
            render_observation_subblocks(lid, outcome, ScreenDenseEmitError)
        )

        for r in outcome.get("anchor_consultations") or []:
            consult_rows.append(_render_consult_row(lid, r))
        for r in outcome.get("attribute_updates") or []:
            attr_upd_rows.extend(_render_attr_upd_rows(lid, r))

    out: list[str] = [":L findings [" + "|".join(_LEAD_COLS) + "]"]
    out.extend(lead_rows)
    for b in sub_blocks:
        out.append("")
        out.append(b)
    if consult_rows:
        out.append("")
        out.append(":R consultations [" + "|".join(_CONSULT_COLS) + "]")
        out.extend(consult_rows)
    if attr_upd_rows:
        out.append("")
        out.append(":R attr_updates [" + "|".join(_ATTR_UPD_COLS) + "]")
        out.extend(attr_upd_rows)
    return "\n".join(out)


def _render_lead_row(entry: dict[str, Any], outcome: dict[str, Any]) -> str:
    qd = entry.get("query_details") or {}
    if not isinstance(qd, dict):
        raise ScreenDenseEmitError(
            f"findings[{entry.get('id')!r}].query_details must be a dict"
        )
    if not entry.get("name"):
        raise ScreenDenseEmitError(
            f"screen findings row missing name: {entry!r}"
        )
    cells = {
        "id":            entry["id"],
        "name":          entry["name"],
        "loop":          entry.get("loop", 0),
        "target":        entry.get("target", ""),
        "mode":          entry.get("mode", "screen"),
        "system":        qd.get("system", ""),
        "template":      qd.get("template", ""),
        "screen_result": outcome.get("screen_result", ""),
    }
    return "|".join(cell(cells[c]) for c in _LEAD_COLS)


def _render_consult_row(lid: str, r: dict[str, Any]) -> str:
    cells = [
        lid,
        r.get("result", ""),
        r.get("grounding_kind", ""),
        r.get("anchor_kind", ""),
        r.get("anchor_id", ""),
        r.get("authority_for_question", ""),
        r.get("as_of", ""),
        r.get("anchor_query", ""),
    ]
    return "|".join(cell(c) for c in cells)


def _render_attr_upd_rows(lid: str, upd: dict[str, Any]) -> list[str]:
    target = upd.get("target")
    if not isinstance(target, str) or not target:
        raise ScreenDenseEmitError(
            f"attribute_updates entry missing target: {upd!r}"
        )
    updates = upd.get("updates")
    if not isinstance(updates, dict):
        raise ScreenDenseEmitError(
            f"attribute_updates entry on {target!r} has non-dict updates"
        )
    rows: list[str] = []
    for k, v in updates.items():
        rows.append("|".join(cell(c) for c in [lid, target, k, _flatten(v)]))
    return rows


def _flatten(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return str(v)
