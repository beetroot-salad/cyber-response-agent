"""Dense-format emitter for the GATHER phase `findings:` block.

Parallel to `_conclude_dense.py` (handler-authored emit + parse) and the
read-only on-disk parser in `_dense_parser.py`. GATHER's lead-pick write
records *which* leads PREDICT picked at loop N; ANALYZE later overlays a
graded findings entry with the same `id` (validator tolerates duplicate
ids — `_primary_lead_at_loop` returns the first match).

This module emits only. The on-disk parser (`companion_dict_from_blocks`)
covers the read path; round-trip parity is checked via that loader.

Surface produced (per `docs/dense-investigation-format.md`):

    :L findings [id|name|loop|target|mode|system|template|query|window|status|tests]
    l-001|enrich-source|1|v-001|lead-pick|wazuh|tpl-x|"<query>"|24h|active|

Optional sub-blocks per lead, only when populated:

    :L l-001.substitutions [key|value]
    user|alice

    :V l-001.observations.vertices [id|type|class|ident|attrs]
    ...

    :E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs]
    ...

The dict shape consumed mirrors the legacy gather YAML (one entry per
lead): `{id, loop, name, target, mode, query_details: {system, template,
query, time_window, substitutions}, outcome: {observations?}, resolutions:
[]}`. Resolutions are always empty for lead-pick; if a caller passes a
non-empty list this module raises (gather doesn't grade).
"""

from __future__ import annotations

from typing import Any


class GatherDenseEmitError(ValueError):
    """Raised on a malformed input dict to the gather emitter."""


_LEAD_COLS = [
    "id", "name", "loop", "target", "mode",
    "system", "template", "query", "window", "status", "tests",
]
_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]


def emit_gather_findings_dense(findings: list[dict[str, Any]]) -> str:
    """Render gather's lead-pick findings as one or more dense blocks.

    Returns the concatenated block text (no fence). Returns an empty
    string when `findings` is empty — caller should skip the write.
    """
    if not findings:
        return ""
    if not isinstance(findings, list):
        raise GatherDenseEmitError(
            f"emit_gather_findings_dense: expected list, got "
            f"{type(findings).__name__}"
        )

    lead_rows: list[str] = []
    sub_blocks: list[str] = []

    for entry in findings:
        if not isinstance(entry, dict):
            raise GatherDenseEmitError(
                f"findings entry must be a dict, got {type(entry).__name__}"
            )
        if entry.get("resolutions"):
            raise GatherDenseEmitError(
                f"gather findings entry {entry.get('id')!r} carries "
                f"non-empty resolutions; gather is lead-pick only"
            )
        lead_rows.append(_render_lead_row(entry))
        sub_blocks.extend(_render_lead_subblocks(entry))

    out: list[str] = []
    out.append(":L findings [" + "|".join(_LEAD_COLS) + "]")
    out.extend(lead_rows)
    for block in sub_blocks:
        out.append("")
        out.append(block)
    return "\n".join(out)


def _render_lead_row(entry: dict[str, Any]) -> str:
    qd = entry.get("query_details") or {}
    if not isinstance(qd, dict):
        raise GatherDenseEmitError(
            f"findings[{entry.get('id')!r}].query_details must be a dict"
        )
    cells = {
        "id":       entry.get("id", ""),
        "name":     entry.get("name", ""),
        "loop":     entry.get("loop", ""),
        "target":   entry.get("target", ""),
        "mode":     entry.get("mode", ""),
        "system":   qd.get("system", ""),
        "template": qd.get("template", ""),
        "query":    qd.get("query", ""),
        "window":   qd.get("time_window", ""),
        "status":   entry.get("status", ""),
        "tests":    _join_csv(entry.get("tests_hypotheses")),
    }
    if not cells["id"] or not cells["name"]:
        raise GatherDenseEmitError(
            f"gather findings row missing id/name: {entry!r}"
        )
    return "|".join(_cell(cells[c]) for c in _LEAD_COLS)


def _render_lead_subblocks(entry: dict[str, Any]) -> list[str]:
    """Emit `l-{id}.*` sub-blocks for one lead. Order: substitutions,
    observation vertices, observation edges. Each only when populated.
    """
    out: list[str] = []
    lid = entry["id"]
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
        raise GatherDenseEmitError(
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


def _join_csv(values: Any) -> str:
    if not values:
        return ""
    if isinstance(values, str):
        return values
    return ",".join(str(v) for v in values)


def _block(header: str, rows: list[str]) -> str:
    return "\n".join([header, *rows])
