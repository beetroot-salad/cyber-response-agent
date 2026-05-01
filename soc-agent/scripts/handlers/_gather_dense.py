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

from scripts.handlers._dense_emit_common import (
    cell,
    flatten_window,
    render_observation_subblocks,
    render_substitutions_subblock,
)


class GatherDenseEmitError(ValueError):
    """Raised on a malformed input dict to the gather emitter."""


_LEAD_COLS = [
    "id", "name", "loop", "target", "mode",
    "system", "template", "query", "window", "status", "tests",
]


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

        lid = entry["id"]
        qd = entry.get("query_details") or {}
        if isinstance(qd, dict):
            subs = render_substitutions_subblock(lid, qd)
            if subs:
                sub_blocks.append(subs)

        outcome = entry.get("outcome") or {}
        if isinstance(outcome, dict):
            sub_blocks.extend(
                render_observation_subblocks(lid, outcome, GatherDenseEmitError)
            )

    out: list[str] = []
    out.append(":L findings [" + "|".join(_LEAD_COLS) + "]")
    out.extend(lead_rows)
    for b in sub_blocks:
        out.append("")
        out.append(b)
    return "\n".join(out)


def _render_lead_row(entry: dict[str, Any]) -> str:
    qd = entry.get("query_details") or {}
    if not isinstance(qd, dict):
        raise GatherDenseEmitError(
            f"findings[{entry.get('id')!r}].query_details must be a dict"
        )
    if not entry.get("id") or not entry.get("name"):
        raise GatherDenseEmitError(
            f"gather findings row missing id/name: {entry!r}"
        )
    cells = {
        "id":       entry["id"],
        "name":     entry["name"],
        "loop":     entry.get("loop", ""),
        "target":   entry.get("target", ""),
        "mode":     entry.get("mode", ""),
        "system":   qd.get("system", ""),
        "template": qd.get("template", ""),
        "query":    qd.get("query", ""),
        "window":   flatten_window(qd.get("time_window", "")),
        "status":   entry.get("status", ""),
        "tests":    _join_csv(entry.get("tests_hypotheses")),
    }
    return "|".join(cell(cells[c]) for c in _LEAD_COLS)


def _join_csv(values: Any) -> str:
    if not values:
        return ""
    if isinstance(values, str):
        return values
    return ",".join(str(v) for v in values)
