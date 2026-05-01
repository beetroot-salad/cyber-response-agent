"""Shared cell/row/observation helpers for dense-format emitters.

`_gather_dense.py`, `_analyze_dense.py`, and `_conclude_dense.py` all author
`:::invlang` blocks by hand. The cell escape, attr serialization, and
observation-row shapes are identical across them — this module is the
single source of truth.

Phase-specific emitters keep their own `*EmitError` class (so retry
prompts can quote a phase-tagged message) and pass it via `error_cls` to
the helpers that can fail loud.
"""

from __future__ import annotations

from typing import Any


_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]


def cell(value: Any) -> str:
    """Stringify a value for one `|`-separated cell. Escapes embedded `|`."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).replace("|", "\\|")


def serialize_attrs(attrs: dict[str, Any]) -> str:
    """`{k: v, ...}` → `key=value;key=value`, dropping `None` values."""
    if not attrs:
        return ""
    return ";".join(f"{k}={v}" for k, v in attrs.items() if v is not None)


def flatten_window(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, dict):
        return ";".join(f"{k}={v}" for k, v in value.items() if v is not None)
    return str(value)


def flatten_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(flatten_value(x) for x in v)
    if isinstance(v, dict):
        return ";".join(f"{k}={flatten_value(val)}" for k, val in v.items())
    return str(v)


def block(header: str, rows: list[str]) -> str:
    return "\n".join([header, *rows])


def render_vertex_row(v: dict[str, Any]) -> str:
    cells = [
        v.get("id", ""),
        v.get("type", ""),
        v.get("classification", ""),
        v.get("identifier", ""),
        serialize_attrs(v.get("attributes") or {}),
    ]
    return "|".join(cell(c) for c in cells)


def render_edge_row(e: dict[str, Any], error_cls: type[Exception]) -> str:
    when = e.get("when") or {}
    timestamp = when.get("timestamp", "") if isinstance(when, dict) else ""
    auth = e.get("authority") or {}
    if not isinstance(auth, dict) or not auth.get("kind") or not auth.get("source"):
        raise error_cls(
            f"observation edge {e.get('id')!r} missing authority kind/source"
        )
    cells = [
        e.get("id", ""),
        e.get("relation", ""),
        e.get("source_vertex", ""),
        e.get("target_vertex", ""),
        timestamp,
        f"{auth['kind']}:{auth['source']}",
        serialize_attrs(e.get("attributes") or {}),
    ]
    return "|".join(cell(c) for c in cells)


def vertex_header() -> str:
    return ":V {prefix}.observations.vertices [" + "|".join(_VERTEX_COLS) + "]"


def edge_header() -> str:
    return ":E {prefix}.observations.edges [" + "|".join(_EDGE_COLS) + "]"


def render_observation_subblocks(
    lid: str,
    outcome: dict[str, Any],
    error_cls: type[Exception],
) -> list[str]:
    """Emit `:V l-{id}.observations.vertices` and `:E l-{id}.observations.edges`
    sub-blocks when the lead's outcome carries them. Returns `[]` otherwise.
    """
    obs = outcome.get("observations")
    if not isinstance(obs, dict):
        return []
    out: list[str] = []
    verts = obs.get("vertices") or []
    edges = obs.get("edges") or []
    if verts:
        out.append(block(
            f":V {lid}.observations.vertices [" + "|".join(_VERTEX_COLS) + "]",
            [render_vertex_row(v) for v in verts],
        ))
    if edges:
        out.append(block(
            f":E {lid}.observations.edges [" + "|".join(_EDGE_COLS) + "]",
            [render_edge_row(e, error_cls) for e in edges],
        ))
    return out


def render_substitutions_subblock(lid: str, qd: dict[str, Any]) -> str | None:
    subs = qd.get("substitutions")
    if not isinstance(subs, dict) or not subs:
        return None
    rows = [f"{cell(k)}|{cell(v)}" for k, v in subs.items()]
    return block(f":L {lid}.substitutions [key|value]", rows)
