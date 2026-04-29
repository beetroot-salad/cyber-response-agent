"""Dense-format parser for the contextualize-prologue subagent output.

The subagent emits two blocks (no envelope, no fences):

    :V prologue.vertices [id|type|class|ident|attrs?]
    v-001|endpoint|monitoring-host|172.22.0.10|

    :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
    e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-rule-5710|target_user=sensu;outcome=failed

`parse_prologue_dense` returns the canonical YAML-shaped dict the contextualize
handler embeds into `investigation.md`:

    {
        "prologue": {
            "vertices": [{"id", "type", "classification", "identifier", "attributes?"}, ...],
            "edges": [{"id", "relation", "source_vertex", "target_vertex",
                       "when?": {"timestamp": ...}, "attributes?": {...},
                       "authority": {"kind", "source"}}, ...],
        }
    }

Mirrors `_predict_dense.py`'s fail-fast discipline: the first violation raises
`PrologueOutputError` with a message the agent can read directly. No silent
coercion.
"""

from __future__ import annotations

import re
from typing import Any


class PrologueOutputError(ValueError):
    """Raised on any malformed prologue dense output."""


_HEADER_RE = re.compile(
    r"^:(?P<tag>[VE])\s+(?P<name>\S+)\s*\[(?P<cols>[^\]]*)\]\s*$"
)


_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]


def _strip_envelope(stdout: str) -> str:
    text = stdout.strip()
    if not text:
        raise PrologueOutputError("prologue output is empty")
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline == -1:
            raise PrologueOutputError("prologue output: bare ``` with no body")
        body = text[first_newline + 1 :]
        if body.rstrip().endswith("```"):
            body = body.rstrip()[:-3]
        return body.strip()
    return text


def _split_cells(row: str) -> list[str]:
    return [c.strip() for c in row.split("|")]


def _parse_attrs(cell: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not cell:
        return out
    for kv in cell.split(";"):
        kv = kv.strip()
        if not kv:
            continue
        if "=" not in kv:
            raise PrologueOutputError(
                f"prologue attrs cell has bare token without `=`: {kv!r}"
            )
        k, v = kv.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise PrologueOutputError(
                f"prologue attrs cell has empty key: {kv!r}"
            )
        out[k] = v
    return out


def _parse_auth(cell: str) -> dict[str, str]:
    if ":" not in cell:
        raise PrologueOutputError(
            f"prologue edge auth_kind:source cell missing `:`: {cell!r}"
        )
    kind, source = cell.split(":", 1)
    kind = kind.strip()
    source = source.strip()
    if not kind or not source:
        raise PrologueOutputError(
            f"prologue edge auth_kind:source cell has empty kind or source: "
            f"{cell!r}"
        )
    return {"kind": kind, "source": source}


def _row_cells(blk_tag: str, blk_name: str, expected: list[str], row: str) -> list[str]:
    cells = _split_cells(row)
    if len(cells) < len(expected):
        cells = cells + [""] * (len(expected) - len(cells))
    elif len(cells) > len(expected):
        raise PrologueOutputError(
            f":{blk_tag} {blk_name}: row has more cells than columns "
            f"(expected {len(expected)}, got {len(cells)}): {row!r}"
        )
    return cells


def _vertex_row(row: str) -> dict[str, Any]:
    cells = _row_cells("V", "prologue.vertices", _VERTEX_COLS, row)
    vid, vtype, vclass, vident, vattrs = cells
    if not vid or not vtype or not vclass or not vident:
        raise PrologueOutputError(
            f":V prologue.vertices row missing required cell "
            f"(id/type/class/ident all required): {row!r}"
        )
    out: dict[str, Any] = {
        "id": vid,
        "type": vtype,
        "classification": vclass,
        "identifier": vident,
    }
    attrs = _parse_attrs(vattrs)
    if attrs:
        out["attributes"] = attrs
    return out


def _edge_row(row: str) -> dict[str, Any]:
    cells = _row_cells("E", "prologue.edges", _EDGE_COLS, row)
    eid, rel, src, tgt, when, auth, attrs = cells
    if not eid or not rel or not src or not tgt or not auth:
        raise PrologueOutputError(
            f":E prologue.edges row missing required cell "
            f"(id/rel/src/tgt/auth_kind:source all required): {row!r}"
        )
    out: dict[str, Any] = {
        "id": eid,
        "relation": rel,
        "source_vertex": src,
        "target_vertex": tgt,
    }
    if when:
        out["when"] = {"timestamp": when}
    parsed_attrs = _parse_attrs(attrs)
    if parsed_attrs:
        out["attributes"] = parsed_attrs
    out["authority"] = _parse_auth(auth)
    return out


def parse_prologue_dense(stdout: str) -> dict[str, Any]:
    """Parse the dense prologue envelope into the canonical YAML-shaped dict.

    Raises `PrologueOutputError` on the first violation.
    """
    text = _strip_envelope(stdout)

    # Split into blocks by header lines. Tolerant of blank lines between
    # blocks; intolerant of content before the first header or unknown tags.
    vertices: list[dict[str, Any]] | None = None
    edges: list[dict[str, Any]] | None = None
    cur_tag: str | None = None
    cur_rows: list[dict[str, Any]] | None = None

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        m = _HEADER_RE.match(stripped)
        if m:
            tag = m.group("tag")
            name = m.group("name")
            cols = [c.strip().rstrip("?") for c in m.group("cols").split("|")]
            if tag == "V":
                if name != "prologue.vertices":
                    raise PrologueOutputError(
                        f":V block name must be `prologue.vertices`, got {name!r}"
                    )
                if cols != _VERTEX_COLS:
                    raise PrologueOutputError(
                        f":V prologue.vertices columns must be "
                        f"{_VERTEX_COLS!r}, got {cols!r}"
                    )
                if vertices is not None:
                    raise PrologueOutputError(
                        ":V prologue.vertices declared more than once"
                    )
                vertices = []
                cur_tag = "V"
                cur_rows = vertices
            elif tag == "E":
                if name != "prologue.edges":
                    raise PrologueOutputError(
                        f":E block name must be `prologue.edges`, got {name!r}"
                    )
                if cols != _EDGE_COLS:
                    raise PrologueOutputError(
                        f":E prologue.edges columns must be "
                        f"{_EDGE_COLS!r}, got {cols!r}"
                    )
                if edges is not None:
                    raise PrologueOutputError(
                        ":E prologue.edges declared more than once"
                    )
                edges = []
                cur_tag = "E"
                cur_rows = edges
            else:
                raise PrologueOutputError(
                    f"prologue output: unknown block tag :{tag} "
                    f"(only :V and :E allowed)"
                )
            continue

        # Reject any other `:X ...` looking header (catches typos like `:R`).
        if stripped.startswith(":") and re.match(r"^:[A-Za-z]\b", stripped):
            raise PrologueOutputError(
                f"prologue output: unrecognized block header: {stripped!r}"
            )

        if cur_tag is None or cur_rows is None:
            raise PrologueOutputError(
                f"prologue output: row before any block header: {stripped!r}"
            )
        if cur_tag == "V":
            cur_rows.append(_vertex_row(stripped))
        else:
            cur_rows.append(_edge_row(stripped))

    if vertices is None:
        raise PrologueOutputError(
            "prologue output missing `:V prologue.vertices` block"
        )
    if edges is None:
        raise PrologueOutputError(
            "prologue output missing `:E prologue.edges` block"
        )

    return {"prologue": {"vertices": vertices, "edges": edges}}
