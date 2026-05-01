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
coercion. Tokenization (cell splitting, attrs/auth parsing, header detection)
is delegated to `_dense_primitives.py` — the single source of truth for the
line grammar shared with the on-disk parser and the other per-phase parsers.
"""

from __future__ import annotations

from typing import Any

from scripts.handlers import _dense_primitives as _prim


class PrologueOutputError(ValueError):
    """Raised on any malformed prologue dense output."""


_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]
_VALID_TAGS = frozenset("VE")


def strip_envelope(stdout: str) -> str:
    """Strip an optional ```...``` fence around dense subagent output.

    Public so the CONTEXTUALIZE handler can hand the validated dense body
    straight into the on-disk ```invlang fence without re-serializing.
    """
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


def _vertex_row(row: str) -> dict[str, Any]:
    block = _prim.DenseBlock(
        tag="V", name="prologue.vertices", columns=_VERTEX_COLS, rows=[]
    )
    cells = _prim.row_cells(block, row, error_cls=PrologueOutputError)
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
    attrs = _prim.parse_attrs(vattrs, error_cls=PrologueOutputError)
    if attrs:
        out["attributes"] = attrs
    return out


def _edge_row(row: str) -> dict[str, Any]:
    block = _prim.DenseBlock(
        tag="E", name="prologue.edges", columns=_EDGE_COLS, rows=[]
    )
    cells = _prim.row_cells(block, row, error_cls=PrologueOutputError)
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
    parsed_attrs = _prim.parse_attrs(attrs, error_cls=PrologueOutputError)
    if parsed_attrs:
        out["attributes"] = parsed_attrs
    out["authority"] = _prim.parse_auth(auth, error_cls=PrologueOutputError)
    return out


def parse_prologue_dense(stdout: str) -> dict[str, Any]:
    """Parse the dense prologue envelope into the canonical YAML-shaped dict.

    Raises `PrologueOutputError` on the first violation.
    """
    text = strip_envelope(stdout)
    blocks = _prim.tokenize_blocks(
        text, valid_tags=_VALID_TAGS, error_cls=PrologueOutputError
    )

    vertices: list[dict[str, Any]] | None = None
    edges: list[dict[str, Any]] | None = None

    for blk in blocks:
        if blk.tag == "V":
            if blk.name != "prologue.vertices":
                raise PrologueOutputError(
                    f":V block name must be `prologue.vertices`, got "
                    f"{blk.name!r}"
                )
            if blk.columns != _VERTEX_COLS:
                raise PrologueOutputError(
                    f":V prologue.vertices columns must be "
                    f"{_VERTEX_COLS!r}, got {blk.columns!r}"
                )
            if vertices is not None:
                raise PrologueOutputError(
                    ":V prologue.vertices declared more than once"
                )
            vertices = [_vertex_row(row) for row in blk.rows]
        else:  # blk.tag == "E"
            if blk.name != "prologue.edges":
                raise PrologueOutputError(
                    f":E block name must be `prologue.edges`, got {blk.name!r}"
                )
            if blk.columns != _EDGE_COLS:
                raise PrologueOutputError(
                    f":E prologue.edges columns must be "
                    f"{_EDGE_COLS!r}, got {blk.columns!r}"
                )
            if edges is not None:
                raise PrologueOutputError(
                    ":E prologue.edges declared more than once"
                )
            edges = [_edge_row(row) for row in blk.rows]

    if vertices is None:
        raise PrologueOutputError(
            "prologue output missing `:V prologue.vertices` block"
        )
    if edges is None:
        raise PrologueOutputError(
            "prologue output missing `:E prologue.edges` block"
        )

    return {"prologue": {"vertices": vertices, "edges": edges}}
