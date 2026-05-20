"""Tolerant ```invlang parser for defender investigation.md files.

Defender investigations target the same companion shape as soc-agent (the
v2 invlang spec), but writers in the defender stack emit a few patterns
the strict soc-agent parser rejects:

1. Unescaped `|` inside `attrs` cells on `:V` / `:E` rows
   e.g. `flags=EXE_WRITABLE|EXE_LOWER_LAYER` from Falco fields written
   through unchanged. The strict parser counts cells and rejects.

2. Extra empty cells on `:H` hypothesize rows (15 cells where the spec
   declares 14). The model emits an extra `||` separator between refuts
   and authz; the strict parser then mis-aligns refuts content into the
   attr_preds column and fails sub-cell pattern matching.

3. `:T resolutions` rows whose annotation has no supporting-edges
   section, so the `⟂` separator is missing.

This parser produces the same canonical companion dict shape consumed
by query code, but absorbs the surface drift above. No on-disk
migration — historical defender investigations remain untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

INVLANG_FENCE_RE = re.compile(r"```invlang\n(.*?)\n```", re.DOTALL)
HEADER_RE = re.compile(
    r"^:(?P<tag>[A-Z])\s+(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\s*\[(?P<cols>[^\]]*)\])?\s*$"
)
_STORY_HEADER_RE = re.compile(r"^###\s+story\s+(h-[\w\-]+)\s*$")
_LEAD_PREFIX_RE = re.compile(r"^l-(?P<id>[A-Za-z0-9]+)\.(?P<sub>.+)$")
_TOP_LEVEL_HYP_P_RE = re.compile(
    r"^(h-[\w\-]+)\.(preds|attr_preds|refuts|authz|comparisons)$"
)


class DefenderParseError(ValueError):
    """Raised on a parse failure the tolerant parser still can't recover from."""


@dataclass
class Block:
    tag: str
    name: str
    columns: list[str] | None
    rows: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cell-level helpers
# ---------------------------------------------------------------------------


def _split_cells_raw(row: str) -> list[str]:
    """Split a row on `|`, honoring `\\|` as escape. Trims each cell."""
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(row):
        ch = row[i]
        if ch == "\\" and i + 1 < len(row) and row[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "|":
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur).strip())
    return parts


def _collapse_extra_cells_into_attrs(
    cells: list[str], expected: int
) -> list[str]:
    """For rows whose final column is `attrs`, join any cells beyond the
    expected count back into the last column with `|` separators.

    Handles the defender Falco-flags case (`EXE_WRITABLE|EXE_LOWER_LAYER`)
    where the unescaped pipe should have been part of the attrs value.
    """
    if len(cells) <= expected:
        return cells + [""] * (expected - len(cells))
    head = cells[: expected - 1]
    tail = "|".join(cells[expected - 1 :])
    return head + [tail]


_HYP_PRED_CELL_RE = re.compile(r"^p\d+:")
_HYP_ATTR_PRED_CELL_RE = re.compile(r"^ap\d+:")
_HYP_REFUT_CELL_RE = re.compile(r"^r\d+(?:\[|:)")
_HYP_AUTHZ_CELL_RE = re.compile(r"^ac\d+:")


def _normalize_hypothesis_cells(cells: list[str], expected: int) -> list[str]:
    """Normalize a hypothesis row to exactly `expected` cells (14 for the
    canonical schema) by content-aware binning of the middle slice.

    The 14-column schema partitions into:

        [ id, name, attached_to, rel, parent_type, parent_class, parent_attrs ]   # 7 leading positional
        [ preds, attr_preds, refuts, authz ]                                       # 4 middle, content-typed
        [ integrity_waived, weight, status ]                                       # 3 trailing positional

    The middle slot for each row is *bin-routed by content marker*
    (`p<n>:`, `ap<n>:`, `r<n>...`, `ac<n>:`). This tolerates the
    defender drift pattern where one extra empty cell appears between
    refuts and authz: the row has 15 cells but binning still places
    the refuts content in slot 9 and the authz content in slot 10.

    Rows shorter than `expected` are right-padded with empty cells.
    """
    if expected != 14:
        # The schema is fixed; if a caller declares a different width,
        # fall back to plain pad/truncate so we don't silently invent a
        # routing for an unknown layout.
        return (cells + [""] * expected)[:expected]

    out = ["" for _ in range(expected)]
    # Leading positional cells (up to 7 from the head).
    for i in range(min(7, len(cells))):
        out[i] = cells[i]
    # Trailing positional cells (up to 3 from the tail).
    for j in range(1, min(3, len(cells)) + 1):
        out[expected - j] = cells[-j]

    # Middle slice: everything between the leading 7 and trailing 3.
    middle_start = 7
    middle_end = len(cells) - 3
    if middle_end <= middle_start:
        return out

    preds_acc: list[str] = []
    attr_preds_acc: list[str] = []
    refut_acc: list[str] = []
    authz_acc: list[str] = []
    unbinned: list[str] = []
    for c in cells[middle_start:middle_end]:
        if not c:
            continue
        if _HYP_ATTR_PRED_CELL_RE.match(c):
            attr_preds_acc.append(c)
        elif _HYP_PRED_CELL_RE.match(c):
            preds_acc.append(c)
        elif _HYP_REFUT_CELL_RE.match(c):
            refut_acc.append(c)
        elif _HYP_AUTHZ_CELL_RE.match(c):
            authz_acc.append(c)
        else:
            unbinned.append(c)

    out[7] = ";".join(preds_acc)
    out[8] = ";".join(attr_preds_acc)
    out[9] = ";".join(refut_acc)
    out[10] = ";".join(authz_acc)
    # Unbinned middle cells are non-empty cells that didn't match any
    # known content marker. We swallow them rather than raising — the
    # advisory loader prioritizes "load every defender case we can"
    # over strict-schema rejection. Add a console warning only on the
    # CLI path; the parser stays silent here.
    return out


def _parse_attrs(cell: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not cell:
        return out
    for kv in cell.split(";"):
        kv = kv.strip()
        if not kv or "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _parse_auth(cell: str) -> dict[str, str]:
    if ":" not in cell:
        return {"kind": cell.strip(), "source": ""}
    kind, source = cell.split(":", 1)
    return {"kind": kind.strip(), "source": source.strip()}


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    return s


def _split_csv(s: str) -> list[str]:
    return [t.strip() for t in s.split(",") if t.strip()] if s else []


def _split_csv_or_semi(s: str) -> list[str]:
    if not s:
        return []
    sep = ";" if ";" in s else ","
    return [t.strip() for t in s.split(sep) if t.strip()]


def _split_subcells(cell: str) -> list[str]:
    """Top-level semicolon-split that honors double-quoted spans."""
    out: list[str] = []
    cur: list[str] = []
    in_q = False
    i = 0
    while i < len(cell):
        ch = cell[i]
        if ch == "\\" and i + 1 < len(cell):
            cur.append(cell[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
            i += 1
            continue
        if ch == ";" and not in_q:
            tok = "".join(cur).strip()
            if tok:
                out.append(tok)
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tok = "".join(cur).strip()
    if tok:
        out.append(tok)
    return out


# ---------------------------------------------------------------------------
# Block tokenization (per fence)
# ---------------------------------------------------------------------------


def _tokenize_fence(body: str) -> tuple[list[Block], dict[str, str]]:
    blocks: list[Block] = []
    stories: dict[str, str] = {}
    cur: Block | None = None
    cur_story_hid: str | None = None
    cur_story_lines: list[str] = []

    def flush_story() -> None:
        nonlocal cur_story_hid, cur_story_lines
        if cur_story_hid and cur_story_lines:
            stories[cur_story_hid] = "\n".join(cur_story_lines)
        cur_story_hid = None
        cur_story_lines = []

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        m_story = _STORY_HEADER_RE.match(stripped)
        if m_story:
            flush_story()
            cur_story_hid = m_story.group(1)
            cur = None
            continue

        m = HEADER_RE.match(stripped)
        if m:
            flush_story()
            cols_raw = m.group("cols")
            cols = (
                [c.strip().rstrip("?") for c in cols_raw.split("|")]
                if cols_raw is not None
                else None
            )
            cur = Block(
                tag=m.group("tag"),
                name=m.group("name"),
                columns=cols,
                rows=[],
            )
            blocks.append(cur)
            continue

        if cur_story_hid is not None:
            cur_story_lines.append(stripped)
            continue

        if cur is None:
            # Loose content before first block — skip silently.
            continue
        cur.rows.append(stripped)

    flush_story()
    return blocks, stories


# ---------------------------------------------------------------------------
# Schema-mapping projection
# ---------------------------------------------------------------------------


_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]
_HYP_COLS = [
    "id", "name", "attached_to", "rel",
    "parent_type", "parent_class", "parent_attrs",
    "preds", "attr_preds", "refuts", "authz",
    "integrity_waived", "weight", "status",
]


def _vertex_record(block: Block, row: str) -> dict[str, Any]:
    cols = block.columns or _VERTEX_COLS
    raw_cells = _split_cells_raw(row)
    # Last column is `attrs` for both spec and defender — absorb extras.
    cells = _collapse_extra_cells_into_attrs(raw_cells, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("type"):
        raise DefenderParseError(f":V {block.name} vertex missing id/type: {row!r}")
    out: dict[str, Any] = {
        "id": rec["id"],
        "type": rec["type"],
        "classification": rec.get("class", ""),
        "identifier": rec.get("ident", ""),
    }
    if rec.get("attrs"):
        out["attributes"] = _parse_attrs(rec["attrs"])
    return out


def _edge_record(block: Block, row: str) -> dict[str, Any]:
    cols = block.columns or _EDGE_COLS
    raw_cells = _split_cells_raw(row)
    cells = _collapse_extra_cells_into_attrs(raw_cells, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("rel"):
        raise DefenderParseError(f":E {block.name} edge missing id/rel: {row!r}")
    out: dict[str, Any] = {
        "id": rec["id"],
        "relation": rec["rel"],
        "source_vertex": rec.get("src", ""),
        "target_vertex": rec.get("tgt", ""),
    }
    if rec.get("when"):
        out["when"] = {"timestamp": rec["when"]}
    auth_col = next((c for c in cols if c.startswith("auth_kind")), None)
    if auth_col and rec.get(auth_col):
        out["authority"] = _parse_auth(rec[auth_col])
    if rec.get("attrs"):
        out["attributes"] = _parse_attrs(rec["attrs"])
    return out


_PRED_RE = re.compile(r"^(?P<id>p\d+):(?P<subject>[^:]+):(?P<claim>.*)$")
_ATTR_PRED_RE = re.compile(
    r"^(?P<id>ap\d+):(?P<target>[^:]+):(?P<attribute>[^:]+):(?P<claim>.*)$"
)
_REFUT_RE = re.compile(
    r"^(?P<id>r\d+)(?:\[(?P<refs>[^\]]*)\])?:(?P<claim>.*)$"
)
_AUTHZ_RE = re.compile(
    r"^(?P<id>ac\d+):(?P<edge_ref>[^:]+):(?P<anchor_kind>[^:]+):"
    r"(?P<predicate>\"[^\"]*\"|[^:]+):(?P<on_unauth>[^/]+)/(?P<on_indet>.+)$"
)


def _parse_pred_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _PRED_RE.match(sub)
        if not m:
            continue
        out.append({
            "id": m.group("id"),
            "subject": m.group("subject").strip(),
            "claim": _unquote(m.group("claim").strip()),
        })
    return out


def _parse_attr_pred_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _ATTR_PRED_RE.match(sub)
        if not m:
            continue
        out.append({
            "id": m.group("id"),
            "target": m.group("target").strip(),
            "attribute": m.group("attribute").strip(),
            "claim": _unquote(m.group("claim").strip()),
        })
    return out


def _parse_refut_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _REFUT_RE.match(sub)
        if not m:
            continue
        rec: dict[str, Any] = {
            "id": m.group("id"),
            "claim": _unquote(m.group("claim").strip()),
        }
        refs = m.group("refs")
        if refs:
            rec["refutes_predictions"] = _split_csv(refs)
        out.append(rec)
    return out


def _parse_authz_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _AUTHZ_RE.match(sub)
        if not m:
            continue
        out.append({
            "id": m.group("id"),
            "edge_ref": m.group("edge_ref").strip(),
            "anchor_kind": m.group("anchor_kind").strip(),
            "predicate": _unquote(m.group("predicate").strip()),
            "on_unauthorized": m.group("on_unauth").strip(),
            "on_indeterminate": m.group("on_indet").strip(),
        })
    return out


def _hypothesis_record(block: Block, row: str) -> dict[str, Any]:
    cols = block.columns or _HYP_COLS
    raw_cells = _split_cells_raw(row)
    cells = _normalize_hypothesis_cells(raw_cells, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("name"):
        raise DefenderParseError(f":H {block.name} missing id/name: {row!r}")
    out: dict[str, Any] = {"id": rec["id"], "name": rec["name"]}
    if rec.get("attached_to"):
        out["attached_to_vertex"] = rec["attached_to"]
    if rec.get("rel"):
        out.setdefault("proposed_edge", {})["relation"] = rec["rel"]
    if rec.get("parent_type") or rec.get("parent_class"):
        pv: dict[str, Any] = {}
        if rec.get("parent_type"):
            pv["type"] = rec["parent_type"]
        if rec.get("parent_class"):
            pv["classification"] = rec["parent_class"]
        out.setdefault("proposed_edge", {})["parent_vertex"] = pv
    if rec.get("parent_attrs"):
        out.setdefault("proposed_edge", {}).setdefault(
            "parent_vertex", {}
        )["attributes"] = _parse_attrs(rec["parent_attrs"])
    if rec.get("preds"):
        out["predictions"] = _parse_pred_subcells(rec["preds"])
    if rec.get("attr_preds"):
        out["attribute_predictions"] = _parse_attr_pred_subcells(rec["attr_preds"])
    if rec.get("refuts"):
        out["refutation_shape"] = _parse_refut_subcells(rec["refuts"])
    if rec.get("authz"):
        out["authorization_contract"] = _parse_authz_subcells(rec["authz"])
    if rec.get("integrity_waived"):
        out["integrity_waived"] = rec["integrity_waived"]
    if rec.get("weight"):
        out["weight"] = None if rec["weight"] == "null" else rec["weight"]
    if rec.get("status"):
        out["status"] = rec["status"]
    return out


def _lead_header_record(
    block: Block, row: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    cols = block.columns or []
    raw_cells = _split_cells_raw(row)
    cells = raw_cells + [""] * max(0, len(cols) - len(raw_cells))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("name"):
        raise DefenderParseError(f":L findings missing id/name: {row!r}")
    identity: dict[str, Any] = {
        "id": rec["id"], "name": rec["name"], "target": rec.get("target", ""),
    }
    for k_in, k_out in (
        ("loop", "loop"),
        ("mode", "mode"),
        ("trust_root", "trust_root_reached"),
        ("screen_result", "screen_result"),
        ("status", "status"),
    ):
        if rec.get(k_in):
            v = rec[k_in]
            if k_in == "loop":
                try:
                    v = int(v)
                except ValueError:
                    pass
            identity[k_out] = v
    if rec.get("tests"):
        identity["tests_hypotheses"] = _split_csv(rec["tests"])
    if rec.get("fail_reason"):
        identity.setdefault("outcome", {})["failure_reason"] = rec["fail_reason"]
    query_details: dict[str, Any] = {}
    for k_in, k_out in (
        ("system", "system"),
        ("template", "template"),
        ("query", "query"),
        ("window", "time_window"),
    ):
        if rec.get(k_in):
            query_details[k_out] = rec[k_in]
    return identity, query_details


_RESOLUTION_LINE_RE = re.compile(
    r"^(?P<hyp>[^\s]+)\s+(?P<before>\S+)\s*→\s*(?P<after>\S+)\s+"
    r"\[(?P<inner>.*)\]\s*$"
)


def _parse_resolution_line(row: str) -> dict[str, Any] | None:
    """Parse one `:T resolutions` row tolerantly.

    Defender writers sometimes drop the `⟂` supporting-edges separator
    entirely when the resolution rests on inline reasoning rather than a
    cited edge. In that case the bracketed inner is treated as the
    annotation, supporting_edges/supporting_marker are absent.
    Returns None if the head can't be parsed.
    """
    m = _RESOLUTION_LINE_RE.match(row)
    if not m:
        return None
    inner = m.group("inner")
    annotation = ""
    if "::" in inner:
        bracketed, annotation = inner.split("::", 1)
        annotation = annotation.strip()
    else:
        bracketed = inner

    record: dict[str, Any] = {
        "hypothesis": m.group("hyp"),
        "before": m.group("before"),
        "after": m.group("after"),
    }
    lead_id: str | None = None

    if "⟂" in bracketed:
        head, supp = bracketed.split("⟂", 1)
        head_tokens = head.split()
        if len(head_tokens) >= 2:
            lead_id = head_tokens[0]
            record["severity_of_test"] = head_tokens[-1]
        supp_text = supp.strip()
        record["supporting_edges"] = re.findall(r"e-[A-Za-z0-9]+", supp_text)
        if supp_text and not supp_text.startswith("e-"):
            record["supporting_marker"] = supp_text
    else:
        # No ⟂: tolerant path. Try first whitespace-delimited token as a
        # lead-id if it looks like one; otherwise leave unattributed.
        head_tokens = bracketed.split()
        if head_tokens and re.match(r"^l-[\w\-]+$", head_tokens[0]):
            lead_id = head_tokens[0]
        record["supporting_edges"] = []
        if not annotation:
            annotation = bracketed.strip()

    if annotation:
        record["reasoning"] = annotation
    return {"lead_id": lead_id, "record": record}


# ---------------------------------------------------------------------------
# Top-level projection: blocks → canonical companion dict
# ---------------------------------------------------------------------------


def _project_lead_subblock(tag: str, sub: str, block: Block, lead: dict[str, Any]) -> None:
    if tag == "V" and sub == "observations.vertices":
        lead.setdefault("outcome", {}).setdefault("observations", {})["vertices"] = [
            _vertex_record(block, row) for row in block.rows
        ]
        return
    if tag == "E" and sub == "observations.edges":
        lead.setdefault("outcome", {}).setdefault("observations", {})["edges"] = [
            _edge_record(block, row) for row in block.rows
        ]
        return
    if tag == "H" and sub == "new_hypotheses":
        lead["new_hypotheses"] = [_hypothesis_record(block, row) for row in block.rows]
        return
    # Other lead-scoped variants (substitutions, lead_preds, impact_preds) —
    # ignored for the advisory-retrieval surface; they don't materially
    # affect query results we plan to support.


_CONCLUDE_SUB_TABLES = {
    "surviving": ("surviving_hypotheses", ["hyp_id", "final_weight"]),
    "deferred_authz": ("deferred_authorizations", ["contract_ref", "rationale"]),
    "deferred_impact": ("deferred_impact_predictions", ["prediction_ref", "rationale"]),
    "deferred_preds": ("deferred_predictions", ["prediction_ref", "rationale"]),
    "ceiling_test": ("ceiling_test", ["kind", "subject"]),
}


def _project_conclude_scalars(conclude: dict[str, Any], rows: list[str]) -> None:
    termination: dict[str, Any] = {}
    for row in rows:
        m = re.match(r"^(\S+)\s+(.*)$", row)
        if not m:
            continue
        key = m.group(1)
        raw = m.group(2).strip()
        value: Any = None if raw == "null" else _unquote(raw)
        if key == "termination.category":
            termination["category"] = value
        elif key == "termination.rationale":
            termination["rationale"] = value
        elif key in (
            "disposition", "impact_verdict", "impact_severity",
            "confidence", "matched_archetype", "ceiling_rationale", "summary",
        ):
            conclude[key] = value
    if termination:
        conclude["termination"] = termination


def _project_conclude_sub(block: Block, conclude: dict[str, Any]) -> None:
    sub = block.name[len("conclude."):]
    info = _CONCLUDE_SUB_TABLES.get(sub)
    if not info:
        return
    dict_key, _expected = info
    if not block.rows:
        return
    if len(block.rows) == 1 and block.rows[0].strip().lower() == "none":
        if dict_key != "ceiling_test":
            conclude[dict_key] = []
        return

    cols = block.columns or _expected
    if dict_key == "ceiling_test":
        cells = _split_cells_raw(block.rows[0])
        conclude[dict_key] = dict(zip(cols, cells, strict=False))
        return

    bucket: list[Any] = []
    for row in block.rows:
        cells = _split_cells_raw(row)
        if dict_key == "surviving_hypotheses":
            if cells and cells[0]:
                bucket.append(cells[0])
        else:
            bucket.append(dict(zip(cols, cells, strict=False)))
    conclude[dict_key] = bucket


def companion_from_blocks(blocks: list[Block]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    findings: dict[str, dict[str, Any]] = {}
    current_lead: str | None = None

    def lead_bucket(lead_id: str) -> dict[str, Any]:
        lead = findings.setdefault(lead_id, {"id": lead_id})
        lead.setdefault("outcome", {})
        lead.setdefault("query_details", {})
        lead.setdefault("resolutions", [])
        return lead

    for block in blocks:
        tag, name = block.tag, block.name

        if tag == "V" and name == "prologue.vertices":
            out.setdefault("prologue", {})["vertices"] = [
                _vertex_record(block, row) for row in block.rows
            ]
            continue
        if tag == "E" and name == "prologue.edges":
            out.setdefault("prologue", {})["edges"] = [
                _edge_record(block, row) for row in block.rows
            ]
            continue

        if tag == "H" and name == "hypothesize.hypotheses":
            hypotheses = []
            for row in block.rows:
                try:
                    hypotheses.append(_hypothesis_record(block, row))
                except DefenderParseError:
                    continue
            out.setdefault("hypothesize", {})["hypotheses"] = hypotheses
            continue

        if tag == "L" and name == "findings":
            last_lead_id: str | None = None
            for row in block.rows:
                try:
                    identity, query_details = _lead_header_record(block, row)
                except DefenderParseError:
                    continue
                lead_id = identity["id"]
                lead = lead_bucket(lead_id)
                lead.update(identity)
                if query_details:
                    lead.setdefault("query_details", {}).update(query_details)
                last_lead_id = lead_id
            if last_lead_id:
                current_lead = last_lead_id
            continue

        m = _LEAD_PREFIX_RE.match(name)
        if m:
            lead_id = "l-" + m.group("id")
            sub = m.group("sub")
            lead = lead_bucket(lead_id)
            _project_lead_subblock(tag, sub, block, lead)
            current_lead = lead_id
            continue

        if tag == "R" and name in ("authz", "consultations", "impact", "attr_updates"):
            # Resolution rows are columnar — fold them onto the current
            # (or row-explicit) lead's outcome bucket. For the advisory
            # surface we project loosely: keep raw rows under
            # `outcome.{bucket}` without enforcing required cells.
            if not block.columns:
                continue
            cols = block.columns
            bucket_key = {
                "authz": "authorization_resolutions",
                "consultations": "anchor_consultations",
                "impact": "impact_resolutions",
                "attr_updates": "attribute_updates",
            }[name]
            for row in block.rows:
                cells = _split_cells_raw(row)
                rec = dict(zip(cols, cells, strict=False))
                lead_id = rec.get("resolved_by") or rec.get("lead") or current_lead
                if not lead_id:
                    continue
                lead = lead_bucket(lead_id)
                if name == "attr_updates":
                    tgt = rec.get("target")
                    key = rec.get("key")
                    val = rec.get("value", "")
                    if not tgt or not key:
                        continue
                    au = lead.setdefault("outcome", {}).setdefault(
                        "attribute_updates", []
                    )
                    for entry in au:
                        if entry.get("target") == tgt and isinstance(
                            entry.get("updates"), dict
                        ):
                            entry["updates"][key] = val
                            break
                    else:
                        au.append({"target": tgt, "updates": {key: val}})
                else:
                    lead.setdefault("outcome", {}).setdefault(
                        bucket_key, []
                    ).append(rec)
            continue

        if tag == "T" and name == "conclude":
            _project_conclude_scalars(out.setdefault("conclude", {}), block.rows)
            continue
        if tag == "T" and name.startswith("conclude."):
            _project_conclude_sub(block, out.setdefault("conclude", {}))
            continue

        if tag == "T" and name == "resolutions":
            for row in block.rows:
                parsed = _parse_resolution_line(row)
                if not parsed:
                    continue
                lead_id = parsed["lead_id"] or current_lead
                if not lead_id:
                    continue
                lead = lead_bucket(lead_id)
                lead.setdefault("resolutions", []).append(parsed["record"])
                current_lead = lead_id
            continue

        if tag == "T" and name == "shelved":
            cols = block.columns or []
            for row in block.rows:
                cells = _split_cells_raw(row)
                rec = dict(zip(cols, cells, strict=False))
                hyp = rec.get("hyp_id")
                if not hyp:
                    continue
                lead_id = rec.get("by_lead") or current_lead
                if not lead_id:
                    continue
                lead = lead_bucket(lead_id)
                lead.setdefault("shelved", []).append(hyp)
                if rec.get("rationale"):
                    lead.setdefault("shelved_rationales", {})[hyp] = _unquote(
                        rec["rationale"]
                    )
            continue

        # Unknown block — skip silently for resilience.

    if findings:
        out["findings"] = list(findings.values())
    return out


def parse_dense_companion(text: str) -> dict[str, Any]:
    """Walk every ```invlang fence in `text` and project to companion dict."""
    blocks: list[Block] = []
    for match in INVLANG_FENCE_RE.finditer(text):
        fence_blocks, _stories = _tokenize_fence(match.group(1))
        blocks.extend(fence_blocks)
    if not blocks:
        return {}
    return companion_from_blocks(blocks)
