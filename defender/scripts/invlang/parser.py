"""Strict ```invlang parser aligned with the current defender schema.

Source of truth: `defender/skills/dense-language/SKILL.md`. Cell counts
and required separators (`⟂` on `:T resolutions`) are enforced; rows
that don't match are dropped *with a warning* and parsing continues
past them, so a single bad row never silently corrupts a file or
takes down the rest of the load.

What we don't do
----------------
- No tolerance for unescaped `|` inside attrs cells (Falco
  `flags=A|B` etc.). The schema delimits cells with `|`; literal
  values containing `|` must escape it as `\|` or go in raw payloads
  (per the SKILL's "keep high-cardinality details in raw gather
  payloads, not invlang cells" guideline).
- No tolerance for `:H` rows with extra empty cells. The schema
  declares 14 columns; rows with more are rejected.
- No tolerance for `:T resolutions` without the `⟂` supporting-edges
  separator. The annotation grammar is `<lead> <pred-refs> <severity>
  ⟂ <supporting-edges> :: <annotation>`.

What we surface
---------------
Per-row failures land in a `ParseWarning` list returned alongside
the parsed body. The corpus loader threads these into each
`Companion.parse_warnings` and aggregates them in `LoadReport` so
post-mortem debugging always has a paper trail.
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


class RowError(ValueError):
    """Raised inside a row projection. Caught by the block driver, which
    records the failure as a `ParseWarning` and moves on to the next
    row instead of aborting the file."""


@dataclass
class ParseWarning:
    """One row or block we couldn't project, with enough context to
    diagnose later (which file, which block, which row, why).
    `file_path` is filled in by the corpus loader since the parser
    itself only sees text."""
    block: str           # ":H hypothesize.hypotheses", ":T resolutions", ...
    row_index: int       # 0-based row index within the block
    row: str             # the raw row text (truncated to 200 chars)
    reason: str          # the RowError message
    file_path: str = ""  # set by the corpus loader

    def format(self) -> str:
        loc = self.file_path or "(unknown file)"
        return (
            f"{loc}: {self.block} row {self.row_index}: {self.reason} "
            f"| row={self.row[:200]!r}"
        )


@dataclass
class Block:
    tag: str
    name: str
    columns: list[str] | None
    rows: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cell-level helpers (strict)
# ---------------------------------------------------------------------------


def _split_cells(row: str) -> list[str]:
    """Split a row on `|`, honoring `\\|` as an escape."""
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


def _row_cells(block: Block, row: str, expected: int) -> list[str]:
    """Strict cell-count check: too many cells = RowError (the typical
    LLM hiccup is an unescaped `|` inside an attrs value). Short rows
    are right-padded — that's not a hiccup, just trailing-optional cells.
    """
    cells = _split_cells(row)
    if len(cells) > expected:
        raise RowError(
            f"row has {len(cells)} cells but {expected} expected "
            f"(check for unescaped `|` inside an attrs/value cell)"
        )
    if len(cells) < expected:
        cells = cells + [""] * (expected - len(cells))
    return cells


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
# Block tokenization
# ---------------------------------------------------------------------------


def _tokenize_fence(body: str) -> list[Block]:
    blocks: list[Block] = []
    cur: Block | None = None
    in_story = False

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if _STORY_HEADER_RE.match(stripped):
            # Defender SKILL doesn't use `### story` blocks today; tolerate
            # the header (consume following lines until next block) but
            # don't project. Soc-agent uses it for hypothesis prose.
            in_story = True
            cur = None
            continue

        m = HEADER_RE.match(stripped)
        if m:
            in_story = False
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
            )
            blocks.append(cur)
            continue

        if in_story or cur is None:
            continue
        cur.rows.append(stripped)
    return blocks


# ---------------------------------------------------------------------------
# Sub-cell projections (raise RowError on malformed sub-cells)
# ---------------------------------------------------------------------------


_PRED_RE = re.compile(r"^(?P<id>p\d+):(?P<subject>[^:]+):(?P<claim>.*)$")
_ATTR_PRED_RE = re.compile(
    r"^(?P<id>ap\d+):(?P<target>[^:]+):(?P<attribute>[^:]+):(?P<claim>.*)$"
)
_REFUT_RE = re.compile(r"^(?P<id>r\d+)(?:\[(?P<refs>[^\]]*)\])?:(?P<claim>.*)$")
_AUTHZ_RE = re.compile(
    r"^(?P<id>ac\d+):(?P<edge_ref>[^:]+):(?P<anchor_kind>[^:]+):"
    r"(?P<predicate>\"[^\"]*\"|[^:]+):(?P<on_unauth>[^/]+)/(?P<on_indet>.+)$"
)


def _parse_pred_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _PRED_RE.match(sub)
        if not m:
            raise RowError(f"prediction sub-cell malformed: {sub!r}")
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
            raise RowError(f"attribute_prediction sub-cell malformed: {sub!r}")
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
            raise RowError(f"refutation sub-cell malformed: {sub!r}")
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
            raise RowError(f"authz contract sub-cell malformed: {sub!r}")
        out.append({
            "id": m.group("id"),
            "edge_ref": m.group("edge_ref").strip(),
            "anchor_kind": m.group("anchor_kind").strip(),
            "predicate": _unquote(m.group("predicate").strip()),
            "on_unauthorized": m.group("on_unauth").strip(),
            "on_indeterminate": m.group("on_indet").strip(),
        })
    return out


# ---------------------------------------------------------------------------
# Row → record projections
# ---------------------------------------------------------------------------


_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]


def _vertex_record(block: Block, row: str) -> dict[str, Any]:
    cols = block.columns or _VERTEX_COLS
    cells = _row_cells(block, row, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("type"):
        raise RowError("vertex missing id/type")
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
    cells = _row_cells(block, row, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("rel"):
        raise RowError("edge missing id/rel")
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


def _hypothesis_record(block: Block, row: str) -> dict[str, Any]:
    cols = block.columns or []
    cells = _row_cells(block, row, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("name"):
        raise RowError("hypothesis missing id/name")
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
    cells = _row_cells(block, row, len(cols))
    rec = dict(zip(cols, cells, strict=False))
    if not rec.get("id") or not rec.get("name"):
        raise RowError("findings row missing id/name")
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


def _resolution_record(row: str) -> tuple[str | None, dict[str, Any]]:
    """Parse `<hyp> <before> → <after> [<lead> <pred-refs> <sev> ⟂ <edges> :: <ann>]`.

    The `⟂` separator is required by the current schema. Rows that omit
    it raise RowError and are dropped with a warning.
    """
    m = _RESOLUTION_LINE_RE.match(row)
    if not m:
        raise RowError("resolution head doesn't match `<hyp> <before> → <after> [...]`")
    inner = m.group("inner")
    annotation = ""
    if "::" in inner:
        bracketed, annotation = inner.split("::", 1)
        annotation = annotation.strip()
    else:
        bracketed = inner
    if "⟂" not in bracketed:
        raise RowError("resolution missing `⟂` supporting-edges separator")
    head, supp = bracketed.split("⟂", 1)
    head_tokens = head.split()
    if len(head_tokens) < 2:
        raise RowError("resolution head needs lead-id + severity")
    lead_id = head_tokens[0]
    severity = head_tokens[-1]
    supp_text = supp.strip()
    record: dict[str, Any] = {
        "hypothesis": m.group("hyp"),
        "before": m.group("before"),
        "after": m.group("after"),
        "severity_of_test": severity,
        "supporting_edges": re.findall(r"e-[A-Za-z0-9]+", supp_text),
    }
    if supp_text and not supp_text.startswith("e-"):
        record["supporting_marker"] = supp_text
    if annotation:
        record["reasoning"] = annotation
    return lead_id, record


# ---------------------------------------------------------------------------
# Block driver: catches RowError per row, records ParseWarning, continues
# ---------------------------------------------------------------------------


def _project_rows(
    block: Block,
    project_one,
    warnings: list[ParseWarning],
) -> list[Any]:
    """Drive a row-projection function across `block.rows`. Each row
    failure becomes a ParseWarning; the rest of the block continues."""
    out: list[Any] = []
    for idx, row in enumerate(block.rows):
        try:
            out.append(project_one(block, row))
        except RowError as e:
            warnings.append(ParseWarning(
                block=f":{block.tag} {block.name}",
                row_index=idx,
                row=row,
                reason=str(e),
            ))
    return out


_CONCLUDE_SUB_TABLES = {
    "surviving": "surviving_hypotheses",
    "deferred_authz": "deferred_authorizations",
    "deferred_impact": "deferred_impact_predictions",
    "deferred_preds": "deferred_predictions",
    "ceiling_test": "ceiling_test",
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


def _project_conclude_sub(
    block: Block, conclude: dict[str, Any], warnings: list[ParseWarning]
) -> None:
    sub = block.name[len("conclude."):]
    dict_key = _CONCLUDE_SUB_TABLES.get(sub)
    if not dict_key:
        return
    if not block.rows:
        return
    if len(block.rows) == 1 and block.rows[0].strip().lower() == "none":
        if dict_key != "ceiling_test":
            conclude[dict_key] = []
        return
    cols = block.columns or []
    if dict_key == "ceiling_test":
        try:
            cells = _row_cells(block, block.rows[0], len(cols))
        except RowError as e:
            warnings.append(ParseWarning(
                block=f":{block.tag} {block.name}", row_index=0,
                row=block.rows[0], reason=str(e),
            ))
            return
        conclude[dict_key] = dict(zip(cols, cells, strict=False))
        return

    bucket: list[Any] = []
    for idx, row in enumerate(block.rows):
        try:
            cells = _row_cells(block, row, len(cols))
        except RowError as e:
            warnings.append(ParseWarning(
                block=f":{block.tag} {block.name}", row_index=idx,
                row=row, reason=str(e),
            ))
            continue
        if dict_key == "surviving_hypotheses":
            if cells and cells[0]:
                bucket.append(cells[0])
        else:
            bucket.append(dict(zip(cols, cells, strict=False)))
    conclude[dict_key] = bucket


# ---------------------------------------------------------------------------
# Top-level projection
# ---------------------------------------------------------------------------


def _project_lead_subblock(
    tag: str,
    sub: str,
    block: Block,
    lead: dict[str, Any],
    warnings: list[ParseWarning],
) -> None:
    if tag == "V" and sub == "observations.vertices":
        lead.setdefault("outcome", {}).setdefault("observations", {})["vertices"] = (
            _project_rows(block, _vertex_record, warnings)
        )
        return
    if tag == "E" and sub == "observations.edges":
        lead.setdefault("outcome", {}).setdefault("observations", {})["edges"] = (
            _project_rows(block, _edge_record, warnings)
        )
        return
    if tag == "H" and sub == "new_hypotheses":
        lead["new_hypotheses"] = _project_rows(block, _hypothesis_record, warnings)
        return
    # Other lead-scoped variants (substitutions, lead_preds, impact_preds)
    # are not part of the advisory-retrieval surface.


def companion_from_blocks(
    blocks: list[Block],
) -> tuple[dict[str, Any], list[ParseWarning]]:
    """Project blocks → canonical companion dict + per-row warnings."""
    out: dict[str, Any] = {}
    warnings: list[ParseWarning] = []
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
            out.setdefault("prologue", {})["vertices"] = (
                _project_rows(block, _vertex_record, warnings)
            )
            continue
        if tag == "E" and name == "prologue.edges":
            out.setdefault("prologue", {})["edges"] = (
                _project_rows(block, _edge_record, warnings)
            )
            continue
        if tag == "H" and name == "hypothesize.hypotheses":
            out.setdefault("hypothesize", {})["hypotheses"] = (
                _project_rows(block, _hypothesis_record, warnings)
            )
            continue

        if tag == "L" and name == "findings":
            last_lead_id: str | None = None
            for idx, row in enumerate(block.rows):
                try:
                    identity, query_details = _lead_header_record(block, row)
                except RowError as e:
                    warnings.append(ParseWarning(
                        block=f":{tag} {name}", row_index=idx,
                        row=row, reason=str(e),
                    ))
                    continue
                lead = lead_bucket(identity["id"])
                lead.update(identity)
                if query_details:
                    lead.setdefault("query_details", {}).update(query_details)
                last_lead_id = identity["id"]
            if last_lead_id:
                current_lead = last_lead_id
            continue

        m = _LEAD_PREFIX_RE.match(name)
        if m:
            lead_id = "l-" + m.group("id")
            sub = m.group("sub")
            lead = lead_bucket(lead_id)
            _project_lead_subblock(tag, sub, block, lead, warnings)
            current_lead = lead_id
            continue

        if tag == "R" and name in ("authz", "consultations", "impact", "attr_updates"):
            cols = block.columns or []
            bucket_key = {
                "authz": "authorization_resolutions",
                "consultations": "anchor_consultations",
                "impact": "impact_resolutions",
                "attr_updates": "attribute_updates",
            }[name]
            for idx, row in enumerate(block.rows):
                try:
                    cells = _row_cells(block, row, len(cols))
                except RowError as e:
                    warnings.append(ParseWarning(
                        block=f":{tag} {name}", row_index=idx,
                        row=row, reason=str(e),
                    ))
                    continue
                rec = dict(zip(cols, cells, strict=False))
                lead_id = rec.get("resolved_by") or rec.get("lead") or current_lead
                if not lead_id:
                    warnings.append(ParseWarning(
                        block=f":{tag} {name}", row_index=idx,
                        row=row, reason="row has no lead attribution",
                    ))
                    continue
                lead = lead_bucket(lead_id)
                if name == "attr_updates":
                    tgt = rec.get("target")
                    key = rec.get("key")
                    val = rec.get("value", "")
                    if not tgt or not key:
                        warnings.append(ParseWarning(
                            block=f":{tag} {name}", row_index=idx,
                            row=row, reason="attr_updates missing target/key",
                        ))
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
            _project_conclude_sub(block, out.setdefault("conclude", {}), warnings)
            continue

        if tag == "T" and name == "resolutions":
            for idx, row in enumerate(block.rows):
                try:
                    lead_id, record = _resolution_record(row)
                except RowError as e:
                    warnings.append(ParseWarning(
                        block=f":{tag} {name}", row_index=idx,
                        row=row, reason=str(e),
                    ))
                    continue
                lid = lead_id or current_lead
                if not lid:
                    warnings.append(ParseWarning(
                        block=f":{tag} {name}", row_index=idx,
                        row=row, reason="resolution has no lead attribution",
                    ))
                    continue
                lead = lead_bucket(lid)
                lead.setdefault("resolutions", []).append(record)
                current_lead = lid
            continue

        if tag == "T" and name == "shelved":
            cols = block.columns or []
            for idx, row in enumerate(block.rows):
                try:
                    cells = _row_cells(block, row, len(cols))
                except RowError as e:
                    warnings.append(ParseWarning(
                        block=f":{tag} {name}", row_index=idx,
                        row=row, reason=str(e),
                    ))
                    continue
                rec = dict(zip(cols, cells, strict=False))
                hyp = rec.get("hyp_id")
                if not hyp:
                    continue
                lid = rec.get("by_lead") or current_lead
                if not lid:
                    continue
                lead = lead_bucket(lid)
                lead.setdefault("shelved", []).append(hyp)
                if rec.get("rationale"):
                    lead.setdefault("shelved_rationales", {})[hyp] = _unquote(
                        rec["rationale"]
                    )
            continue

        warnings.append(ParseWarning(
            block=f":{tag} {name}", row_index=-1, row="",
            reason="unknown block — no projection rule",
        ))

    if findings:
        out["findings"] = list(findings.values())
    return out, warnings


def parse_dense_companion(
    text: str,
) -> tuple[dict[str, Any], list[ParseWarning]]:
    """Walk every ```invlang fence in `text` and project to companion dict.
    Returns (companion_body, parse_warnings)."""
    blocks: list[Block] = []
    for match in INVLANG_FENCE_RE.finditer(text):
        blocks.extend(_tokenize_fence(match.group(1)))
    if not blocks:
        return {}, []
    return companion_from_blocks(blocks)
