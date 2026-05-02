"""Dense PREDICT envelope parser.

Reads any of the DP / DB / DH grammars (defined in `_dense_outputs.py`) and
emits a dict matching the YAML envelope shape that `score.py` already consumes:

    {"predict": {
        "loop": int,
        "shape": "E"|"A"|"M",
        "hypotheses": [
            {"id", "name", "attached_to_vertex", "proposed_edge", "story",
             "predictions": [...], "attribute_predictions": [...],
             "refutation_shape": [...], "authorization_contract": [...],
             "integrity_waived", "weight", "status"}
        ],
        "branch_plan": {"primary_lead": ..., "predictions": [...]},
        "routing": {"selected_lead", "composite_secondary", ...},
    }}

Returns `(envelope, parse_errors)`. `parse_errors` is a list of strings; if
non-empty, `score.py` should treat parse rate as 0 for D9.

The parser is intentionally fail-soft on cell-shape errors (collects all
problems, still returns a best-effort envelope) but strict on the field-
presence matrix (Shape E with hypotheses → error; Shape A without authz on
any hypothesis → error).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

DEVIATION_KINDS = {"geometry", "cadence", "novel-artifact", "absence"}
NON_DEVIATION_KINDS = {"presence", "absolute"}
ALL_KINDS = DEVIATION_KINDS | NON_DEVIATION_KINDS


@dataclass
class _Block:
    tag: str          # "H", "L", "R", "P"
    name: str         # e.g., "hypotheses", "h-001.preds", "routing", "routing.lead_hints"
    columns: list[str]  # parsed column names; empty for flat key/value blocks
    rows: list[str]   # raw row strings (after the header)


# ---------------------------------------------------------------------------
# Tokenizer

_HEADER_RE = re.compile(
    r"""^:(?P<tag>[A-Z])\s+(?P<name>[A-Za-z0-9_.\-]+)(?:\s*\[(?P<cols>[^\]]+)\])?\s*$"""
)


def _tokenize(text: str) -> tuple[dict[str, Any], list[_Block], dict[str, list[str]], list[str]]:
    """Split text into header, blocks, story prose blocks, and parse errors."""
    errors: list[str] = []
    header: dict[str, Any] = {}
    blocks: list[_Block] = []
    stories: dict[str, list[str]] = {}

    lines = text.splitlines()
    i = 0
    cur_block: _Block | None = None
    cur_story: tuple[str, list[str]] | None = None

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Top-level header: `predict loop=N shape=X`
        if stripped.startswith("predict ") and not header:
            m_loop = re.search(r"loop=(\d+)", stripped)
            m_shape = re.search(r"shape=([EAM])", stripped)
            if not m_loop or not m_shape:
                errors.append(f"malformed predict header: {stripped!r}")
            else:
                header["loop"] = int(m_loop.group(1))
                header["shape"] = m_shape.group(1)
            cur_block = None
            cur_story = None
            i += 1
            continue

        # Story heading: `### story h-NNN`
        m_story = re.match(r"^###\s+story\s+(h-[\w\-]+)\s*$", stripped)
        if m_story:
            if cur_story:
                stories[cur_story[0]] = cur_story[1]
            cur_story = (m_story.group(1), [])
            cur_block = None
            i += 1
            continue

        # Block header: `:T name [cols]` or `:T name`
        m_block = _HEADER_RE.match(stripped)
        if m_block:
            if cur_story:
                stories[cur_story[0]] = cur_story[1]
                cur_story = None
            cols_raw = m_block.group("cols") or ""
            cols = [c.strip().rstrip("?") for c in cols_raw.split("|")] if cols_raw else []
            cur_block = _Block(
                tag=m_block.group("tag"),
                name=m_block.group("name"),
                columns=cols,
                rows=[],
            )
            blocks.append(cur_block)
            i += 1
            continue

        # In-story sentence line
        if cur_story is not None and stripped:
            cur_story[1].append(stripped)
            i += 1
            continue

        # In-block row
        if cur_block is not None and stripped:
            cur_block.rows.append(stripped)
            i += 1
            continue

        # Blank line — closes current story but keeps current block open
        # (blocks span until the next `:T` header or EOF)
        if not stripped and cur_story is not None:
            stories[cur_story[0]] = cur_story[1]
            cur_story = None

        i += 1

    if cur_story:
        stories[cur_story[0]] = cur_story[1]

    if "loop" not in header:
        errors.append("missing predict header line")

    return header, blocks, stories, errors


# ---------------------------------------------------------------------------
# Cell parsers

def _split_cells(row: str) -> list[str]:
    # naive split on `|`, respecting bracket-escape \] inside annotations
    return [c.strip() for c in row.split("|")]


_QUOTED = re.compile(r'^"(.*)"$')


def _unquote(s: str) -> str:
    m = _QUOTED.match(s)
    return m.group(1) if m else s


def _parse_pred_subcell(cell: str, owner_id: str, errors: list[str]) -> dict[str, Any] | None:
    """Parse one packed prediction sub-cell (DP / DH).

    Forms:
      p<n>:<subject>:<kind>:s<m>:"<claim>"
      p<n>:<subject>:<kind>:s<m>:"<claim>":<sk>:<sel>:<dim>     # deviation
    """
    if not cell:
        return None
    # split on `:` but preserve quoted segments
    tokens = _split_colon_preserving_quotes(cell)
    if len(tokens) < 5:
        errors.append(f"{owner_id}: pred cell too short: {cell!r}")
        return None
    pid, subject, kind, story_link, claim = tokens[:5]
    if not re.match(r"^p\d+$", pid):
        errors.append(f"{owner_id}: bad pred id {pid!r}")
        return None
    if kind not in ALL_KINDS:
        errors.append(f"{owner_id}.{pid}: unknown kind {kind!r}")
    out: dict[str, Any] = {
        "id": pid,
        "subject": subject,
        "kind": kind,
        "from_story_link": story_link,
        "claim": _unquote(claim),
    }
    if kind in DEVIATION_KINDS:
        if len(tokens) != 8:
            errors.append(f"{owner_id}.{pid}: deviation kind requires comparison positionals")
        else:
            out["comparison"] = {
                "selector_kind": tokens[5],
                "selector": _unquote(tokens[6]),
                "dimension": tokens[7],
            }
    elif kind in NON_DEVIATION_KINDS and len(tokens) > 5:
        errors.append(f"{owner_id}.{pid}: non-deviation kind must not carry comparison")
    return out


def _parse_attr_pred_subcell(cell: str, owner_id: str, errors: list[str]) -> dict[str, Any] | None:
    """ap<n>:<target>:<attribute>:<kind>:"<claim>" — no comparison, ever."""
    if not cell:
        return None
    tokens = _split_colon_preserving_quotes(cell)
    if len(tokens) != 5:
        errors.append(f"{owner_id}: bad attr_pred cell: {cell!r}")
        return None
    apid, target, attribute, kind, claim = tokens
    if not re.match(r"^ap\d+$", apid):
        errors.append(f"{owner_id}: bad attr_pred id {apid!r}")
        return None
    if kind not in ALL_KINDS:
        errors.append(f"{owner_id}.{apid}: unknown kind {kind!r}")
    return {
        "id": apid,
        "target": target,
        "attribute": attribute,
        "kind": kind,
        "claim": _unquote(claim),
    }


def _parse_refut_subcell(cell: str, owner_id: str, errors: list[str]) -> dict[str, Any] | None:
    """r<n>[<refs>]:<kind>:"<claim>" — comparison positionals on deviation kinds."""
    if not cell:
        return None
    m = re.match(r"^(r\d+)\[([^\]]*)\]:(.+)$", cell)
    if not m:
        errors.append(f"{owner_id}: bad refut cell: {cell!r}")
        return None
    rid, refs_csv, rest = m.group(1), m.group(2), m.group(3)
    refs = [r.strip() for r in refs_csv.split(",") if r.strip()]
    tokens = _split_colon_preserving_quotes(rest)
    if len(tokens) < 2:
        errors.append(f"{owner_id}.{rid}: bad refut tail: {rest!r}")
        return None
    kind, claim = tokens[0], tokens[1]
    if kind == "presence":
        errors.append(f"{owner_id}.{rid}: kind=presence is forbidden on refutations")
    elif kind not in ALL_KINDS:
        errors.append(f"{owner_id}.{rid}: unknown kind {kind!r}")
    out: dict[str, Any] = {
        "id": rid,
        "refutes_predictions": refs,
        "kind": kind,
        "claim": _unquote(claim),
    }
    if kind in DEVIATION_KINDS:
        if len(tokens) != 5:
            errors.append(f"{owner_id}.{rid}: deviation kind refutation requires comparison positionals")
        else:
            out["comparison"] = {
                "selector_kind": tokens[2],
                "selector": _unquote(tokens[3]),
                "dimension": tokens[4],
            }
    elif len(tokens) > 2:
        errors.append(f"{owner_id}.{rid}: non-deviation kind must not carry comparison")
    return out


def _parse_authz_subcell(cell: str, owner_id: str, errors: list[str]) -> dict[str, Any] | None:
    """ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>"""
    if not cell:
        return None
    tokens = _split_colon_preserving_quotes(cell)
    if len(tokens) != 5:
        errors.append(f"{owner_id}: bad authz cell: {cell!r}")
        return None
    acid, edge_ref, anchor_kind, predicate, dispositions = tokens
    if not re.match(r"^ac\d+$", acid):
        errors.append(f"{owner_id}: bad authz id {acid!r}")
        return None
    parts = dispositions.split("/")
    if len(parts) != 2:
        errors.append(f"{owner_id}.{acid}: bad on_unauth/on_indet: {dispositions!r}")
        on_u, on_i = "esc", "esc"
    else:
        on_u, on_i = parts
    return {
        "id": acid,
        "edge_ref": edge_ref,
        "anchor_kind": anchor_kind,
        "predicate": _unquote(predicate),
        "on_unauthorized": on_u,
        "on_indeterminate": on_i,
    }


def _split_colon_preserving_quotes(s: str) -> list[str]:
    """Split on `:` outside of double-quoted strings."""
    out: list[str] = []
    buf: list[str] = []
    in_quote = False
    for ch in s:
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
        elif ch == ":" and not in_quote:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf).strip())
    return out


# ---------------------------------------------------------------------------
# Block dispatch → envelope assembly

def parse_dense(text: str) -> tuple[dict[str, Any], list[str]]:
    header, blocks, stories, errors = _tokenize(text)
    pred: dict[str, Any] = {
        "loop": header.get("loop"),
        "shape": header.get("shape"),
    }
    hypotheses: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    branch_plan: dict[str, Any] = {}
    routing: dict[str, Any] = {}

    # Pass 1: hypotheses (`:H hypotheses`)
    for blk in blocks:
        if blk.tag == "H" and blk.name == "hypotheses":
            mode = "DB" if "preds" not in blk.columns else (
                "DP" if "authz" in blk.columns else "DH"
            )
            for row in blk.rows:
                cells = _split_cells(row)
                if len(cells) < len(blk.columns):
                    cells = cells + [""] * (len(blk.columns) - len(cells))
                elif len(cells) > len(blk.columns):
                    errors.append(f":H row column-count mismatch: {row!r}")
                    continue
                rec = dict(zip(blk.columns, cells))
                hid = rec["id"]
                hyp: dict[str, Any] = {
                    "id": hid,
                    "name": rec.get("name", ""),
                    "attached_to_vertex": rec.get("attached_to", ""),
                    "proposed_edge": {
                        "relation": rec.get("rel", ""),
                        "parent_vertex": {
                            "type": rec.get("parent_type", ""),
                            "classification": rec.get("parent_class", ""),
                            "attributes": _parse_kv_attrs(rec.get("parent_attrs", "")),
                        },
                    },
                    "weight": None if rec.get("weight") in ("null", "") else rec.get("weight"),
                    "status": rec.get("status", "active"),
                    "predictions": [],
                    "attribute_predictions": [],
                    "refutation_shape": [],
                    "authorization_contract": [],
                }
                if rec.get("integrity_waived"):
                    hyp["integrity_waived"] = _unquote(rec["integrity_waived"])
                if mode in ("DP", "DH"):
                    for c in (rec.get("preds") or "").split(";"):
                        p = _parse_pred_subcell(c.strip(), hid, errors)
                        if p:
                            hyp["predictions"].append(p)
                    for c in (rec.get("attr_preds") or "").split(";"):
                        a = _parse_attr_pred_subcell(c.strip(), hid, errors)
                        if a:
                            hyp["attribute_predictions"].append(a)
                    for c in (rec.get("refuts") or "").split(";"):
                        r = _parse_refut_subcell(c.strip(), hid, errors)
                        if r:
                            hyp["refutation_shape"].append(r)
                if mode == "DP":
                    for c in (rec.get("authz") or "").split(";"):
                        a = _parse_authz_subcell(c.strip(), hid, errors)
                        if a:
                            hyp["authorization_contract"].append(a)
                # Story prose
                if hid in stories:
                    hyp["story"] = "\n".join(stories[hid])
                hypotheses.append(hyp)
                by_id[hid] = hyp

    # Pass 2: per-hypothesis sub-blocks (`:P h-NNN.<kind>`)
    for blk in blocks:
        if blk.tag != "P":
            continue
        m = re.match(r"^(h-[\w\-]+)\.(preds|attr_preds|refuts|authz|comparisons)$", blk.name)
        if not m:
            errors.append(f"unknown :P block name: {blk.name}")
            continue
        hid, kind = m.group(1), m.group(2)
        if hid not in by_id:
            errors.append(f":P {blk.name}: hypothesis {hid} not declared")
            continue
        hyp = by_id[hid]
        for row in blk.rows:
            cells = _split_cells(row)
            if len(cells) != len(blk.columns):
                errors.append(f":P {blk.name} row column-count mismatch: {row!r}")
                continue
            rec = dict(zip(blk.columns, cells))
            if kind == "preds":
                hyp["predictions"].append({
                    "id": rec["id"],
                    "subject": rec.get("subject", ""),
                    "kind": rec.get("kind", ""),
                    "from_story_link": rec.get("from_story", ""),
                    "claim": _unquote(rec.get("claim", "")),
                })
            elif kind == "attr_preds":
                hyp["attribute_predictions"].append({
                    "id": rec["id"],
                    "target": rec.get("target", ""),
                    "attribute": rec.get("attribute", ""),
                    "kind": rec.get("kind", ""),
                    "claim": _unquote(rec.get("claim", "")),
                })
            elif kind == "refuts":
                refs = [r.strip() for r in (rec.get("refutes") or "").split(",") if r.strip()]
                if rec.get("kind") == "presence":
                    errors.append(f"{hid}.{rec['id']}: kind=presence forbidden on refutation")
                hyp["refutation_shape"].append({
                    "id": rec["id"],
                    "refutes_predictions": refs,
                    "kind": rec.get("kind", ""),
                    "claim": _unquote(rec.get("claim", "")),
                })
            elif kind == "authz":
                hyp["authorization_contract"].append({
                    "id": rec["id"],
                    "edge_ref": rec.get("edge_ref", "proposed"),
                    "anchor_kind": rec.get("anchor_kind", ""),
                    "predicate": _unquote(rec.get("predicate", "")),
                    "on_unauthorized": rec.get("on_unauth", "esc"),
                    "on_indeterminate": rec.get("on_indet", "esc"),
                })
            elif kind == "comparisons":
                pred_ref = rec.get("pred_ref", "")
                comp = {
                    "selector_kind": rec.get("selector_kind", ""),
                    "selector": _unquote(rec.get("selector", "")),
                    "dimension": rec.get("dimension", ""),
                }
                _attach_comparison(hyp, pred_ref, comp, errors)

    # Pass 3: branch_plan and lead_preds.comparisons
    lead_pred_rows: list[dict[str, Any]] = []
    lp_comparisons: dict[str, dict[str, str]] = {}
    for blk in blocks:
        if blk.tag == "L" and blk.name == "lead_preds":
            for row in blk.rows:
                cells = _split_cells(row)
                if len(cells) < len(blk.columns):
                    cells = cells + [""] * (len(blk.columns) - len(cells))
                elif len(cells) > len(blk.columns):
                    errors.append(f":L lead_preds row column-count mismatch: {row!r}")
                    continue
                rec = dict(zip(blk.columns, cells))
                lp: dict[str, Any] = {
                    "id": rec["id"],
                    "kind": rec.get("kind", ""),
                    "if": _unquote(rec.get("if", "")),
                    "read_as": _unquote(rec.get("read_as", "")),
                    "advance_to": rec.get("advance_to", ""),
                }
                if rec.get("selector_kind"):
                    lp["comparison"] = {
                        "selector_kind": rec.get("selector_kind"),
                        "selector": _unquote(rec.get("selector", "")),
                        "dimension": rec.get("dimension", ""),
                    }
                lead_pred_rows.append(lp)
        elif blk.tag == "L" and blk.name == "lead_preds.comparisons":
            for row in blk.rows:
                cells = _split_cells(row)
                if len(cells) < len(blk.columns):
                    cells = cells + [""] * (len(blk.columns) - len(cells))
                elif len(cells) > len(blk.columns):
                    errors.append(f":L lead_preds.comparisons row column-count mismatch: {row!r}")
                    continue
                rec = dict(zip(blk.columns, cells))
                lp_comparisons[rec["pred_ref"]] = {
                    "selector_kind": rec.get("selector_kind", ""),
                    "selector": _unquote(rec.get("selector", "")),
                    "dimension": rec.get("dimension", ""),
                }
    for lp in lead_pred_rows:
        if lp["id"] in lp_comparisons:
            lp["comparison"] = lp_comparisons[lp["id"]]
    if lead_pred_rows:
        # Branch_plan needs a primary_lead — pull from routing.selected_lead
        # (filled below) or first error.
        branch_plan = {"primary_lead": None, "predictions": lead_pred_rows}

    # Pass 4: routing
    for blk in blocks:
        if blk.tag == "R" and blk.name == "routing":
            for row in blk.rows:
                m = re.match(r"^(\w+)\s+(.+)$", row)
                if not m:
                    errors.append(f":R routing bad row: {row!r}")
                    continue
                k, v = m.group(1), m.group(2).strip()
                if k == "composite_secondary":
                    routing[k] = [] if v == "-" else [s.strip() for s in v.split(",")]
                elif k == "override_data_source":
                    routing[k] = None if v == "-" else v
                else:
                    routing[k] = _unquote(v)
        elif blk.tag == "R" and blk.name == "routing.lead_hints":
            hints: dict[str, str] = {}
            for row in blk.rows:
                cells = _split_cells(row)
                if len(cells) >= 2:
                    hints[cells[0]] = _unquote(cells[1])
            routing["lead_hints"] = hints
        elif blk.tag == "R" and blk.name == "routing.scope_override":
            so: dict[str, Any] = {}
            for row in blk.rows:
                cells = _split_cells(row)
                if len(cells) >= 2:
                    k, v = cells[0], cells[1]
                    so[k] = int(v) if v.isdigit() else v
            routing["scope_override"] = so

    if branch_plan and "primary_lead" in branch_plan and branch_plan["primary_lead"] is None:
        branch_plan["primary_lead"] = routing.get("selected_lead")

    pred["hypotheses"] = hypotheses
    if branch_plan:
        pred["branch_plan"] = branch_plan
    pred["routing"] = routing

    # Field-presence matrix enforcement
    shape = pred.get("shape")
    if shape == "E":
        if hypotheses:
            errors.append("Shape E must have no hypotheses")
        if not branch_plan:
            errors.append("Shape E missing branch_plan / :L lead_preds")
    elif shape == "A":
        if not hypotheses:
            errors.append("Shape A requires ≥1 hypothesis")
        elif not any(h.get("authorization_contract") for h in hypotheses):
            errors.append("Shape A requires ≥1 authorization_contract")
        if branch_plan:
            errors.append("Shape A must not carry branch_plan")
    elif shape == "M":
        if len(hypotheses) < 2:
            errors.append("Shape M requires ≥2 hypotheses")
        if branch_plan:
            errors.append("Shape M must not carry branch_plan")

    # Story-presence check
    if shape in ("A", "M"):
        for h in hypotheses:
            if not h.get("story"):
                errors.append(f"{h['id']}: missing story prose block")

    # from_story_link → sentence ID consistency
    for h in hypotheses:
        story_ids = set(re.findall(r"^(s\d+)\.", h.get("story", ""), flags=re.MULTILINE))
        for p in h["predictions"]:
            link = p.get("from_story_link", "")
            if link and link not in story_ids:
                errors.append(f"{h['id']}.{p['id']}: from_story_link {link!r} not in story sentence IDs {sorted(story_ids)}")

    return {"predict": pred}, errors


def _parse_kv_attrs(cell: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for kv in cell.split(";"):
        kv = kv.strip()
        if not kv:
            continue
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _attach_comparison(hyp: dict, pred_ref: str, comp: dict, errors: list[str]) -> None:
    for bucket in ("predictions", "refutation_shape"):
        for entry in hyp[bucket]:
            if entry["id"] == pred_ref:
                entry["comparison"] = comp
                return
    errors.append(f"{hyp['id']}: comparison row references unknown pred_ref {pred_ref!r}")


if __name__ == "__main__":
    import sys

    text = sys.stdin.read()
    env, errs = parse_dense(text)
    import json

    print(json.dumps({"envelope": env, "errors": errs}, indent=2))
