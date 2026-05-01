"""On-disk dense-block parser for `investigation.md`.

Reads ```` ```invlang ```` fenced blocks and projects them onto the
canonical companion dict shape (matches `schema.md`). Consumed by:

  - `hooks/scripts/invlang_validate.py` (PreToolUse validator)
  - `scripts/invlang/corpus.py`         (corpus loader)

This module owns the **schema-mapping projection**. The line-grammar
primitives (cell helpers, block tokenizer, fence regex) live in
`_dense_primitives.py` — the single source of truth shared with the
subagent-output parsers (`_prologue_dense`, `_predict_dense`,
`_conclude_dense`).

Public surface:

    INVLANG_BLOCK_RE              regex matching ```invlang fences
    DenseBlock                    tokenized block (re-exported from primitives)
    DenseParseError               raised on first projection violation
    parse_dense_blocks_in_text    walk all fences in markdown text → blocks
    companion_dict_from_blocks    project blocks onto canonical dict shape
    parse_dense_companion         convenience: text → companion dict

Schema-mapping table (per `docs/dense-investigation-format.md` §Schema mapping):

    :V prologue.vertices            → prologue.vertices[]
    :E prologue.edges               → prologue.edges[]
    :H hypothesize.hypotheses       → hypothesize.hypotheses[]
    :L findings                     → findings[<id>] (flat: id, name, loop,
                                       target, mode, ...; query_details
                                       sub-dict for system/template/query/
                                       time_window/substitutions)
    :V l-{id}.observations.vertices → findings[<id>].outcome.observations.vertices[]
    :E l-{id}.observations.edges    → findings[<id>].outcome.observations.edges[]
    :L l-{id}.lead_preds            → findings[<id>].predictions[]
    :L l-{id}.impact_preds          → findings[<id>].impact_predictions[]
    :L l-{id}.substitutions         → findings[<id>].query_details.substitutions{}
    :H l-{id}.new_hypotheses        → findings[<id>].new_hypotheses[]
    :R authz                        → findings[<lead>].outcome.authorization_resolutions[]
    :R consultations                → findings[<lead>].outcome.anchor_consultations[]
    :R impact                       → findings[<lead>].outcome.impact_resolutions[]
    :R attr_updates                 → findings[<lead>].outcome.attribute_updates[]
    :T resolutions                  → findings[<lead>].resolutions[]
    :T shelved                      → findings[<lead>].shelved[]
    :T conclude (+sub-tables)       → conclude{...}
    :G frontier                     → (derived view, no canonical projection)

Unknown tags or block names raise `DenseParseError` — silent skip would
allow malformed dense content to escape validation.
"""

from __future__ import annotations

import re
from typing import Any

from scripts.handlers import _dense_primitives as _prim
from scripts.handlers._dense_primitives import (
    DenseBlock,
    INVLANG_FENCE_RE as INVLANG_BLOCK_RE,
    split_csv as _split_csv,
    split_csv_or_semi as _split_csv_or_semi,
    split_subcells as _split_subcells,
    split_cells as _split_cells,
    tokenize_blocks,
    unquote as _unquote,
)


class DenseParseError(ValueError):
    """Raised on first structural violation while tokenizing or projecting
    a dense block. The message names the offending tag/row so it can be
    surfaced to the writer (validator hook output)."""


_VALID_TAGS = frozenset("VEHLRTG")


def _parse_attrs(cell: str) -> dict[str, str]:
    return _prim.parse_attrs(cell, error_cls=DenseParseError)


def _parse_auth(cell: str) -> dict[str, str]:
    return _prim.parse_auth(cell, error_cls=DenseParseError)


def parse_dense_blocks_in_text(text: str) -> list[DenseBlock]:
    """Walk every ```invlang fence in `text` and tokenize the contents.

    Multiple blocks may share a single fence — they're separated by header
    lines (`:V foo [...]`, `:T conclude`, etc.). Blank lines between blocks
    are tolerated.
    """
    blocks: list[DenseBlock] = []
    for fence_idx, match in enumerate(INVLANG_BLOCK_RE.finditer(text)):
        body = match.group(1)
        blocks.extend(
            tokenize_blocks(
                body,
                valid_tags=_VALID_TAGS,
                error_cls=DenseParseError,
                fence_index=fence_idx,
            )
        )
    return blocks


def _row_cells(block: DenseBlock, row: str) -> list[str]:
    return _prim.row_cells(block, row, error_cls=DenseParseError)


def _row_record(block: DenseBlock, row: str) -> dict[str, str]:
    return _prim.row_record(block, row, error_cls=DenseParseError)


# ---------------------------------------------------------------------------
# Schema-mapping projection (block → canonical companion dict)
# ---------------------------------------------------------------------------


_LEAD_PREFIX_RE = re.compile(r"^l-(?P<id>[A-Za-z0-9]+)\.(?P<sub>.+)$")


def companion_dict_from_blocks(blocks: list[DenseBlock]) -> dict[str, Any]:
    """Project a list of tokenized dense blocks onto the canonical companion
    dict shape (matches `schema.md` and `_LEAD_REQUIRED` in invlang_common).

    Lead row fields (id/name/loop/target, plus query_details siblings) are
    flattened directly onto the finding entry — the validator and corpus
    loader read `findings[i].id`, `.target`, `.query_details.system`, etc.
    The `query_details` envelope holds `{system, template, query,
    time_window, substitutions}` (the row cells that describe how the
    lead was queried), keeping a clean separation from the lead's identity
    and outcome.

    Lead attribution for sub-blocks works in three ways, in priority order:
      1. Block name carries the lead prefix: `:V l-001.observations.vertices`.
      2. The row carries an explicit `lead` cell or (for authz) `resolved_by`.
      3. The block is lexically inside a lead context — the most recently
         seen lead, set either by a `:L findings` row or a `l-{id}.*`
         block name.

    The expected on-disk convention is one phase block per lead, so the
    last-lead context is the lead that block "belongs to".
    """
    out: dict[str, Any] = {}
    findings: dict[str, dict[str, Any]] = {}

    def lead_bucket(lead_id: str) -> dict[str, Any]:
        lead = findings.setdefault(lead_id, {"id": lead_id})
        lead.setdefault("outcome", {})
        lead.setdefault("query_details", {})
        lead.setdefault("resolutions", [])
        return lead

    ctx: dict[str, str | None] = {"current_lead": None}

    for block in blocks:
        _project_block(block, out, lead_bucket, ctx)

    if findings:
        out["findings"] = [findings[lid] for lid in findings]

    return out


def _project_block(
    block: DenseBlock,
    out: dict[str, Any],
    lead_bucket,
    ctx: dict[str, str | None],
) -> None:
    tag = block.tag
    name = block.name

    # Top-level prologue ----------------------------------------------------
    if tag == "V" and name == "prologue.vertices":
        out.setdefault("prologue", {})["vertices"] = [
            _vertex_record(block, row) for row in block.rows
        ]
        return
    if tag == "E" and name == "prologue.edges":
        out.setdefault("prologue", {})["edges"] = [
            _edge_record(block, row) for row in block.rows
        ]
        return

    # Top-level hypotheses --------------------------------------------------
    if tag == "H" and name == "hypothesize.hypotheses":
        out.setdefault("hypothesize", {})["hypotheses"] = [
            _hypothesis_record(block, row) for row in block.rows
        ]
        return

    # Findings header (one row per lead, scalar fields) --------------------
    if tag == "L" and name == "findings":
        last_lead_id: str | None = None
        for row in block.rows:
            identity, query_details = _lead_header_record(block, row)
            lead_id = identity["id"]
            lead = lead_bucket(lead_id)
            lead.update(identity)
            if query_details:
                lead.setdefault("query_details", {}).update(query_details)
            last_lead_id = lead_id
        if last_lead_id:
            ctx["current_lead"] = last_lead_id
        return

    # Lead-scoped sub-blocks (block name carries `l-{id}.` prefix) ---------
    m = _LEAD_PREFIX_RE.match(name)
    if m:
        lead_id = "l-" + m.group("id")
        sub = m.group("sub")
        lead = lead_bucket(lead_id)
        _project_lead_subblock(tag, sub, block, lead)
        ctx["current_lead"] = lead_id
        return

    # Resolution-shaped blocks (lead from explicit cell or current context)
    if tag == "R" and name in ("authz", "consultations", "impact", "attr_updates"):
        _project_resolution(block, lead_bucket, ctx)
        return

    # Conclude --------------------------------------------------------------
    if tag == "T" and (name == "conclude" or name.startswith("conclude.")):
        _project_conclude(block, out)
        return

    # Resolutions / shelved (lead from row's `lead` cell or current context)
    if tag == "T" and name == "resolutions":
        _project_resolutions(block, lead_bucket, ctx)
        return
    if tag == "T" and name == "shelved":
        _project_shelved(block, lead_bucket, ctx)
        return

    # Frontier graph — derived view, no canonical projection ---------------
    if tag == "G" and name == "frontier":
        return

    raise DenseParseError(
        f"unknown dense block: :{tag} {name} (no projection rule defined)"
    )


# --- vertex / edge -----------------------------------------------------------


_VERTEX_COLS = ["id", "type", "class", "ident", "attrs"]
_EDGE_COLS = ["id", "rel", "src", "tgt", "when", "auth_kind:source", "attrs"]


def _vertex_record(block: DenseBlock, row: str) -> dict[str, Any]:
    cells = _row_cells(block, row)
    cols = block.columns or _VERTEX_COLS
    rec = dict(zip(cols, cells))
    if not rec.get("id") or not rec.get("type") or not rec.get("class") or not rec.get("ident"):
        raise DenseParseError(
            f":V {block.name}: vertex row missing required cell "
            f"(id/type/class/ident all required): {row!r}"
        )
    out: dict[str, Any] = {
        "id": rec["id"],
        "type": rec["type"],
        "classification": rec["class"],
        "identifier": rec["ident"],
    }
    if rec.get("attrs"):
        out["attributes"] = _parse_attrs(rec["attrs"])
    if rec.get("placeholder"):
        out["placeholder"] = rec["placeholder"]
    if rec.get("concerns"):
        out["concerns"] = _split_csv_or_semi(rec["concerns"])
    return out


def _edge_record(block: DenseBlock, row: str) -> dict[str, Any]:
    cells = _row_cells(block, row)
    cols = block.columns or _EDGE_COLS
    rec = dict(zip(cols, cells))
    auth_col = _find_col(cols, "auth_kind:source")
    if not rec.get("id") or not rec.get("rel") or not rec.get("src") or not rec.get("tgt"):
        raise DenseParseError(
            f":E {block.name}: edge row missing required cell "
            f"(id/rel/src/tgt all required): {row!r}"
        )
    if not rec.get(auth_col):
        raise DenseParseError(
            f":E {block.name}: edge row missing auth_kind:source cell: {row!r}"
        )
    out: dict[str, Any] = {
        "id": rec["id"],
        "relation": rec["rel"],
        "source_vertex": rec["src"],
        "target_vertex": rec["tgt"],
    }
    if rec.get("when"):
        out["when"] = {"timestamp": rec["when"]}
    out["authority"] = _parse_auth(rec[auth_col])
    if rec.get("attrs"):
        out["attributes"] = _parse_attrs(rec["attrs"])
    if rec.get("status"):
        out["status"] = rec["status"]
    if rec.get("concerns"):
        out["concerns"] = _split_csv_or_semi(rec["concerns"])
    return out


def _find_col(cols: list[str], wanted: str) -> str:
    """Return `wanted` if present, else the first column starting with the
    same prefix (handles `auth_kind:source` columns that we strip `?` from)."""
    if wanted in cols:
        return wanted
    for c in cols:
        if c.startswith(wanted.split(":")[0]):
            return c
    return wanted


# --- hypothesis (with sub-cell unpacking) ------------------------------------


_PRED_RE = re.compile(
    r"^(?P<id>p\d+):(?P<subject>[^:]+):(?P<claim>.*)$"
)
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


def _hypothesis_record(block: DenseBlock, row: str) -> dict[str, Any]:
    rec = _row_record(block, row)
    if not rec.get("id") or not rec.get("name"):
        raise DenseParseError(
            f":H {block.name}: hypothesis row missing id/name: {row!r}"
        )
    out: dict[str, Any] = {
        "id": rec["id"],
        "name": rec["name"],
    }
    if rec.get("attached_to"):
        out["attached_to_vertex"] = rec["attached_to"]
    if rec.get("rel"):
        out.setdefault("proposed_edge", {})["relation"] = rec["rel"]
    if rec.get("parent_type"):
        out.setdefault("proposed_edge", {})["parent_type"] = rec["parent_type"]
    if rec.get("parent_class"):
        out.setdefault("proposed_edge", {})["parent_class"] = rec["parent_class"]
    if rec.get("parent_attrs"):
        out.setdefault("proposed_edge", {})["parent_attributes"] = _parse_attrs(
            rec["parent_attrs"]
        )
    preds_cell = rec.get("preds", "")
    if preds_cell:
        out["predictions"] = _parse_pred_subcells(preds_cell)
    attr_preds_cell = rec.get("attr_preds", "")
    if attr_preds_cell:
        out["attribute_predictions"] = _parse_attr_pred_subcells(attr_preds_cell)
    refuts_cell = rec.get("refuts", "")
    if refuts_cell:
        out["refutation_shape"] = _parse_refut_subcells(refuts_cell)
    authz_cell = rec.get("authz", "")
    if authz_cell:
        out["authorization_contract"] = _parse_authz_subcells(authz_cell)
    if rec.get("integrity_waived"):
        out["integrity_waived"] = rec["integrity_waived"]
    if rec.get("weight"):
        out["weight"] = None if rec["weight"] == "null" else rec["weight"]
    if rec.get("status"):
        out["status"] = rec["status"]
    return out


def _parse_pred_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _PRED_RE.match(sub)
        if not m:
            raise DenseParseError(
                f":H prediction sub-cell malformed (expected `p<n>:<subject>:\"<claim>\"`): {sub!r}"
            )
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
            raise DenseParseError(
                f":H attribute_prediction sub-cell malformed "
                f"(expected `ap<n>:<target>:<attribute>:\"<claim>\"`): {sub!r}"
            )
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
            raise DenseParseError(
                f":H refutation sub-cell malformed "
                f"(expected `r<n>[p1,ap1]:\"<claim>\"`): {sub!r}"
            )
        rec: dict[str, Any] = {
            "id": m.group("id"),
            "claim": _unquote(m.group("claim").strip()),
        }
        refs = m.group("refs")
        if refs:
            rec["refutes"] = _split_csv(refs)
        out.append(rec)
    return out


def _parse_authz_subcells(cell: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sub in _split_subcells(cell):
        m = _AUTHZ_RE.match(sub)
        if not m:
            raise DenseParseError(
                f":H authz contract sub-cell malformed "
                f"(expected `ac<n>:<edge_ref>:<anchor_kind>:\"<predicate>\":esc/esc`): "
                f"{sub!r}"
            )
        out.append({
            "id": m.group("id"),
            "edge_ref": m.group("edge_ref").strip(),
            "anchor_kind": m.group("anchor_kind").strip(),
            "predicate": _unquote(m.group("predicate").strip()),
            "on_unauthorized": m.group("on_unauth").strip(),
            "on_indeterminate": m.group("on_indet").strip(),
        })
    return out


# --- lead header and lead-scoped sub-blocks ---------------------------------


def _lead_header_record(
    block: DenseBlock, row: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project one `:L findings` row into (identity, query_details).

    Identity fields land flat on the finding entry: id, name, loop, target,
    mode, status, trust_root_reached, failure_reason, screen_result,
    tests_hypotheses. Query-shape fields go under `query_details`: system,
    template, query, time_window. (Substitutions land via the dedicated
    `:L l-{id}.substitutions` sub-block.)
    """
    rec = _row_record(block, row)
    if not rec.get("id") or not rec.get("name"):
        raise DenseParseError(
            f":L findings row missing id/name: {row!r}"
        )
    identity: dict[str, Any] = {
        "id": rec["id"],
        "name": rec["name"],
        "target": rec.get("target", ""),
    }
    for k_in, k_out in (
        ("loop", "loop"),
        ("mode", "mode"),
        ("trust_root", "trust_root_reached"),
        ("fail_reason", "failure_reason"),
        ("screen_result", "screen_result"),
        ("status", "status"),
    ):
        if rec.get(k_in):
            value = rec[k_in]
            if k_in == "loop":
                try:
                    value = int(value)
                except ValueError:
                    pass
            identity[k_out] = value
    if rec.get("tests"):
        identity["tests_hypotheses"] = _split_csv(rec["tests"])

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


def _project_lead_subblock(
    tag: str,
    sub: str,
    block: DenseBlock,
    lead: dict[str, Any],
) -> None:
    """Route an `l-{id}.<sub>` block onto its parent lead."""
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
    if tag == "L" and sub == "lead_preds":
        lead["predictions"] = [
            _row_record(block, row) for row in block.rows
        ]
        return
    if tag == "L" and sub == "impact_preds":
        lead["impact_predictions"] = [
            _row_record(block, row) for row in block.rows
        ]
        return
    if tag == "L" and sub == "substitutions":
        subs: dict[str, str] = {}
        for row in block.rows:
            cells = _split_cells(row)
            if len(cells) < 2:
                raise DenseParseError(
                    f":L substitutions row missing key|value: {row!r}"
                )
            subs[cells[0]] = cells[1]
        lead.setdefault("query_details", {})["substitutions"] = subs
        return
    if tag == "H" and sub == "new_hypotheses":
        lead["new_hypotheses"] = [
            _hypothesis_record(block, row) for row in block.rows
        ]
        return
    raise DenseParseError(
        f"unknown lead-scoped sub-block: :{tag} {block.name}"
    )


# --- resolutions (lead inferred from row's `lead` cell) ---------------------


def _project_resolution(
    block: DenseBlock,
    lead_bucket,
    ctx: dict[str, str | None],
) -> None:
    """Project a `:R authz|consultations|impact|attr_updates` block."""
    name = block.name
    bucket_key = {
        "authz": "authorization_resolutions",
        "consultations": "anchor_consultations",
        "impact": "impact_resolutions",
        "attr_updates": "attribute_updates",
    }[name]

    for row in block.rows:
        rec = _row_record(block, row)
        explicit_lead = rec.get("lead")
        explicit_resolved_by = rec.get("resolved_by")
        if explicit_lead and explicit_resolved_by and explicit_lead != explicit_resolved_by:
            raise DenseParseError(
                f":R {name}: row has both `lead` and `resolved_by` cells "
                f"with conflicting values ({explicit_lead!r} vs "
                f"{explicit_resolved_by!r}). Use one column or set both to "
                f"the same lead id: {row!r}"
            )
        # Precedence (deterministic): `resolved_by` is the canonical column
        # name for authz rows, `lead` is an alias accepted for ergonomics,
        # then fall back to lexical context. Both map onto `resolved_by_lead`
        # via `_canonical_resolution_key`.
        lead_id = explicit_resolved_by or explicit_lead or ctx["current_lead"]
        if not lead_id:
            raise DenseParseError(
                f":R {name}: row has no lead attribution. Provide a `lead` "
                f"cell, a `resolved_by` cell, or place this block lexically "
                f"under a lead context (after a `:L findings` row or a "
                f"`l-{{id}}.*` block): {row!r}"
            )
        lead = lead_bucket(lead_id)
        lead.setdefault("outcome", {}).setdefault(bucket_key, []).append(
            _resolution_row(name, rec)
        )


def _resolution_row(kind: str, rec: dict[str, str]) -> dict[str, Any]:
    """Project a row dict onto the canonical resolution record shape.

    Column names from the dense spec map onto the canonical YAML field
    names via `_canonical_resolution_key`. We unpack semicolon-packed
    fields (`conditioning?`, `concerns?`) into lists.
    """
    out: dict[str, Any] = {}
    for k, v in rec.items():
        if not v:
            continue
        canonical = _canonical_resolution_key(k)
        if k in ("conditioning", "concerns"):
            out[canonical] = _split_csv_or_semi(v)
        else:
            out[canonical] = v
    return out


def _canonical_resolution_key(k: str) -> str:
    """Map dense column names to canonical YAML field names.

    The dense column headers in `docs/dense-investigation-format.md` use
    short names (`grounding`, `authority`, `fulfills`, `resolved_by`); the
    canonical YAML schema in `schema.md` and the validator's required-field
    constants in `invlang_common.py` use the long forms. The mapping must
    match those long forms exactly so the 29 invlang validator rules see
    the field names they expect.
    """
    return {
        "as_of": "as_of",
        "effective_window": "effective_window",
        "anchor_query": "anchor_query",
        "conditioning": "conditioning_context",
        "concerns": "concerns",
        "edge": "edge",
        "verdict": "verdict",
        "anchor_id": "anchor_id",
        "anchor_kind": "anchor_kind",
        "grounding": "grounding_kind",
        "authority": "authority_for_question",
        "fulfills": "fulfills_contract",
        "resolved_by": "resolved_by_lead",
        "lead": "resolved_by_lead",
        "cites_past_case": "cites_past_case",
        "result": "result",
        "pred_ref": "prediction_ref",
        "dim": "dimension",
        "observed": "observed",
        "matched_pred": "matched_prediction",
        "reasoning": "reasoning",
        "target": "target",
        "key": "key",
        "value": "value",
    }.get(k, k)


# --- :T resolutions / :T shelved -------------------------------------------


def _project_resolutions(
    block: DenseBlock,
    lead_bucket,
    ctx: dict[str, str | None],
) -> None:
    """Each `:T resolutions` row is one weight-transition for one hypothesis.

    Form: `<hyp-id>  <before> → <after>    [<lead-id> <pred/refut-ids> <severity> ⟂ <supp-edges> :: <annotation>]`
    Lead context is updated to the row's lead-id for any subsequent
    lead-scoped blocks lacking their own attribution.
    """
    for row in block.rows:
        parsed = _parse_resolution_line(row)
        lead_id = parsed["lead_id"]
        lead = lead_bucket(lead_id)
        lead.setdefault("resolutions", []).append(parsed["record"])
        ctx["current_lead"] = lead_id


_RESOLUTION_LINE_RE = re.compile(
    r"^(?P<hyp>[^\s]+)\s+(?P<before>\S+)\s*→\s*(?P<after>\S+)\s+"
    r"\[(?P<inner>.*)\]\s*$"
)


def _parse_resolution_line(row: str) -> dict[str, Any]:
    m = _RESOLUTION_LINE_RE.match(row)
    if not m:
        hint = ""
        if "→" not in row and ("->" in row or "=>" in row):
            hint = " (note: weight transition uses unicode `→`, not `->` or `=>`)"
        elif "→" in row and "⟂" not in row and ("|_|" in row or "_|_" in row or "|-|" in row):
            hint = " (note: supporting-edges separator uses unicode `⟂`, not ASCII look-alikes)"
        raise DenseParseError(
            f":T resolutions row malformed "
            f"(expected `<hyp> <before> → <after> [<lead> <preds> <severity> ⟂ <edges> :: <ann>]`): "
            f"{row!r}{hint}"
        )
    inner = m.group("inner")
    annotation = ""
    if "::" in inner:
        bracketed, annotation = inner.split("::", 1)
        annotation = annotation.strip()
    else:
        bracketed = inner
    if "⟂" not in bracketed:
        raise DenseParseError(
            f":T resolutions row missing supp-edges separator `⟂`: {row!r}"
        )
    head, supp = bracketed.split("⟂", 1)
    head_tokens = head.split()
    if len(head_tokens) < 2:
        raise DenseParseError(
            f":T resolutions row inner head needs lead-id + severity: {row!r}"
        )
    lead_id = head_tokens[0]
    severity = head_tokens[-1]
    pred_tokens = head_tokens[1:-1]
    supp_text = supp.strip()
    record: dict[str, Any] = {
        "hypothesis_id": m.group("hyp"),
        "before": m.group("before"),
        "after": m.group("after"),
        "severity_of_test": severity,
        "supporting_edges": [t for t in re.findall(r"e-[A-Za-z0-9]+", supp_text)],
        "matched_prediction_ids": [t for t in pred_tokens if t.startswith("p")],
        "matched_refutation_ids": [t for t in pred_tokens if t.startswith("r")],
    }
    # `supporting_marker` is only present when supp is a non-edge marker
    # (e.g. `no-authority`). When supp lists edge ids, the edges live in
    # `supporting_edges` and the marker field is omitted entirely.
    if supp_text and not supp_text.startswith("e-"):
        record["supporting_marker"] = supp_text
    if annotation:
        record["reasoning"] = annotation
    return {"lead_id": lead_id, "record": record}


def _project_shelved(
    block: DenseBlock,
    lead_bucket,
    ctx: dict[str, str | None],
) -> None:
    for row in block.rows:
        rec = _row_record(block, row)
        if not rec.get("hyp_id"):
            raise DenseParseError(
                f":T shelved row missing hyp_id: {row!r}"
            )
        lead_id = rec.get("by_lead") or ctx["current_lead"]
        if not lead_id:
            raise DenseParseError(
                f":T shelved row missing by_lead and no lead context: {row!r}"
            )
        lead = lead_bucket(lead_id)
        lead.setdefault("shelved", []).append({
            "hypothesis_id": rec["hyp_id"],
            "rationale": _unquote(rec.get("rationale", "")),
        })


# --- conclude ---------------------------------------------------------------


_CONCLUDE_SUB_TABLES = {
    "surviving":         ("surviving_hypotheses",          ["hyp_id", "final_weight"]),
    "deferred_authz":    ("deferred_authorizations",       ["contract_ref", "rationale"]),
    "deferred_impact":   ("deferred_impact_predictions",   ["prediction_ref", "rationale"]),
    "deferred_preds":    ("deferred_predictions",          ["prediction_ref", "rationale"]),
    "ceiling_test":      ("ceiling_test",                  ["kind", "subject"]),
}


def _project_conclude(block: DenseBlock, out: dict[str, Any]) -> None:
    conclude = out.setdefault("conclude", {})
    if block.name == "conclude":
        _absorb_conclude_scalars(conclude, block.rows)
        return

    sub = block.name[len("conclude."):]
    if sub not in _CONCLUDE_SUB_TABLES:
        raise DenseParseError(
            f":T conclude.{sub}: unknown sub-table "
            f"(valid: {sorted(_CONCLUDE_SUB_TABLES)})"
        )
    dict_key, expected_cols = _CONCLUDE_SUB_TABLES[sub]
    if block.columns is None or block.columns != expected_cols:
        raise DenseParseError(
            f":T conclude.{sub} columns must be {expected_cols!r}, got "
            f"{block.columns!r}"
        )

    if not block.rows:
        raise DenseParseError(
            f":T conclude.{sub} has no rows (expected at least `none`)"
        )
    if len(block.rows) == 1 and block.rows[0].strip().lower() == "none":
        if dict_key == "ceiling_test":
            return
        conclude[dict_key] = []
        return

    if dict_key == "ceiling_test":
        if len(block.rows) != 1:
            raise DenseParseError(
                f":T conclude.{sub} expects exactly one row (or `none`), "
                f"got {len(block.rows)}"
            )
        cells = _row_cells(block, block.rows[0])
        conclude[dict_key] = dict(zip(expected_cols, cells))
        return

    bucket: list[Any] = []
    for row in block.rows:
        cells = _row_cells(block, row)
        if dict_key == "surviving_hypotheses":
            hyp_id = cells[0]
            if not hyp_id:
                raise DenseParseError(
                    f":T conclude.{sub} row has empty hyp_id: {row!r}"
                )
            bucket.append(hyp_id)
        else:
            entry = dict(zip(expected_cols, cells))
            for col in expected_cols:
                if not entry.get(col):
                    raise DenseParseError(
                        f":T conclude.{sub} row missing required cell "
                        f"`{col}`: {row!r}"
                    )
            bucket.append(entry)
    conclude[dict_key] = bucket


def _absorb_conclude_scalars(conclude: dict[str, Any], rows: list[str]) -> None:
    termination: dict[str, Any] = {}
    for row in rows:
        m = re.match(r"^(\S+)\s+(.*)$", row)
        if not m:
            raise DenseParseError(
                f":T conclude scalar row malformed (expected `key value`): {row!r}"
            )
        key = m.group(1)
        value = _parse_conclude_scalar_value(m.group(2).strip())
        if key == "termination.category":
            termination["category"] = value
        elif key == "termination.rationale":
            termination["rationale"] = value
        elif key in (
            "disposition",
            "impact_verdict",
            "impact_severity",
            "confidence",
            "matched_archetype",
            "ceiling_rationale",
            "summary",
        ):
            conclude[key] = value
        else:
            raise DenseParseError(
                f":T conclude scalar row has unknown key: {key!r}"
            )
    if termination:
        conclude["termination"] = termination


def _parse_conclude_scalar_value(raw: str) -> Any:
    if raw == "null":
        return None
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"')
    return raw


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------


def parse_dense_companion(text: str) -> dict[str, Any]:
    """Walk ```invlang fences in `text` and project to the canonical
    companion dict. Returns an empty dict if no fences are present."""
    blocks = parse_dense_blocks_in_text(text)
    if not blocks:
        return {}
    return companion_dict_from_blocks(blocks)
