"""Dense-format parser for the PREDICT subagent output envelope.

Parallel to `parse_analyze_envelope_dense` in `_output_parser.py`. Reads the
DB grammar (per-hypothesis sub-blocks) selected by the bake-off in branch
`predict-dense-bakeoff` and emits a dict shaped like the legacy YAML envelope
so the routing-validation helpers in `_output_parser.py` (`_extract_routing`,
`_extract_scope_override`) can be reused unchanged.

Returned envelope shape (mirrors `predict.<...>` from the YAML form):

    {
        "loop": int,
        "shape": "E"|"A"|"M",
        "hypotheses": [
            {
                "id", "name", "attached_to_vertex", "proposed_edge",
                "story", "predictions": [...], "attribute_predictions": [...],
                "refutation_shape": [...], "authorization_contract": [...],
                "integrity_waived"?, "weight", "status",
            },
        ],
        "branch_plan": {"primary_lead": ..., "predictions": [...]} | None,
        "routing": {"selected_lead", "composite_secondary", ...},
    }

Raises `PredictOutputError` (imported from `_output_parser`) on the first
structural rule violation. Validations performed at this layer:

  - Header line shape: `predict loop=<int> shape=<E|A|M>`.
  - Block tag set: `:H hypotheses`, `:L lead_preds[.comparisons]`,
    `:R routing[.lead_hints|.scope_override]`, `:P h-{id}.<sub>`.
  - `kind` slot ∈ closed set; `kind=presence` forbidden on refutations.
  - `kind ∈ deviation set` requires a `comparison` slot (sub-block or
    trailing positionals on the prediction sub-cell).
  - Story prose required for every declared hypothesis (Shape A / M).
  - `from_story` references in `:P h-{id}.preds` rows must name a sentence
    ID present in that hypothesis's story prose.
  - Per-hypothesis sub-blocks (`:P h-{id}.*`) target a hypothesis declared
    in `:H hypotheses`.

Routing-shape validation (selected_lead, composite_secondary, lead_hints,
scope_override) is delegated to `_extract_routing` in `_output_parser.py` —
this module only assembles the routing dict from the dense rows.
"""

from __future__ import annotations

import re
from typing import Any

from scripts.handlers import _dense_primitives as _prim
from scripts.handlers._dense_primitives import DenseBlock as _Block

DEVIATION_KINDS = frozenset({"geometry", "cadence", "novel-artifact", "absence"})
NON_DEVIATION_KINDS = frozenset({"presence", "absolute"})
ALL_KINDS = DEVIATION_KINDS | NON_DEVIATION_KINDS


_HEADER_LINE_RE = re.compile(r"^predict\s+loop=(\d+)\s+shape=([A-Za-z]+)\s*$")
_STORY_HEADER_RE = re.compile(r"^###\s+story\s+(h-[\w\-]+)\s*$")
_SENTENCE_ID_RE = re.compile(r"^(s\d+)\.")


# Predict uses primitives' `unquote` directly — same `\\"` semantics. The
# `_QUOTED_RE` shape (`^"(.*)"$`) was equivalent on inputs the producer
# emits (no embedded backslash quotes in this surface).
_unquote = _prim.unquote


def _strip_envelope(stdout: str, error_cls: type[Exception]) -> str:
    text = stdout.strip()
    if not text:
        raise error_cls("predict output is empty")
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline == -1:
            raise error_cls("predict output: bare ``` with no body")
        body_start = first_newline + 1
        if text.endswith("```"):
            body = text[body_start:-3].rstrip()
        else:
            body = text[body_start:].rstrip()
        return body.strip()
    return text


def _flush_story(stories: dict[str, list[str]], cur_story: tuple[str, list[str]] | None) -> None:
    if cur_story:
        stories[cur_story[0]] = cur_story[1]


def _tokenize(
    text: str, error_cls: type[Exception]
) -> tuple[dict[str, Any], list[_Block], dict[str, list[str]]]:
    """Split into header dict, list of `:`-blocks, and {hid: [sentence-lines]}."""
    header: dict[str, Any] = {}
    blocks: list[_Block] = []
    stories: dict[str, list[str]] = {}

    cur_block: _Block | None = None
    cur_story: tuple[str, list[str]] | None = None

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        if not header and stripped.startswith("predict "):
            m_h = _HEADER_LINE_RE.match(stripped)
            if not m_h:
                raise error_cls(
                    f"predict header line malformed: {stripped!r} "
                    f"(expected `predict loop=<int> shape=<E|A|M>`)"
                )
            header["loop"] = int(m_h.group(1))
            header["shape"] = m_h.group(2)
            cur_block = None
            cur_story = None
            continue

        m_story = _STORY_HEADER_RE.match(stripped)
        if m_story:
            _flush_story(stories, cur_story)
            cur_story = (m_story.group(1), [])
            cur_block = None
            continue

        m_block = _prim.HEADER_RE.match(stripped)
        if m_block:
            _flush_story(stories, cur_story)
            cur_story = None
            cols_raw = m_block.group("cols") or ""
            cols = (
                [c.strip().rstrip("?") for c in cols_raw.split("|")]
                if cols_raw
                else []
            )
            cur_block = _Block(
                tag=m_block.group("tag"),
                name=m_block.group("name"),
                columns=cols,
                rows=[],
            )
            blocks.append(cur_block)
            continue

        if cur_story is not None and stripped:
            cur_story[1].append(stripped)
            continue

        if cur_block is not None and stripped:
            cur_block.rows.append(stripped)
            continue

        # Blank line: tolerated inside both story and block — they stay open
        # until the next `###`/`:` header (or EOF).

    _flush_story(stories, cur_story)

    if "loop" not in header:
        raise error_cls(
            "predict output missing header line `predict loop=<int> shape=<E|A|M>`"
        )

    return header, blocks, stories


def _parse_kv_attrs(cell: str) -> dict[str, str]:
    """Tolerant key=value;key=value parser.

    Differs from `_prim.parse_attrs` in that it silently drops bare tokens
    (no `=`) instead of raising. The predict subagent has historically
    emitted permissive attrs; tightening to fail-fast is a separate change.
    """
    out: dict[str, str] = {}
    for kv in cell.split(";"):
        kv = kv.strip()
        if not kv or "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _row_to_rec(
    blk: _Block, row: str, error_cls: type[Exception]
) -> dict[str, str]:
    """Predict-flavored row→record. The shared primitive emits a fully
    qualified error message; this wrapper preserves predict's terser form
    for backwards-compat with the predict-bakeoff test fixtures.
    """
    cells = _prim.split_cells(row)
    cols = blk.columns or []
    if len(cells) < len(cols):
        cells = cells + [""] * (len(cols) - len(cells))
    elif len(cells) > len(cols):
        raise error_cls(
            f":{blk.tag} {blk.name}: row has more cells than columns: {row!r}"
        )
    return dict(zip(cols, cells, strict=False))


# ---------------------------------------------------------------------------
# Parse helpers (one per pass)
# ---------------------------------------------------------------------------


def _parse_hypotheses_block(
    blocks: list, stories: dict, error_cls: type[Exception]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Pass 1: parse :H hypotheses → (hypotheses list, by_id lookup)."""
    hypotheses: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for blk in blocks:
        if blk.tag != "H" or blk.name != "hypotheses":
            continue
        for row in blk.rows:
            rec = _row_to_rec(blk, row, error_cls)
            hid = rec.get("id", "")
            if not hid:
                raise error_cls(f":H hypotheses: row missing id: {row!r}")
            attrs = _parse_kv_attrs(rec.get("parent_attrs", ""))
            hyp: dict[str, Any] = {
                "id": hid,
                "name": rec.get("name", ""),
                "attached_to_vertex": rec.get("attached_to", ""),
                "proposed_edge": {
                    "relation": rec.get("rel", ""),
                    "parent_vertex": {
                        "type": rec.get("parent_type", ""),
                        "classification": rec.get("parent_class", ""),
                    },
                },
                "weight": (
                    None
                    if rec.get("weight") in ("null", "", None)
                    else rec.get("weight")
                ),
                "status": rec.get("status", "active") or "active",
                "predictions": [],
                "attribute_predictions": [],
                "refutation_shape": [],
                "authorization_contract": [],
            }
            if attrs:
                hyp["proposed_edge"]["parent_vertex"]["attributes"] = attrs
            iw = rec.get("integrity_waived", "")
            if iw:
                hyp["integrity_waived"] = _unquote(iw)
            if hid in stories:
                hyp["story"] = "\n".join(stories[hid])
            hypotheses.append(hyp)
            by_id[hid] = hyp
    return hypotheses, by_id


def _apply_pred_row(
    hyp: dict, hid: str, rec: dict, error_cls: type[Exception]
) -> None:
    k = rec.get("kind", "")
    if k not in ALL_KINDS:
        raise error_cls(
            f"{hid}.{rec.get('id')}: unknown kind {k!r} "
            f"(must be one of {sorted(ALL_KINDS)})"
        )
    hyp["predictions"].append({
        "id": rec["id"],
        "subject": rec.get("subject", ""),
        "kind": k,
        "from_story_link": rec.get("from_story", ""),
        "claim": _unquote(rec.get("claim", "")),
    })


def _apply_attr_pred_row(
    hyp: dict, hid: str, rec: dict, error_cls: type[Exception]
) -> None:
    k = rec.get("kind", "")
    if k not in ALL_KINDS:
        raise error_cls(f"{hid}.{rec.get('id')}: unknown kind {k!r}")
    hyp["attribute_predictions"].append({
        "id": rec["id"],
        "target": rec.get("target", ""),
        "attribute": rec.get("attribute", ""),
        "kind": k,
        "claim": _unquote(rec.get("claim", "")),
    })


def _apply_refut_row(
    hyp: dict, hid: str, rec: dict, error_cls: type[Exception]
) -> None:
    k = rec.get("kind", "")
    if k == "presence":
        raise error_cls(
            f"{hid}.{rec.get('id')}: kind=presence is forbidden "
            f"on refutations (presence-test refutation anti-pattern)"
        )
    if k not in ALL_KINDS:
        raise error_cls(f"{hid}.{rec.get('id')}: unknown kind {k!r}")
    refs = [r.strip() for r in (rec.get("refutes") or "").split(",") if r.strip()]
    hyp["refutation_shape"].append({
        "id": rec["id"],
        "refutes_predictions": refs,
        "kind": k,
        "claim": _unquote(rec.get("claim", "")),
    })


def _apply_authz_row(
    hyp: dict, hid: str, rec: dict, error_cls: type[Exception]  # noqa: ARG001
) -> None:
    hyp["authorization_contract"].append({
        "id": rec["id"],
        "edge_ref": rec.get("edge_ref", "proposed") or "proposed",
        "anchor_kind": rec.get("anchor_kind", ""),
        "predicate": _unquote(rec.get("predicate", "")),
        "on_unauthorized": rec.get("on_unauth", "esc") or "esc",
        "on_indeterminate": rec.get("on_indet", "esc") or "esc",
    })


_P_KIND_HANDLERS: dict = {
    "preds": _apply_pred_row,
    "attr_preds": _apply_attr_pred_row,
    "refuts": _apply_refut_row,
    "authz": _apply_authz_row,
}


def _parse_per_hypothesis_blocks(
    blocks: list, by_id: dict[str, dict[str, Any]], error_cls: type[Exception]
) -> None:
    """Pass 2: parse :P h-NNN.{kind} blocks, updating by_id hypotheses in place.

    Done in two phases so `comparisons` rows can reference p*/r* IDs regardless
    of block order. Phase 2a collects preds/attr_preds/refuts/authz; phase 2b
    attaches comparisons once all prediction/refutation buckets are complete.
    """
    deferred_comparisons: list[tuple[str, str, dict]] = []
    for blk in blocks:
        if blk.tag != "P":
            continue
        m = re.match(
            r"^(h-[\w\-]+)\.(preds|attr_preds|refuts|authz|comparisons)$",
            blk.name,
        )
        if not m:
            raise error_cls(f"unknown :P block name: {blk.name!r}")
        hid, kind = m.group(1), m.group(2)
        if hid not in by_id:
            raise error_cls(
                f":P {blk.name}: hypothesis {hid!r} not declared in :H hypotheses"
            )
        hyp = by_id[hid]
        for row in blk.rows:
            rec = _row_to_rec(blk, row, error_cls)
            if kind in _P_KIND_HANDLERS:
                _P_KIND_HANDLERS[kind](hyp, hid, rec, error_cls)
            elif kind == "comparisons":
                deferred_comparisons.append((hid, rec.get("pred_ref", ""), {
                    "selector_kind": rec.get("selector_kind", ""),
                    "selector": _unquote(rec.get("selector", "")),
                    "dimension": rec.get("dimension", ""),
                }))
    for hid, pred_ref, comp in deferred_comparisons:
        _attach_comparison(by_id[hid], pred_ref, comp, error_cls)


def _parse_branch_plan(
    blocks: list, error_cls: type[Exception]
) -> list[dict[str, Any]]:
    """Pass 3: parse :L lead_preds[.comparisons] → lead_pred_rows with comparisons."""
    lead_pred_rows: list[dict[str, Any]] = []
    lp_comparisons: dict[str, dict[str, str]] = {}
    for blk in blocks:
        if blk.tag != "L":
            continue
        if blk.name == "lead_preds":
            for row in blk.rows:
                rec = _row_to_rec(blk, row, error_cls)
                k = rec.get("kind", "")
                if k not in ALL_KINDS:
                    raise error_cls(
                        f":L lead_preds {rec.get('id')!r}: unknown kind {k!r}"
                    )
                lead_pred_rows.append({
                    "id": rec["id"],
                    "kind": k,
                    "if": _unquote(rec.get("if", "")),
                    "read_as": _unquote(rec.get("read_as", "")),
                    "advance_to": rec.get("advance_to", ""),
                })
        elif blk.name == "lead_preds.comparisons":
            for row in blk.rows:
                rec = _row_to_rec(blk, row, error_cls)
                lp_comparisons[rec["pred_ref"]] = {
                    "selector_kind": rec.get("selector_kind", ""),
                    "selector": _unquote(rec.get("selector", "")),
                    "dimension": rec.get("dimension", ""),
                }
        else:
            raise error_cls(f"unknown :L block name: {blk.name!r}")
    for lp in lead_pred_rows:
        if lp["id"] in lp_comparisons:
            lp["comparison"] = lp_comparisons[lp["id"]]
    return lead_pred_rows


def _parse_routing_kv_block(blk: Any, error_cls: type[Exception]) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in blk.rows:
        m = re.match(r"^(\S+)\s+(.+)$", row)
        if not m:
            raise error_cls(f":R routing bad row: {row!r}")
        result[m.group(1)] = m.group(2).strip()
    return result


def _parse_routing_lead_hints(blk: Any, error_cls: type[Exception]) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in blk.rows:
        rec = _row_to_rec(blk, row, error_cls)
        lead = rec.get("lead", "")
        if lead:
            result[lead] = _unquote(rec.get("hint", ""))
    return result


def _parse_scope_override_block(blk: Any, error_cls: type[Exception]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for row in blk.rows:
        rec = _row_to_rec(blk, row, error_cls)
        key = rec.get("key", "")
        value = rec.get("value", "")
        if key == "window_hours":
            try:
                result[key] = int(value)
            except ValueError:
                raise error_cls(
                    f":R routing.scope_override.window_hours must be an "
                    f"integer, got {value!r}"
                ) from None
        elif key == "anchor":
            result[key] = value
        elif key:
            raise error_cls(f":R routing.scope_override: unknown key {key!r}")
    return result


def _assemble_routing(
    routing_block: dict[str, str],
    lead_hints: dict[str, str],
    scope_override: dict[str, Any],
) -> dict[str, Any]:
    routing: dict[str, Any] = {}
    if routing_block:
        routing["selected_lead"] = routing_block.get("selected_lead", "")
        cs_raw = routing_block.get("composite_secondary", "-")
        routing["composite_secondary"] = (
            [] if (cs_raw == "-" or not cs_raw)
            else [s.strip() for s in cs_raw.split(",") if s.strip()]
        )
        ods = routing_block.get("override_data_source", "-")
        if ods != "-" and ods:
            routing["override_data_source"] = ods
        rationale = routing_block.get("rationale", "")
        if rationale:
            routing["rationale"] = _unquote(rationale)
    if lead_hints:
        routing["lead_hints"] = lead_hints
    if scope_override:
        routing["scope_override"] = scope_override
    return routing


def _parse_routing_section(
    blocks: list, error_cls: type[Exception]
) -> dict[str, Any]:
    """Pass 4: parse :R routing.* blocks and assemble the routing dict."""
    routing_block: dict[str, str] = {}
    lead_hints: dict[str, str] = {}
    scope_override: dict[str, Any] = {}
    for blk in blocks:
        if blk.tag != "R":
            continue
        if blk.name == "routing":
            routing_block = _parse_routing_kv_block(blk, error_cls)
        elif blk.name == "routing.lead_hints":
            lead_hints = _parse_routing_lead_hints(blk, error_cls)
        elif blk.name == "routing.scope_override":
            scope_override = _parse_scope_override_block(blk, error_cls)
        else:
            raise error_cls(f"unknown :R block name: {blk.name!r}")
    return _assemble_routing(routing_block, lead_hints, scope_override)


def _validate_story_and_sentence_refs(
    hypotheses: list[dict[str, Any]], shape: str, error_cls: type[Exception]
) -> None:
    """Validate story prose presence and from_story_link refs for shapes A and M."""
    if shape not in ("A", "M"):
        return
    for h in hypotheses:
        if not h.get("story"):
            raise error_cls(
                f"{h['id']}: missing story prose block "
                f"(`### story {h['id']}` heading + `s1.`/`s2.` lines)"
            )
        story_ids = {
            _SENTENCE_ID_RE.match(line).group(1)
            for line in h["story"].splitlines()
            if _SENTENCE_ID_RE.match(line)
        }
        for p in h["predictions"]:
            link = p.get("from_story_link", "")
            if link and link not in story_ids:
                raise error_cls(
                    f"{h['id']}.{p['id']}: from_story_link={link!r} not in "
                    f"story sentence IDs {sorted(story_ids)}"
                )


def _check_pred_entry_comparison(
    hid: str, entry: dict, bucket: str, error_cls: type[Exception]
) -> None:
    k = entry.get("kind", "")
    has_comp = "comparison" in entry
    if bucket == "attribute_predictions":
        if has_comp:
            raise error_cls(
                f"{hid}.{entry['id']}: attribute_predictions must not carry comparison"
            )
        return
    if k in DEVIATION_KINDS and not has_comp:
        raise error_cls(
            f"{hid}.{entry['id']}: kind={k!r} requires a "
            f"comparison row in :P {hid}.comparisons"
        )
    if k in NON_DEVIATION_KINDS and has_comp:
        raise error_cls(
            f"{hid}.{entry['id']}: kind={k!r} must not carry a comparison row"
        )


def _validate_comparison_requirements(
    hypotheses: list[dict[str, Any]],
    lead_pred_rows: list[dict[str, Any]],
    error_cls: type[Exception],
) -> None:
    """Check deviation-kind predictions carry a comparison row, and vice versa."""
    for h in hypotheses:
        for bucket in ("predictions", "attribute_predictions", "refutation_shape"):
            for entry in h[bucket]:
                _check_pred_entry_comparison(h["id"], entry, bucket, error_cls)
    for lp in lead_pred_rows:
        k = lp.get("kind", "")
        has_comp = "comparison" in lp
        if k in DEVIATION_KINDS and not has_comp:
            raise error_cls(
                f"lead_pred {lp['id']!r}: kind={k!r} requires a row in "
                f":L lead_preds.comparisons"
            )
        if k in NON_DEVIATION_KINDS and has_comp:
            raise error_cls(
                f"lead_pred {lp['id']!r}: kind={k!r} must not carry a comparison row"
            )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_predict_dense(
    stdout: str, error_cls: type[Exception]
) -> dict[str, Any]:
    """Parse the dense PREDICT envelope. Returns a dict mirroring the YAML
    `predict:` envelope shape. Raises `error_cls` on first structural error.

    `error_cls` is `PredictOutputError` in production; passing it as a
    parameter avoids an import cycle with `_output_parser.py`.
    """
    text = _strip_envelope(stdout, error_cls)
    header, blocks, stories = _tokenize(text, error_cls)
    pred: dict[str, Any] = {"loop": header["loop"], "shape": header["shape"]}

    hypotheses, by_id = _parse_hypotheses_block(blocks, stories, error_cls)
    _parse_per_hypothesis_blocks(blocks, by_id, error_cls)
    lead_pred_rows = _parse_branch_plan(blocks, error_cls)
    routing = _parse_routing_section(blocks, error_cls)

    pred["hypotheses"] = hypotheses
    if lead_pred_rows:
        primary = routing.get("selected_lead") if routing else None
        pred["branch_plan"] = {"primary_lead": primary, "predictions": lead_pred_rows}
    pred["routing"] = routing

    _validate_story_and_sentence_refs(hypotheses, pred["shape"], error_cls)
    _validate_comparison_requirements(hypotheses, lead_pred_rows, error_cls)
    return pred


def _attach_comparison(
    hyp: dict, pred_ref: str, comp: dict, error_cls: type[Exception]
) -> None:
    for bucket in ("predictions", "refutation_shape"):
        for entry in hyp[bucket]:
            if entry["id"] == pred_ref:
                entry["comparison"] = comp
                return
    for entry in hyp["attribute_predictions"]:
        if entry["id"] == pred_ref:
            raise error_cls(
                f"{hyp['id']}: :P {hyp['id']}.comparisons references "
                f"attribute_prediction {pred_ref!r}; attribute_predictions "
                f"do not carry comparisons (only p*/r* do)"
            )
    raise error_cls(
        f"{hyp['id']}: :P {hyp['id']}.comparisons row references unknown "
        f"pred_ref {pred_ref!r} (must name a p* or r* on the same hypothesis)"
    )
