"""Dense-format emitter + parser for the REPORT phase `conclude:` block.

Parallel to `_prologue_dense.py` (CONTEXTUALIZE) and `_predict_dense.py`
(PREDICT). Unlike those modules, the REPORT phase is **handler-authored**:
`scripts/handlers/report.py` mechanically composes the conclude dict from
the ANALYZE routing payload and writes it directly to `investigation.md`.
There is no subagent-emitted dense envelope to parse — instead this module
provides:

  - `emit_conclude_dense(conclude)`  for the producer (handler).
  - `parse_conclude_dense(text)`     for the consumers (corpus loader,
                                     invlang validator, precheck judges).

The dict shape on both sides matches the legacy YAML form (`schema.md
§Conclude`), so callers walking `body["conclude"]` are unchanged:

    {
      "termination": {"category": ..., "rationale": ...},
      "disposition": "benign" | "true_positive" | "unclear",
      "impact_verdict": "none" | "within" | "exceeds" | "indeterminate",
      "impact_severity": None | "low" | "moderate" | "high",
      "confidence": "high" | "medium" | "low",
      "matched_archetype": <name> | None,
      "ceiling_rationale": <str>,
      "summary": <str>,
      "surviving_hypotheses": ["h-001", ...],
      "deferred_authorizations": [{"contract_ref": ..., "rationale": ...}],
      "deferred_impact_predictions": [{"prediction_ref": ..., "rationale": ...}],
      "deferred_predictions": [{"prediction_ref": ..., "rationale": ...}],
      "ceiling_test": {"kind": ..., "subject": ...},
    }

Empty-array convention: a sub-table whose only row is `none` parses to an
empty list. Symmetrically, the emitter omits a sub-table entirely when the
input dict lacks the corresponding key (preserves the missing-vs-empty
distinction the YAML form had — the schema validator rules walk these with
`.get(...) or []`, so absence and `[]` are equivalent there, but downstream
consumers that distinguish should remain consistent across the migration).

Surface (per `docs/dense-investigation-format.md` §Conclude, locked):

    :T conclude
    termination.category   <category>
    termination.rationale  "<sentence>"
    disposition            <verdict>
    impact_verdict         <verdict>
    impact_severity        <null|low|moderate|high>
    confidence             <high|medium|low>
    matched_archetype      <name|null>
    ceiling_rationale      <sentence|n/a>
    summary                "<one sentence>"

    :T conclude.surviving [hyp_id|final_weight]
    h-001|+

    :T conclude.deferred_authz [contract_ref|rationale]
    none

    :T conclude.deferred_impact [prediction_ref|rationale]
    none

    :T conclude.deferred_preds [prediction_ref|rationale]
    none

    :T conclude.ceiling_test [kind|subject]
    none
"""

from __future__ import annotations

import re
from typing import Any

from scripts.handlers import _dense_primitives as _prim


class ConcludeOutputError(ValueError):
    """Raised on malformed dense conclude blocks."""


# ---------------------------------------------------------------------------
# Surface constants
# ---------------------------------------------------------------------------

_SCALAR_KEYS = (
    "termination.category",
    "termination.rationale",
    "disposition",
    "impact_verdict",
    "impact_severity",
    "confidence",
    "matched_archetype",
    "ceiling_rationale",
    "summary",
)

_SUB_TABLES = {
    # block name suffix → (dict key, columns)
    "surviving":         ("surviving_hypotheses",          ["hyp_id", "final_weight"]),
    "deferred_authz":    ("deferred_authorizations",       ["contract_ref", "rationale"]),
    "deferred_impact":   ("deferred_impact_predictions",   ["prediction_ref", "rationale"]),
    "deferred_preds":    ("deferred_predictions",          ["prediction_ref", "rationale"]),
    "ceiling_test":      ("ceiling_test",                  ["kind", "subject"]),
}

_HEADER_RE = re.compile(
    r"^:T\s+conclude(?:\.(?P<sub>[a-z_]+))?(?:\s*\[(?P<cols>[^\]]*)\])?\s*$"
)


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------

def _quote_if_phrase(value: Any) -> str:
    """Return `value` formatted for the scalar table.

    Strings containing whitespace are wrapped in double quotes (matches the
    spec's `"<sentence>"` convention for `termination.rationale` /
    `summary`). Booleans-as-text and ids stay bare. None renders as `null`.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    s = str(value)
    if not s:
        return '""'
    if any(ch.isspace() for ch in s):
        # Escape embedded double quotes — cheap, parser uses the same rule.
        return '"' + s.replace('"', '\\"') + '"'
    return s


def emit_conclude_dense(conclude: dict[str, Any]) -> str:
    """Render a conclude dict as the dense block format.

    Sub-tables are emitted only when the dict carries the corresponding
    key. Scalars are emitted in the canonical order; missing scalars are
    omitted (preserves the YAML-era convention that absent fields are
    distinct from empty ones).
    """
    if not isinstance(conclude, dict):
        raise ConcludeOutputError(
            f"emit_conclude_dense: expected dict, got {type(conclude).__name__}"
        )

    lines: list[str] = [":T conclude"]
    flat = _flatten_scalars(conclude)
    width = max((len(k) for k in flat), default=0)
    for key in _SCALAR_KEYS:
        if key not in flat:
            continue
        lines.append(f"{key.ljust(width)}  {_quote_if_phrase(flat[key])}")

    # Sub-tables in the canonical order.
    for sub, (dict_key, cols) in _SUB_TABLES.items():
        if dict_key not in conclude:
            continue
        value = conclude[dict_key]
        lines.append("")
        lines.append(f":T conclude.{sub} [{'|'.join(cols)}]")

        if dict_key == "ceiling_test":
            # Object, not array — single row or `none`.
            if not value:
                lines.append("none")
            elif isinstance(value, dict):
                lines.append(_render_object_row(value, cols))
            else:
                raise ConcludeOutputError(
                    f"conclude.ceiling_test must be a dict, got "
                    f"{type(value).__name__}"
                )
            continue

        # Array sub-tables.
        if not value:
            lines.append("none")
            continue
        if not isinstance(value, list):
            raise ConcludeOutputError(
                f"conclude.{dict_key} must be a list, got {type(value).__name__}"
            )
        for entry in value:
            lines.append(_render_array_row(dict_key, entry, cols))

    return "\n".join(lines)


def _flatten_scalars(conclude: dict[str, Any]) -> dict[str, Any]:
    """Project the nested-but-mostly-flat conclude dict onto the scalar
    namespace used by `:T conclude` (dot-paths for `termination.*`)."""
    flat: dict[str, Any] = {}
    termination = conclude.get("termination") or {}
    if isinstance(termination, dict):
        if "category" in termination:
            flat["termination.category"] = termination["category"]
        if "rationale" in termination:
            flat["termination.rationale"] = termination["rationale"]
    for key in (
        "disposition",
        "impact_verdict",
        "impact_severity",
        "confidence",
        "matched_archetype",
        "ceiling_rationale",
        "summary",
    ):
        if key in conclude:
            flat[key] = conclude[key]
    return flat


def _render_array_row(dict_key: str, entry: Any, cols: list[str]) -> str:
    """Render one row of a list-shaped sub-table.

    `surviving_hypotheses` accepts a bare string (legacy YAML shape) or a
    `{hyp_id, final_weight}` dict. The other arrays are always
    `{contract_ref|prediction_ref, rationale}` dicts.
    """
    if dict_key == "surviving_hypotheses" and isinstance(entry, str):
        return f"{entry}|"  # final_weight unknown → empty cell
    if not isinstance(entry, dict):
        raise ConcludeOutputError(
            f"conclude.{dict_key} entry must be a dict, got "
            f"{type(entry).__name__}: {entry!r}"
        )
    cells = [_cell(entry.get(c, "")) for c in cols]
    return "|".join(cells)


def _render_object_row(entry: dict[str, Any], cols: list[str]) -> str:
    cells = [_cell(entry.get(c, "")) for c in cols]
    return "|".join(cells)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    s = str(value)
    # Cells separated by `|` — escape any embedded pipes.
    return s.replace("|", "\\|")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_conclude_dense(text: str) -> dict[str, Any] | None:
    """Find `:T conclude` (and any `:T conclude.<sub>`) blocks in `text` and
    assemble the canonical conclude dict.

    Returns None if no `:T conclude` header is present (no dense conclude
    block authored in this text). Raises `ConcludeOutputError` on malformed
    blocks (header found but rows fail to parse).
    """
    blocks = list(_iter_conclude_blocks(text))
    if not blocks:
        return None

    out: dict[str, Any] = {}
    seen_main = False
    seen_subs: set[str] = set()

    for sub, cols, rows in blocks:
        if sub is None:
            if seen_main:
                raise ConcludeOutputError(
                    "duplicate `:T conclude` block (the scalars table) "
                    "appears more than once"
                )
            seen_main = True
            _absorb_scalars(out, rows)
        else:
            if sub not in _SUB_TABLES:
                raise ConcludeOutputError(
                    f":T conclude.{sub}: unknown sub-table (valid: "
                    f"{sorted(_SUB_TABLES)})"
                )
            if sub in seen_subs:
                raise ConcludeOutputError(
                    f":T conclude.{sub}: declared more than once"
                )
            seen_subs.add(sub)
            _absorb_sub(out, sub, cols, rows)

    if not seen_main:
        # Sub-tables without a parent scalar block are malformed — the
        # producer always emits the scalars block when emitting any sub.
        raise ConcludeOutputError(
            "found `:T conclude.<sub>` rows but no `:T conclude` scalars "
            "block"
        )

    return out


def _iter_conclude_blocks(
    text: str,
) -> list[tuple[str | None, list[str] | None, list[str]]]:
    """Walk `text` and yield (sub_name | None, columns | None, body_rows).

    Body rows are stripped, blank-and-comment lines dropped. The walk stops
    a block at the next `:T` / `:R` / `:V` / `:E` / `:H` / `:L` / `:A` / `:G`
    / `:P` header or at a line beginning a markdown phase header (`## `).
    """
    out: list[tuple[str | None, list[str] | None, list[str]]] = []
    cur_sub: str | None = None
    cur_cols: list[str] | None = None
    cur_rows: list[str] = []
    in_block = False

    def flush():
        nonlocal in_block, cur_sub, cur_cols, cur_rows
        if in_block:
            out.append((cur_sub, cur_cols, cur_rows))
        in_block = False
        cur_sub = None
        cur_cols = None
        cur_rows = []

    block_header = re.compile(r"^:[A-Z]\b")

    for raw in text.splitlines():
        line = raw.strip()
        m = _HEADER_RE.match(line)
        if m:
            flush()
            in_block = True
            cur_sub = m.group("sub")
            cols_raw = m.group("cols")
            cur_cols = (
                [c.strip().rstrip("?") for c in cols_raw.split("|")]
                if cols_raw is not None
                else None
            )
            cur_rows = []
            continue

        if in_block:
            if not line:
                continue
            # Any other dense-block header or a markdown phase header ends
            # the current conclude block.
            if block_header.match(line) or line.startswith("## "):
                flush()
                # Re-evaluate this line for a fresh conclude header.
                m2 = _HEADER_RE.match(line)
                if m2:
                    in_block = True
                    cur_sub = m2.group("sub")
                    cols_raw = m2.group("cols")
                    cur_cols = (
                        [c.strip().rstrip("?") for c in cols_raw.split("|")]
                        if cols_raw is not None
                        else None
                    )
                    cur_rows = []
                continue
            cur_rows.append(line)

    flush()
    return out


def _absorb_scalars(out: dict[str, Any], rows: list[str]) -> None:
    """Parse the scalar table rows (`key  value` lines) into the dict."""
    termination: dict[str, Any] = {}
    for row in rows:
        # Split on the first run of whitespace; keys never contain spaces.
        m = re.match(r"^(\S+)\s+(.*)$", row)
        if not m:
            raise ConcludeOutputError(
                f":T conclude scalar row is malformed (expected `key value`): "
                f"{row!r}"
            )
        key = m.group(1)
        raw = m.group(2).strip()
        value = _parse_scalar_value(raw)

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
            out[key] = value
        else:
            raise ConcludeOutputError(
                f":T conclude scalar row has unknown key: {key!r}"
            )

    if termination:
        out["termination"] = termination


def _parse_scalar_value(raw: str) -> Any:
    if raw == "null":
        return None
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"')
    return raw


def _absorb_sub(
    out: dict[str, Any],
    sub: str,
    cols: list[str] | None,
    rows: list[str],
) -> None:
    dict_key, expected_cols = _SUB_TABLES[sub]
    if cols is None:
        raise ConcludeOutputError(
            f":T conclude.{sub} block missing column header `[…]`"
        )
    if cols != expected_cols:
        raise ConcludeOutputError(
            f":T conclude.{sub} columns must be {expected_cols!r}, got "
            f"{cols!r}"
        )

    if not rows:
        raise ConcludeOutputError(
            f":T conclude.{sub} has no rows (expected at least `none` or "
            f"populated rows)"
        )
    if len(rows) == 1 and rows[0].strip().lower() == "none":
        if dict_key == "ceiling_test":
            return  # ceiling_test absent
        out[dict_key] = []
        return

    if dict_key == "ceiling_test":
        if len(rows) != 1:
            raise ConcludeOutputError(
                f":T conclude.{sub} expects exactly one row (or `none`), "
                f"got {len(rows)}"
            )
        cells = _split_row(rows[0], expected_cols, sub)
        out[dict_key] = dict(zip(expected_cols, cells))
        return

    bucket: list[Any] = []
    for row in rows:
        cells = _split_row(row, expected_cols, sub)
        if dict_key == "surviving_hypotheses":
            # Legacy YAML shape was list[str]; preserve the bare-id form so
            # validator rules walking the field don't change.
            hyp_id = cells[0]
            if not hyp_id:
                raise ConcludeOutputError(
                    f":T conclude.{sub} row has empty hyp_id: {row!r}"
                )
            bucket.append(hyp_id)
        else:
            entry = dict(zip(expected_cols, cells))
            for col in expected_cols:
                if not entry.get(col):
                    raise ConcludeOutputError(
                        f":T conclude.{sub} row missing required cell "
                        f"`{col}`: {row!r}"
                    )
            bucket.append(entry)
    out[dict_key] = bucket


def _split_row(row: str, cols: list[str], sub: str) -> list[str]:
    """Pipe-split a sub-table row against `cols`. Honors `\\|` escapes via
    the shared primitive and emits a phase-tagged error on overlong rows.
    """
    parts = _prim.split_cells(row)
    if len(parts) < len(cols):
        parts = parts + [""] * (len(cols) - len(parts))
    elif len(parts) > len(cols):
        raise ConcludeOutputError(
            f":T conclude.{sub} row has more cells than columns "
            f"(expected {len(cols)}, got {len(parts)}): {row!r}"
        )
    return parts
