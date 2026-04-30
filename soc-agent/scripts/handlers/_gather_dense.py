"""Dense-format parser for the gather / gather-composite subagent output prefix.

The subagents emit a top-of-trailer dense block carrying lead row-identity and
outcome status, before the conventional ```yaml gather: ... ``` envelope:

    :L findings [id|name|status]
    l-001|approved-monitoring-sources-lookup|ok
    l-002|process-lineage|dropped_attempt

    ```yaml
    gather:
      loop: 1
      leads:
        - id: l-001
          query: { ... }
          characterization: { ... }
        - id: l-002
          query: { ... }
          status_detail: ...
    ```

The dense block is the canonical surface for `name` and `status`; the YAML
body retains `id` (for cross-referencing) plus everything that resists
tabulation: per-lead `query`, `characterization`, `baseline`, `health_probe`,
`status_detail`, `escalate_trigger`, `escalate_context`, `notes`, `raw`,
plus the top-level `loop` and `cross_lead_notes`.

`parse_gather_dense` returns an order-preserving list of dicts; the caller
joins with the YAML envelope's `leads[*]` by `id`.

Mirrors `_prologue_dense.py`'s fail-fast discipline: first violation raises
`GatherDenseError`. No silent coercion.
"""

from __future__ import annotations

import re


VALID_LEAD_STATUSES = frozenset({
    "ok",               # lead executed, full characterization
    "partial",          # lead executed, some bullets "not available"
    "data_missing",     # source answered, empty result (verified)
    "dropped_attempt",  # structural refusal / skipped
    "probe_broken",     # health probe returned count_fn_error / baseline_no_samples
    "siem_error",       # SIEM CLI returned an error that couldn't be resolved
    "error",            # single-gather generic error (escalate_trigger carries the specific reason)
})


class GatherDenseError(ValueError):
    """Raised on any malformed gather dense-block output."""


_HEADER_RE = re.compile(
    r"^:L\s+findings\s*\[(?P<cols>[^\]]*)\]\s*$"
)

_FINDINGS_COLS = ["id", "name", "status"]

_YAML_FENCE_START_RE = re.compile(r"^```yaml\s*$", re.MULTILINE)
_GATHER_TOP_LEVEL_RE = re.compile(r"^gather:\s*$", re.MULTILINE)


def split_dense_and_yaml(stdout: str) -> tuple[str, str]:
    """Split subagent stdout into (dense_prefix, yaml_envelope).

    The YAML envelope starts at the first ` ```yaml ` fence (preferred) or,
    failing that, at the first top-level `gather:` line. Everything before
    is dense.

    Raises `GatherDenseError` if neither marker is found — without a YAML
    envelope there's nothing for the gather handler to operate on.
    """
    fence = _YAML_FENCE_START_RE.search(stdout)
    if fence:
        split = fence.start()
        return stdout[:split], stdout[split:]
    top_level = _GATHER_TOP_LEVEL_RE.search(stdout)
    if top_level:
        split = top_level.start()
        return stdout[:split], stdout[split:]
    raise GatherDenseError(
        "gather output: no `gather:` YAML envelope found after dense block"
    )


def parse_gather_dense(text: str) -> list[dict[str, str]]:
    """Parse the `:L findings [id|name|status]` block.

    Returns an order-preserving list of `{"id", "name", "status"}` dicts.
    Empty input, missing header, duplicate ids, and status enum violations
    raise `GatherDenseError`.
    """
    body = _strip_outer_fence(text).strip()
    if not body:
        raise GatherDenseError("gather dense block is empty")

    rows: list[dict[str, str]] | None = None
    seen_ids: set[str] = set()

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        header_match = _HEADER_RE.match(stripped)
        if header_match:
            cols = [c.strip().rstrip("?") for c in header_match.group("cols").split("|")]
            if cols != _FINDINGS_COLS:
                raise GatherDenseError(
                    f":L findings columns must be {_FINDINGS_COLS!r}, got {cols!r}"
                )
            if rows is not None:
                raise GatherDenseError(
                    ":L findings declared more than once"
                )
            rows = []
            continue

        if stripped.startswith(":") and re.match(r"^:[A-Za-z]\b", stripped):
            raise GatherDenseError(
                f"gather dense: unrecognized block header: {stripped!r}"
            )

        if rows is None:
            raise GatherDenseError(
                f"gather dense: row before `:L findings` header: {stripped!r}"
            )

        cells = [c.strip() for c in stripped.split("|")]
        if len(cells) != len(_FINDINGS_COLS):
            raise GatherDenseError(
                f":L findings row must have {len(_FINDINGS_COLS)} cells "
                f"(id|name|status), got {len(cells)}: {stripped!r}"
            )
        rid, rname, rstatus = cells
        if not rid or not rname or not rstatus:
            raise GatherDenseError(
                f":L findings row missing required cell "
                f"(id/name/status all required): {stripped!r}"
            )
        if rid in seen_ids:
            raise GatherDenseError(
                f":L findings row id={rid!r} duplicates a prior row"
            )
        if rstatus not in VALID_LEAD_STATUSES:
            raise GatherDenseError(
                f":L findings row status={rstatus!r} not in "
                f"{sorted(VALID_LEAD_STATUSES)}"
            )
        seen_ids.add(rid)
        rows.append({"id": rid, "name": rname, "status": rstatus})

    if rows is None:
        raise GatherDenseError(
            "gather output missing `:L findings` dense block"
        )
    if not rows:
        raise GatherDenseError(":L findings block must have at least one row")
    return rows


def _strip_outer_fence(text: str) -> str:
    body = text.strip()
    if body.startswith("```"):
        first_newline = body.find("\n")
        if first_newline == -1:
            return body
        inner = body[first_newline + 1:]
        if inner.rstrip().endswith("```"):
            inner = inner.rstrip()[:-3]
        return inner.strip()
    return body
