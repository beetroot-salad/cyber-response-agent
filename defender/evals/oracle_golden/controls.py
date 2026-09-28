#!/usr/bin/env python3
"""Control-window measurement for oracle-calibration cases.

A control answers *would this row be here anyway?* It must use the lead's own query
predicate: a control on a broader filter describes a different envelope, invisibly. Here a
control is the lead's own ES|QL string with only the two `@timestamp` bounds changed, so no
path can widen the predicate.

Window arithmetic and query rewriting are pure (no clock, no network); execution is one
`infra/bin/es.sh` call, the same transport the elastic adapter uses.

Payloads are emitted in the SAME shape the production `esql` verb stores
(`{query, columns, row_count, values}`), so `judge.py` compares attack-window and control
payloads like with like.

Usage:
  controls.py <case_dir> [--offsets-days 7,14,21] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.scripts.adapters.elastic_adapter import esql_payload  # noqa: E402
# `split_commands` is re-exported for `validate_cases` and tests. The F401 `noqa` must stay on
# the name's own line: ruff ignores a `noqa` on a separate comment line.
from defender.scripts.adapters.esql_text import (  # noqa: E402
    split_commands,  # noqa: F401
    split_first_command,
)

ES_SH = REPO_ROOT / "infra" / "bin" / "es.sh"

# The two bounds a lead's ES|QL carries. Three groups so a rewrite restores the operator and
# quoting exactly, changing only the timestamps.
_BOUND = re.compile(r'(@timestamp\s*(?:>=|>|<=|<)\s*")([^"]+)(")')

# The operator inside a `_BOUND` match's first group. Not a fourth capture group, because
# callers depend on `_BOUND`'s group numbering.
_OPERATOR = re.compile(r"(?:>=|>|<=|<)")

# Whole weeks back, so the weekday matches: the playground's baseline generators are
# schedule-shaped (weekday/weekend multipliers).
DEFAULT_OFFSETS_DAYS = (7, 14, 21)

#: Minimum control window. A duration-matched control for a short operation observes almost
#: nothing, so routine activity grades `+event`. Widening only moves a class toward `+noise`,
#: which costs recall, never a false detection.
MIN_CONTROL_SECONDS = 3600

ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")


def parse_iso(text: str) -> datetime:
    """Parse the timestamp literals ES|QL carries (with or without millis)."""
    normalized = text.replace("Z", "+0000")
    for fmt in ISO_FORMATS:
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    raise ValueError(f"unparseable ES|QL timestamp literal: {text!r}")


def format_iso(when: datetime) -> str:
    """Render back in the literal shape ES|QL accepts (millisecond Z form)."""
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def esql_bounds(query: str) -> list[str]:
    """The `@timestamp` literals this query filters on, in source order."""
    return [m.group(2) for m in _BOUND.finditer(query)]


def _operator_of(prefix: str) -> str:
    """The comparison operator inside a `_BOUND` match's first group."""
    found = _OPERATOR.search(prefix)
    # Unreachable; asserted because a default would silently pick a bound direction.
    assert found is not None, f"_BOUND matched without an operator: {prefix!r}"
    return found.group(0)


def esql_operators(query: str) -> list[str]:
    """The comparison operator of each `@timestamp` bound, in source order.

    Source order is not semantic order: a query may write its upper bound first, so
    rewrites bind replacements by operator, not position.
    """
    return [_operator_of(m.group(1)) for m in _BOUND.finditer(query)]


def bounds_name_a_window(query: str) -> bool:
    """Do this query's `@timestamp` bounds bound a window — exactly one each way?

    Two literals are not automatically a window: `@timestamp >= A AND @timestamp >= B`
    bounds nothing above.
    """
    ops = esql_operators(query)
    return (sum(op.startswith(">") for op in ops) == 1
            and sum(op.startswith("<") for op in ops) == 1)


def esql_window(query: str) -> tuple[datetime, datetime] | None:
    """The (start, end) window a query filters on, or `None` if it has no bounds.

    `None` is common: some leads carry no `@timestamp` predicate, and a pair that is not
    one lower and one upper bound names no window either. Callers must not invent one.
    """
    # One lower plus one upper bound already implies exactly two bounds.
    if not bounds_name_a_window(query):
        return None
    start, end = (parse_iso(b) for b in esql_bounds(query))
    return (start, end) if start < end else (end, start)


def shift_esql_window(query: str, start: datetime, end: datetime) -> str:
    """The same query with only its two `@timestamp` literals replaced.

    `start` replaces the `>=`/`>` bound and `end` the `<=`/`<` bound, matched by operator
    rather than position: a query written upper-bound-first would otherwise get crossed
    bounds, an unsatisfiable predicate whose zero rows read as an empty baseline.

    Raises unless there is exactly one lower and one upper bound. Returning the query
    unchanged would re-measure the attack window as its own baseline, turning every
    `+event` into `+noise`.
    """
    bounds = esql_bounds(query)
    if len(bounds) != 2:
        raise ValueError(
            f"expected exactly 2 @timestamp bounds to shift, found {len(bounds)}")
    if not bounds_name_a_window(query):
        raise ValueError(
            f"expected one lower and one upper @timestamp bound to shift, found "
            f"{esql_operators(query)} — this pair names no window")
    lo, hi = format_iso(start), format_iso(end)
    return _BOUND.sub(
        lambda m: m.group(1)
        + (lo if _operator_of(m.group(1)).startswith(">") else hi)
        + m.group(3),
        query)


def add_esql_window(query: str, start: datetime, end: datetime) -> str:
    """Add a `@timestamp` restriction to a query that carries none.

    An unbounded query's payload mixes the attack with all history. Its control is the same
    predicate restricted to a baseline window, compared against its *attack contribution*:
    the same predicate restricted to the attack window.

    Inserted as its own `WHERE` immediately after the source command, where it can only
    narrow the row set. The source command ends at the first `|`, not the first newline: in
    a one-line `FROM logs-zeek.ssh-* | LIMIT 1`, a clause after `LIMIT` would filter one
    arbitrary row and read as an empty baseline.
    """
    if esql_bounds(query):
        raise ValueError("query already carries @timestamp bounds — shift, do not add")
    if not query.strip():
        raise ValueError("empty query")
    clause = (f'| WHERE @timestamp >= "{format_iso(start)}" '
              f'AND @timestamp < "{format_iso(end)}"')
    # The tail is kept verbatim so nothing but the clause changes. `split_first_command`
    # ignores a `|` inside a string literal.
    head, tail = split_first_command(query)
    placed = f"{head.rstrip()}\n{clause}"
    return f"{placed}\n{tail}" if tail else placed


def shape_matched_windows(start: datetime, end: datetime,
                          offsets_days: tuple[int, ...] = DEFAULT_OFFSETS_DAYS,
                          min_seconds: int = MIN_CONTROL_SECONDS,
                          ) -> list[tuple[str, datetime, datetime]]:
    """Named control windows: the same clock time, whole weeks earlier.

    Widened symmetrically about the operation's midpoint to at least `min_seconds`
    (see `MIN_CONTROL_SECONDS`); whole-week offsets keep the weekday.
    """
    midpoint = start + (end - start) / 2
    half = max((end - start) / 2, timedelta(seconds=min_seconds) / 2)
    lo, hi = midpoint - half, midpoint + half
    return [(f"C-{days}d", lo - timedelta(days=days), hi - timedelta(days=days))
            for days in offsets_days]


#: Liveness per exact control window, so a case's queries do not re-probe the same windows.
_LIVENESS: dict[tuple[str, str], bool] = {}


def named_cell(payload: dict, name: str, default: Any = None) -> Any:
    """The named cell of a columnar ES|QL payload's FIRST row, or `default`.

    Resolves the column index from `columns` rather than hardcoding it. `default` covers
    both "no rows" and "no such column" (measured nothing, which is not a zero).
    """
    columns = payload.get("columns", [])
    rows = payload.get("values", [])
    idx = next((i for i, c in enumerate(columns) if c.get("name") == name), None)
    if idx is None or not rows:
        return default
    row = rows[0]
    return row[idx] if idx < len(row) else default


def window_is_live(start: datetime, end: datetime) -> bool:
    """Was the environment RUNNING during this window?

    The stack is levered up and down, so a control window can land in a gap. A dead window
    returns zero rows for every query, which would read as "no baseline".

    Probes total ingest across `logs-*`: no live hour is silent, because the agents emit
    metricbeat continuously.
    """
    key = (format_iso(start), format_iso(end))
    if key not in _LIVENESS:
        probe = (f'FROM logs-*\n| WHERE @timestamp >= "{key[0]}" AND @timestamp < "{key[1]}"\n'
                 f"| STATS total = COUNT(*)")
        total = named_cell(run_esql(probe), "total", default=0)
        _LIVENESS[key] = bool(total)
    return _LIVENESS[key]


def run_esql(query: str, *, timeout: int = 180) -> dict:
    """Execute one ES|QL query, returning the production `esql` verb's payload shape."""
    proc = subprocess.run(
        [str(ES_SH), "/_query?format=json",
         "-H", "Content-Type: application/json",
         "-d", json.dumps({"query": query})],
        capture_output=True, text=True, encoding="utf-8",
        timeout=timeout, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"es.sh failed ({proc.returncode}): {proc.stderr.strip()[:400]}")
    resp = json.loads(proc.stdout)
    if "error" in resp:
        raise RuntimeError(f"ES|QL error: {json.dumps(resp['error'])[:400]}")
    # The adapter's own shaper, so attack and control payloads cannot drift apart in shape.
    return esql_payload(query, resp)


def measure_controls(query: str, offsets_days: tuple[int, ...] = DEFAULT_OFFSETS_DAYS,
                     *, operation_window: tuple[datetime, datetime] | None = None,
                     dry_run: bool = False) -> tuple[list[dict], dict | None]:
    """Measure this query's controls, and its attack-window contribution if needed.

    - The query **carries bounds**: shift them; the stored payload already is the
      attack-window measurement.
    - The query **carries none**: restrict it to `operation_window` for the attack
      contribution and to shifted windows for the baseline. Without an
      `operation_window`, return no controls (the labeler reads that as `needs-label`).

    Returns `(controls, attack_contribution)`, the latter `None` when the stored
    payload already is the attack-window measurement.
    """
    window = esql_window(query)
    contribution = None

    if window is not None:
        windows = shape_matched_windows(*window, offsets_days)
        rewrite = shift_esql_window
    elif esql_bounds(query):
        # Bounds that name no window (odd count, or both one way): nothing to shift, and
        # adding a window would mix it with the original bounds. Refuse.
        return [], None
    elif operation_window is not None:
        windows = shape_matched_windows(*operation_window, offsets_days)
        rewrite = add_esql_window
        restricted = add_esql_window(query, *operation_window)
        contribution = {
            "window": [format_iso(operation_window[0]), format_iso(operation_window[1])],
            "query": restricted,
            "payload": None if dry_run else run_esql(restricted),
        }
    else:
        return [], None

    out = []
    for name, start, end in windows:
        shifted = rewrite(query, start, end)
        live = True if dry_run else window_is_live(start, end)
        out.append({"name": name, "window": [format_iso(start), format_iso(end)],
                    "query": shifted,
                    # A dead window is not a control; recorded to show what was tried.
                    "live": live,
                    "payload": None if (dry_run or not live) else run_esql(shifted)})
    return out, contribution


def _operation_window(case_dir: Path) -> tuple[datetime, datetime] | None:
    """The real operation's window, from the manifest.

    `attack.window` for a catalog scenario, `operation.window` for a hand-run one. `None`
    when absent; guessing would silently define the baseline.
    """
    import yaml  # local: keeps the pure window helpers importable without pyyaml
    manifest_path = case_dir / "manifest.yaml"
    if not manifest_path.is_file():
        return None
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    for block in ("attack", "operation"):
        window = (manifest.get(block) or {}).get("window")
        if isinstance(window, list) and len(window) == 2:
            return (parse_iso(window[0]), parse_iso(window[1]))
    return None


def lead_queries(case_dir: Path) -> list[tuple[str, int, dict]]:
    """(lead_id, seq, params) for every query, in the order the case assembler stored them.

    `seq` is the queries table's seq, which names the observed payload (`{seq}.json`). It
    differs from list position once `∅.` sentinel rows are split out, and pairing by
    position would baseline one query against another's envelope. Cases without a `seq`
    field fall back to position, which is exact for them (no sentinels were split out).
    """
    text = (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8")
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        for index, q in enumerate(row.get("queries", [])):
            out.append((row["lead_id"], q.get("seq", index), q.get("params") or {}))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("case_dir", type=Path, help="golden case directory")
    p.add_argument("--offsets-days", default=",".join(str(d) for d in DEFAULT_OFFSETS_DAYS),
                   help="comma-separated whole-day offsets back from the attack window")
    p.add_argument("--dry-run", action="store_true",
                   help="derive the control queries but do not execute them")
    ns = p.parse_args(argv)

    offsets = tuple(int(x) for x in ns.offsets_days.split(",") if x.strip())
    out_root = ns.case_dir / "hidden" / "controls"
    operation_window = _operation_window(ns.case_dir)
    if operation_window is None:
        print("!! manifest carries no operation window — queries without their own "
              "@timestamp bounds cannot be controlled and will stay `needs-label`")
    measured = skipped = 0

    for lead_id, seq, params in lead_queries(ns.case_dir):
        query = params.get("query")
        if not isinstance(query, str):
            skipped += 1          # state/lookup query — no window, nothing to shift
            continue
        observed = ns.case_dir / "hidden" / "observed" / lead_id / f"{seq}.json"
        if observed.is_file() and observed.stat().st_size == 0:
            # Zero-byte means the query errored at capture; the labeler excludes it anyway.
            skipped += 1
            print(f"  {lead_id}/{seq}: errored at capture (zero-byte payload) — skipped")
            continue
        try:
            controls, contribution = measure_controls(
                query, offsets, operation_window=operation_window, dry_run=ns.dry_run)
        except RuntimeError as exc:
            # Record nothing: an empty control set would mean "empty baseline".
            skipped += 1
            print(f"  {lead_id}/{seq}: control query failed — skipped ({exc})"[:200])
            continue
        if not controls:
            skipped += 1
            why = ("@timestamp bounds that name no window"
                   if esql_bounds(query) else
                   "no time bounds and no operation window")
            print(f"  {lead_id}/{seq}: {why} — not controllable")
            continue
        record = {"lead_id": lead_id, "seq": seq, "controls": controls}
        if contribution is not None:
            record["attack_contribution"] = contribution
        if not ns.dry_run:
            dest = out_root / lead_id
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{seq}.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8")
        counts = [c["payload"]["row_count"] if c["payload"] else "?" for c in controls]
        extra = ""
        if contribution is not None:
            got = contribution["payload"]
            extra = f"  attack-window={got['row_count'] if got else '?'} (restricted)"
        print(f"  {lead_id}/{seq}: {len(controls)} controls, row_counts={counts}{extra}")
        measured += 1

    print(f"\nmeasured {measured} queries, skipped {skipped} (no shiftable window)")
    print(f"{'would write' if ns.dry_run else 'wrote'} {out_root}")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main())
