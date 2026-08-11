#!/usr/bin/env python3
"""Control-window measurement for oracle-calibration cases (#711).

A control answers one question: *would this row be here anyway?* Get it wrong and
the lead's result class is wrong, silently. The procedure doc's first rule is
**measure a control with the lead's own query predicate** — a control taken on a
broader filter describes a different envelope, and the mismatch is invisible.
Case-003 broke exactly that rule (its control counted *all* dev-ws-1 auth docs
while the lead filters `event.outcome IS NOT NULL`), and the `-noise` label it
justified did not survive re-measurement.

This module makes that rule true **by construction** rather than by discipline: a
control IS the lead's own ES|QL string with nothing changed but the two
`@timestamp` bounds. There is no path here that can widen a predicate, because
there is no path here that can write one.

Split deliberately in two:
  - window arithmetic and query rewriting — pure, no clock, no network, unit-tested;
  - execution — one `infra/bin/es.sh` call, the same transport the elastic adapter
    and `extract_alert.py` use.

Payloads are emitted in the SAME shape the production `esql` verb stores
(`{query, columns, row_count, values}`), so `label.py` compares attack-window and
control payloads like with like rather than reconciling two formats.

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

ES_SH = REPO_ROOT / "infra" / "bin" / "es.sh"

# The two bounds a lead's ES|QL carries. Captured as three groups so a rewrite can
# put back the operator and quoting exactly as the query had them — the goal is a
# string that differs from the original in the timestamps and NOTHING else.
_BOUND = re.compile(r'(@timestamp\s*(?:>=|>|<=|<)\s*")([^"]+)(")')

# Shape-matched by default: whole weeks back, so a Saturday capture is controlled
# against prior Saturdays. The playground's baseline generators are
# schedule-shaped (weekday/weekend multipliers), so a weekday control for a
# weekend capture is not a control at all — it is a different environment.
DEFAULT_OFFSETS_DAYS = (7, 14, 21)

#: A control window must be long enough to have a chance of SEEING the baseline.
#: Duration-matching is the wrong instinct here: case-004's operation lasted 21
#: seconds, and 21-second control windows observed almost nothing, so a routine
#: `sre.alice -> db-1` login graded `+event` — a manufactured catch. The
#: hand-written seed controls already used an hour for a three-minute attack
#: (case-001: 07:30-08:30 controlling 07:45-07:48); this makes that practice the
#: default. Widening can only move a class toward `+noise`, which is the safe
#: direction: it costs recall, never a false detection.
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


def esql_window(query: str) -> tuple[datetime, datetime] | None:
    """The (start, end) window a query filters on, or `None` if it has no bounds.

    `None` is a real and common answer, not an error: case-001's zeek leads carry
    no `@timestamp` predicate at all, so their payload mixes historical baseline
    with the attack. Those cannot be controlled by shifting — there is no bound to
    shift — and the caller must say so rather than inventing a window.
    """
    bounds = esql_bounds(query)
    if len(bounds) != 2:
        return None
    start, end = (parse_iso(b) for b in bounds)
    return (start, end) if start < end else (end, start)


def shift_esql_window(query: str, start: datetime, end: datetime) -> str:
    """The same query with only its two `@timestamp` literals replaced.

    Raises when the query does not carry exactly two bounds — silently returning
    the query unchanged would produce a "control" that re-measures the attack
    window and reports every event as baseline, turning every `+event` into
    `+noise`. That is the most dangerous possible failure of this module, so it is
    an exception rather than a fallback.
    """
    replacements = [format_iso(start), format_iso(end)]
    if len(esql_bounds(query)) != len(replacements):
        raise ValueError(
            f"expected exactly 2 @timestamp bounds to shift, found {len(esql_bounds(query))}")
    counter = iter(replacements)
    return _BOUND.sub(lambda m: m.group(1) + next(counter) + m.group(3), query)


def add_esql_window(query: str, start: datetime, end: datetime) -> str:
    """Add a `@timestamp` restriction to a query that carries none.

    Case-001's six zeek queries filter on host and IP but not on time, so their
    stored payload mixes the attack with months of history and there is no bound
    to shift. The control for such a query is the same predicate restricted to a
    baseline window — and its *attack contribution* is the same predicate
    restricted to the attack window. Comparing those two is the only way the
    activity's delta is visible at all; comparing the unbounded payload against a
    bounded control would compare two different questions.

    Inserted as its own `WHERE` immediately after the source command, which
    narrows the row set and cannot widen it — the property that matters.
    """
    if esql_bounds(query):
        raise ValueError("query already carries @timestamp bounds — shift, do not add")
    lines = query.splitlines()
    if not lines:
        raise ValueError("empty query")
    clause = (f'| WHERE @timestamp >= "{format_iso(start)}" '
              f'AND @timestamp < "{format_iso(end)}"')
    return "\n".join([lines[0], clause, *lines[1:]])


def shape_matched_windows(start: datetime, end: datetime,
                          offsets_days: tuple[int, ...] = DEFAULT_OFFSETS_DAYS,
                          min_seconds: int = MIN_CONTROL_SECONDS,
                          ) -> list[tuple[str, datetime, datetime]]:
    """Named control windows: the same clock time, whole weeks earlier.

    Widened symmetrically about the operation's midpoint to at least
    `min_seconds`, because a control shorter than the baseline's own period
    cannot observe the baseline at all — see `MIN_CONTROL_SECONDS`. Whole-week
    offsets keep the weekday, which matters: the Poisson baseline generators are
    schedule-shaped, so a weekday control for a weekend capture is not a control.
    """
    midpoint = start + (end - start) / 2
    half = max((end - start) / 2, timedelta(seconds=min_seconds) / 2)
    lo, hi = midpoint - half, midpoint + half
    return [(f"C-{days}d", lo - timedelta(days=days), hi - timedelta(days=days))
            for days in offsets_days]


#: Liveness answers per control window, so a case's ~50 queries do not re-probe
#: the same three windows. Keyed by the exact window, never by day.
_LIVENESS: dict[tuple[str, str], bool] = {}


def named_cell(payload: dict, name: str, default: Any = None) -> Any:
    """The named cell of a columnar ES|QL payload's FIRST row, or `default`.

    `values` is the wire's own positional form since #834 — cell `i` binds to `columns[i]` —
    so a read resolves the index off `columns` instead of hardcoding one. Pure, and named,
    so the reader a caller runs is the reader a test can pin; a test that re-derives the
    index inline pins its own copy and stays green when the caller regresses to `row[0]`.

    `default` covers both "no rows" and "no such column": a probe whose projection does not
    carry the name has measured nothing, which is not the same fact as a zero.
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

    The stack is levered up and down between snapshots, so a control window can
    land in a gap when the server did not exist. A dead window returns zero rows
    for every query, which is indistinguishable from "this stream has no
    baseline" — and reading it that way suppresses real `-noise`: case-003's
    `l-002` control at 2026-07-18 is empty only because the environment was
    levered down between 07-17 and 07-25, while the same query a week earlier
    returns 444 auth documents.

    The probe is total ingest across `logs-*` for the window. Zero documents from
    ANY host means the environment was not running; no live playground-v2 hour is
    silent, because the agents alone emit metricbeat continuously.
    """
    key = (format_iso(start), format_iso(end))
    if key not in _LIVENESS:
        probe = (f'FROM logs-*\n| WHERE @timestamp >= "{key[0]}" AND @timestamp < "{key[1]}"\n'
                 f"| STATS total = COUNT(*)")
        # Positional, because `values` is now the wire's own columnar form (#834). The index
        # is resolved from `columns` rather than hardcoded to 0: this probe projects a single
        # column today, and a name lookup does not rot if it ever projects two.
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
    # Through the ADAPTER's own shaper, not a second copy of it. This module used to
    # re-implement the zip under a docstring promising "the production `esql` verb's payload
    # shape" — two producers, one promise, and nothing keeping them equal. #834 changed that
    # shape; had the copy stayed, `label.py` would have gone on comparing an attack window
    # in one encoding against its controls in the other.
    return esql_payload(query, resp)


def measure_controls(query: str, offsets_days: tuple[int, ...] = DEFAULT_OFFSETS_DAYS,
                     *, operation_window: tuple[datetime, datetime] | None = None,
                     dry_run: bool = False) -> tuple[list[dict], dict | None]:
    """Measure this query's controls, and its attack-window contribution if needed.

    Two shapes, because the leads really come in two shapes:

    - the query **carries bounds** — shift them; the stored observed payload is
      already the attack-window measurement, so nothing extra is needed.
    - the query **carries none** (case-001's zeek leads) — its stored payload
      mixes the attack with all history. Restrict it to `operation_window` to get
      the activity's actual contribution, and to the shifted windows for the
      baseline. Without an `operation_window` there is nothing to compare and the
      honest answer is no controls at all, which the labeler reads as
      `needs-label`.

    Returns `(controls, attack_contribution)`, the latter `None` when the stored
    payload already is the attack-window measurement.
    """
    window = esql_window(query)
    contribution = None

    if window is not None:
        windows = shape_matched_windows(*window, offsets_days)
        rewrite = shift_esql_window
    elif esql_bounds(query):
        # An ODD number of `@timestamp` bounds — one, or three. Neither route is
        # safe: there is no window to shift, and adding one would leave the
        # original bound in place, so the "control" would filter on a mix of the
        # attack window and the baseline window. Real defender queries do carry
        # these shapes; refuse rather than measure the wrong thing.
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
                    # A window the environment was not running in is not a control.
                    # Recorded rather than dropped, so the case shows what was tried.
                    "live": live,
                    "payload": None if (dry_run or not live) else run_esql(shifted)})
    return out, contribution


def _operation_window(case_dir: Path) -> tuple[datetime, datetime] | None:
    """The real operation's window, from the manifest.

    Read from whichever provenance block the case carries — `attack.window` for a
    catalog scenario, `operation.window` for a hand-run one. Absent for a case
    whose manifest never recorded one, and that absence is reported rather than
    guessed: inventing a window here would silently define the baseline.
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


def _lead_queries(case_dir: Path) -> list[tuple[str, int, dict]]:
    """(lead_id, seq, params) for every query, in the order build_case.py stored them."""
    text = (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8")
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        for seq, q in enumerate(row.get("queries", [])):
            out.append((row["lead_id"], seq, q.get("params") or {}))
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

    for lead_id, seq, params in _lead_queries(ns.case_dir):
        query = params.get("query")
        if not isinstance(query, str):
            skipped += 1          # state/lookup query — no window, nothing to shift
            continue
        observed = ns.case_dir / "hidden" / "observed" / lead_id / f"{seq}.json"
        if observed.is_file() and observed.stat().st_size == 0:
            # A zero-byte payload is an ERRORED query (query_tool.py writes "" on a
            # non-zero exit). Controlling it would only re-run the same broken
            # query; the labeler already excludes it from the comparison.
            skipped += 1
            print(f"  {lead_id}/{seq}: errored at capture (zero-byte payload) — skipped")
            continue
        try:
            controls, contribution = measure_controls(
                query, offsets, operation_window=operation_window, dry_run=ns.dry_run)
        except RuntimeError as exc:
            # A query that will not run cannot be controlled. Record nothing rather
            # than an empty control set — an empty control set means "the baseline
            # was empty", which would turn every row into a `+event`.
            skipped += 1
            print(f"  {lead_id}/{seq}: control query failed — skipped ({exc})"[:200])
            continue
        if not controls:
            skipped += 1
            print(f"  {lead_id}/{seq}: no time bounds and no operation window — "
                  f"not controllable")
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
    sys.exit(main())
