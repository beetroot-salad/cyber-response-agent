#!/usr/bin/env python3
"""Print wall-time and cost for one or more defender runs.

Usage:
    python3 scripts/analytics/run_stats.py <run_dir> [<run_dir> ...]

Reads each run's `tool_trace.jsonl` and pulls the trailing
`type:"result"` event, which carries `duration_ms`, `duration_api_ms`,
`total_cost_usd`, `num_turns`, and the token usage breakdown. Prints
one row per run plus a totals row when more than one is given.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def load_result(run_dir: Path) -> dict | None:
    trace = run_dir / "tool_trace.jsonl"
    if not trace.is_file():
        return None
    last_result: dict | None = None
    for line in trace.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "result":
            last_result = event
    return last_result


def fmt_row(name: str, r: dict) -> str:
    wall_s = (r.get("duration_ms") or 0) / 1000
    api_s = (r.get("duration_api_ms") or 0) / 1000
    cost = r.get("total_cost_usd") or 0
    turns = r.get("num_turns") or 0
    u = r.get("usage") or {}
    in_t = u.get("input_tokens", 0)
    out_t = u.get("output_tokens", 0)
    cr_t = u.get("cache_read_input_tokens", 0)
    cc_t = u.get("cache_creation_input_tokens", 0)
    return (
        f"{name:<30} wall={wall_s:7.1f}s api={api_s:7.1f}s "
        f"cost=${cost:6.3f} turns={turns:3d} "
        f"in={in_t:>6} out={out_t:>6} cache_r={cr_t:>8} cache_w={cc_t:>6}"
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: run_stats.py <run_dir> [<run_dir> ...]", file=sys.stderr)
        return 64

    rows: list[tuple[str, dict]] = []
    for arg in argv[1:]:
        run_dir = Path(arg).resolve()
        result = load_result(run_dir)
        if result is None:
            print(f"# no result event in {run_dir}", file=sys.stderr)
            continue
        rows.append((run_dir.name, result))

    if not rows:
        return 1

    for name, r in rows:
        print(fmt_row(name, r))

    if len(rows) > 1:
        total_wall = sum((r.get("duration_ms") or 0) for _, r in rows) / 1000
        total_api = sum((r.get("duration_api_ms") or 0) for _, r in rows) / 1000
        total_cost = sum((r.get("total_cost_usd") or 0) for _, r in rows)
        total_turns = sum((r.get("num_turns") or 0) for _, r in rows)
        print(
            f"{'TOTAL':<30} wall={total_wall:7.1f}s api={total_api:7.1f}s "
            f"cost=${total_cost:6.3f} turns={total_turns:3d}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
