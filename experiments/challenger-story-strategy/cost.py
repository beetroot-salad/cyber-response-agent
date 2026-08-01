#!/usr/bin/env python3
"""Cost and wall time per arm, from the per-call logs.

Two wall-time numbers, because they differ for the lens arm and the difference is the
whole point of it: `wall` is what the run actually took (its per-lead checks are issued
concurrently), `serial` is the sum of call durations — what it would cost in latency if
the lens calls were issued one at a time.

Tokens are ESTIMATED from prompt characters at 4 chars/token, not measured. Payload JSON
tokenizes worse than prose, so treat these as a floor. No cache discount is applied; the
arms that resend the full payload set each pass would benefit most from prompt caching,
so the spread below is an upper bound on their real cost.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, "/workspace/defender")
from scripts.pricing import PRICING as PRICES  # noqa: E402

CHARS_PER_TOKEN = 4
MODEL = "glm-5.2"


def rows(base: Path) -> list[dict]:
    out = []
    for fixture in sorted(p for p in base.iterdir() if p.is_dir()):
        for arm in sorted(p for p in fixture.iterdir() if p.is_dir()):
            mp = arm / "meta.json"
            if not mp.is_file():
                continue
            m = json.loads(mp.read_text())
            calls = m.get("calls_detail") or []
            in_tok = sum(c["prompt_chars"] for c in calls) / CHARS_PER_TOKEN
            out_tok = sum(c["output_chars"] for c in calls) / CHARS_PER_TOKEN
            p = PRICES[MODEL]
            out.append({
                "round": base.name, "arm": arm.name,
                "calls": len(calls),
                "in_ktok": round(in_tok / 1000, 1),
                "out_ktok": round(out_tok / 1000, 1),
                "usd": round(in_tok / 1e6 * p["in"] + out_tok / 1e6 * p["out"], 4),
                "serial_s": round(sum(c["seconds"] for c in calls)),
                "wall_s": round(max((c["seconds"] for c in calls), default=0)) if arm.name == "lens"
                          else round(sum(c["seconds"] for c in calls)),
            })
    return out


def main() -> int:
    allrows = []
    for d in ("runs_v2", "runs_v3"):
        base = Path(__file__).parent / d
        if base.is_dir():
            allrows += rows(base)
    if not allrows:
        print("no runs yet")
        return 0
    cols = ["round", "arm", "calls", "in_ktok", "out_ktok", "usd", "serial_s", "wall_s"]
    w = {c: max(len(c), *(len(str(r[c])) for r in allrows)) for c in cols}
    print("  ".join(c.ljust(w[c]) for c in cols))
    print("  ".join("-" * w[c] for c in cols))
    for r in allrows:
        print("  ".join(str(r[c]).ljust(w[c]) for c in cols))
    print("\nwall_s for `lens` is the slowest single call (checks run concurrently); the "
          "fold and seed are additive on top — see serial_s for the un-parallelized cost.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
