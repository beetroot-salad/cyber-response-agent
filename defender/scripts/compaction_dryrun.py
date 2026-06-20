#!/usr/bin/env python3
"""Offline dry-run of per-loop compaction over a recorded run.

Step 0 of the Phase-B validation ladder (design doc §Validation): compaction
is a pure history-rewrite, so we replay it over a recorded `llm_requests.jsonl`
— no API, no stack, no drift — to (a) exercise loop-detection and the
prefix-builder on a real history and (b) get a first *mechanical* savings
number before anything touches the live driver.

What it does NOT capture: trajectory divergence (the agent may behave
differently once it sees compacted context). That needs a live A/B run — this
only measures the rewrite applied to the history the agent actually produced.

Usage:
    python3 defender/scripts/compaction_dryrun.py <run_dir|llm_requests.jsonl>
    python3 defender/scripts/compaction_dryrun.py /tmp/defender-runs/<id> --json

Token figures are estimates: char-counted payload converted with a
chars-per-token ratio calibrated from this run's own generated output (printed
for audit). The headline mechanical figure — history-payload chars removed —
is tokenizer-free and exact.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root → defender.*

from defender.runtime import compaction as C


@dataclass
class StepMetric:
    seq: int
    action: str
    loop: int | None
    full_chars: int
    comp_chars: int
    input_tokens: int  # recorded Phase-A total prompt tokens for this request
    reason: str | None


def _load_main_records(path: Path, agent: str) -> list[dict]:
    records = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("agent_id") == agent:
                records.append(rec)
    records.sort(key=lambda r: r.get("seq", 0))
    return records


def _tokens_per_char(metrics: list["StepMetric"]) -> tuple[float, float] | None:
    """Least-squares fit of recorded prompt tokens vs full history chars.

    `prompt_tokens(i) ≈ a · history_chars(i) + b`, where `a` is tokens/char
    and the intercept `b` is the fixed system-prompt + tool-schema overhead
    (constant across requests, so it cancels out of any char *delta*).
    Calibrating on the input we actually want to model — far steadier than a
    chars/token ratio derived from generated output. Returns (a, b) or None.
    """
    pts = [(m.full_chars, m.input_tokens) for m in metrics
           if m.input_tokens > 0 and m.full_chars > 0]
    n = len(pts)
    if n < 2:
        return None
    sx = sum(x for x, _ in pts)
    sy = sum(y for _, y in pts)
    sxx = sum(x * x for x, _ in pts)
    sxy = sum(x * y for x, y in pts)
    denom = n * sxx - sx * sx
    if denom == 0:
        return None
    a = (n * sxy - sx * sy) / denom
    b = (sy - a * sx) / n
    return a, b


def _cache_split(records: list[dict]) -> dict[str, int]:
    """Recorded fresh / cache-read / cache-creation input tokens (top-level usage).

    Compaction shrinks the prompt, but billed cost depends on the cache: a
    cache-read token is ~0.1x a fresh one. This contextualises the headline.
    """
    fresh = read = create = 0
    for rec in records:
        if rec.get("kind") != "response":
            continue
        u = rec.get("usage") or {}
        fresh += int(u.get("input_tokens", 0) or 0)
        read += int(u.get("cache_read_input_tokens", 0) or 0)
        create += int(u.get("cache_creation_input_tokens", 0) or 0)
    return {"fresh": fresh, "cache_read": read, "cache_creation": create}


def dry_run(records: list[dict]) -> list[StepMetric]:
    history: list[dict] = []
    investigation_md = ""
    state: C.FrozenState | None = None
    metrics: list[StepMetric] = []
    pending: tuple[C.CompactionStep, int, int] | None = None  # step, full_chars, comp_chars

    for rec in records:
        msg = rec.get("message", {})
        kind = rec.get("kind")
        if kind == "request":
            history.append(msg)
            step = C.compact(history, investigation_md, state)
            state = step.state
            pending = (step, C.history_chars(history), C.history_chars(step.history))
        elif kind == "response":
            if pending is not None:
                step, full_c, comp_c = pending
                usage = (rec.get("message") or {}).get("usage") or {}
                metrics.append(
                    StepMetric(
                        seq=rec.get("seq", -1),
                        action=step.action,
                        loop=step.loop,
                        full_chars=full_c,
                        comp_chars=comp_c,
                        input_tokens=int(usage.get("input_tokens", 0) or 0),
                        reason=step.reason,
                    )
                )
                pending = None
            investigation_md = C.apply_writes(investigation_md, msg)
            history.append(msg)
    return metrics


def _resolve_jsonl(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        return p / "llm_requests.jsonl"
    return p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="a run dir or a llm_requests.jsonl path")
    ap.add_argument("--agent", default="main", help="agent_id to compact (default: main)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    path = _resolve_jsonl(args.target)
    if not path.is_file():
        print(f"no llm_requests.jsonl at {path}", file=sys.stderr)
        return 1

    records = _load_main_records(path, args.agent)
    if not records:
        print(f"no records for agent_id={args.agent!r} in {path}", file=sys.stderr)
        return 1

    metrics = dry_run(records)
    cache = _cache_split(records)
    fit = _tokens_per_char(metrics)  # (tokens_per_char, system+tools intercept)
    tpc = fit[0] if fit else None
    overhead = round(fit[1]) if fit else None

    total_full = sum(m.full_chars for m in metrics)
    total_comp = sum(m.comp_chars for m in metrics)
    dropped_chars = total_full - total_comp
    total_prompt_tokens = sum(m.input_tokens for m in metrics)
    est_dropped_tokens = (tpc * dropped_chars) if tpc else 0.0
    implied_k = (1 / tpc) if tpc else None  # chars/token
    actions: dict[str, int] = {}
    for m in metrics:
        actions[m.action] = actions.get(m.action, 0) + 1

    if args.json:
        print(json.dumps({
            "agent": args.agent,
            "requests": len(metrics),
            "actions": actions,
            "chars_per_token_implied": round(implied_k, 3) if implied_k else None,
            "system_tools_token_overhead": overhead,
            "history_payload_chars": {"full": total_full, "compacted": total_comp,
                                      "dropped": dropped_chars,
                                      "reduction_pct": round(100 * dropped_chars / total_full, 1) if total_full else 0.0},
            "prompt_tokens": {"recorded_total": total_prompt_tokens,
                              "estimated_dropped": round(est_dropped_tokens),
                              "estimated_reduction_pct": round(100 * est_dropped_tokens / total_prompt_tokens, 1) if total_prompt_tokens else 0.0},
            "recorded_cache_split": cache,
            "steps": [vars(m) for m in metrics],
        }, indent=2))
        return 0

    print(f"compaction dry-run — agent={args.agent!r}, {len(metrics)} model requests")
    print("  actions: " + ", ".join(f"{a}={n}" for a, n in sorted(actions.items())))
    print()
    print("  history-payload chars (tokenizer-free, exact):")
    print(f"    full       {total_full:>12,}")
    print(f"    compacted  {total_comp:>12,}")
    print(f"    dropped    {dropped_chars:>12,}   ({100 * dropped_chars / total_full:.1f}% of history payload)" if total_full else "    dropped    0")
    print()
    _k = f"{implied_k:.2f}" if implied_k else "n/a"
    print(f"  prompt-token estimate (regressed on recorded tokens; "
          f"~{_k} chars/token, system+tools≈{overhead:,} tok):"
          if overhead is not None else
          "  prompt-token estimate (insufficient data to calibrate):")
    print(f"    recorded total prompt tokens   {total_prompt_tokens:>12,}")
    if total_prompt_tokens and tpc:
        print(f"    estimated tokens dropped       {round(est_dropped_tokens):>12,}   "
              f"(~{100 * est_dropped_tokens / total_prompt_tokens:.1f}% of total prompt tokens)")
    print(f"    recorded input split: fresh={cache['fresh']:,}  "
          f"cache_read={cache['cache_read']:,}  cache_creation={cache['cache_creation']:,}")
    print("    (most input is cache_read @ ~0.1x; compaction's $ win is on the "
          "creation/fresh portion + a longer-lived cache — see design doc)")
    print()
    print("  per-request:")
    print(f"    {'seq':>5}  {'loop':>4}  {'action':<11}  {'full_ch':>9}  {'comp_ch':>9}  {'in_tok':>7}  reason")
    for m in metrics:
        print(f"    {m.seq:>5}  {str(m.loop):>4}  {m.action:<11}  {m.full_chars:>9,}  "
              f"{m.comp_chars:>9,}  {m.input_tokens:>7,}  {m.reason or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
