#!/usr/bin/env python3
"""Cost + verdict extraction for the judge A/B (GLM 5.2 vs Kimi K3).

`run_judge_ab.py` prints agreement metrics but no cost, and it keeps the verdict TEXT
only inside each config's trace. This walks the traces it leaves under `--out` and emits
both:

  * per-arm token totals and cost per judge invocation, and
  * the paired verdict text, so Opus can adjudicate which reasoning is better.

**Cost is reported under BOTH K3 price hypotheses.** Fireworks omits K3 from /v1/models
and quotes it two ways on the web ($3/$15 at 1M ctx, $0.95/$4.00 at 262k — the latter
byte-identical to K2.6's row, which is what a page-template artifact looks like).
`pricing.PRICING` carries the conservative pair; the alternate is applied here to the
same token counts. The billing dashboard settles which is real.

Reads the layout `run_config` writes: <out>/<label>/<case_id>/{judge_trace.jsonl,
judge_benign_trace.jsonl}, where label ∈ {ref-a, ref-b, cand}.

    python3 experiments/judge-glm52-vs-kimik3/analyze.py --runs <out_dir> [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._run_paths import WIRE_LOG_DIR  # noqa: E402
from defender.scripts.pricing import PRICING, model_key  # noqa: E402

# The 262k-context SKU. Not in pricing.PRICING on purpose: that table feeds real accounting
# and must carry one number per model, the conservative one. This is a what-if applied to
# the same counts, so both hypotheses are reported off one run.
#
# Its cache_r is a GUESS (Fireworks publishes no cache rate for K3 at either SKU), set to
# the input rate — i.e. assuming no cache discount at all. That guess dominates the answer:
# see the sensitivity block, where cache reads are ~86% of all tokens the judge consumes.
K3_CHEAP = {"in": 0.95, "out": 4.0, "cache_w": 0.95, "cache_r": 0.95}

# Cache-read rates to sweep for the candidate. The judge re-reads a large frozen prompt every
# turn, so this one unpublished number moves the cost answer more than the in/out rates do.
CACHE_R_SWEEP = (0.0, 0.30, 0.60, 0.95, 3.00)

_USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
_TRACE_NAMES = ("judge_trace.jsonl", "judge_benign_trace.jsonl")


def trace_path(root: Path, name: str) -> Path | None:
    """The non-empty judge trace `name` names under `root`, or `None`.

    `<root>/wire_logs/<name>` FIRST: `_pydantic_stage.run_stage` writes every stage trace through
    `observe.stage_trace_path` now, which puts it one level down (`_run_paths.WIRE_LOG_DIR` — the
    read gate refuses the component to every agent). The pre-move root path stays as a fallback
    because this tool is pointed at whatever arm dirs the operator already has on disk; without
    the first candidate a current run reads as "no trace", which `collect` silently skips and
    the report then prints as zero invocations. Shared with `adjudicate.py`, which imports it.
    """
    for candidate in (root / WIRE_LOG_DIR / name, root / name):
        if candidate.is_file() and candidate.stat().st_size:
            return candidate
    return None


def _cost(usage: dict, price: dict) -> float:
    return (
        usage["input_tokens"] * price["in"]
        + usage["output_tokens"] * price["out"]
        + usage["cache_creation_input_tokens"] * price["cache_w"]
        + usage["cache_read_input_tokens"] * price["cache_r"]
    ) / 1_000_000


def read_trace(path: Path) -> dict:
    """One judge invocation: summed usage, the model that served it, and the verdict text.

    The verdict is the LAST text part in the trace — the judge's terminal message once it
    stops calling tools. Intermediate text (its lead-by-lead narration) is not the doc.
    """
    usage = dict.fromkeys(_USAGE_KEYS, 0)
    model = ""
    verdict = ""
    n_responses = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue  # a truncated tail line is a data point about the run, not a crash
        if rec.get("kind") != "response":
            continue
        n_responses += 1
        model = rec.get("model") or model
        for k in _USAGE_KEYS:
            usage[k] += int((rec.get("usage") or {}).get(k, 0) or 0)
        for part in rec.get("message", {}).get("parts", []):
            if part.get("part_kind") == "text" and part.get("content", "").strip():
                verdict = part["content"]
    return {
        "usage": usage,
        "model": model,
        "verdict_text": verdict,
        "n_responses": n_responses,
        "total_tokens": sum(usage.values()),
    }


def collect(runs_dir: Path) -> dict:
    per_arm: dict[str, list[dict]] = defaultdict(list)
    for label_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        for case_dir in sorted(p for p in label_dir.iterdir() if p.is_dir()):
            for name in _TRACE_NAMES:
                trace = trace_path(case_dir, name)
                if trace is None:
                    continue
                rec = read_trace(trace)
                rec["case_id"] = case_dir.name
                rec["direction"] = "benign" if "benign" in name else "adversarial"
                per_arm[label_dir.name].append(rec)
    return per_arm


def summarize(per_arm: dict) -> dict:
    out = {}
    for label, invocations in sorted(per_arm.items()):
        totals = dict.fromkeys(_USAGE_KEYS, 0)
        for inv in invocations:
            for k in _USAGE_KEYS:
                totals[k] += inv["usage"][k]
        n = len(invocations)
        model = invocations[0]["model"] if invocations else ""
        key = model_key(model)
        priced = {"listed": _cost(totals, PRICING[key])}
        if key == "kimi-k3":
            priced["k3_cheap_sku"] = _cost(totals, K3_CHEAP)
        out[label] = {
            "model": model,
            "price_row": key,
            "n_invocations": n,
            "tokens": totals,
            "cost_total": priced,
            "cost_per_invocation": {k: v / n for k, v in priced.items()} if n else {},
            # The judge is two calls per learning cycle (adversarial + benign legs).
            "cost_per_cycle": {k: 2 * v / n for k, v in priced.items()} if n else {},
            "mean_responses_per_invocation": (
                sum(i["n_responses"] for i in invocations) / n if n else 0.0
            ),
        }
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--runs", type=Path, required=True, help="the driver's --out dir")
    p.add_argument("--json", type=Path, help="also write the full record (incl. verdict text)")
    args = p.parse_args(argv)

    per_arm = collect(args.runs)
    if not per_arm:
        print(f"no judge traces under {args.runs}", file=sys.stderr)
        return 1
    summary = summarize(per_arm)

    print("# Judge A/B — cost\n")
    for label, s in summary.items():
        t = s["tokens"]
        print(f"## {label} — {s['model']} (priced as {s['price_row']})")
        print(f"invocations: {s['n_invocations']}   "
              f"mean model responses/invocation: {s['mean_responses_per_invocation']:.1f}")
        print(f"tokens: in={t['input_tokens']:,} out={t['output_tokens']:,} "
              f"cache_w={t['cache_creation_input_tokens']:,} "
              f"cache_r={t['cache_read_input_tokens']:,}")
        for hyp, v in s["cost_per_invocation"].items():
            print(f"  ${v:.4f} / judge invocation   "
                  f"(${s['cost_per_cycle'][hyp]:.4f} / learning cycle)   [{hyp}]")
        print()

    ref = summary.get("ref-a")
    cand = summary.get("cand")
    if ref and cand and ref["cost_per_invocation"] and cand["cost_per_invocation"]:
        base = ref["cost_per_invocation"]["listed"]
        print("## candidate vs reference, per invocation")
        for hyp, v in cand["cost_per_invocation"].items():
            ratio = v / base if base else float("inf")
            print(f"  {hyp}: ${v:.4f} vs ${base:.4f}  →  {ratio:.2f}x")
        print()

        # The published in/out rates are not what decides this. Cache reads dominate the
        # judge's token mix, and K3's cache-read rate is unpublished at BOTH quoted SKUs —
        # so the honest presentation is the range, not a point estimate.
        t = cand["tokens"]
        n = cand["n_invocations"]
        share = t["cache_read_input_tokens"] / sum(t.values()) if sum(t.values()) else 0.0
        print("## candidate cost sensitivity to K3's UNPUBLISHED cache-read rate")
        print(f"  cache reads are {share:.0%} of the candidate's tokens "
              f"({t['cache_read_input_tokens']:,} of {sum(t.values()):,})")
        for row_name, row in (("$3/$15", PRICING["kimi-k3"]), ("$0.95/$4.00", K3_CHEAP)):
            costs = []
            for cr in CACHE_R_SWEEP:
                c = _cost(t, {**row, "cache_r": cr}) / n
                costs.append(f"{cr:.2f}→${c:.4f}")
            print(f"  {row_name:12} " + "  ".join(costs))
        print(f"  (reference glm-5.2 at its published $0.14 cache read: ${base:.4f})")
        print()

    if args.json:
        args.json.write_text(
            json.dumps({"summary": summary, "invocations": per_arm}, indent=2),
            encoding="utf-8",
        )
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
