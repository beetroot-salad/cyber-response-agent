#!/usr/bin/env python3
"""Token + cost accounting per run, split by the model each lane actually called."""
import json
import sys
from collections import defaultdict
from pathlib import Path

# USD per million tokens. Fireworks serverless Standard tier.
RATES = {
    "kimi-k2p6":     {"in": 0.95, "out": 4.00, "cr": 0.16},
    "kimi-k3":       {"in": 3.00, "out": 15.00, "cr": 0.30},
    "glm-5p2":       {"in": 1.40, "out": 4.40, "cr": 0.14},
    "glm-5p3-flash": {"in": 0.15, "out": 0.50, "cr": 0.03},
    "glm-5p3":       {"in": 1.40, "out": 4.40, "cr": 0.26},  # docs.fireworks.ai/serverless/pricing, fetched 2026-09-09
}

def key(model: str) -> str:
    m = model.rsplit("/", 1)[-1].lower()
    for name in ("glm-5p3-flash", "glm-5p3", "glm-5p2", "kimi-k3", "kimi-k2p6"):
        if name in m:
            return name
    return m

def tally(run_dir: Path):
    agg = defaultdict(lambda: {"reqs":0,"in":0,"out":0,"cr":0,"cw":0,"reason":0})
    log = run_dir / "wire_logs" / "llm_requests.jsonl"
    if not log.is_file():
        return agg
    for line in log.open():
        d = json.loads(line)
        if d.get("kind") != "response":
            continue
        m = d.get("message", {})
        u = m.get("usage") or {}
        a = agg[key(m.get("model_name",""))]
        a["reqs"] += 1
        a["cr"] += u.get("cache_read_tokens",0)
        a["cw"] += u.get("cache_write_tokens",0)
        # input_tokens is the full prompt; cache reads are a subset billed cheaper
        a["in"] += max(0, u.get("input_tokens",0) - u.get("cache_read_tokens",0) - u.get("cache_write_tokens",0))
        a["out"] += u.get("output_tokens",0)
        a["reason"] += (u.get("details") or {}).get("reasoning_tokens",0)
    return agg

def main(dirs):
    for rd in dirs:
        rd = Path(rd)
        agg = tally(rd)
        print(f"\n=== {rd.name} ===")
        total, unpriced = 0.0, []
        for k, a in sorted(agg.items()):
            r = RATES.get(k)
            toks = a["in"] + a["cr"] + a["cw"] + a["out"]
            if r is None:
                unpriced.append((k, a))
                print(f"  {k:16s} reqs={a['reqs']:3d} tok={toks:>9,}  cost=UNPRICED")
                continue
            c = (a["in"]*r["in"] + a["cw"]*r["in"] + a["cr"]*r["cr"] + a["out"]*r["out"]) / 1e6
            total += c
            print(f"  {k:16s} reqs={a['reqs']:3d} tok={toks:>9,}  ${c:.4f}")
        print(f"  {'PRICED TOTAL':16s} {'':21s} ${total:.4f}")
        for k, a in unpriced:
            print(f"  ! {k}: in={a['in']:,} cache_r={a['cr']:,} out={a['out']:,} reasoning={a['reason']:,}")

if __name__ == "__main__":
    main(sys.argv[1:])
