import json, sys, os
from datetime import datetime

# Per-model rates ($/MTok: in, out, cache_read, cache_write). The finder may be
# Sonnet (judgment) while the executor is Haiku — price each response by its model.
RATES = {"haiku": (1.00, 5.00, 0.10, 1.25), "sonnet": (3.00, 15.00, 0.30, 3.75)}

def _rate(model):
    return RATES["sonnet"] if "sonnet" in (model or "").lower() else RATES["haiku"]

def parse_ts(t):
    if not t: return None
    try: return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
    except Exception: return None

def _cost_of(rows):
    """($cost, response_count) over the response rows of one agent group, each
    response priced by its own model (finder Sonnet / executor Haiku)."""
    cost = 0.0; n = 0
    for d in rows:
        if d.get("kind") != "response":
            continue
        n += 1
        u = d["message"].get("usage", {}) or {}
        i, o, cr, cw = _rate(d.get("model") or (d.get("message") or {}).get("model_name"))
        cost += ((u.get("input_tokens", 0) or 0) * i + (u.get("output_tokens", 0) or 0) * o
                 + (u.get("cache_read_tokens", 0) or 0) * cr + (u.get("cache_write_tokens", 0) or 0) * cw) / 1e6
    return cost, n

def analyze(rd):
    rows = [json.loads(l) for l in open(f"{rd}/llm_requests.jsonl")]
    def grp(*prefixes):
        return [d for d in rows if (d.get("agent_id") or "").startswith(prefixes)]
    # Finder = the per-lead agent ("finder:"; legacy single-agent gather is "gather:").
    # Executor = the per-measurement agent ("exec:").
    finder = grp("finder:", "gather:")
    execu = grp("exec:",)
    ts = [t for d in finder + execu if (t := parse_ts(d["message"].get("timestamp")))]
    fcost, fresp = _cost_of(finder)
    ecost, eresp = _cost_of(execu)
    dur = (max(ts) - min(ts)) if len(ts) >= 2 else 0
    gs = f"{rd}/gather_summaries/l-001.md"
    cap = os.path.exists(gs) and "hit its request limit" in open(gs).read()
    done = os.path.exists(gs) and not cap
    return dict(name=os.path.basename(rd), fresp=fresp, eresp=eresp,
                dur=dur, cost=fcost+ecost, fcost=fcost, ecost=ecost,
                outcome=("CAP-STUB" if cap else ("COMPLETE" if done else "?")))

hdr = f"{'run':14} {'find':>4} {'exec':>4} {'dur(s)':>7} {'cost$':>7} {'find$':>7} {'exec$':>7}  outcome"
print(hdr)
rows = [analyze(f"/tmp/defender-runs/{r}") for r in sys.argv[1:] if os.path.isdir(f"/tmp/defender-runs/{r}")]
for a in rows:
    print(f"{a['name']:14} {a['fresp']:>4} {a['eresp']:>4} {a['dur']:>7.1f} "
          f"{a['cost']:>7.4f} {a['fcost']:>7.4f} {a['ecost']:>7.4f}  {a['outcome']}")
if rows:
    import statistics as st
    print(f"{'MEAN':14} {st.mean(a['fresp'] for a in rows):>4.0f} "
          f"{st.mean(a['eresp'] for a in rows):>4.0f} {st.mean(a['dur'] for a in rows):>7.1f} "
          f"{st.mean(a['cost'] for a in rows):>7.4f} {st.mean(a['fcost'] for a in rows):>7.4f} "
          f"{st.mean(a['ecost'] for a in rows):>7.4f}")
