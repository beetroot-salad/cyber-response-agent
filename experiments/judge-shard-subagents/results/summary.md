# judge-shard-subagents — results (N=3 per arm)

Both arms: `claude-sonnet-4-6`, single fixture `rerun-100001-envelope-split`.
Baseline = current judge.md, no tools. Proposed = consult-via-shards
protocol (3 parallel Haiku Task dispatches with contrasting framings)
+ `--allowed-tools Task`.

## Run table

| trial      | rc | seconds | outcome  | findings (type / anchor) |
|------------|----|---------|----------|---------------------------|
| baseline/1 | 0  | 146.6   | survived | lead-set/no-lead-exists, analyze-discipline/l-002, observability/host-query |
| baseline/2 | 0  | 169.8   | survived | analyze-discipline/l-002, lead-set/no-lead-exists, observability/host-query |
| baseline/3 | 0  | 126.1   | survived | lead-set/no-lead-exists, analyze-discipline/l-002, observability/no-system-covers-this |
| proposed/1 | 0  | 214.8   | survived | analyze-discipline/l-002, lead-set/no-lead-exists, observability/host-query |
| proposed/2 | 0  | 282.1   | survived | lead-set/no-lead-exists, analyze-discipline/l-002, observability/host-query |
| proposed/3 | 0  | 234.0   | survived | lead-set/no-lead-exists, analyze-discipline/l-002, observability/no-system-covers-this |

Mean latency: baseline 147.5s, proposed 243.6s (**+65%**).

## Outcome agreement
All 6 trials: `survived`. Zero verdict divergence.

## Finding-set agreement
Every trial in both arms produced exactly the same three (type, anchor)
tuples — modulo `observability` splitting between `host-query` (4 runs)
and `no-system-covers-this` (2 runs, one per arm). The case is dominant
enough that both judge variants converge on the same gaps:

1. **lead-set / no-lead-exists** — no lead correlates docker-exec to
   SSH-session/host caller identity.
2. **analyze-discipline / l-002** — legitimacy contract `ac1` never
   resolved before benign disposition; frequency baseline conflated
   with authorization.
3. **observability** — Docker host exec→session attribution surface
   uncovered.

## Decision criteria check
- *Proposed wins if ≥2 of 3 proposed runs surface a finding no baseline
  run surfaces* — **not met**. Every proposed finding tuple is matched
  by a baseline finding tuple.
- *Current retained if proposed matches or under-performs baseline
  coverage, or Task dispatch is unreliable* — **met on coverage**, and
  proposed exhibits a real reliability regression (below).

## Reliability regression in proposed
**proposed/3 leaked a preamble** before the YAML doc:

```
Now I have the three framings. Let me synthesize:

- **Subagent A** (red-teamer): ...
- **Subagent B** (...): ...
- **Subagent C** (...): ...

outcome: survived
...
```

`loop.py`'s `strip_yaml_fence` does not strip leading prose, only
fences and XML wrappers — this output would fail `yaml.safe_load` in
production. Two of three proposed runs respected the "first character
is `o`" contract; one did not. Baseline runs all respected it.

The prompt instructs "Do not mention the subagents in your YAML
output" but the leak happened *outside* the YAML, in the same response
stream — a gap the current prompt does not close.

## Verdict
**Retain current.** The proposed variant adds ~65% latency, introduces
a YAML-prefix regression in 1/3 runs, and surfaces no findings the
baseline misses on this case. The consultation framing did not change
what the judge saw — the encounter's structure (one clearly
load-bearing authorization gap on a benign-disposition rule-100001
case) is strong enough to dominate any reading.

## Limits of this experiment
- N=3 and a single fixture — this is an existence check, not a
  generalization claim. A case with more ambiguous projection-vs-actual
  divergence might show different dynamics.
- We did not capture per-trial tool-call traces, so the *content* of
  the Haiku consultations was not inspected (only the final YAML).
  proposed/3 incidentally exposed three framing perspectives that
  largely converged on the same identity-grounding gap the baseline
  found unaided.
- A future variant worth trying: consult-via-shards on a fixture where
  baseline runs diverge on outcome or findings — i.e. pick a case the
  judge currently struggles with, not one it solves cleanly.
