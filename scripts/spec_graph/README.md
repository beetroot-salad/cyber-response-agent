# scripts/spec_graph — mechanical granularity checks for write-tests spec graphs

A write-tests spec graph (`defender/tests/spec_graph_*.yaml`) is a lossy projection of the
code's behavioral domain: *demands* bound to graph elements, with gate rules R0–R5 computing
blind-spot shapes over the bindings. The gate rules are only as good as the partition, the
axes, and the binding-edges they're handed — so a graph **coarser than reality** passes green
while real bugs escape.

These two checks re-derive part of the graph from an **independent** channel (the prose, the
call graph) and diff. They catch two of the three escape classes seen in #551; the third
(input-partition granularity, e.g. a `..`-path that resolves to `/`) is not mechanizable from
the graph alone and wants property-based / differential-oracle testing at impl time instead.

## check_binds.py — prose ⊄ binds (assertion-weakness / dropped-invariant class)

The gate rules reason over `binds` (edges), not the natural-language `outcome`. A value named
in a demand's prose but not wired into its `binds` is invisible to the rules, so the realized
test can silently drop the assertion.

```
python scripts/spec_graph/check_binds.py [spec_graph.yaml ...]
```

Flags each `<concept>=<threaded-value>` in a demand's prose where the concept is modelled
elsewhere in the graph but absent from that demand's `binds`. In #551 this catches
`d3_gather_threads_not_restamps` naming `salt=deps.salt` while binding only `defender_tree` —
the exact under-binding that left the gather salt-not-split (injection-defense) invariant
unguarded. Waive a conscious incidental mention under a top-level `binds_waivers:` map (see the
graph); prefer *binding* the concept so the test is forced to assert it.

## check_actors.py — execution-context census (missing-consumer / missing-axis class)

`structure.actors` is authored from the design doc, so it captures production consumers and
misses execution contexts nobody wrote down — especially **subprocess re-execs**, where a
"constant" like `PATHS.defender_dir` silently relocates onto a different tree.

```
python scripts/spec_graph/check_actors.py [spec_graph.yaml] [--base <ref>]
```

Derives — from the CODE, not the design — every CLI/harness/eval entrypoint that drives a
changed module (in-process import) or **re-executes a defender module as a subprocess**, and
diffs against what the graph models. In #551 it flags `evals/harness_lead.py` with the precise
signature `subprocess re-exec of ['lead_author'] (relocates PATHS)` — the root cause of the
`requires_explicit_tree` false-positive that broke the lead-author eval harness. It also flags
`evals/harness.py` (the same relocated-PATHS hazard class). Model the context as an actor —
which surfaces its hidden axes — or waive an out-of-scope context under a top-level
`actor_waivers:` list. Do **not** waive a `relocates PATHS` context to go green: that redness
is the signal.

## What these do NOT catch (be honest about the residual)

- **Input-partition granularity** (a guard's invalid domain modelled as one coarse bucket; the
  `..`→`/` bypass). The ground truth is the invariant, not the graph — use property-based
  testing (`resolve(operand) within resolve(root)`) and mutation testing at impl time.
- **An axis present in no representation.** The frame problem is not closed here; these checks
  only shrink the unknown space by triangulating against independent projections. The best
  hedge is running all perturbation lanes (perturb the binding/prose, the consumer set, the
  input domain, the environment) shallow rather than one lane deep — the #551 incident data
  shows the gaps arrive one per lane.
