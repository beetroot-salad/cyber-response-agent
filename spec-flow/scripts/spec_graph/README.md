# spec_graph — mechanical granularity checks for write-tests spec graphs

A write-tests spec graph (`spec_graph_*.yaml`, committed beside the tests) is a lossy projection
of the code's behavioral domain: *demands* bound to graph elements, with gate rules R0–R6 computing
blind-spot shapes over the bindings. The gate rules are only as good as the partition, the axes,
and the binding-edges they're handed — so a graph **coarser than reality** passes green while real
bugs escape.

These two checks re-derive part of the graph from an **independent** channel (the prose, the call
graph) and diff. They catch two of the three escape classes that motivated them; the third
(input-partition granularity, e.g. a `..`-path that resolves to `/`) is not mechanizable from the
graph alone and wants property-based / differential-oracle testing at impl time instead.

Both read the project profile (`.claude/spec-flow.json`, key `specGraph`) for the things that are
not portable — where the project's source lives, which stems are entrypoints, what the graph calls
each actor. See `_config.py`.

**Invoke them through `spec-graph`**, the wrapper in the plugin's `bin/` (which Claude Code puts on
the Bash PATH). It resolves the scripts from its own location and discovers an interpreter with
PyYAML, so nothing has to know where the plugin is installed — `$CLAUDE_PLUGIN_ROOT` does *not*
expand inside SKILL.md prose, and a repo-relative venv path breaks inside a git worktree.

## check_binds.py — prose ⊄ binds (assertion-weakness / dropped-invariant class)

The gate rules reason over `binds` (edges), not the prose. A value named in a demand's prose but not
wired into its `binds` is invisible to the rules, so the realized test can silently drop the
assertion.

```
spec-graph binds [graph.yaml ...] [--config <path>]
```

Where the prose lives depends on form: a `form: test` demand is a pointer with no `outcome`, so its
prose is the docstring of the test it names via `discharged_by`; a `form: clause`/`waiver` demand
keeps an `outcome`. The check scans whichever holds the prose — the pointed-to test's docstring
(found among the `*.py` beside the graph), or the `outcome` — for each `<concept>=<threaded-value>`
where the concept is modelled elsewhere in the graph but absent from that demand's `binds`. A
`discharged_by` that names no test is a dangling pointer, also flagged — as is one pointing at a
test with no docstring (the prose is required to live there); `shuffle-premises` copies
(`*.copyN.py`) are excluded from the scan. The canonical catch: a demand
whose prose read "…threads `salt=deps.salt`…" bound only the anchor tree — the exact under-binding
that left a prompt-injection defence unguarded, with every test green. Waive a conscious incidental
mention under a top-level `binds_waivers:` map; prefer *binding* the concept so the test is forced to
assert it.

The same script runs a second, independent scan: **inspected but never exercised**. A demand
binding `drives(A->B)` whose test names `B` *only inside an `assert`* is flagged — the demand
claims a wiring, the test checks a shape, and the shape holds whether or not `A` is wired to `B`.
The catch it was forged on (#540): a `parity` demand discharged by
`assert isinstance(deps.box, BoxExecutor)`, where `AgentDeps.box` defaults to
`field(default_factory=BoxExecutor)` — the inert default and a live container are the same type,
so the assertion could not fail, and two bash-enabled roles shipped with no box attached.

The rule is deliberately narrow. `B` **absent** from the test is *not* flagged: a test that drives
the real loop reaches `B` through production wiring and never names it. Only "named, and named
nowhere but an assertion" is the defect shape. Waive under a top-level `exercise_waivers:` map
(keyed by demand id → seam names); prefer driving `A` and asserting the observable outcome. The
two findings are counted separately in the summary line — they name different slips.

## check_actors.py — execution-context census (missing-consumer / missing-axis class)

`structure.actors` is authored from the design doc, so it captures production consumers and misses
execution contexts nobody wrote down — especially **subprocess re-execs**, where a module-level
"constant" (the anchor path a guard trusts) silently relocates onto a different tree.

```
spec-graph actors [graph.yaml] [--base <ref>] [--config <path>]
```

Derives — from the CODE, not the design — every CLI/harness/eval entrypoint that drives a changed
module (in-process import) or **re-executes one of the project's own modules as a subprocess**, and
diffs against what the graph models. The canonical catch: an eval harness flagged with the precise
signature `subprocess re-exec of ['lead_author'] (relocates the tree anchor)` — the root cause of a
guard false-positive that the design-authored actor list could never have surfaced. Model the context
as an actor — which surfaces its hidden axes — or waive an out-of-scope context under a top-level
`actor_waivers:` list. Do **not** waive a re-exec context to go green: that redness is the signal.

## What these do NOT catch (be honest about the residual)

- **Input-partition granularity** (a guard's invalid domain modelled as one coarse bucket; the
  `..`→`/` bypass). The ground truth is the invariant, not the graph — use property-based testing
  (`resolve(operand)` stays within `resolve(root)`) and mutation testing at impl time.
- **An axis present in no representation.** The frame problem is not closed here; these checks only
  shrink the unknown space by triangulating against independent projections. The best hedge is
  running all perturbation lanes (perturb the binding/prose, the consumer set, the input domain, the
  environment) shallow rather than one lane deep — the incident data shows the gaps arrive one per
  lane.
