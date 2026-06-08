# Experiment: thinking-effort tradeoff (defender investigation loop)

## Question

**Engineering / characterization** — How does `claude -p --effort {high|medium|low}` on the defender's
investigation runtime trade quality against cost and run time, on the same alert? Specifically: can the
defender drop below `high` without introducing a false negative (the cardinal sin) or materially weakening
evidence/archetype grounding?

This is a tradeoff-curve characterization, not a pick-one-winner. The deliverable is a 3-point cost/quality/time
curve per fixture, plus a recommendation on the production default.

## Load-bearing facts (verified before drafting)

- `run.py` accepts `--effort` and forwards it to the runtime `claude -p` (`run.py:152,170`). Default `effort=None`
  → no flag → the subprocess inherits **`CLAUDE_EFFORT=high`** from the environment. **The current production
  effort is therefore `high`** → the `high` arm IS the regression baseline (no separate 4th arm needed).
- All investigation reasoning runs in **6 `subagent_type: claude` Task subagents** (gather/predict/analyze/etc.),
  spawned with no per-subagent effort override. They run in-session, so they *should* inherit the runtime's
  resolved effort. **This is the experiment's primary risk** — see §Validation gate.
- The run's `result` stream-json event is the authoritative whole-run rollup (subagents included, single
  `claude -p` process): `total_cost_usd`, `usage.output_tokens`, `duration_ms`, `num_turns`. Per-message
  `usage.output_tokens` is NOT reliable (summed to 1862 vs result's 72583) — **use the result event, not a sum.**
- Cost is spread: a baseline `high` run was $3.16 / 72.6k output tok / ~27.6 min / 37 turns, with cache_read 1.56M
  dominating input. Effort moves *output (thinking)* tokens, so its lever on total $ is bounded by the output share.

## Variants

One variable: the `--effort` value on the runtime `claude -p`. Everything else identical. Each arm sets **both**
the flag and the env var so subagents can't silently read a stale `CLAUDE_EFFORT=high`:

```
# high  (== current production default; regression baseline)
CLAUDE_EFFORT=high   DEFENDER_RUNS_BASE=… run.py <alert> --no-learn --effort high  --run-id <fix>-high
# medium
CLAUDE_EFFORT=medium DEFENDER_RUNS_BASE=… run.py <alert> --no-learn --effort medium --run-id <fix>-med
# low
CLAUDE_EFFORT=low    DEFENDER_RUNS_BASE=… run.py <alert> --no-learn --effort low  --run-id <fix>-low
```

`--no-learn` isolates the investigation loop (the learning loop runs its own per-stage efforts — curators low,
judges — which would be constant across arms and dilute the signal).

## Fixtures

Two alert.json files, **frozen once** into `fixtures/` and replayed byte-identical across all three efforts, so
the only thing differing within a fixture's 3 runs is effort. (Gather subagents still query live ES; alert input
is fixed.) Both sourced live 2026-06-08 ~06:40Z, projected from the raw `kibana.alert.*` envelope (ancestor auth
events resolved by id) via `project_alert.py`.

Note: the two fixtures exercise **different detection rules** — the experiment compares effort *within* each
fixture (3 runs each), not across them, so a shared detector isn't required. The originally-planned
"same-detector benign-vs-malicious" A/B fell through: `cross-tier-ssh-probe` fires `v2 sshd success after
failures` (invalid-user brute-force), not the cross-tier-pivot EQL, and an invalid-user pattern can't be made
cleanly benign by a CR. So the benign fixture is sourced from genuine SRE baseline activity instead.

- `fixtures/malicious-cross-tier-probe.json` — rule **`v2 sshd success after failures`**. `dev.dana` (an
  *invalid user* — no such account) doing failed SSH from office-ws-1 (172.18.0.21) against **db-1**, no covering
  CR. Fired via `cross-tier-ssh-probe --cr-mode none --seed 42`. **Ground truth: escalate** (unauthorized
  brute-force against a database from a workstation — unambiguous). The headline zero-false-negative test: does
  `low` still escalate?
- `fixtures/benign-cross-tier-pivot.json` — rule **`v2 cross-tier SSH pivot`**. `sre.alice` (real SRE account)
  **successful** SSH to **web-1** from 172.18.0.11 — the documented `sre-multihop-ssh` baseline (jump-box trust
  edge). No covering CR (ad-hoc SRE ops are CR-free by design). **Ground truth: benign baseline** — the agent
  must ground legitimacy on the real-account + documented-trust-path pattern, not a CR. *Caveat:* the defender is
  conservative-by-default, so a grounded escalation here is not a hard false positive; for the benign arm the
  quality question is "does effort change the disposition / authorization grounding," not a binary benign==correct.

## Preconditions (live stack)

VPS up (`infra/bin/up.sh`), egress IP allowlisted, self-healing SSH tunnel running (plain `-fN` dies), ES preflight
green (`elastic_cli.py health-check`). Tear the tunnel down after. (Full recipe: reference_v2_live_run_workflow.)

## Trials

- **Validation pass: 1 per effort per fixture = 6 live runs.** Confirms the harness, the metric extraction, and —
  critically — the validation gate below. No scale-up until this passes.
- **Scale-up:** decide N after validation (likely N=3/arm = 18 runs to separate effort from live variance) and
  write `analyze.py` before launching it.

## Validation gate (must hold or we stop and pivot)

1. **Effort propagates.** `low` total_cost_usd / output_tokens must be materially below `high` on the same fixture.
   If `low ≈ high`, `--effort` isn't reaching the 6 subagents → pivot to setting effort per-subagent before any
   scale-up. (Diagnostic: orchestrator thinking-char share from the trace; if only the orchestrator's thinking
   shrinks and total barely moves, that confirms non-propagation.)
2. **Metrics extractable.** `result` event present with cost/tokens/duration on all 6 runs; disposition parseable
   from `report.md`.

## Metrics (per run, from the `result` event + report.md)

| Metric | Source | Dimension |
|---|---|---|
| `total_cost_usd`, `output_tokens`, cache_read/creation | result event | cost |
| `duration_ms`, `num_turns` (+ harness wall-clock) | result event | time |
| orchestrator thinking chars, thinking/text ratio | trace content blocks | diagnostic (where output went) |
| disposition vs ground truth; escalated? | report.md frontmatter | quality (cardinal) |
| legitimacy gating correct; `matched_archetype` valid; evidence sufficiency | report.md / investigation.md | quality |

Ranking when aggregating: per-occurrence mean with `n` shown as support (no count-weighted scores).

## Mid-run finding (after xt-mal-high, 2026-06-08)

The `mal` fixture is not a clean "malicious→escalate" case: the EQL rule produced a **false-positive
correlation** — it host.name-joined `dev.dana`'s *failed* invalid-user spray (no breach) to an *unrelated*
authorized `sre.chen` login. High effort correctly decomposed it: `benign` disposition for the correlation +
both authorization contracts grounded + the dev.dana spray flagged as a **companion finding warranting separate
investigation**. So disposition alone is misleading; the quality lens is **nuance retention** — does each effort
level still (a) decompose the spurious join, (b) ground the authorized leg, (c) flag the spray? `analyze.py`
captures disposition plus `spray_flag` / `authz` heuristics; the final read inspects all 6 reports directly.

## Decision criteria

- **`low`/`medium` viable** if disposition is correct on BOTH fixtures (malicious escalates — no false negative;
  benign stays authorized), legitimacy gating + archetype grounding intact, at materially lower cost/time than
  `high`. → recommend lowering the production default.
- **`high` retained** if any sub-`high` arm produces a false negative, misses the escalation, drops the archetype
  match, or weakens evidence grounding on either fixture.
- **Inconclusive / re-scope** if effort fails to propagate (gate #1) or live-ES variance swamps the effort effect
  at N=1 (→ rely on the N=3 scale-up).

## Layout

```
experiments/effort-tradeoff/
  plan.md            # this file
  fixtures/          # malicious-cross-tier-probe.json, benign-cross-tier-pivot.json (frozen)
  runs/              # symlinks/pointers to /tmp/defender-runs-v2/<fixture>-<effort>/
  analyze.py         # written before scale-up; reads result events + report.md
  results/           # validation.md (mid-run), final.md
  variants/          # the 3 invocation lines above (no prompt diff — flag-only)
```
