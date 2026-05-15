# Actor author prompt — discipline + model comparison

Two experiments, single shared fixture. Exp 1 validates PR #208's prompt cleanup against the pre-cleanup version. Exp 2 swaps Sonnet for Haiku on the cleaned prompt.

## Question

- **Exp 1** (engineering): did the PR #208 cleanup preserve or improve discipline + clarity vs the pre-cleanup ("verbose") prompt?
- **Exp 2** (engineering): on the cleaned prompt, is Haiku within tolerance of Sonnet on the discipline metrics?

## Variants

### Exp 1

- `current` — `defender/learning/author_actor.md` at HEAD (post-c148a05). Regression validator.
- `verbose` — pre-c148a05 prompt (from PR commit `f6aefcc`) **with a minimal forward-check stanza added back**, so both arms exercise the same forward-check gate. Without this injection, `verify_forward_command:` in the user prompt is unmoored and the arms differ on more than one variable.

Differences (`current` vs `verbose`):
- defender-curator disclaimer paragraph
- "What you receive" schema preamble
- `judge_outcome` outcome-routing table
- new-first vs fold-first workflow order
- both-channel collapse vs split
- absence vs presence of forward-check section

Model fixed: Sonnet 4.6 in both arms.

### Exp 2

- `sonnet` — current prompt + `LEARNING_AUTHOR_ACTOR_MODEL=claude-sonnet-4-6`. Same runs as Exp 1's `current` arm — reuse, don't re-run.
- `haiku` — current prompt + `LEARNING_AUTHOR_ACTOR_MODEL=claude-haiku-4-5`.

Prompt fixed.

## Fixtures

Single shared batch under `experiments/actor-author-discipline/fixtures/`:

- `_pending/actor_observations.jsonl` — 6–10 observations across `caught` / `incoherent` / `survived` outcomes.
- `runs/{run_id}/` — `actor_story.md`, `projected_telemetry.yaml`, `judge_findings.yaml`, `actor_trace.jsonl` per source run.
- `lessons-actor/{tradecraft,environment}/*.md` — seeded with 2–3 lessons per channel, crafted to create:
  - fold opportunities for ≥2 observations
  - contradiction-with-replacement opportunity for ≥1 env observation
  - both-channel split opportunity for ≥1 observation
- `README.md` — bootstrap notes + expected counts (the implicit "ground truth" for harness sanity).

Harness (`harness.py`) per trial: copy fixture → tmpdir → set `LEARNING_PENDING_DIR` + lessons-actor path → run `author_actor.py` → snapshot result + git history.

## Trials

- **Validation pass**: 1 trial per variant per experiment (4 author runs).
- **Scale-up**: N=5 per arm. Mid-run analysis at N=2/arm.
- Reuse Exp 1 `current` for Exp 2 `sonnet` → 15 author runs total.

`analyze.py` written before scale-up. Metrics:

- **Code-based per lesson**: body wordcount (median + max per channel); extra frontmatter fields; `source_observation_ids` correctness; lead-with-claim (first ≤25 words contain no preamble keywords).
- **Code-based per run**: fold count, new count, stale-flip count, both-channel split count, `consumed_skip` reasons, commit-trailer presence, HEAD-touches-only-lessons-actor.
- **LLM judge (Haiku)**: attacker-framing pass/fail per env lesson, clarity 1–5. Three reps majority vote. Calibrate post-Exp-1 against hand-labels on the Exp 1 outputs before using for Exp 2.
- **Aggregation**: per-occurrence mean with `n` shown as support. No count-weighted composites.

## Decision criteria

**Exp 1**:
- `current` retained if: median body wordcount ≤ verbose AND zero regression on code-based discipline AND clarity ≥ verbose minus 0.3.
- `verbose` reverted to (wholly or in part) if: code-based discipline drops on ≥2 metrics OR clarity drops by >0.5.
- Tie on discipline + verbose shorter bodies → schema preamble may be disciplining length, investigate before deciding.

**Exp 2**:
- `haiku` adopted if: all code-based metrics within 10% of Sonnet AND no >0.5 clarity drop AND forward-check BAD rate within 20% of Sonnet.
- `sonnet` retained if: Haiku regresses on ≥2 code-based metrics OR forward-check BAD rate ≥1.5× Sonnet's.
- Mixed (e.g., Haiku fine on tradecraft, weak on env) → propose per-channel model split as follow-up, don't decide globally.

## Layout

```
experiments/actor-author-discipline/
  plan.md
  variants/current.md
  variants/verbose.md
  fixtures/
    _pending/actor_observations.jsonl
    runs/{run_id}/...
    lessons-actor/{tradecraft,environment}/*.md
    README.md
  harness.py
  runs/{exp,arm}/trial-{N}/
  analyze.py
  results/{exp1,exp2}-{midrun,final}.md
```

## Sequencing

1. Bootstrap fixture via 4–6 fresh defender runs (in background).
2. Stage `variants/current.md` and `variants/verbose.md`.
3. Seed `fixtures/lessons-actor/` once observation set is known.
4. Write `harness.py` + `analyze.py`.
5. Validation pass: 4 author runs.
6. If clean, scale-up Exp 1.
7. Mid-run at N=2, then proceed or adjust.
8. Repeat for Exp 2.

## Follow-up arms (not yet scheduled)

### Exp 3 — parallel forward-check via Agent tool

**Motivation.** In trial 1 of the underfold subexperiment, `verify_forward_actor.py` (Haiku, sequential per write) accounted for ~38% of the author's wall time: 4 writes × ~30s ≈ 110s of 285s. The author waits on each gate before moving to the next probe; cost scales linearly with batch size.

**Variant.** Register a `verify_forward_actor` plugin subagent (system prompt = `verify_forward_actor.md`, read-only tools). Replace the prompt's "run the exact command…" stanza with: "after you've written all lessons in the batch, spawn one `verify_forward_actor` subagent per written file in a single tool block; handle BADs in a second pass." Drops the python shim, removes the path-substitution failure modes the prompt currently guards against, and parallelizes the gate via the Agent tool's native concurrency.

**Question.** Does the parallel-gate variant preserve verdict fidelity (no drift in GOOD/BAD distribution vs. sequential) while cutting wall time roughly proportionally to batch size?

**Setup.** Reuse the underfold fixture (3 seeds + 4 probes) as a tractable batch with mixed fold/new outcomes. Two arms:
- `seq` — current prompt + per-write Bash gate (baseline; reuses underfold trials).
- `parallel` — modified prompt + Agent-tool gate.

**Metrics.**
- Wall time per trial; gate-time share.
- GOOD/BAD distribution per arm per probe. Same observations should reach the same verdicts; drift signals isolation or context-bleed problems.
- Retry incidence — how often BAD lands on a finished pass; does the second-pass fix flow work end-to-end.
- Touched-files count + analyzer outcome parity with the sequential arm.

**Decision.**
- Adopt `parallel` if: wall-time drop ≥30%, GOOD/BAD distribution within ±1 verdict of `seq` across probes, no new failure modes in retry handling.
- Stay sequential if: verdict drift ≥2 cases or any silent failure in BAD propagation.

**Pre-flight verification (cheap, before standing up the arm).** Confirm the author runner's `claude -p --print` invocation actually permits nested Agent/Task tool calls — same shape investigate uses, so it should work, but worth a one-shot check before migrating the prompt.

**Sequencing.** Pending the underfold result. Worth doing regardless of underfolding outcome — the time savings are independent of the prompt-discipline question.
