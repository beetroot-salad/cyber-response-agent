# predict-analyze-format-ab

Two paired A/B experiments on the 5710-bait failing run.

## Question

Engineering — two paired A/Bs:

- **A/B-1:** Does feeding ANALYZE the dense PREDICT trailer inline (instead of YAML invlang via on-demand Read) reduce wall time and/or X-class violations on a fork-shaped fixture?
- **A/B-2:** Does replacing PREDICT's NL stories with structured-fact tuples (preserving sentence IDs) reduce wall time / output tokens without raising parser-rejection or grade-tier degradation downstream?

## Variants

### A/B-1 — analyze input format

- **control:** current `soc-agent/agents/analyze.md` — reads `## PREDICT (loop N)` from `investigation.md` on demand (YAML invlang fence).
- **treatment:** patched to receive the dense PREDICT envelope inline as `<predict_dense loop=N>...</predict_dense>` in the prompt; the read-on-demand bullet for PREDICT is removed; **no fallback** — analyze must grade from the dense form.

### A/B-2 — predict story format

- **control:** current predict SKILL.md / dense-schema §7 — NL prose stories `sN. <sentence>`.
- **treatment:** structured-fact tuples `sN: {key=value; key=value}` preserving sentence-ID semantics so predictions still cite `from_story=sN`. Parser regex `^(s\d+)\.` widened to `^(s\d+)[\.:]` for the experiment scope only.

## Fixture

`/tmp/soc-agent-orchestrate-eval/20260429-202152-rule5710/runs/e00fe8c3-7c47-400e-8df0-ee276651ecc1/`

Prompts replayed verbatim from `subagent_outputs/`:
- `20260429T203448662999Z-predict-57417cd6.txt` — predict L2 prompt + reference stdout
- `20260429T204243448642Z-analyze-66833cd2.txt` — analyze L2 prompt + reference stdout

Shape-current as of commit `9be69cd` (post #155) + #156 prologue migration. Fork-shaped (Shape M, 2 hypotheses) — load-bearing for both variables.

## Trials

- Validation: 1 per variant per A/B (4 trials).
- Scale-up: N=3 per variant per A/B (12 trials total). N=3 is exploratory — wall variance on Sonnet at this duration is wide; effect sizes <20% will be in the noise.
- Mid-run analysis: not required at N=3.
- `analyze.py` written before scale-up.

## Decision criteria

**A/B-1:**
- proposed wins iff: mean wall ≤ −15% AND X-class violation rate not increased AND no new parser rejections AND grade-tier distribution does not collapse `++`/`--` → `+`/`-`.
- current retained iff: wall delta < 10% OR any new parser rejection OR X-violation rate increases OR analyze fails to enumerate `p*`/`r*` literals correctly.

**A/B-2:**
- proposed wins iff: mean wall ≤ −15% AND output tokens ≤ −20% AND parser-rejection rate stays at 0 AND downstream analyze grade-tier distribution matches NL-control within ±1 row.
- current retained iff: wall delta < 10% OR any predict parser rejection OR `from_story` references break OR downstream analyze regrades >1 row differently.

A "tie" outcome is treated as "current retained".

## Layout

```
tasks-scratch/predict-analyze-format-ab/
  plan.md
  variants/
  fixtures/
  runs/
    ab1-analyze/{control,treatment}/trial-{1,2,3}/
    ab2-predict/{control,treatment}/trial-{1,2,3}/
  analyze.py
  results/
```

## Replay harness

Direct `claude -p --model sonnet --system-prompt-file <variant> --plugin-dir soc-agent --output-format text`, prompt on stdin. Same model + flag set as `soc-agent/scripts/handlers/_subagent.py:225`. No orchestrator pass-through (isolates the variable). For A/B-2 treatment, downstream analyze is run with the **control** analyze variant against the predict treatment's stdout to measure regression.
