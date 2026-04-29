# PREDICT dense-format bake-off

Variant calibration to pick the dense PREDICT trailer grammar (DP / DB / DH) before migrating the production subagent. Parallel to PR #153 (analyze dense trailer).

## Variants

All three share: dense block-shape grammar (no YAML), `kind` slot on every prediction-shaped row, story prose with sentence IDs (`s1.`, `s2.`, ...), `comparison` required when `kind ∈ {geometry, cadence, novel-artifact, absence}`, `kind: presence` forbidden on refutations, field-presence matrix enforced at parse time.

| Variant | `:H` density | preds / attr_preds / refuts | authz contracts | comparisons |
|---|---|---|---|---|
| **DP** | packed | inside `:H` row cells (`;`-separated) | inside `:H` row cell (`authz?`) | trailing positionals on the prediction sub-cell |
| **DB** | metadata only | per-hypothesis `:P h-{id}.preds`/`.attr_preds`/`.refuts` blocks | per-hypothesis `:P h-{id}.authz` block | per-hypothesis `:P h-{id}.comparisons` block |
| **DH** | hybrid | preds / attr_preds / refuts packed in `:H` row | per-hypothesis `:P h-{id}.authz` block | per-hypothesis `:P h-{id}.comparisons` block |

See `_dense_outputs.py` for the exact grammar each variant defines, and `variants/{DP,DB,DH}.md` for the rendered subagent prompts.

## Files

| Path | Purpose |
|---|---|
| `_dense_outputs.py` | Grammar definitions for DP / DB / DH (`OUTPUT_FORMAT_*`) + `COMMON_PREFACE` |
| `build_dense_variants.py` | Splices V1.6 preamble + tail with variant-specific Output format → `variants/{DP,DB,DH}.md` |
| `dense_parser.py` | Reads any of the three dense grammars → `{predict: {...}}` dict matching the YAML envelope shape `score.py` consumes. Returns `(envelope, parse_errors)`. |
| `test_dense_parser.py` | Smoke test: each variant's worked example parses without errors. |
| `parse_outputs.py` | Post-runner: walks `runs/{DP,DB,DH}/` and converts `predict_output.txt` → `envelope.yaml` + `parse_errors.json`. Optional `--faithfulness` flag runs the Haiku quiz. |
| `faithfulness.py` | D11 scorer: spawns Haiku-only on the dense trailer + 5-question quiz; scores 0–1 vs structural answers from the envelope. |

## Running the bake-off

```bash
cd /workspace/.claude/worktrees/predict-dense-bakeoff/evals/predict

# 0. Smoke check parser
python3 test_dense_parser.py

# 1. Dry-run (case-001 only, 1 rep per variant) — sanity check Sonnet's first emission
python3 runner.py --variant DP --variant DB --variant DH --case case-001 --reps 1
python3 parse_outputs.py --variant DP --variant DB --variant DH --case case-001
# inspect: runs/{DP,DB,DH}/case-001/rep-1/{predict_output.txt, envelope.yaml, parse_errors.json}

# 2. Full sweep (5 cases × 3 variants × 5 reps = 75 runs)
python3 runner.py --variant DP --variant DB --variant DH --reps 5 --parallel 6
python3 parse_outputs.py --variant DP --variant DB --variant DH --faithfulness
python3 score.py --variant DP --variant DB --variant DH

# 3. Aggregate
python3 -c "import json; d=json.load(open('results/all.json')); [print(v, round(d[v]['aggregate']['mean_score'],3)) for v in d if 'aggregate' in d[v]]"
```

## Decision criteria

Cut to one variant if:
- **D9 parse rate ≥ 95%** (no remediation needed on first emission)
- **D11 faithfulness ≥ 4.5/5 mean** (Haiku auditor can answer the 5-question quiz from the trailer alone)
- **D1–D5 within 10% of V1.6 baseline** (dense form doesn't regress shape selection or forbidden-pattern rates vs current YAML)

Tiebreaker: lower output token cost.

If all three fall below D9 = 95%, packed sub-cells are not viable for PREDICT — fall back to DB (full sub-blocks) and re-run with stricter remediation handling.

## Open items still to resolve

- Symbolic-story option (raised in design discussion): defer to v1 — v0 uses prose with sentence IDs. If parse rates / faithfulness hold, revisit symbolic stories as an opt-in upgrade.
- Story-symbolic comparison: not in v0 bake-off; would require a fourth variant with same grammar but `### story` block written in operator-style notation.
