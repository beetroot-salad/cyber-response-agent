## PLAN — always-on advisory retrieval (no discretion)

At every PLAN turn **once you have authored at least one `?:H`** —
*before* authoring any `:L` rows for that turn — Bash the advisory
CLI with the current frontier:

```bash
python3 experiments/advisory-ab/plan_only/fake_advisory.py \
    --signature wazuh-rule-NNNN \
    --class lead_discrimination \
    --frontier '?hypothesis-one' \
    --frontier '?hypothesis-two' \
    --top-k 5
```

Each `--frontier` flag takes one `?hypothesis` name; repeat for each
live `:H` row.

Pass `--signature` from `alert.rule.id`. If you have not yet authored
any `:H` rows for this PLAN turn, **author them first, then call**.
Do not call with an empty frontier.

This arm tests whether always-on advisory is worth the cost on cases
where it does not help. You do **not** decide whether the block is
useful — once you have a frontier you call every PLAN turn
unconditionally and ignore the output if it does not bear on your
current branch.

**Do not pre-check the corpus yourself** by listing run dirs, reading
investigation.md files, or Globbing /tmp/defender-runs.

Treat the block as **precedent, not evidence**. Do not cite
`case_id`s in `:R` or `:T`.
