## PLAN — always-on advisory retrieval (no discretion)

At every PLAN turn **once you have authored at least one `?:H`** —
*before* authoring any `:L` rows for that turn — Bash the advisory
CLI with the current frontier:

```bash
python3 -m defender.scripts.invlang.cli advisory \
    /tmp/defender-runs \
    --signature wazuh-rule-NNNN \
    --classes lead_discrimination \
    --frontier '?hypothesis-one,?hypothesis-two' \
    --top-k 5
```

Pass `--signature` from `alert.rule.id`. Pass `--frontier` as the
comma-separated list of currently live `?:H` names. If you have not
yet authored any `:H` rows for this PLAN turn, **author them first,
then call**. Do not call with an empty frontier — the loop-1 fallback
is degenerate and the experiment is asking what always-on costs at
the frontier you actually have.

This arm tests whether always-on advisory is worth the cost on cases
where it does not help. You do **not** decide whether the block is
useful — once you have a frontier you call every PLAN turn
unconditionally and ignore the output if it is loud-empty or does
not bear on your current branch.

Treat the block as **precedent, not evidence**. Do not cite
`case_id`s in `:R` or `:T`.
