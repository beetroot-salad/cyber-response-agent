## PLAN — always-on advisory retrieval (no discretion)

At every PLAN turn (loop 1, 2, 3, ...) — *before* authoring any `:L`
rows — Bash the advisory CLI with the current frontier:

```bash
python3 -m defender.scripts.invlang.cli advisory \
    /tmp/defender-runs \
    --signature wazuh-rule-NNNN \
    --classes lead_discrimination \
    --frontier '?hypothesis-one,?hypothesis-two' \
    --top-k 5
```

Pass `--signature` from `alert.rule.id`. Pass `--frontier` as the
comma-separated list of currently live `?:H` names (empty allowed on
loop 1 if you have not yet authored hypotheses; in that case the CLI
falls back to the top-K recurring leads for the signature).

This arm tests whether always-on advisory is worth the cost on cases
where it does not help. You do **not** decide whether the block is
useful — you call every PLAN turn unconditionally and ignore the
output if it is loud-empty or does not bear on your current branch.

Treat the block as **precedent, not evidence**. Do not cite
`case_id`s in `:R` or `:T`.
