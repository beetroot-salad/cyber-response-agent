## PLAN — always-on advisory retrieval (no discretion)

At every PLAN turn **once you have authored at least one `?:H`** —
*before* authoring any `:L` rows for that turn — Bash the advisory
CLI with the current frontier:

```bash
python3 -m defender.scripts.invlang.cli /tmp/defender-runs advisory \
    --signature wazuh-rule-NNNN \
    --class lead_discrimination \
    --frontier '?hypothesis-one' \
    --frontier '?hypothesis-two' \
    --top-k 5
```

CLI arg order is **corpus_root first, then `advisory`**. Each
`--frontier` flag takes one `?hypothesis` name; repeat for each live
`:H` row.

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

**Do not pre-check the corpus yourself** by listing run dirs, reading
investigation.md files, or Globbing /tmp/defender-runs. The CLI does
its own corpus scan; trust the response.

Treat the block as **precedent, not evidence**. Do not cite
`case_id`s in `:R` or `:T`.
