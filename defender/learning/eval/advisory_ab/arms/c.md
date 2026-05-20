## PLAN — inline advisory retrieval

If you are about to author `:L` leads but are unsure which lead will
actually discriminate between the hypotheses on the frontier — and
this signature has past cases in the corpus — Bash the advisory CLI
inline for a precedent read.

When to skip: if your `:H` predictions already commit you to an
obvious next lead, just author it. Advisory is for the cases where
two or more hypotheses on the frontier look equally plausible.

Call:

```bash
python3 -m defender.scripts.invlang.cli advisory \
    /tmp/defender-runs \
    --signature wazuh-rule-NNNN \
    --classes lead_discrimination \
    --frontier '?hypothesis-one,?hypothesis-two' \
    --top-k 5
```

Pass `--signature` from `alert.rule.id` in `alert.json`. Pass
`--frontier` as a comma-separated list of your current live `?:H`
names. The output is a markdown block with one section ("Lead
discrimination") summarizing how each candidate lead has historically
shifted hypothesis weights on this signature.

Treat it as **precedent, not evidence** — do not cite `case_id`s in
`:R` or `:T`. Use the block to pick or order your next `:L` rows,
then proceed normally.
