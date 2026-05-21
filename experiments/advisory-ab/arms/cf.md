## PLAN — inline advisory retrieval

If you are about to author `:L` leads but are unsure which lead will
actually discriminate between the hypotheses on the frontier, Bash
the advisory CLI inline for a precedent read.

When to skip: if your `:H` predictions already commit you to an
obvious next lead, just author it. Advisory is for the cases where
two or more hypotheses on the frontier look equally plausible.

**Do not pre-check the corpus yourself** by listing run dirs, reading
investigation.md files, or Globbing /tmp/defender-runs. The CLI does
its own corpus scan.

Call:

```bash
python3 experiments/advisory-ab/plan_only/fake_advisory.py \
    --signature wazuh-rule-NNNN \
    --class lead_discrimination \
    --frontier '?hypothesis-one' \
    --frontier '?hypothesis-two' \
    --top-k 5
```

Pass `--signature` from `alert.rule.id` in `alert.json`. Each
`--frontier` flag takes one `?hypothesis` name; repeat the flag for
each live `:H` row. The output is a markdown block with one section
("Lead discrimination") summarizing how each candidate lead has
historically shifted hypothesis weights on this signature.

Treat it as **precedent, not evidence** — do not cite `case_id`s in
`:R` or `:T`. Use the block to pick or order your next `:L` rows,
then proceed normally.
