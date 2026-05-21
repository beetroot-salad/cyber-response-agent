## PLAN — always-on NL Bash wrapper for advisory retrieval

At every PLAN turn **once you have authored at least one `?:H`** —
*before* authoring any `:L` rows for that turn — Bash the advisory
NL wrapper with a one-paragraph description of what you're trying to
discriminate:

```bash
python3 experiments/advisory-ab/plan_only/advisory_nl.py \
    "<one paragraph: include the signature id, the hypothesis names \
     on your current frontier, and a sentence about what \
     discrimination you're trying to make>"
```

The wrapper accepts a single free-text argument. Include the
signature id (e.g. `wazuh-rule-5710`), each hypothesis name on the
current frontier (e.g. `?monitoring-probe` and `?credential-spray`),
and the discrimination question you're asking. The wrapper takes
care of constructing the CLI call internally.

If you have not yet authored any `:H` rows for this PLAN turn,
**author them first, then call**. Do not call before you have a
frontier — the wrapper needs hypothesis context.

This arm tests whether the NL surface adds value over a deterministic
structured CLI call. You do **not** decide whether the block is
useful — once you have a frontier you call every PLAN turn
unconditionally and ignore the output if it does not bear on your
current branch.

**Do not pre-check the corpus yourself** by listing run dirs, reading
investigation.md files, or Globbing /tmp/defender-runs. The wrapper
does its own corpus scan.

Treat the block as **precedent, not evidence**. Do not cite
`case_id`s in `:R` or `:T`.
