## PLAN — inline advisory retrieval (framing-only, no call)

If you are about to author `:L` leads but are unsure which lead will
actually discriminate between the hypotheses on the frontier, advisory
retrieval normally helps here.

When to skip: if your `:H` predictions already commit you to an
obvious next lead, just author it. Advisory is for the cases where
two or more hypotheses on the frontier look equally plausible.

**Do not pre-check the corpus yourself** by listing run dirs, reading
investigation.md files, or Globbing /tmp/defender-runs.

**For this run, advisory is unavailable — do NOT call the CLI.**
Skip the retrieval step and author `:L` from the alert and prior
context alone.

The block, if it had been available, would have been a markdown
summary with one section ("Lead discrimination") showing how each
candidate lead has historically shifted hypothesis weights on this
signature. Treat the absence as **precedent unknown** — pick or order
your next `:L` rows from the alert alone, then proceed normally.
