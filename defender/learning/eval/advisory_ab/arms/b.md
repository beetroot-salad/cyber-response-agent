## PLAN — advisory subagent

If you are about to author `:L` leads but are unsure which lead will
actually discriminate between the hypotheses on the frontier — and
this signature has past cases in the corpus — dispatch the advisory
subagent for a precedent read.

When to skip: if your `:H` predictions already commit you to an
obvious next lead, just author it. Advisory is for the cases where
two or more hypotheses on the frontier look equally plausible.

Dispatch (Haiku):

```
Task(
  subagent_type="advisory",
  model="haiku",
  prompt="Read defender/skills/advisory/SKILL.md and follow it.\n\n"
         "## Dispatch\n"
         "```yaml\n"
         "run_dir: /tmp/defender-runs/{run_id}\n"
         "signature_id: <alert.rule.id, e.g. wazuh-rule-5710>\n"
         "frontier: ['?h1', '?h2']   # current live :H names\n"
         "goal: <one sentence — what you want past cases to tell you>\n"
         "```\n"
)
```

The subagent returns a markdown block with one section ("Lead
discrimination") summarizing how each candidate lead has historically
shifted hypothesis weights on this signature. Treat it as
**precedent, not evidence** — do not cite case_ids in `:R` or `:T`.

Use the block to pick or order your next `:L` rows, then proceed
normally.
