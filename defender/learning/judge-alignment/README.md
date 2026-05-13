# Judge-alignment dataset

Synthetic judge inputs for validating `defender/learning/judge.md` against human
labels. Each batch (`batch_NN.md`) is a self-contained markdown file with 3
samples; each sample bundles the four artifacts the judge sees (alert,
investigation excerpt, actor story, projected telemetry) plus the human-expected
outcome and rationale.

Outcome enum (from `judge.md`):

- **caught** — actual lead results refute the oracle's projection on a
  load-bearing aspect of the story.
- **survived** — every lead's actual result is consistent with the oracle's
  projection (or projection empty + no other lead refutes).
- **incoherent** — the story contradicts the alert or investigation regardless
  of lead coverage.
- **undecidable** — the story's load-bearing claim requires telemetry from a
  system affirmatively `not-deployed` here.
- **skip-passthrough** — actor emitted SKIP.

Samples are compact but faithful — alert.json is trimmed to load-bearing fields,
investigation excerpts quote lead descriptions and gather/analyze results,
projections quote the events the oracle would synthesize. The judge prompt is
designed to operate on these surfaces, not on full-length transcripts.

Each sample also carries an **`Expected actor observation (gist)`** line — one
sentence naming the load-bearing actor-side element (the refuted prediction for
`caught`, the alert/story contradiction for `incoherent`, the untested strategic
miss for `survived`, or the missing-system pin for `undecidable`). The human
reviewer compares the judge's actual `actor_observations[]` entries against
this gist to score observation pertinence.

## Acceptance criteria

- Outcome agreement ≥80% between judge and human label across the 30-row set.
- Observation pertinence ≥70% — fraction of judge `actor_observations`
  substantively matching the expected-observation gist.
- No silent failures: every case must produce a parseable judge YAML doc.
  Parse failures count as outcome disagreement.
- Below either floor → judge prompt iteration precedes any actor-author rollout.

## Method

1. Generate 30 samples in 10 batches of 3, varied across domain (SSH, DNS,
   FIM, container exec, web), disposition shape (benign/inconclusive/escalate),
   investigation depth (single-lead vs multi-lead), and actor framing (coherent
   attack, story refuted by leads, story alert-incompatible, story requiring
   missing system, SKIP).
2. Human reviewer reads each batch and either ratifies the label or pushes back.
3. After all batches are labeled, run the judge on each sample and compare.
   Disagreements drive judge-prompt edits.
