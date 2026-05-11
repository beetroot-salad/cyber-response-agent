---
title: Actor-learning loop — defender capability against a learning actor
status: doing
groups: defender, learning-loop, actor
---

**Motivation.** Defender's `lessons/` accumulates monotonically; actor is
memoryless across cases and reads a hand-curated `mitre_corpus.py`. The
asymmetry guarantees a plateau — defender either exhausts the actor's
static strategy space or its judge-gradable neighborhood, and learning
yield drops to zero. Classic self-play collapse if uncorrected.

**Scope (problem statement #1).** Build a self-play loop in which the
defender accumulates lessons from adversarial alert investigations and
the actor's job is to keep those investigations hard. Success is
measured by **defender disposition correctness on a held-out alert set
with ground-truth labels** — judge-independent at eval time. Actor is
curriculum; defender is the artifact. Equilibrium-mode self-play
(problem statement #2) is explicitly deferred.

**Design.** `defender/docs/learning-loop-actor-learning.md` (this branch).

## Sequencing — one PR each

- [ ] **Held-out fixture set + persist-stage filter.** 20–30 alerts with
  ground-truth labels; learning loop's persist stage drops held-out
  findings before they reach `_pending/`. Unblocks primary-metric
  baseline against current defender.
- [ ] **Actor-side judge calibration set.** ~30 rows. Humans label
  `(alert, story, lead_sequence) → caught/survived/incoherent/undecidable`.
  Mirrors `defender/learning/judge-alignment/`. Highest leverage —
  every downstream actor-author decision is built on this signal.
- [ ] **`defender/lessons-actor/` corpus structure** — tradecraft +
  environment channels, schemas, seed lessons. No code yet.
- [ ] **Actor.md edit — grep-after-Section-0 phase.** Validate retrieval
  reliability at MVP (Sonnet expected clean, Haiku may miss).
- [ ] **Actor author** — `defender/learning/author_actor.py` +
  `author_actor.md`. Consumes `actor_observations` on `caught` only
  (failure-only channel). Routes to tradecraft or environment;
  environment prompt enforces attacker-framing constraint (no
  visibility-surface prose). Author commit on fire is the generation
  boundary (trailer `Generation: N`).
- [ ] **Secondary metric harness.** Replay actor stage from
  `gen-{N-3}` commit against held-out; feed stories to current
  defender; report catch rate. Divergence diagnostic.
- [ ] **End-to-end wiring** — defender author + actor author concurrent
  on independent queues + thresholds (default 5 each).

## Locked decisions (see design doc)

- Memoryless-across-cases dropped; actor reads `lessons-actor/`.
- Tradecraft keyed on MITRE technique IDs (grep retrieval).
- Archetype frontmatter: multi-value YAML list, `internal | external`
  only. Grep-friendly.
- Actor model = Sonnet (Haiku misses retrieval).
- Tradecraft authoring: **failure-only**, from `outcome: caught` only.
  No positive-pattern channel at MVP. Judge v3 schema unchanged.
- Environment lessons: attacker-framed only; no defender-visibility
  prose. Framing rule enforced at author write time.
- Retrieval: audit-only at MVP via `tool_trace.jsonl`; Section 0 may
  not be revised post-retrieval.
- Environment claims: one file per write, cache-style, contradiction-
  only invalidation, `system_ref` required for `live`. No time-based
  TTL at MVP. **Known unbounded risk**: stale-but-uncontradicted
  claims can pollute curriculum — accept and watch via divergence.
- Generation = actor-author commit SHA. Git is the manifest; no
  separate snapshot dir. No-op author runs do not advance N.
- Secondary metric is a **divergence diagnostic**, not a single-cause
  verdict. Re-running judge calibration is first-line diagnosis.
- Independent corpora — no actor↔defender environment reconciliation
  at MVP.
- K=3 for frozen-actor replay.
- Single actor lineage (no population) at MVP.

## Out of scope at MVP

Cross-author reconciliation, time-based TTL on environment, multi-actor
populations, tradecraft probe-evidence gate, equilibrium-mode metrics.
