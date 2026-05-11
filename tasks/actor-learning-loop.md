---
title: Actor-learning loop — defender capability against a learning actor
status: doing
groups: defender, learning-loop, actor
---

**Motivation.** Defender's `lessons/` accumulates monotonically; actor is
memoryless across cases and reads a hand-curated `mitre_corpus.py`. The
asymmetry plausibly drives a plateau (defender exhausts actor's static
strategy space or its judge-gradable neighborhood). Static actor is the
most actionable lever among several candidate plateau causes — judge
sensitivity, oracle limits, held-out drift — distinguished post-hoc via
the divergence diagnostic on the secondary metric.

**Scope (problem statement #1).** Build a self-play loop in which the
defender accumulates lessons from adversarial alert investigations and
the actor's job is to keep those investigations hard. Success is
measured by **defender disposition correctness on a held-out alert set
with ground-truth labels** — judge-independent at eval time. Actor is
curriculum; defender is the artifact. Equilibrium-mode self-play
(problem statement #2) is explicitly deferred.

**Design.** `defender/docs/learning-loop-actor-learning.md` (this branch).

## Sequencing — one PR each

- [ ] **Held-out fixture set + persist-stage filter.** 24–30 alerts with
  ground-truth labels (≥8 per class: benign/malicious/inconclusive).
  Persist stage drops both `defender_findings` and `actor_observations`
  from held-out runs before either `_pending/` queue is touched.
  Unblocks primary-metric baseline against current defender.
- [ ] **Actor-side judge calibration set.** ~30 rows. Humans label
  the judge's full input tuple:
  `(alert, investigation.md, actor story, projected_telemetry.yaml)
  → caught/survived/incoherent/undecidable`. Mirrors
  `defender/learning/judge-alignment/`. Highest leverage — every
  downstream actor-author decision is built on this signal.
- [ ] **`defender/lessons-actor/` corpus structure** — tradecraft +
  environment channels, schemas, seed lessons. No code yet.
- [ ] **Actor.md edit — grep-after-Section-0 phase.** Validate retrieval
  reliability at MVP (Sonnet expected clean, Haiku may miss). Includes
  switching the actor invocation to stream-json, persisting
  `actor_trace.jsonl`, and adding the missed-retrieval audit script.
- [ ] **Actor author** — `defender/learning/author_actor.py` +
  `author_actor.md`. `caught` → tradecraft + environment authoring;
  `incoherent` → environment invalidation only (closes the
  contradiction-only loop for stale env claims). Environment prompt
  enforces attacker-framing constraint (no visibility-surface prose).
  Author commit on fire is the generation boundary; trailer asserts
  `Generation: N` + actor-model identifier (for replay pinning).
- [ ] **Secondary metric harness.** Two-worktree replay: current
  defender investigates held-out from HEAD; frozen actor from
  `gen-{N-3}` writes a story against that lead sequence; current
  oracle + judge grade. Reads actor-model pin from `gen-{N-3}` commit
  trailer. Divergence diagnostic.
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
- Tradecraft realism gate: **none at MVP.** Non-duplication is the
  only check. Mitigated by per-generation human review + retirement
  instrumentation. Probe-evidence-style gate is follow-up.
- Primary metric: exact-match on `disposition` with asymmetric
  per-class floors (≥90% malicious recall, ≥70% on benign/inconclusive).
  `inconclusive` is a labeled disposition, not abstention.
- Environment lessons: attacker-framed only; no defender-visibility
  prose. Framing rule enforced at author write time.
- Retrieval: audit-only at MVP via `actor_trace.jsonl` (captured by
  the actor-grep PR via stream-json invocation); Section 0 may not
  be revised post-retrieval.
- Stage-specific model env vars (`ACTOR_MODEL`, `ORACLE_MODEL`,
  `JUDGE_MODEL`) introduced in the actor-grep PR; only `ACTOR_MODEL`
  is overridden by the generation trailer at replay time.
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
