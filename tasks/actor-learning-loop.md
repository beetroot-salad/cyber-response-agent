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

- [x] **Held-out fixture set + persist-stage filter.** 24 alerts under
  `defender/fixtures/held-out/{slug}/{alert.json,ground_truth.yaml}`,
  8 per class. `defender/run.py` propagates the sidecar
  `ground_truth.yaml` into the run dir; `defender/learning/loop.py`
  `is_held_out()` gate short-circuits the persist stage before
  `append_findings` is called. Baseline harness:
  `defender/learning/eval_held_out.py`. Synthesis caveat (alerts are
  bootstrap synthetic shapes) called out in the held-out README.
- [x] **Actor-side judge calibration set.** Existing
  `defender/learning/judge-alignment/` extended in place. Each of the
  30 samples now carries an `Expected actor observation (gist)` line
  alongside the existing expected outcome and findings. README adds
  the acceptance criteria block: outcome agreement ≥80%, observation
  pertinence ≥70%, zero parse failures; below either floor → judge
  prompt iteration precedes actor-author rollout.
- [x] **`defender/lessons-actor/` corpus structure** — tradecraft +
  environment channels, lean retrieval-only schemas, per-channel
  `_TEMPLATE.md`. No seed lessons; env invalidation/mutation fields
  (`subject`, `status`, `superseded_by`) deferred to actor-author PR
  below where the access pattern is concrete.
- [x] **Actor.md edit — grep-after-Section-0 phase.** Validate retrieval
  reliability at MVP (Sonnet expected clean, Haiku may miss). Switches
  the actor invocation to stream-json, persists `actor_trace.jsonl`
  (tradecraft + environment index/grep/read events), and ships
  `defender/scripts/lessons_actor_index.py` — the description-listing
  CLI the actor uses to scan `relevance_criteria` before reading
  files. Env lessons flow through the same retrieval path (filtered by
  archetype only); no preloaded snapshot artifact. No standalone audit
  script — analytics fold into ad-hoc analysis on the trace JSONL.
- [x] **Actor pending queue + persist-stage rotation.** Producer half
  only: persist stage writes `_pending/actor_observations.jsonl` with
  one self-contained entry per judge `actor_observations[i]`, stable
  ID `{run_id}/{observation_index}`, dedup on ID. Schema mirrors
  `findings.jsonl` style (inlined `type` / `subject_anchor` /
  `subject_topic` / `observation` / `judge_outcome` /
  `alert_rule_key` / `source_run_dir`). Producer's only outcome
  filter is `skip-passthrough`; the caught / incoherent / survived
  authoring policy is the **author's** job (item #6). No rejected
  side queue — defender's `author.py` uses hold-with-reason on
  retried entries; the actor author can adopt the same pattern when
  it lands. Shared helpers (`_source_run_dir`, `_load_jsonl_ids`,
  `_append_jsonl`) factored in `loop.py` for the next queue caller.
- [ ] **Actor author** — `defender/learning/author_actor.py` +
  `author_actor.md`. Designs and lands the env-channel invalidation
  schema (equivalence key, status, supersession refs — shape TBD
  against the concrete access pattern) on top of the lean retrieval-
  only frontmatter shipped by the corpus-structure PR.
  `caught` → tradecraft + environment authoring
  (contradiction-with-replacement); `incoherent` → environment
  stale-only invalidation (closes the contradiction-only loop for
  stale env claims; no replacement live file written). Per-case
  inputs include `actor_env_lessons.yaml` + `actor_trace.jsonl` so
  the author can identify the specific stale subject. Environment
  prompt enforces attacker-framing constraint (no visibility-surface
  prose). Repo-level lock
  (`defender/learning/_author.lock`) wraps the **entire fold-and-
  commit flow** including child-agent execution that mutates files —
  not just the final `git commit`. Order: acquire queue lock first,
  then repo lock; release in reverse. Author commit on fire is the
  generation boundary; trailer asserts `Generation: N` +
  actor-model identifier (for replay pinning).
- [ ] **Secondary metric harness.** Two-worktree replay: current
  defender investigates held-out from HEAD; frozen actor from
  `gen-{N-3}` writes a story against that lead sequence; current
  oracle + judge grade. Reads actor-model pin from `gen-{N-3}` commit
  trailer. **Scope rules**: eligibility by ground-truth label
  (benign/inconclusive only — malicious held-out is primary-only);
  executed set is the eligible subset where current defender did not
  escalate. **Metric reporting**: three numbers per generation —
  eligible set size (fixed), executed/eligible ratio, catch rate over
  executed (skip-passthrough excluded from denominator, reported
  separately as SKIP rate). Divergence diagnostic.
- [ ] **End-to-end wiring** — defender author + actor author concurrent
  on independent queues + thresholds (default 5 each).

## Locked decisions (see design doc)

- Memoryless-across-cases dropped; actor reads `lessons-actor/`.
- Tradecraft keyed on MITRE technique IDs (grep retrieval).
- `actor_type` frontmatter (formerly `archetype`): multi-value YAML
  list, `internal | external` only. Grep-friendly. Tradecraft hook
  field is `relevance_criteria` (formerly `description`).
- Actor model = Sonnet (Haiku misses retrieval).
- Tradecraft authoring: **failure-only**, from `outcome: caught` only.
  No positive-pattern channel at MVP. Judge v3 schema unchanged.
- Tradecraft realism gate: **none at MVP.** Non-duplication is the
  only check. Mitigated by per-generation human review + retirement
  instrumentation. Probe-evidence-style gate is follow-up.
- Primary metric: exact-match on `disposition` with asymmetric
  per-class floors (≥90% malicious recall, ≥70% on benign/inconclusive).
  `inconclusive` is a labeled disposition, not abstention. Failed
  runs (crashes, timeouts, missing/invalid report) count wrong
  against ground truth; failure rate reported separately.
- Plateau measured on the **defender-author commit sequence**. Each
  defender-author commit produces an eval checkpoint
  `(defender_sha, actor_generation)`; actor-author commits do not
  advance the plateau test.
- Environment lessons: attacker-framed only; no defender-visibility
  prose. Framing rule enforced at author write time.
- Retrieval: audit-only at MVP via `actor_trace.jsonl` (stream-json
  capture of all index-CLI / Grep / Read calls); Section 0 may not
  be revised post-retrieval.
- Stage-specific model env vars (`ACTOR_MODEL`, `ORACLE_MODEL`,
  `JUDGE_MODEL`), one default per stage, no shared fallback;
  only `ACTOR_MODEL` is overridden by the generation trailer at
  replay time.
- Environment claims at MVP: lean retrieval-only frontmatter
  (`actor_type` + `relevance_criteria` + `recorded_at`), discovered
  on the same path as tradecraft via
  `defender/scripts/lessons_actor_index.py --channel environment`
  (no preload). Invalidation/mutation schema (equivalence key,
  status, supersession ref, grounding ref) deferred to actor-author
  PR — its access pattern designs the fields. No time-based TTL.
  **Known unbounded risk**: stale-but-uncontradicted claims can
  pollute curriculum — accept and watch via divergence.
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
