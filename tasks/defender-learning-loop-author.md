---
title: Defender learning loop — real author phase
status: done
groups: defender, learning-loop
---

**Goal.** Replace the V0 stub author with a real author phase that consumes `defender/learning/_pending/findings.jsonl` and produces durable lesson edits. Follow-up to `defender-learning-loop-v0.md`.

**Prereqs.** V0 orchestrator + judge YAML contract shipped. Real findings accumulating in the queue from at least one round of /tmp runs.

## Open design questions (must resolve before implementation)

These were deferred from the V0 PR because each warrants its own discussion:

### 1. Dedup mechanism

Options on the table:

- **(a) LLM-driven semantic dedup** — author reads existing `lessons.md` + recent git log of learning edits, decides per-finding whether it's a refinement, dup, or new lesson. Flexible; no schema commitment; relies on author prompt quality.
- **(b) Structural dedup key** — `(alert_rule_key, type, normalized_subject)`. Stable across runs but `subject` normalization is fragile (lead-position references like `l-001` need resolution to `query.id`).
- **(c) Hybrid** — structural key kills exact-match dups inside a batch; LLM handles semantic dedup against the existing corpus.

V0 design assumes the author is an LLM with dedup context (option a or c). Pin this here.

### 2. `lessons.md` schema

Freeform body with frontmatter limited to retrieval keys. Concrete shape TBD — likely:

```markdown
---
keys: []   # retrieval keys, unused at V0, populated when V0.5/V1 retrieval lands
---

# Defender lessons

<freeform body — author defines section conventions on first emission>
```

Author decides section structure on the first lesson it writes; subsequent lessons follow the precedent.

### 3. Author transaction model

- Preflight scope: which files allowed dirty? (Author-target files only — `defender/learning/lessons.md`, `defender/skills/*/SKILL.md`.)
- Lock file at `_pending/_lock` to prevent concurrent author runs and to fail-loud on crashed prior runs (no LLM auto-replay).
- Commit-then-mark: stage edits, commit, then rewrite jsonl with `batch_id`, `consumed_at`, `consumed_commit`. Crash before mark → human resolves via lock.
- Batch size cap (e.g. 20 findings per author invocation).

### 4. Routing edge cases

- `observability` finding with no covering system in `defender/skills/`: create a new system doc, append to a "system-coverage gaps" lesson, or fail-loud and queue for human review? (Note: prior discussion concluded "no separate human queue" — folds into a `lessons.md` section.)
- `analyze-discipline` cross-signature vs rule-narrow: who decides which section?
- Recurrent signature-specific lessons → trigger graduation to `defender/skills/signatures/{rule_key}.md`.

### 5. Defender-side load of `lessons.md`

`defender/SKILL.md` adds a PLAN-time `Skill` (or Read) of the lessons file. Decide whether this is unconditional or gated on file size.

## Done when

- All five design questions above resolved in the PR description with concrete choices.
- Real author replaces the V0 stub.
- `lessons.md` exists with at least one author-emitted lesson grounded in a real /tmp run.
- Author transaction verified by deliberate mid-author crash test (lock detected, no partial state, human-recoverable).
- `defender/SKILL.md` references `defender/learning/lessons.md` as a PLAN-time load.
