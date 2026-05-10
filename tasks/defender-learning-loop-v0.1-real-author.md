---
title: Defender learning loop V0.1 — real author (replaces stub)
status: done
groups: defender, learning-loop
---

**Goal.** Replace the stub author landed in V0 with a real LLM author that drains `defender/learning/_pending/findings.jsonl` into a checked-in lessons corpus, with semantic dedup, fold-by-rewrite, atomic commit, and a per-edit verification check.

**Prereqs.**
- V0 (`tasks/defender-learning-loop-v0.md`) shipped — the orchestrator, judge YAML contract, persistence layout, and stub author exist; `_pending/findings.jsonl` is being populated by real runs.
- Verification-method experiment complete (`experiments/defender-author-verification/results/final.md`). Outcome: forward-check alone, single Haiku rep, against the source case's transcript + ground-truth disposition.

**Note on versioning.** V1 is the corpus-≥-30 milestone where retrieval shifts to invlang-keyed matching. This task (V0.1) is the intermediate step that makes the lesson corpus real but keeps retrieval naive (load-all-descriptions at PLAN time).

## Locked design

### Lesson shape

- **One file per lesson.** Flat layout under `defender/lessons/` (no per-signature sharding yet — usage will tell us if/when to shard).
- **Skill-pattern file**: YAML frontmatter + freeform markdown body.
  - **Retrieval frontmatter** (loaded into PLAN-time prompt): `name`, `description` (one short line).
  - **Bookkeeping frontmatter** (in file, not loaded into the prompt): `source_finding_ids`, `created_at`. Anything else earns its place over time based on observed retrieval needs.
- **Lesson type — pitfalls only for V0.1.** Pattern: "you assumed/skipped X; should have considered Y; here's the check." Corrective and outcome-neutral. Framing-type lessons ("this configuration is a known pattern…") are deferred until we have an adversarial test that proves they improve robustness without inducing outcome bias.

### Author

- **LLM author** (not a deterministic script). Judge findings are already actionable; the author's job is dedup + light generalization + fold + verify, not writing from scratch.
- **Per-batch flow:**
  1. Acquire lock at `_pending/.lock` (preflight refuses concurrent runs).
  2. Read pending findings batch.
  3. For each finding: load all existing lesson descriptions (V0.1 scale tolerates this; tighten when corpus grows past ~30) and decide *new lesson* | *fold into existing* | *skip*.
  4. **Fold semantics**: rewrite the existing lesson body holistically; update `description` if the new finding broadens scope; append to `source_finding_ids`.
  5. Run the per-edit verification check (see below) on each new/folded lesson.
  6. Commit atomically — single git commit naming `batch_id` and source run dirs.
  7. Only after commit succeeds, mark findings `consumed_at` / `consumed_commit` and rotate them out of `_pending/findings.jsonl` into `_pending/consumed.jsonl`.
  8. On any failure mid-flight: leave the queue intact; idempotent retry on next tick (re-emitted finding hits dedup via `source_finding_ids`).

### Verification (per-edit check) — settled by the methodology experiment

V0.1 ships **forward alone** as the auto-gate. The verification-method experiment (`experiments/defender-author-verification/results/final.md`) ran 4 bad + 4 good hand-crafted lessons through three candidate checks (forward / reverse / regression) at N=3 Haiku reps, and 8 full Sonnet defender reruns as oracle:

| Check | TNR (oracle BAD caught) | TPR (oracle GOOD accepted) | Agreement |
|---|---|---|---|
| **forward** | **2/2 = 100%** | **5/6 = 83%** | **7/8 = 88%** |
| reverse | 50% | 0% | 13% (dead) |
| regression | 100% | 33% | 50% (noisy) |

Forward clears the pre-stated strong-win bar (TNR ≥ 90% ∧ TPR ≥ 80%). Reverse and regression are dropped.

**Concrete gate behavior:**
- After each new/folded lesson is written, run forward check (Haiku, single rep) on the lesson against its source case's full investigation transcript + ground-truth disposition.
- Forward verdict GOOD → lesson commits.
- Forward verdict BAD → lesson held back; surface in commit message / PR description for human review.
- Single rep at edit time is fine; replication is for statistical TNR/TPR measurement, not per-edit gating.

**Acknowledged blind spot.** The same-case oracle (and therefore forward) cannot detect "regresses-elsewhere" lessons — those that are correct on the original case but wrong on variants (T2/T4 typology). Two of four intentionally-bad lessons in the experiment slipped past oracle on this basis. Mitigations:
- PR-review surface — humans can spot overgeneralized phrasing in lesson bodies before merge.
- Post-deployment observability (V1+ work) — once corpus is large enough, A/B test new lessons against held-out cases.
- Skip the author entirely on cases that did not reach a confident ground-truth disposition (forward isn't applicable without ground truth).

### Routing — observability gaps

Findings whose finding type is `observability` with no covering system land as **pitfall lessons** (so the agent stops planning gather steps that need that system) **and** are surfaced in the commit message for human review. No separate gaps log file.

### Defender-side wiring

- `defender/SKILL.md` PLAN section loads all lesson frontmatter (`name` + `description`) eagerly at V0.1 scale.
- Body is loaded on demand when the agent picks a specific lesson to consult.
- Hook-driven retrieval at PLAN / post-GATHER / post-resolutions is V1 work, not V0.1.

## Out of scope (push further)

- **Invlang-keyed retrieval** — V1 milestone; requires lesson bodies to embed invlang fragments and PLAN to query by shape. Trigger: corpus ≥ ~30 lessons.
- **Framing-type lessons** — deferred pending an adversarial bias test.
- **Lesson deletion / refutation / decay** — append-only for V0.1; lifecycle work is V2.
- **Per-signature playbook layer** (lessons folded into `signatures/{id}/playbook.md`) — defer until per-signature vs. cross-cutting split is clear from real lesson distribution.
- **Aggregation N:1** beyond what dedup-fold gives us naturally.
- **CI gating on lesson quality** (Haiku reviewer over the corpus).
- **Auto-PR mode** — V0.1 commits direct to the loop's branch.
- **Benign-defender mode** — running the actor on `malicious` dispositions needs a different prompt shape; out of scope.
- **Sampling at the loop level** — V0 is per-run-dir API only; directory-walking sampler is a follow-up.

## Done when

- Real author drains `_pending/findings.jsonl` into `defender/lessons/` with semantic dedup, fold-by-rewrite, and atomic commit.
- A finding processed twice (same `finding_id`, retry after a crash) does not produce two lessons (idempotency via `source_finding_ids`).
- Lock file prevents two concurrent loop ticks from corrupting the queue or producing conflicting commits.
- Forward verification check (Haiku, single rep) gates each lesson write; BAD verdicts hold the lesson for human review.
- `defender/SKILL.md` PLAN section loads all lesson `name` + `description` at runtime; body loaded on demand.
- A failure mid-batch (simulated git push failure) leaves the queue intact and recovers cleanly on the next tick.
- Observability-gap findings produce a pitfall lesson and a commit-message line.
