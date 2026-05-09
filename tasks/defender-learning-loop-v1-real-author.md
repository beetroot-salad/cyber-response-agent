---
title: Defender learning loop V1 — real author (replaces stub)
status: backlog
groups: defender, learning-loop
---

**Goal.** Replace the stub author landed in V0 with the real author phase: drain `defender/learning/_pending/findings.jsonl` into a checked-in lessons corpus, with dedup, transaction safety, and routing.

**Prereqs.** V0 (`tasks/defender-learning-loop-v0.md`) shipped — the orchestrator, judge YAML contract, persistence layout, and stub author exist; `_pending/findings.jsonl` is being populated by real runs.

## In scope

1. **`lessons.md` schema.** Freeform body for the lesson text; YAML frontmatter limited to retrieval keys (e.g. `id`, `applies_to_alert_rule_keys`, `judge_finding_types`, `created_at`, `source_finding_ids`). One lesson per file under a chosen layout (flat under `defender/lessons/`, or sharded by `alert_rule_key`).
2. **Dedup.** Before writing a new lesson, check whether the finding overlaps an existing lesson. POC-grade: lexical/embedding similarity on `subject` + `finding` text scoped to the same `alert_rule_key` and `type`. Decide merge vs. append vs. skip.
3. **Transaction model.** Atomic per-batch:
   - acquire lock file under `_pending/.lock` (preflight refuses concurrent runs);
   - read findings batch;
   - apply edits to `defender/lessons/`;
   - commit (real git commit, single message naming the batch_id and source_run_dirs);
   - only after commit succeeds, mark findings `consumed_at` / `consumed_commit` and rotate them out of `_pending/findings.jsonl` into `_pending/consumed.jsonl` (or delete).
   - On any failure mid-flight: leave the queue intact; idempotent retry on next tick.
4. **Routing for `observability` findings with no covering system.** Decide where these land — a dedicated `defender/lessons/_observability_gaps.md` log? Skip into a separate queue? Surface in the commit message?
5. **Defender-side wiring.** Once lessons exist, load them at PLAN time (`defender/SKILL.md` PLAN section) — either eagerly or via a Skill the agent loads on demand. Don't preload full bodies; expose a retrieval surface.
6. **Sampling at the loop level (optional).** The V0 loop is per-run-dir API only; V1 may add a directory-walking sampler with thresholds (e.g. "process every Nth run", "only run if signature has < M lessons").

## Out of scope (push further)

- Invlang-keyed retrieval — requires the lesson body to embed invlang fragments and the defender PLAN to query by invlang shape. Defer until lesson volume warrants it.
- Per-signature playbook layer (lessons folded into `signatures/{id}/playbook.md`) — defer until cross-cutting vs. per-signature split is clear from real lesson distribution.
- Aggregation across many findings into a single lesson (vs. 1:1 finding→lesson). POC ratio is 1:1 unless dedup decides otherwise.
- CI gating on lesson quality (Haiku reviewer). Useful but not blocking V1.
- Auto-PR mode (vs. direct commit-to-branch). V1 commits to the branch the loop runs on; PR flow is a follow-up.
- Benign-defender mode — currently the loop only runs the actor on `inconclusive`/`benign` dispositions. Running it on `malicious` (defender-was-correct) requires a different prompt shape and is out of scope.

## Done when

- Real author drains `_pending/findings.jsonl` into `defender/lessons/` with dedup + atomic commit.
- A finding processed twice (same finding_id, retry after a crash) does not produce two lessons.
- Lock file prevents two concurrent loop ticks from corrupting the queue or producing conflicting commits.
- `defender/SKILL.md` PLAN section references the lessons surface.
- A failure mid-batch (e.g. simulated git push failure) leaves the queue intact and is recoverable on the next tick.
