---
title: Decouple run / learn / author so live runs can be concurrent (dev loop)
status: doing
groups: defender, learning
---

**Context.** The `defender-v2-env` worktree (which kept live-run auto-commits off
the dev branch) was collapsed into `main` (2026-06-09). The original fix — an
ephemeral per-run worktree — was reworked once we traced the loop: after
decoupling, **only the serial author commits**, so per-run *git* isolation is no
longer the problem to solve. This task is the **dev** implementation. The
production container/DB shape lives in `docs/platform-design.md` (§4.3/§4.4) and
is out of scope here. **Phase 1 shipped 2026-06-10** (see checklist below).

**Shape.** Three stages, two boundaries:

1. **Run** — concurrent; holds SIEM creds. Investigate → persist run-dir
   artifacts. Does **not** commit. Dev isolation = separate processes + per-run
   `/tmp` run dirs (a run no longer mutates the repo once lead-author's commit
   moves out, so **no per-run git worktree** is needed).
2. **Learn** — concurrent; FS + LLM only, no git. actor → oracle → judge over the
   persisted artifacts → append findings to the queue. (In dev Phase 1 this still
   runs in `run.py`'s process, after the investigation; off-process learn is
   Phase 2.)
3. **Author** — serial; FS + LLM + git. Drain the queue (batched ≈ today's
   `LEARNING_AUTHOR_THRESHOLD`), fold/supersede against the live corpus,
   forward-check, commit. Phase 1 commits **locally**; PR/auto-merge is Phase 2.

Boundaries: run→learn = the persisted run-dir artifact; learn→author = the
findings queue + an author-work marker.

**Findings queue.** A substrate behind the `LoopPaths` seam (`_loop_config.py`),
relocated out-of-repo via `DEFENDER_LEARNING_STATE_DIR` (resolved + created once;
unset → in-repo default, preserving today's behavior and the test fixtures). The
**single source of truth** both producer (`_loop_persist.append_*`) and consumer
(the three authors + lead_author) resolve from. Kept the existing **single-JSONL +
`fcntl.flock`** design (no sharding — sharding only mattered for git-merge
conflicts, and the queue is out-of-repo). Findings already carry a stable
`finding_id`; concurrency safety is the flock, not unique filenames.

**Author git discipline (Phase 2).** Each authoring batch branches off
freshly-fetched `origin/main`; serial → no corpus conflict; findings stay queued
until the PR merges so a rejected/edited PR can't corrupt the next batch.

**Boundaries & recovery.**
- **run→learn / learn→author handoff is durable.** `run_one` writes an atomic
  `author-queue/<run-id>.json` marker (`{run_id, run_dir}`) into `$STATE_DIR`. The
  serial drainer lead-authors each queued run dir; a vanished `/tmp` run dir →
  `author-queue/failed/<run-id>.json` (`failed: artifact-missing`), surfaced, not
  silently dropped.
- **Consumed-ledger already existed** — lessons record `source_finding_ids` in
  frontmatter and the author filters the queue against them
  (`author._partition_pre_author`), so recovery after a crash between merge and
  queue-cleanup is idempotent (re-run = already-covered → skip). The finding state
  machine (`held` / `consumed_idempotent` / `consumed_skip` / `held_forward_bad`)
  also already existed; Phase 1 reused both rather than rebuilding them.
- **Queue rotate concurrency.** `author.py` rotate does a re-read-merge under
  `.findings.lock` (its instance lock `.lock` ≠ the producer's queue lock, so a
  concurrent append during its batch is real and must be preserved). The two
  observation authors keep a held-only rotate: they hold their queue lock across
  the whole batch (`acquire_queue_lock`), so the producer's append blocks and no
  row can arrive mid-batch — re-locking there only deadlocks.
- **Author serialization** = single drainer + a dedicated non-blocking
  `flock($STATE_DIR/.author-drain.lock)` (distinct from the curators' repo lock,
  so the curators it calls don't self-deadlock). A second drainer exits cleanly.

**Gating (Phase 3).** `merge_mode` default intended `auto_on_green` (schema/
validator + forward-check GOOD + held-out/secondary eval no-regression), gated on
the revert path + lesson→outcome traceability surface existing; until then default
`human_review`. Rationale + accepted residual in platform-design §4.4.

**Phase 1 — shipped (this PR):**
- [x] `DEFENDER_LEARNING_STATE_DIR` seam on `LoopPaths` (state_dir; runs/pending/
      locks/author-queue derive from it); single source of truth for producer +
      consumers. Kept single-JSONL + flock (no sharding).
- [x] `run_one` no longer authors or commits — produces findings + writes the
      `author-queue/<run-id>.json` marker. `lead_author`'s per-run commit moved out
      of the run path.
- [x] Serial `author_drain()` + `loop.py --author-drain`: lead-authors each queued
      run dir (artifact-missing → surfaced), then the three threshold-gated
      curators. Commits locally.
- [x] `author.py` rotate: re-read-merge under `.findings.lock` (preserves a
      concurrent producer append); observation authors keep held-only rotate.
- [x] Tests: `test_loop.py` (+6: rotate-merge, marker, drain happy/missing,
      curator triggering, singleton lock); updated `test_held_out_filter` to the
      new no-commit/marker contract; `conftest` rebind. Affected suites green
      per-directory (58 / 16 / 111).

**Phase 2 — deferred:**
- [ ] Author worktree off freshly-fetched `origin/main` per batch + `gh pr create`
      (extend `lead_author.maybe_push`) + auto-merge wiring.
- [ ] Off-process LEARN worker (SIEM-free) draining run-dir artifacts; promote the
      in-`run.py` learn call to a standalone stage.
- [ ] Live end-to-end verification: real alert → concurrent `run.py` → drain →
      lesson commit (needs claude + the v2 stack).

**Phase 3 — deferred:**
- [ ] `merge_mode` knob; wire the green bar (forward-check author-time +
      `eval_held_out.py` / `eval_secondary.py` at PR time). Default `human_review`
      until the revert + traceability surface exist.
- [ ] Automated revert hook + lesson→outcome traceability surface (gates flipping
      the default to `auto_on_green`).

**Deferred / known scaling gaps (not MVP-blocking):**
- Lesson loading at PLAN is enumerate-all-frontmatter; retrieval-based top-k is the
  fix once the corpus grows (no cap today — supersession is the only pressure, and
  it's LLM-imperfect, so semantic dups can slip cross-batch).
- Observation authors hold their queue lock across the whole batch, so a concurrent
  learn's observation append stalls until the batch finishes (bounded; acceptable
  at PoC volume — the findings path uses the better brief-lock rotate).

**Pending from the collapse:**
- #238 (flow-map) is MERGEABLE; #247 (learning-judge-surface) is CONFLICTING —
  rebase or re-land onto the reworked `defender/learning/`.
