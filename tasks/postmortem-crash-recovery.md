---
title: Post-mortem crash recovery — restart, orphan detection, retries
status: backlog
groups: post-mortem, reliability
---

Follow-on to `tasks/postmortem-lead-pool-normalization.md`.

The lead-pool-normalization task lands the post-mortem pipeline as a
detached subprocess spawned from `stop_handler.py` with **fail-loud**
discipline: stdout/stderr to `runs/postmortem/{run_id}/run.log`,
unhandled exception leaves a `proposals.failed` marker, no retries.

That's intentionally the minimum. This task covers the recovery
behaviors we deferred:

- **Orphan detection** — a post-mortem subprocess crashed (or was
  killed mid-run) leaves a partial state. On the next agent boot or
  on demand, scan `runs/postmortem/*/` for runs missing a terminal
  `proposals.md` *and* a `proposals.failed` marker (i.e. neither
  succeeded nor failed cleanly) and decide policy: re-run, mark
  abandoned, surface to operator.
- **Restart-on-boot** — should the next agent invocation pick up
  abandoned post-mortems? Probably opt-in (CLI flag or scheduled
  sweep), not automatic.
- **Retries** — a transient failure (Haiku 5xx, rate limit) should
  probably be retryable without human intervention. Bound the retries
  and surface persistent failures.
- **Concurrent-spawn safety** — if `stop_handler.py` fires twice for
  the same run (shouldn't happen, but), make sure we don't double-
  spawn. Lockfile in `runs/postmortem/{run_id}/`.

Out of scope until the pipeline itself is producing useful proposals —
no point hardening a path nobody's exercising yet.
