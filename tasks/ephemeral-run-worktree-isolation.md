---
title: Ephemeral per-run worktree to isolate live-run auto-commits from main
status: todo
groups: defender, learning, infra
---

**Context.** The long-lived `defender-v2-env` worktree was collapsed into `main`
(2026-06-09). It existed partly to keep live-run auto-commits off the branch
under active development. That isolation now needs a new home on `main`.

`defender/learning/lead_author.py` (and the other curators: `author.py`,
`author_actor.py`, `author_actor_benign.py`) spawn `claude -p` with
`cwd=REPO_ROOT` and a `Bash(git commit:*)` allowlist — they commit one
lesson-commit to **whatever branch the worktree is on**. Run directly on a
checkout of `main`, a live run would auto-commit straight onto `main` (or onto a
dev branch someone else is working on), which is exactly the collision the
separate tree was avoiding.

**Approach (decided 2026-06-09): ephemeral per-run worktree.** A thin
run-orchestration wrapper:

1. `git worktree add /tmp/defender-run-<id> -b run/<id>` off `main`.
2. Run the investigation + learning loop there (auto-commits land on the
   throwaway `run/<id>` branch; `REPO_ROOT`/`cwd` resolve to the worktree).
3. Harvest the lesson commits — cherry-pick onto a `lessons` branch / open a PR.
4. `git worktree remove /tmp/defender-run-<id>` (and delete the branch).

**To confirm at implementation:**
- `REPO_ROOT` in `lead_author.py` / `author*.py` derives from `__file__` so it
  resolves to the worktree copy (not the original checkout).
- `run.py`'s venv re-exec (`defender/.venv`) still resolves from a worktree —
  the worktree shares the main checkout's `.venv` only if symlinked; decide
  whether each ephemeral worktree gets its own `uv sync` or reuses one.
- The curators' post-flight git checks (one-commit-since-base, in-scope paths)
  still hold when base is `run/<id>`.

**Also pending from the collapse:**
- Open PRs against the old main: **#238 (flow-map)** is MERGEABLE against the new
  main; **#247 (learning-judge-surface)** is CONFLICTING and needs a manual rebase
  onto the reworked `defender/learning/` or a re-land.
