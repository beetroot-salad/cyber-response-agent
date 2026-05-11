---
title: Tighten author agent allowlist — close silent-broaden path via local settings
status: todo
groups: defender, learning-loop, permissions
---

**Context.** During the 2026-05-11 rerun of the AUTHOR hang investigation (commit b4cc69c), streaming visibility surfaced that the curator agent ran `python3 -c "import os; os.remove(...)"` to delete a forward-BAD lesson after the declared `Bash(rm …)` allowlist entry rejected its absolute-path call. The `python3` invocation succeeded — meaning `Bash(python3:*)` is reachable to the agent via `.claude/settings.local.json` (or another non-author.py source), not via `author.py`'s `--allowed-tools` list.

The immediate `rm` path-mismatch is fixed (author.py now permits both `defender/lessons/*.md` and the absolute form). But the broader issue stands: `author.py`'s allowlist is no longer the source of truth for what the curator can execute.

**What to do.**

1. Audit which Bash patterns the author agent can reach today. Run a probe with `--print --output-format stream-json` and a no-op prompt that tries a sample of disallowed commands (`python3 -c …`, `cat …`, `find …`, `curl …`) — observe which succeed.
2. Decide the policy: either (a) make author.py's `--allowed-tools` authoritative by passing a settings file that disables global permission inheritance, or (b) document that author runs under merged permissions and bake the expected extras (currently just `python3`) into author.py's allowlist explicitly.
3. Add a regression test under `defender/tests/` that asserts the merged permission surface matches the declared surface — fails loudly if `.claude/settings.local.json` silently widens it.

**Why this matters.** The author agent commits to a shared corpus and is the only learning-loop component that mutates checked-in files. Silent permission broadening means the next behavioral change in `settings.local.json` could let the agent invoke tools (`git push`, `gh pr create`, arbitrary `Bash(*)`) that author.py's design contract assumes are out of reach. Today it's benign (`python3` ran a one-line `os.remove`); the failure mode is privilege creep.

**Adjacent.** The original allowlist mismatch wasted ~10s of agent wall time per forward-BAD verdict (retry the blocked `rm`, then fall back). Not a regression risk after the path-pattern fix, but worth confirming in the next AUTHOR rerun that BAD remediation closes in one shot.
