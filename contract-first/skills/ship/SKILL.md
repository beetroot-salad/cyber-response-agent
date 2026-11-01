---
name: ship
description: "Branch, commit, push, and open a PR for the current changes."
effort: low
---

# Ship Changes

Branch, commit, push, and open a PR.

The **default branch** is the one the remote repository reports, not a guess from local branch names.

- If already on a feature branch with an open PR, just push new commits.
- If on the default branch, create a branch. Derive the name from the changes.
- Derive commit message and PR title from the diff — don't ask the user.
- PR body: `## Summary` (2-4 bullets), `## Test plan`.
- Never commit secrets.
- Check if the branch is behind the default branch. If it is, rebase before pushing unless the owning workflow explicitly pins ancestry (write-code-from-tests does so with the recorded contract base/ref). For a pinned branch, follow that workflow's stop/escalation rule instead. If an allowed rebase has conflicts, stop and tell the user.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- ship §mechanics default-branch | ctx: github | `gh repo view --json defaultBranchRef -q .defaultBranchRef.name`.
- ship §mechanics secrets | ctx: past-runs | `.env` files, credentials, tokens.
