---
name: ship
description: "Branch, commit, push, and open a PR for the current changes."
effort: low
---

# Ship Changes

Branch, commit, push, and open a PR.

The **default branch** is `main` unless the project profile (`.claude/spec-flow.json`) sets `conventions.defaultBranch`.

- If already on a feature branch with an open PR, just push new commits.
- If on the default branch, create a branch. Derive the name from the changes.
- Derive commit message and PR title from the diff — don't ask the user.
- PR body: `## Summary` (2-4 bullets), `## Test plan`.
- Never commit secrets (`.env`, credentials, tokens).
- Check if the branch is behind the default branch. If it is, rebase before pushing unless the owning workflow explicitly pins ancestry (write-code-from-spec does so with the spec_graph's `base:` field). For a pinned branch, follow that workflow's stop/escalation rule instead. If an allowed rebase has conflicts, stop and tell the user.
