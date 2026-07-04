---
name: write-code-from-spec
description: "Turn an approved design and its pre-written test spec into shipped, CI-green code. Work in an isolated worktree, read the issue/design and the committed tests, implement real code until the suite passes locally, ship a PR that closes the issue, then watch CI and repair failures until green — honestly (fix the cause, never weaken a test or a gate) and within a bounded repair loop that hands a stuck run back to a human with the PR and session linked. Use after write-tests, once the spec is approved; it is write-tests' mirror — write-tests pins intent as tests, write-code-from-spec makes the code match."
argument-hint: "[issue # or design doc path]"
---

# Write code from spec

The pre-written tests are the spec. This phase writes the real code that makes them pass and ships it green. Run it after `write-tests` and the human's approval of the spec, and before `review`. Inputs: the issue or design doc, and the approved test suite — committed on the branch by write-tests, or sitting in the working tree.

One rule sits above the rest and makes this phase the mirror of write-tests: **you make the code match the tests, never the tests match the code.** The suite is the contract the human approved. If a test looks wrong, that is a spec question, not a green-the-build task — surface it (§2), don't quietly edit it. A suite you weakened to pass is no longer a spec.

## 0. Work in an isolated worktree

Never implement in the main checkout. This phase edits source, runs the full test/lint suite, pushes, and re-pushes fixes across a multi-minute CI loop — all of which must not touch the developer's working tree or race another card's edits (in this repo, parallel edit-agents sharing one worktree have silently clobbered each other's uncommitted work via a stray `git stash`/`git checkout`).

- **Orchestrator flow:** the worktree already exists — `write-tests` created it and committed the approved tests there, and `write-code-from-spec → review` share it (`card.worktree_path`, branch `flow/issue-<n>`). Adopt that tree; don't make a second one.
- **Manual flow:** create one before writing any code — `git worktree add ../wt-issue-<n> -b <branch>` (or `EnterWorktree`) — and do everything below inside it.

Confirm you're in the worktree (`git rev-parse --show-toplevel`) before step 1. On failure the tree is *kept*, not removed, so `claude --resume` and retry reuse the exact state (§5); only a cancel discards it.

## 1. Plan against the spec

Load the issue/design (`gh issue view <n> --comments`, or read the doc) for intent, then read the committed tests — they are the precise version. The tests already encode the resolved forks: each one names an injected fault or input and the observable outcome the code must produce, and each drives a specific entry point through specific injection seams. Before writing anything, know:

- the entry point(s) under test and their signatures,
- the seams the fakes enter through (a `deps` param, a constructor arg) — the implementation must expose *exactly* those; a test can't reach a seam the code doesn't offer,
- the return-value / error / side-effect contract each test asserts.

The prose says why; the tests say what. Where they disagree, the approved tests win — or it's a fork to surface.

## 2. Implement to green — locally, against the whole gate

Write real code until the suite passes. Run the same command CI runs, not a subset:

```
cd defender && uv run pytest tests/ learning/ -m "not llm and not live"
```

Then mirror the *rest* of CI locally **before shipping** — here CI is far more than pytest, and a change that's pytest-green still bounces off the lint and type gates. The hard gates, from `.github/workflows/ci.yml` (the source of truth — run what it runs; don't trust this list to stay current):

- `defender/.venv/bin/ruff check . --select E,F --ignore E402,E501` (repo-wide) and `ruff check defender` (extended families),
- `defender/.venv/bin/mypy --config-file defender/pyproject.toml`,
- the baseline-ratcheted custom lints under `scripts/lint/lint_*.py` (monkeypatch, unsafe-jsonl-io, raw-git-subprocess, unanchored-default, vulture, duplicate-helpers, …) — each blocks only on a *new* finding, and each has an inline-suppression escape hatch documented in its own module.

Running these locally collapses the CI-repair loop in §4 from minutes-per-round to seconds. (Running in a git worktree? The shared `.venv` editable install points at the main checkout — prepend `PYTHONPATH=<worktree-root>` to the pytest call or you test the wrong tree.)

Fix the cause, not the test. If making the code honest genuinely requires a test to change — the spec had a bug, or a fork was never actually resolved — stop and kick it back to the human as a spec question; shipping code that passes a quietly-loosened test defeats the whole pipeline.

## 3. Ship

Ship the change — see the `ship` skill for the branch/commit/push/open-PR mechanics. By step 0 you're already on the card's branch inside the worktree, so this is a push-and-open (the orchestrator flow); run standalone against a plain checkout it still branches first. Two additions specific to this phase:

- **Link the issue** in the PR body (`Closes #<n>`) so the merge closes it.
- **Report the PR number** as part of the outcome — on failure as well as success, so a PR that opened but never greened stays linked and `claude --resume`-able.

## 4. Watch CI and repair — bounded, honest

`gh pr checks --watch` blocks until every required check settles and aggregates them all — no per-suite bookkeeping. Green → §5.

On red, one round is: `gh pr checks` to see which check failed → `gh run view <run-id> --log-failed` to read the actual failure → fix the real cause → push → re-watch. Two disciplines keep the loop safe:

- **Honest repair only.** Green the build by fixing what's broken — never by weakening a test, sprinkling `# type: ignore`, or baselining a finding your change introduced. (Adding to a lint baseline is legitimate *only* for a genuinely-accepted new pattern, annotated in the PR — never a way to dodge a real finding.)
- **Bounded loop.** Cap the repair attempts (or a time/cost budget). Each round must make progress; when the cap trips, or two rounds don't move the needle, stop rather than thrash — an unbounded fix loop burns credits and holds the slot forever.

## 5. Exit

- **Succeeded** — the PR is green. Hand off to `review`.
- **Failed to a human** — the bound tripped, or the honest fix is a spec change you can't make here. Say what's red, why you stopped, and leave the PR number and branch intact so `claude --resume` picks up the exact state. Failing out cleanly is a designed outcome, not a defect — the human supplies the judgment the loop couldn't.
