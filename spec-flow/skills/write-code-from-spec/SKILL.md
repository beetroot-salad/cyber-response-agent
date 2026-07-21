---
name: write-code-from-spec
description: "Turn a settled design and its pre-written test spec into shipped, CI-green code. Work in an isolated worktree, read the issue/design and the committed tests, implement real code until the suite passes locally, ship a PR that closes the issue, then watch CI and repair failures until green — honestly (fix the cause, never weaken a test or a gate) and within a bounded repair loop that hands a stuck run back to a human with the PR and session linked. Also looses an adversarial implementer against the spec in parallel, so non-discriminating tests surface before merge. Use after write-tests has committed and pushed the spec; it is write-tests' mirror — write-tests pins intent as tests, write-code-from-spec makes the code match."
argument-hint: "[issue # or design doc path]"
effort: medium
---

# Write code from spec

The pre-written tests are the spec. This phase writes the real code that makes them pass and ships it green. Run it after `write-tests` has committed and pushed the spec, and before `finalize`. Inputs: the issue or design doc, the committed spec — the tests plus `spec_graph_*.yaml` on write-tests' branch — and the **project profile** (`.claude/spec-flow.json`), which carries what this skill does not hardcode: the gate commands to run before shipping, the project's traps, and how to invoke the spec_graph checks. Read the profile first; if it is missing, run `/spec-flow:init`.

One rule sits above the rest and makes this phase the mirror of write-tests: **you make the code match the tests, never the tests match the code.** The committed suite is the contract. If a test looks wrong, that is a spec question, not a green-the-build task — surface it (§3), don't quietly edit it. A suite you weakened to pass is no longer a spec.

## 0. Work in an isolated worktree

Never implement in the main checkout. This phase edits source, runs the full test/lint suite, pushes, and re-pushes fixes across a multi-minute CI loop — all of which must not touch the developer's working tree or race another job's edits (parallel edit-agents sharing one worktree have silently clobbered each other's uncommitted work via a stray `git stash`/`git checkout`).

**Adopt the branch that carries the committed spec** — `git worktree add ../wt-issue-<n> <spec-branch>` (or `EnterWorktree` onto it) — and do everything below inside it. Minting a fresh `-b` branch from the default branch leaves §1 with no spec commits to gate. If a worktree for that branch already exists (whatever created it — `write-tests`, or a caller that drives this pipeline), adopt it rather than making a second one.

Confirm you're in the worktree (`git rev-parse --show-toplevel`) before step 1. On failure the tree is *kept*, not removed, so `claude --resume` and retry reuse the exact state (§6); only a cancel discards it.

## 1. Plan against the spec

**Gate the inputs first.** The spec must exist as a discrete, committed, reviewable artifact *before* any implementation: check that the spec ref's diff (`git diff --stat <base>...<spec-ref>` — three-dot, so commits that landed on `<base>` after the spec forked don't masquerade as spec changes) touches only test files and `spec_graph_*.yaml`. The spec ref is the branch tip write-tests committed; the artifact's `base:` field records the fork point. If the tests are uncommitted, or the spec commit mixes in source, stop and kick it back to write-tests. This is not ceremony: co-committing tests+impl in one change has repeatedly shipped bug classes whose lessons were already written down — a spec phase that never ran discretely can't bite.

**Then gate the spec's granularity that is observable before code exists.** Run `spec-graph binds <artifact>` over the committed graph (`spec-graph` is on your PATH — the plugin ships it). A prose⊄binds orphan (an invariant the tests will silently drop) is a **spec defect**, exactly like a wrong-looking test — surface it (§3) and kick it back to write-tests; don't implement against a spec you already know is coarse. If the graph carries a conscious `binds_waivers:` entry for the finding, that's a resolved decision — proceed. The actors check is not meaningful yet: it derives its target set from the production-code diff, which this branch does not have until §3.

Load the issue/design (`gh issue view <n> --comments`, or read the doc) for intent, then read the committed tests — they are the precise version. Among those comments is **write-tests' handoff note**: it is addressed to you, and it carries what the diff cannot show — which forks the human resolved and which reading they picked, what ran degraded, and the next action. Read it before the tests, and treat a conflict between it and the committed tests as a fork to surface (§3), not a choice to make quietly. The tests already encode the resolved forks: each one names an injected fault or input and the observable outcome the code must produce, and each drives a specific entry point through specific injection seams. Before writing anything, know:

- the entry point(s) under test and their signatures,
- the seams the fakes enter through (a `deps` param, a constructor arg) — the implementation must expose *exactly* those; a test can't reach a seam the code doesn't offer,
- the return-value / error / side-effect contract each test asserts.

Then read `spec_graph_*.yaml` alongside the tests (vocabulary and address forms: the `write-tests` skill's `references/schema.md`, a sibling of this skill in the plugin): the implementation must **realize its address space** — expose exactly the declared seams, build payloads with the declared part-structure (a `parts` list of `{role, source}` entries means the template is never *also* the system prompt), interpolate every axis the identity facets require. Reconcile at the address-space altitude — seams, payload parts, identity axes, domain members; internal helpers and private modules are not "invented scope". A structural mismatch — an address the code never realizes, or contract-level structure the spec never declared — is a spec question, exactly like a wrong-looking test. A `form: test` demand is a pointer: its `discharged_by` names the test that carries the contract prose, its `binds` the addresses — read the test for the *what*, the demand for the *addresses* — so a demand with no `outcome` is expected, not incomplete.

The prose says why; the tests say what. Where they disagree, the committed tests win — or it's a fork to surface.

## 2. Loose the adversary

The suite you are about to satisfy claims to discriminate — that green cannot be reached by code that betrays the intent. The adversary is the empirical check on that claim, run while you implement. Once §1's gates pass and **before you write any code**, spawn one **Opus subagent** on `references/adversary.md` (sibling of this file). Its dispatch is a pointer, not a payload: the charge path, a fresh worktree detached at the spec ref (`git worktree add --detach ../wt-issue-<n>-adversary <spec-ref>` — detached, because the spec branch is already checked out here; it must fork from the same ignorance you did and never see your code), the profile path, the spec_graph path, the issue number, and the attack deck path (`.claude/spec-flow-attacks.md`). Its game: green `gate.test` with code that violates a stated intent; every exploit that works is a non-discriminating test, named before it can hide a real bug.

Collect it before you ship (§4). Its findings are **spec defects**, routed like §1's graph findings — post them to the issue thread, and the merge-gate human decides per hole: kick back to write-tests to tighten, or accept with the record. Never a reason to edit the suite yourself, and never a repair task. If it is still running at your ship point, ship and record that the adversarial pass ran incomplete; if it found nothing, record that too — no findings is a sample, not a certificate.

## 3. Implement to green — locally, against the whole gate

Write real code until the suite passes. Run the same command CI runs, not a subset — the profile's `gate.test`.

Then mirror the *rest* of CI locally **before shipping**. CI is almost always more than the test suite, and a change that is test-green still bounces off the lint and type gates; each round-trip through CI to discover that costs minutes, and running them locally collapses the §5 repair loop to seconds. The profile's `gate.checks` lists them, and `gate.notes` carries the project's traps (a venv that resolves to the wrong tree from a worktree, an env var the suite needs). The profile's `gate.ciConfig` is the **source of truth** — read it and run what it actually runs; a hand-maintained list drifts, so when the two disagree, believe the CI config and fix the profile.

**Close the two loops the graph couldn't.** Now that the code exists, two granularity checks run against reality rather than the spec:

- **Run `spec-graph actors <artifact> --base <base>`** — the census now diffs over the *real* implementation, so it catches an execution context the code reaches that the spec never modelled — a caller you added, or a guard you introduced that makes an existing harness/subprocess context newly load-bearing. An unmodelled re-exec driver is a spec question to kick back, not a green-the-build edit.
- **Probe any guard the change adds or tightens** — the input-partition slice `check_binds`/`check_actors` structurally cannot see. State the guard's invariant (e.g. `resolve(operand)` stays within `resolve(root)`) and fuzz it, and treat a surviving mutation of the guard's own checks (delete the `..` reject, the whitespace reject) as an under-tested partition. This is the impl-time lane — the invalid domain is defined by the invariant, not by the code's existing branches, so characterizing "same as the old guard" imports the old guard's blind spots.

**Close every deferred claim.** Enumerate both the claims ledger's `verdict: deferred` entries and `handoff.deferred`; probe each against the implementation and record its claim id, exact probe, observation, and resulting verdict in the PR body under `## Deferred claims`. Do not edit the committed spec_graph merely to record implementation evidence. A refuted claim or one that still cannot be answered is a spec question: post the evidence to the issue and stop for the human; only settled results proceed to shipping.

Fix the cause, not the test. If making the code honest genuinely requires a test to change — the spec had a bug, or a fork was never actually resolved — stop and kick it back to the human as a spec question; shipping code that passes a quietly-loosened test defeats the whole pipeline.

## 4. Ship

Ship the change — see the `ship` skill for the branch/commit/push/open-PR mechanics. This branch's ancestry is pinned by the spec_graph `base:` field: do **not** apply `ship`'s default rebase-before-push rule. If the repository requires an up-to-date branch, stop for a human rather than rewriting the spec branch beneath its recorded base. By step 0 you are already on the spec's branch inside the worktree, so this is a push-and-open, not a fresh branch. Three additions specific to this phase:

- **Link the issue** in the PR body (`Closes #<n>`) so the merge closes it.
- **Carry the adversary's verdict** in the PR body — each hole with its violated clause, or that it ran clean at its bound (or incomplete) — so the merge-gate human weighs the spec's tightness alongside the code.
- **Report the PR number** as part of the outcome — on failure as well as success, so a PR that opened but never greened stays linked and `claude --resume`-able.

## 5. Watch CI and repair — bounded, honest

`gh pr checks --watch` blocks until every required check settles and aggregates them all — no per-suite bookkeeping. Green → §6.

On red, one round is: `gh pr checks` to see which check failed → `gh run view <run-id> --log-failed` to read the actual failure → fix the real cause → push → re-watch. Two disciplines keep the loop safe:

- **Honest repair only.** Green the build by fixing what's broken — never by weakening a test, sprinkling `# type: ignore`, or baselining a finding your change introduced. (Adding to a lint baseline is legitimate *only* for a genuinely-accepted new pattern, annotated in the PR — never a way to dodge a real finding.)
- **Bounded loop.** Cap the repair attempts (or a time/cost budget). Each round must make progress; when the cap trips, or two rounds don't move the needle, stop rather than thrash — an unbounded fix loop burns credits and holds the slot forever.

## 6. Exit

- **Succeeded** — the PR is green. Hand off to `finalize`.
- **Failed to a human** — the bound tripped, or the honest fix is a spec change you can't make here. Say what's red, why you stopped, and leave the PR number and branch intact so `claude --resume` picks up the exact state. Failing out cleanly is a designed outcome, not a defect — the human supplies the judgment the loop couldn't.
