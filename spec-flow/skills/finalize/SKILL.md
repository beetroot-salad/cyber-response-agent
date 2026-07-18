---
name: finalize
description: "Close out the green PR that write-code-from-spec shipped: apply every fix you're confident in inline, file the rest as follow-up issues, feed process findings back to the human, and re-green the PR before the merge gate. Meets the code cold — it does not read the spec's rationale. Use after write-code-from-spec, as the last stage before a human merges."
argument-hint: "[issue # or PR #]"
effort: xhigh
---

# Finalize

`write-code-from-spec`'s mirror: rather than writing code to satisfy a spec, this reads the shipped PR and makes it better — fixing what it can, filing what it can't, feeding what it learns back into the pipeline, and leaving the PR green for the human who merges it. It is the last stage before the merge gate, and the only one whose job is to *disagree* with what came before.

## Meet the code cold

**Do not read the spec's rationale.** The issue thread carries `write-tests`' handoff note and the discussion that produced the design — a record of which forks were resolved and why. That record is written for the implementer, not for you. A reviewer who has read the reasoning behind each choice will confirm it: the argument is right there, already made, and the cheapest thing a mind can do with a good argument is agree with it. Your value is the one thing the rest of the pipeline structurally cannot supply — a reader who has not been told what to think.

So: read the **code**, the **diff**, and the **tests as the contract they are**. Do not go looking for the design's justification of a choice you find questionable; if it looks wrong, say it looks wrong. If the design *did* settle it, the human at the merge gate will say so — that costs one comment. The reverse error, a reviewer talked out of a real finding by a persuasive design note, costs a bug.

One exception, and it is a different thing entirely: **the prior review trail.** Follow-up issues already filed against this work, and earlier review comments on the PR, are *review* output, not spec rationale. Read those (`gh pr view <n> --comments`, `gh issue list --search`), because they tell you what a previous pass already surfaced — and reconcile with them (below).

## Do the work

Run `/code-review --fix` over the PR, and then:

- **Apply every fix you're confident in, inline** — not just the trivial ones. Holding back to cosmetic changes wastes the pass; a fix you'd defend in a comment is a fix you should make.
- **Look past the diff.** A smell or a bug in the code this change touches or depends on counts, even when it isn't in the changed lines. The diff is where you start, not where you stop.
- **Reconcile against the prior review trail.** Do the cheap cleanups an earlier pass deferred; fix — or file — the out-of-diff bugs it noted and moved on from. Leave only genuine design choices for a human.
- **File a follow-up issue for anything you surface but don't fix**, naming the finding and where it lives (`file:line`). A finding that exists only in a chat message is a finding that is already lost.

Fix honestly: never green the build by weakening a test, suppressing a type error, or baselining a finding this change introduced. The tests are the approved spec — if one of them is genuinely wrong, that is a finding to raise, not a line to edit.

## Feed the pipeline

You just met a class of bug the pipeline shipped green — data no other stage has: the upstream stages argued from inside the design; you were the first reader to see what landed. When a finding has a *systemic* lever — a stage that should have caught it, not just this one line — name it.

It shipped green because it passed *every* stage that could have stopped it, so walk it back earliest-first and find where the defense should have held:

- **`discuss-issue`** — was the class never scoped, so the design never had to answer for it?
- **`write-tests`** — was there a demand a non-discriminating test discharged, or no demand at all?
- **a mechanical net** — would a lint gate or CI check fire on the shape regardless of who wrote it?

That walk is diagnosis, not the verdict — it tells you where the defense *should* have held, so you understand the miss instead of papering over it. Choosing the lever is a separate call, on cost and reliability. If the class reduces to a **mechanical shape**, a gate may be the better fix outright — it is cheap and deterministic, where an upstream rule only shifts the odds. If the class is **semantic** — an unverified reachability claim, a test that can't discriminate — no gate can hold it and the fix has to go upstream, or it catches this one shape while the class leaks through others. Often it is both: the upstream rule *and* the gate as belt-and-suspenders. What you must not do is let low LOC stand in for the diagnosis — reach for the gate because you understood the miss, never to avoid it.

For each, hand the human a grounded candidate, not a verdict: the finding at `file:line` (the evidence — a lever with no bug behind it is a guess), the class, the stage where it slipped, and the lever you'd pull.

This goes in your exit report, to the human at the merge gate — not into the skills, and not into an issue. **You never edit the pipeline's own skills or gates.** A single PR is one data point, and single-PR process intuitions are usually wrong until weighed against other PRs; that weighing is the human's, and the durable form — a memory, an issue, a rule change — is theirs to choose. Your job is to not lose the insight while the context is hot.

Be opportunistic, not dutiful: most passes surface no systemic lever, and a manufactured one is noise. If the misses were one-offs, say so and skip this.

## Re-green, then hand off

If you pushed any commit, the PR's green is now a claim about the *old* code. Re-run the watch (`gh pr checks --watch`) and repair until it is green again — the human merge gate exists precisely because "the PR is green" is supposed to be true. A review that changed nothing is already green; say so and stop.

Exit by reporting: what you fixed inline, what you filed (with issue numbers), the process findings for the human (or that there were none), and the PR's final CI state. The human merges — you don't.
