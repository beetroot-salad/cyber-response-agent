---
name: review
description: "Review the green PR that write-code-from-spec shipped: apply every fix you're confident in inline, file the rest as follow-up issues, and re-green the PR before handing it to the human merge gate. Meets the code cold — it does not read the spec's rationale. Use after write-code-from-spec, as the last stage before a human merges."
argument-hint: "[issue # or PR #]"
effort: xhigh
---

# Review

`write-code-from-spec`'s mirror: rather than writing code to satisfy a spec, this reads the shipped PR and makes it better — fixing what it can, filing what it can't, and leaving the PR green for the human who merges it. It is the last stage before the merge gate, and the only one whose job is to *disagree* with what came before.

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

## Re-green, then hand off

If you pushed any commit, the PR's green is now a claim about the *old* code. Re-run the watch (`gh pr checks --watch`) and repair until it is green again — the human merge gate exists precisely because "the PR is green" is supposed to be true. A review that changed nothing is already green; say so and stop.

Exit by reporting: what you fixed inline, what you filed (with issue numbers), and the PR's final CI state. The human merges — you don't.
