---
name: finalize
description: "Close out the green PR that write-code-from-spec shipped: apply every fix you're confident in inline, file the rest as follow-up issues, trace what escaped back to the stage that should have held it, feed process findings back to the human, and re-green the PR before the merge gate. Meets the code cold — it does not read the spec's rationale. Use after write-code-from-spec, as the last stage before a human merges."
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

You just met a class of bug the pipeline shipped green — data no other stage has: the upstream stages argued from inside the design; you were the first reader to see what landed. It shipped because it passed *every* stage that could have stopped it, so before naming a lever, nail down where the defense actually broke.

That diagnosis is a subagent's job, not yours. For each finding that is a real defect the suite let through (not a style nit), spawn a **tracer** on `references/trace.md` (sibling of this file) with the finding, the PR and issue numbers, and the spec ref. It walks the bug back through the record earliest-first — design-doc scope, graph demands, discharging tests, the human's fork resolutions, the write-tests frontier chain, linked transcripts — and returns an attribution *proven by a cited artifact*, or marked provisional where the trail is gone. The tracer reads everything you must not — rationale, handoff notes, transcripts — which is exactly why it is a subagent: dispatch it only after your review findings are settled, and take back its verdict, never the design's argument.

Its attributions feed two channels, deliberately different:

- **Deck-eligible findings** — the tracer marks them: intent was stated and the suite greened anyway — get their exploit shape **appended to `.claude/spec-flow-attacks.md`**, the attack deck the adversarial implementer replays against every future spec. Append it with your inline fixes so the entry rides this PR past the merge-gate human. This is the one pipeline artifact you write: an append-only factual record — each entry an artifact-proven exploit that shipped — never doctrine.
- **Process findings** — the lever candidates — go in your exit report, to the human at the merge gate; not into the skills, and not into an issue. **You never edit the pipeline's own skills or gates.** A single PR is one data point, and single-PR process intuitions are usually wrong until weighed against other PRs; that weighing is the human's, and the durable form — a memory, an issue, a rule change — is theirs to choose. Your job is to not lose the insight while the context is hot.

The split is load-bearing, not bookkeeping: the deck teaches the *adversary* (mechanical, automatic, exploit shapes), the exit report teaches *write-tests* (semantic, human-weighed, defect classes). A deck entry that restates a write-tests rule, or a process finding that is really "replay this exploit," collapses the two nets into one — and correlated nets miss the same things.

Choosing the lever stays yours, on cost and reliability, grounded on the tracer's diagnosis. If the class reduces to a **mechanical shape**, a gate may be the better fix outright — it is cheap and deterministic, where an upstream rule only shifts the odds. If the class is **semantic** — an unverified reachability claim, a test that can't discriminate — no gate can hold it and the fix has to go upstream, or it catches this one shape while the class leaks through others. Often it is both: the upstream rule *and* the gate as belt-and-suspenders. What you must not do is let low LOC stand in for the diagnosis — reach for the gate because the tracer showed you the miss, never to avoid the trace. Hand the human a grounded candidate, not a verdict: the finding at `file:line`, the tracer's attribution with its citations, the class, and the lever you'd pull. A *resolved-away* attribution — the human chose this reading — is not a miss; report it as a decision that played out, and skip the lever.

Be opportunistic about levers, dutiful about the deck: a deck entry costs three lines and pays on every future run, so append every deck-eligible escape — but most passes surface no systemic lever, and a manufactured one is noise. If the misses were one-offs, say so.

## Re-green, then hand off

If you pushed any commit, the PR's green is now a claim about the *old* code. Re-run the watch (`gh pr checks --watch`) and repair until it is green again — the human merge gate exists precisely because "the PR is green" is supposed to be true. A review that changed nothing is already green; say so and stop.

Exit by reporting: what you fixed inline, what you filed (with issue numbers), any attack-deck entries you appended, the process findings for the human (or that there were none), and the PR's final CI state. The human merges — you don't.
