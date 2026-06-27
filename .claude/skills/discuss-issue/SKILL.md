---
name: discuss-issue
description: "Take an issue from a bare report to a finalized design. Explain the problem to a system-fluent reader, then interrogate it from several angles — whether to do it at all, the real root cause, what makes it non-trivial, correctness, completeness, scope, clarity; seed a design discussion with the alternative fixes and their tradeoffs and a recommendation; run the discussion to close the open forks; then finalize as a design doc or a refined issue. Use when a GitHub issue needs to become a design before anyone implements it."
argument-hint: "[issue number]"
---

# Discuss issue

Turn a bare issue into a finalized design — one that is consistent with the current state of the codebase, simple enough, and elegant. The arc: **explain** the issue, **analyze** it from several angles (including what makes it hard), **seed** the discussion (the alternative fixes with tradeoffs and a recommendation), **discuss** to close the open forks, then **finalize** — as a design doc or a refined issue. All in chat.

## 1. Explain the issue

Load it first. If an issue number was passed as an argument, that's the issue to load; otherwise take it from the conversation. Default to a GitHub issue: `gh issue view <n> --comments`. Read the comments — a partial discussion may already be underway, so don't re-seed points already settled there. If given a file path or pasted text instead, work from that.

Then explain the issue — what the problem is, where in the code it lives, and why it surfaces — to a colleague who knows the system and the domain well but hasn't seen this issue or the code it touches. Calibrate to that reader:
- Don't re-explain what the system is or does — they know. Spend the words on *this* problem and its specific mechanism.
- Define any term that's project-specific or coined, and for a term that could be either, say whether it's standard or bespoke. Don't belabor genuinely standard terms.

The point is twofold: it forces you to ground in the actual repo rather than parrot the report, and it confirms you're solving the right problem. If you can't explain the mechanism without hand-waving, you don't understand it yet — go read the code until you can.

## 2. Analyze

Interrogate the issue from the angles below. They are lenses to think through, not a checklist to tick off and not a template for the output. Ground every claim in the actual repo — the issue is a starting point, not a source of truth.

**Should we even do this?** — is the problem real and worth solving now? What's the cost of doing nothing, and does a fix earn the complexity it adds? The honest answer is sometimes "won't fix" or "not yet" — surface that rather than designing past it.

**Why is it an issue — and what's the root cause?** — why does this surface at all? Is the reported symptom the actual problem, or a downstream effect of a deeper cause? Fixing the symptom often papers over the fix that matters. Trace it to the root and decide which level is the one worth fixing.

**What makes this non-trivial?** — why isn't this a one-liner? Name the hard part: the constraints in tension, the invariant that's easy to break, the existing structure the change fights against, the case that resists a clean solution. This is the crux the design has to crack, and it's where the forks in §3 come from. An issue with no crux probably doesn't need this skill.

**Correctness** — verify each factual claim against the codebase. Issues routinely assert "X works like Y" or "Z handles W" from stale memory. Grep and read the named files; flag every claim that conflicts with current code and cite `file:line`. When the claim surface is broad, delegate verification to an Explore subagent. A design built on a false premise is wasted work — this angle gates the rest.

**Completeness** — what's missing to design or act: the motivation (what breaks without it), done criteria (how we'd know it's solved), and constraints, dependencies, or prior art (linked issues, PRs, `defender/docs/`).

**Scope** — what the change is and isn't: what's in, the explicit non-goals, the affected components / blast radius, and whether two problems are wearing one issue (split them).

**Clarity** — name each ambiguity and its candidate readings. Flag undefined referents and terms used loosely.

Then synthesize — don't enumerate. The output is a few tight paragraphs that tell the design's story: what's actually true after grounding, the root cause, the crux that makes it hard, whether it's worth doing, what's in and out of scope. Lead with what's load-bearing and drop angles that surfaced nothing. Do **not** emit one labeled line per angle — that's the checklist this section exists to avoid.

## 3. Seed

You now have the Explanation (§1) and the Analysis (§2). Add the design forks to complete the seed:

- **Alternative fixes** — turn the crux and the open gaps into the real design forks, not trivia. Each fork is a decision the design must make; for each, give 2–3 viable options with their tradeoffs. Order by what unblocks the most downstream choices. Drop anything already resolved in the issue or its comments.
- **Recommendation** — for each fork, your pick and the reason.

The forks should fall out of the challenges named in the analysis. If a fork doesn't trace to something the analysis surfaced, it's probably trivia — cut it.

## 4. Discuss

Resolve the open forks with the user, highest-leverage first.
- Where there's a genuine fork, ask (AskUserQuestion) with your recommendation first.
- Where the codebase or an existing convention dictates the answer, state it and move on — don't manufacture a choice.
- Pull in fresh grounding (read code, check `defender/docs/` and conventions) as resolved forks raise new questions.
- Track resolved vs open out loud. Loop until the open set is empty.

## 5. Finalize

Once the open set is empty, close out one of two ways — match the weight of the outcome:

**Design doc** — when the result is a real design worth its own artifact. Present it in chat in the shape of an existing `defender/docs/*-design.md`:
- **Status** — design; what it depends on or supersedes
- **What this is** — the mechanism in a paragraph
- **Design** — how it works; the load-bearing decisions and why each
- **Kept / dropped** — what's in scope and what's explicitly not
- **Open questions** — anything deferred, and what would close it

Offer to write it to `defender/docs/<name>-design.md`.

**Refined issue** — when the outcome is better folded back into the issue than spun into a doc (smaller change, or the issue is the right home). Rewrite the issue body so it states the resolved problem, scope, chosen approach, and done criteria — no longer a bare report.

Pick by the change's weight; when unsure, ask. Write the doc or update the issue only on the user's go-ahead.
